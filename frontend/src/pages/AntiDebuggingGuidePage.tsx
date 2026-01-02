import React from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  Button,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  alpha,
  useTheme,
  Divider,
  Alert,
  AlertTitle,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import SchoolIcon from "@mui/icons-material/School";
import TerminalIcon from "@mui/icons-material/Terminal";
import SearchIcon from "@mui/icons-material/Search";
import WarningIcon from "@mui/icons-material/Warning";
import TimerIcon from "@mui/icons-material/Timer";
import MemoryIcon from "@mui/icons-material/Memory";
import PsychologyIcon from "@mui/icons-material/Psychology";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";
import LockIcon from "@mui/icons-material/Lock";
import ShieldIcon from "@mui/icons-material/Shield";
import StorageIcon from "@mui/icons-material/Storage";
import SettingsIcon from "@mui/icons-material/Settings";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import SpeedIcon from "@mui/icons-material/Speed";
import ExtensionIcon from "@mui/icons-material/Extension";
import ComputerIcon from "@mui/icons-material/Computer";
import AndroidIcon from "@mui/icons-material/Android";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import { useNavigate, Link } from "react-router-dom";

// Question bank for the quiz (75 questions)
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

const questionBank: QuizQuestion[] = [
  // Section 1: What is Anti-Debugging (6 questions)
  {
    id: 1,
    question: "What is the primary purpose of anti-debugging techniques?",
    options: [
      "To make software run faster",
      "To detect and prevent analysis by debuggers",
      "To encrypt network traffic",
      "To compress executable files"
    ],
    correctAnswer: 1,
    explanation: "Anti-debugging techniques are designed to detect when a debugger is attached and either alter behavior, crash, or terminate to prevent analysis.",
    topic: "What is Anti-Debugging"
  },
  {
    id: 2,
    question: "Which type of software commonly uses anti-debugging techniques?",
    options: [
      "Only malware uses anti-debugging",
      "Only games use anti-debugging",
      "Both legitimate software (DRM, anti-cheat) and malware",
      "Only open-source software"
    ],
    correctAnswer: 2,
    explanation: "Anti-debugging is used by both legitimate software (games, DRM, licensing) and malicious software (malware, ransomware) to prevent analysis.",
    topic: "What is Anti-Debugging"
  },
  {
    id: 3,
    question: "What is the 'cat-and-mouse game' in anti-debugging?",
    options: [
      "A specific debugging technique",
      "The ongoing cycle of new protections and bypasses being developed",
      "A type of malware",
      "A Windows API function"
    ],
    correctAnswer: 1,
    explanation: "The cat-and-mouse game refers to the continuous cycle where developers create new anti-debug techniques and analysts develop bypasses, leading to ever-evolving protections.",
    topic: "What is Anti-Debugging"
  },
  {
    id: 4,
    question: "What happens when anti-debugging code detects a debugger?",
    options: [
      "It always displays an error message",
      "It may crash, terminate, behave differently, or corrupt data",
      "It automatically patches the debugger",
      "It sends an email to the developer"
    ],
    correctAnswer: 1,
    explanation: "When a debugger is detected, anti-debugging code may terminate the process, crash intentionally, alter its behavior, corrupt sensitive data, or take other evasive actions.",
    topic: "What is Anti-Debugging"
  },
  {
    id: 5,
    question: "Why is understanding anti-debugging important for security analysts?",
    options: [
      "To create better malware",
      "To bypass protections during legitimate analysis and malware research",
      "To sell exploits",
      "To avoid using debuggers entirely"
    ],
    correctAnswer: 1,
    explanation: "Security analysts need to understand and bypass anti-debugging to analyze malware samples, perform vulnerability research, and understand software behavior.",
    topic: "What is Anti-Debugging"
  },
  {
    id: 6,
    question: "What is a 'red team' perspective on anti-debugging?",
    options: [
      "Bypassing anti-debugging protections",
      "Implementing anti-debugging to protect software",
      "Reporting anti-debugging as a vulnerability",
      "Ignoring anti-debugging entirely"
    ],
    correctAnswer: 1,
    explanation: "From a red team (offensive) perspective, anti-debugging is about implementing protections. Blue team (defensive) focuses on bypassing them for analysis.",
    topic: "What is Anti-Debugging"
  },

  // Section 2: Windows API-Based Checks (8 questions)
  {
    id: 7,
    question: "What does IsDebuggerPresent() return when a debugger is attached?",
    options: [
      "0 (FALSE)",
      "Non-zero (TRUE)",
      "-1",
      "The debugger's PID"
    ],
    correctAnswer: 1,
    explanation: "IsDebuggerPresent() returns a non-zero value (TRUE) if the calling process is being debugged by a user-mode debugger.",
    topic: "Windows API Checks"
  },
  {
    id: 8,
    question: "What is the easiest way to bypass IsDebuggerPresent()?",
    options: [
      "Delete the kernel32.dll file",
      "Hook the function to always return 0, or set PEB.BeingDebugged to 0",
      "Restart the computer",
      "Use a different operating system"
    ],
    correctAnswer: 1,
    explanation: "IsDebuggerPresent() simply reads the PEB.BeingDebugged flag. Hooking the API or directly setting this flag to 0 bypasses the check.",
    topic: "Windows API Checks"
  },
  {
    id: 9,
    question: "What is the difference between IsDebuggerPresent and CheckRemoteDebuggerPresent?",
    options: [
      "They are identical functions",
      "CheckRemoteDebuggerPresent can check other processes and detects kernel debuggers",
      "IsDebuggerPresent is faster",
      "CheckRemoteDebuggerPresent only works on Windows 10"
    ],
    correctAnswer: 1,
    explanation: "CheckRemoteDebuggerPresent can check if any process (including itself) is being debugged and can detect kernel-mode debuggers, unlike IsDebuggerPresent.",
    topic: "Windows API Checks"
  },
  {
    id: 10,
    question: "Which ProcessInformationClass value detects the debug port?",
    options: [
      "ProcessBasicInformation (0)",
      "ProcessDebugPort (7)",
      "ProcessImageFileName (27)",
      "ProcessHandleCount (20)"
    ],
    correctAnswer: 1,
    explanation: "NtQueryInformationProcess with ProcessDebugPort (7) returns a non-zero value if a debugger is attached, indicating the debug port is in use.",
    topic: "Windows API Checks"
  },
  {
    id: 11,
    question: "What does ProcessDebugFlags (0x1F) return when being debugged?",
    options: [
      "1",
      "0",
      "The debugger name",
      "-1"
    ],
    correctAnswer: 1,
    explanation: "ProcessDebugFlags returns 0 when being debugged (NoDebugInherit flag is cleared), and 1 when NOT being debugged.",
    topic: "Windows API Checks"
  },
  {
    id: 12,
    question: "Which Windows API can hide a thread from the debugger?",
    options: [
      "CreateThread",
      "NtSetInformationThread with ThreadHideFromDebugger",
      "TerminateThread",
      "SuspendThread"
    ],
    correctAnswer: 1,
    explanation: "NtSetInformationThread with ThreadHideFromDebugger (0x11) makes a thread invisible to debuggers - breakpoints won't trigger and the thread can't be traced.",
    topic: "Windows API Checks"
  },
  {
    id: 13,
    question: "What is ProcessDebugObjectHandle used for?",
    options: [
      "Getting the debugger's window handle",
      "Checking if a debug object exists (indicates debugging)",
      "Creating a new debugger",
      "Listing all debuggers on the system"
    ],
    correctAnswer: 1,
    explanation: "ProcessDebugObjectHandle (0x1E) retrieves the debug object handle. If one exists (non-zero), the process is being debugged.",
    topic: "Windows API Checks"
  },
  {
    id: 14,
    question: "Why might malware call NtQueryInformationProcess directly instead of IsDebuggerPresent?",
    options: [
      "It's faster",
      "To avoid API hooks placed on higher-level functions",
      "It uses less memory",
      "It works on Linux too"
    ],
    correctAnswer: 1,
    explanation: "Calling native NT functions directly bypasses potential hooks on Win32 API wrappers like IsDebuggerPresent, making detection harder to bypass.",
    topic: "Windows API Checks"
  },

  // Section 3: PEB & TEB Flag Checks (7 questions)
  {
    id: 15,
    question: "What does PEB stand for?",
    options: [
      "Process Execution Block",
      "Process Environment Block",
      "Primary Entry Block",
      "Program Entry Base"
    ],
    correctAnswer: 1,
    explanation: "PEB stands for Process Environment Block, a structure containing process-wide information including debugging flags.",
    topic: "PEB & TEB Flags"
  },
  {
    id: 16,
    question: "At what offset is BeingDebugged located in the 64-bit PEB?",
    options: [
      "0x00",
      "0x02",
      "0x68",
      "0xBC"
    ],
    correctAnswer: 1,
    explanation: "The BeingDebugged flag is at offset 0x02 in both 32-bit and 64-bit PEB structures.",
    topic: "PEB & TEB Flags"
  },
  {
    id: 17,
    question: "What value does NtGlobalFlag have when a process is created by a debugger?",
    options: [
      "0x00",
      "0x70 (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)",
      "0xFF",
      "0x01"
    ],
    correctAnswer: 1,
    explanation: "When created under a debugger, NtGlobalFlag is typically set to 0x70, enabling various heap debugging features.",
    topic: "PEB & TEB Flags"
  },
  {
    id: 18,
    question: "Which heap flags indicate debugger presence?",
    options: [
      "HEAP_GROWABLE",
      "Flags and ForceFlags fields showing debug heap values",
      "HEAP_NO_SERIALIZE",
      "HEAP_GENERATE_EXCEPTIONS"
    ],
    correctAnswer: 1,
    explanation: "The heap's Flags and ForceFlags fields contain debug-specific values (like HEAP_TAIL_CHECKING_ENABLED) when the process is created under a debugger.",
    topic: "PEB & TEB Flags"
  },
  {
    id: 19,
    question: "How can you access the PEB from assembly on x64 Windows?",
    options: [
      "mov rax, [rip]",
      "mov rax, gs:[0x60]",
      "mov rax, fs:[0x30]",
      "call GetPEB"
    ],
    correctAnswer: 1,
    explanation: "On 64-bit Windows, the PEB is accessed via gs:[0x60]. On 32-bit, it's fs:[0x30].",
    topic: "PEB & TEB Flags"
  },
  {
    id: 20,
    question: "What is the TEB?",
    options: [
      "Thread Execution Block",
      "Thread Environment Block",
      "Task Entry Base",
      "Thread Entry Block"
    ],
    correctAnswer: 1,
    explanation: "TEB stands for Thread Environment Block, containing thread-specific information. It contains a pointer to the PEB.",
    topic: "PEB & TEB Flags"
  },
  {
    id: 21,
    question: "How does ScyllaHide bypass PEB-based checks?",
    options: [
      "It deletes the PEB",
      "It modifies the PEB fields (BeingDebugged, NtGlobalFlag, Heap flags) to non-debug values",
      "It creates a fake PEB",
      "It disables the Windows kernel"
    ],
    correctAnswer: 1,
    explanation: "ScyllaHide patches the PEB structure, setting BeingDebugged to 0, clearing NtGlobalFlag debug bits, and fixing heap flags.",
    topic: "PEB & TEB Flags"
  },

  // Section 4: Timing-Based Detection (7 questions)
  {
    id: 22,
    question: "Why do timing checks detect debuggers?",
    options: [
      "Debuggers slow down the CPU",
      "Single-stepping and breakpoints cause significant delays between instructions",
      "Debuggers use different time zones",
      "Debuggers disable the system clock"
    ],
    correctAnswer: 1,
    explanation: "When single-stepping or hitting breakpoints, there are significant delays (milliseconds to seconds) between instructions that normally execute in nanoseconds.",
    topic: "Timing Detection"
  },
  {
    id: 23,
    question: "What does the RDTSC instruction return?",
    options: [
      "Random data",
      "The CPU's timestamp counter (cycles since reset)",
      "Current date and time",
      "Memory address"
    ],
    correctAnswer: 1,
    explanation: "RDTSC (Read Time-Stamp Counter) returns the number of CPU cycles since the last reset, providing high-precision timing.",
    topic: "Timing Detection"
  },
  {
    id: 24,
    question: "Which registers hold the RDTSC result?",
    options: [
      "RAX only",
      "EDX:EAX (high:low 32 bits)",
      "RBX and RCX",
      "RSP and RBP"
    ],
    correctAnswer: 1,
    explanation: "RDTSC stores the 64-bit timestamp in EDX:EAX, with the high 32 bits in EDX and low 32 bits in EAX.",
    topic: "Timing Detection"
  },
  {
    id: 25,
    question: "What is QueryPerformanceCounter used for in anti-debugging?",
    options: [
      "Counting files",
      "High-resolution timing to detect delays from debugging",
      "Measuring memory usage",
      "Counting CPU cores"
    ],
    correctAnswer: 1,
    explanation: "QueryPerformanceCounter provides high-resolution timestamps used to measure execution time and detect the delays caused by debugging.",
    topic: "Timing Detection"
  },
  {
    id: 26,
    question: "How can timing checks be bypassed?",
    options: [
      "Use a faster computer",
      "Hook timing functions, use VM TSC scaling, or patch the checks",
      "Disable the internet",
      "Use more RAM"
    ],
    correctAnswer: 1,
    explanation: "Timing checks can be bypassed by hooking RDTSC/timing APIs to return controlled values, using VM TSC scaling, or patching out the checks entirely.",
    topic: "Timing Detection"
  },
  {
    id: 27,
    question: "What is a typical threshold for detecting debugging via timing?",
    options: [
      "1 nanosecond",
      "Thousands to millions of cycles (or milliseconds) for simple operations",
      "Exactly 100 cycles",
      "1 hour"
    ],
    correctAnswer: 1,
    explanation: "Simple operations take microseconds normally but milliseconds under debugging. Thresholds of thousands/millions of cycles or tens of milliseconds are common.",
    topic: "Timing Detection"
  },
  {
    id: 28,
    question: "What is GetTickCount64 and why is it used?",
    options: [
      "Gets CPU temperature",
      "Returns milliseconds since system boot, used for coarse timing checks",
      "Counts mouse clicks",
      "Returns the current year"
    ],
    correctAnswer: 1,
    explanation: "GetTickCount64 returns milliseconds since system boot. It's used for timing checks, though with lower resolution than RDTSC or QueryPerformanceCounter.",
    topic: "Timing Detection"
  },

  // Section 5: Exception-Based Techniques (7 questions)
  {
    id: 29,
    question: "What happens when INT 3 (0xCC) is executed without a debugger?",
    options: [
      "Nothing happens",
      "EXCEPTION_BREAKPOINT is raised and can be caught by SEH",
      "The CPU halts",
      "The program restarts"
    ],
    correctAnswer: 1,
    explanation: "INT 3 raises EXCEPTION_BREAKPOINT. Without a debugger, SEH handles it. With a debugger, it typically intercepts the exception first.",
    topic: "Exception-Based Detection"
  },
  {
    id: 30,
    question: "What is special about INT 2D?",
    options: [
      "It's faster than INT 3",
      "It's a kernel debug service interrupt with different behavior under debuggers",
      "It only works on Linux",
      "It generates random numbers"
    ],
    correctAnswer: 1,
    explanation: "INT 2D is a kernel debug service. Under a debugger, it may skip the next byte or behave differently than without a debugger.",
    topic: "Exception-Based Detection"
  },
  {
    id: 31,
    question: "What is the Trap Flag (TF) in EFLAGS?",
    options: [
      "A flag that enables faster execution",
      "When set, generates SINGLE_STEP exception after each instruction",
      "A flag for network trapping",
      "A flag that disables interrupts"
    ],
    correctAnswer: 1,
    explanation: "The Trap Flag (bit 8 of EFLAGS) causes a SINGLE_STEP exception after each instruction, used for single-stepping in debuggers.",
    topic: "Exception-Based Detection"
  },
  {
    id: 32,
    question: "How is the Trap Flag used for anti-debugging?",
    options: [
      "It's never used for anti-debugging",
      "Set TF, execute code, and check if the exception occurred (debuggers often eat it)",
      "It speeds up the debugger",
      "It encrypts memory"
    ],
    correctAnswer: 1,
    explanation: "By setting TF and checking if SINGLE_STEP exception is received, code can detect debuggers that consume the exception for their own single-stepping.",
    topic: "Exception-Based Detection"
  },
  {
    id: 33,
    question: "What is SEH?",
    options: [
      "Secure Encryption Handler",
      "Structured Exception Handling - Windows mechanism for handling exceptions",
      "System Entry Hook",
      "Software Execution Halt"
    ],
    correctAnswer: 1,
    explanation: "SEH (Structured Exception Handling) is Windows' mechanism for handling exceptions. Anti-debugging often uses SEH to catch deliberate exceptions.",
    topic: "Exception-Based Detection"
  },
  {
    id: 34,
    question: "Why might OutputDebugString be used for anti-debugging?",
    options: [
      "It's a fast function",
      "It may set last error differently based on debugger presence (older Windows)",
      "It disables the debugger",
      "It's required by Windows"
    ],
    correctAnswer: 1,
    explanation: "On older Windows versions, OutputDebugString sets different error codes depending on whether a debugger is attached to receive the debug strings.",
    topic: "Exception-Based Detection"
  },
  {
    id: 35,
    question: "What exception code does INT 3 generate?",
    options: [
      "EXCEPTION_ACCESS_VIOLATION (0xC0000005)",
      "EXCEPTION_BREAKPOINT (0x80000003)",
      "EXCEPTION_SINGLE_STEP (0x80000004)",
      "EXCEPTION_ILLEGAL_INSTRUCTION (0xC000001D)"
    ],
    correctAnswer: 1,
    explanation: "INT 3 generates EXCEPTION_BREAKPOINT with code 0x80000003.",
    topic: "Exception-Based Detection"
  },

  // Section 6: Hardware Breakpoint Detection (6 questions)
  {
    id: 36,
    question: "How many hardware breakpoints can x86/x64 CPUs support simultaneously?",
    options: [
      "Unlimited",
      "4 (using DR0-DR3)",
      "8",
      "1"
    ],
    correctAnswer: 1,
    explanation: "x86/x64 processors have 4 debug address registers (DR0-DR3), allowing up to 4 hardware breakpoints at once.",
    topic: "Hardware Breakpoints"
  },
  {
    id: 37,
    question: "Which debug register controls the breakpoint conditions?",
    options: [
      "DR0",
      "DR7",
      "DR4",
      "DR8"
    ],
    correctAnswer: 1,
    explanation: "DR7 is the debug control register that enables breakpoints and specifies their conditions (execution, write, read/write).",
    topic: "Hardware Breakpoints"
  },
  {
    id: 38,
    question: "What API is used to read debug registers on Windows?",
    options: [
      "ReadDebugRegisters",
      "GetThreadContext",
      "QueryDebugInfo",
      "NtReadDebugRegs"
    ],
    correctAnswer: 1,
    explanation: "GetThreadContext with CONTEXT_DEBUG_REGISTERS flag retrieves the debug register values (DR0-DR7) for a thread.",
    topic: "Hardware Breakpoints"
  },
  {
    id: 39,
    question: "What is stored in DR6?",
    options: [
      "Breakpoint addresses",
      "Debug status - which breakpoint was triggered",
      "Thread ID",
      "Memory permissions"
    ],
    correctAnswer: 1,
    explanation: "DR6 is the debug status register showing which breakpoint condition was triggered and other debug event information.",
    topic: "Hardware Breakpoints"
  },
  {
    id: 40,
    question: "How can software detect hardware breakpoints?",
    options: [
      "It can't detect them",
      "Call GetThreadContext and check if DR0-DR3 contain non-zero values",
      "Listen on a network port",
      "Check the registry"
    ],
    correctAnswer: 1,
    explanation: "By calling GetThreadContext, software can read DR0-DR3. Non-zero values indicate hardware breakpoints are set.",
    topic: "Hardware Breakpoints"
  },
  {
    id: 41,
    question: "What is a common bypass for hardware breakpoint detection?",
    options: [
      "Use more breakpoints",
      "Hook GetThreadContext to return zeroed debug registers",
      "Disable the CPU",
      "Use a different computer"
    ],
    correctAnswer: 1,
    explanation: "Hooking GetThreadContext/NtGetContextThread to zero out debug registers in the returned context hides hardware breakpoints.",
    topic: "Hardware Breakpoints"
  },

  // Section 7: Software Breakpoint Detection (6 questions)
  {
    id: 42,
    question: "What byte value represents the INT 3 instruction?",
    options: [
      "0x90 (NOP)",
      "0xCC",
      "0xCD",
      "0x00"
    ],
    correctAnswer: 1,
    explanation: "0xCC is the opcode for INT 3, the software breakpoint instruction. Debuggers patch this byte into code to set breakpoints.",
    topic: "Software Breakpoints"
  },
  {
    id: 43,
    question: "How do software breakpoints work?",
    options: [
      "They use special CPU registers",
      "The debugger replaces the first byte of an instruction with 0xCC",
      "They modify the stack",
      "They change file permissions"
    ],
    correctAnswer: 1,
    explanation: "Software breakpoints work by saving the original byte and replacing it with 0xCC (INT 3). When executed, this triggers a breakpoint exception.",
    topic: "Software Breakpoints"
  },
  {
    id: 44,
    question: "What is code checksum verification?",
    options: [
      "Checking if code is signed",
      "Calculating a hash of code sections to detect modifications like breakpoints",
      "Verifying network packets",
      "Checking file sizes"
    ],
    correctAnswer: 1,
    explanation: "Code checksum verification calculates a hash/CRC of code regions. If breakpoints are inserted (0xCC bytes), the checksum will differ from the expected value.",
    topic: "Software Breakpoints"
  },
  {
    id: 45,
    question: "What is self-modifying code in anti-debugging?",
    options: [
      "Code that updates itself from the internet",
      "Code that decrypts or modifies itself at runtime, breaking if tampered",
      "Code that changes its filename",
      "Code that modifies other programs"
    ],
    correctAnswer: 1,
    explanation: "Self-modifying code decrypts or transforms itself at runtime. If breakpoints are present, the modification produces garbage, causing crashes or incorrect behavior.",
    topic: "Software Breakpoints"
  },
  {
    id: 46,
    question: "Why might code scan API functions for 0xCC?",
    options: [
      "To improve performance",
      "To detect if analysts have set breakpoints on commonly monitored APIs",
      "To count function calls",
      "To measure code size"
    ],
    correctAnswer: 1,
    explanation: "Analysts often set breakpoints on APIs like VirtualAlloc or CreateFile. Checking if these start with 0xCC reveals monitoring.",
    topic: "Software Breakpoints"
  },
  {
    id: 47,
    question: "How can software breakpoint detection be bypassed?",
    options: [
      "Use more breakpoints",
      "Use hardware breakpoints, set breakpoints outside checked regions, or patch the check",
      "Reinstall Windows",
      "Use a Mac"
    ],
    correctAnswer: 1,
    explanation: "Hardware breakpoints don't modify code. Alternatively, set software breakpoints outside scanned regions or disable the scanning code.",
    topic: "Software Breakpoints"
  },

  // Section 8: Anti-VM & Sandbox Detection (8 questions)
  {
    id: 48,
    question: "What does the CPUID hypervisor present bit indicate?",
    options: [
      "CPU model number",
      "The processor is running under a hypervisor/VM",
      "CPU temperature",
      "Number of cores"
    ],
    correctAnswer: 1,
    explanation: "CPUID leaf 1, ECX bit 31 (hypervisor present) is set when running in a virtual machine with a hypervisor.",
    topic: "Anti-VM Detection"
  },
  {
    id: 49,
    question: "Which MAC address prefix indicates VMware?",
    options: [
      "AA:BB:CC",
      "00:0C:29 or 00:50:56",
      "FF:FF:FF",
      "00:00:00"
    ],
    correctAnswer: 1,
    explanation: "VMware virtual network adapters use MAC prefixes 00:0C:29 and 00:50:56. VirtualBox uses 08:00:27.",
    topic: "Anti-VM Detection"
  },
  {
    id: 50,
    question: "What is a common indicator of VirtualBox?",
    options: [
      "Chrome browser installed",
      "Files/registry keys containing 'VBox', VBoxGuest drivers, or 08:00:27 MAC",
      "Windows Update enabled",
      "More than 4GB RAM"
    ],
    correctAnswer: 1,
    explanation: "VirtualBox leaves artifacts: VBox*.sys drivers, registry keys under Oracle\\VirtualBox, MAC prefix 08:00:27, and guest additions files.",
    topic: "Anti-VM Detection"
  },
  {
    id: 51,
    question: "How can malware detect automated sandboxes?",
    options: [
      "Check for sandbox watermarks only",
      "Check for lack of user activity, short uptime, few files, suspicious usernames",
      "Measure internet speed",
      "Count installed fonts"
    ],
    correctAnswer: 1,
    explanation: "Sandboxes often have telltale signs: no mouse movement, minimal documents, suspicious usernames like 'sandbox', short system uptime, and few installed programs.",
    topic: "Anti-VM Detection"
  },
  {
    id: 52,
    question: "What is the CPUID vendor string for VMware?",
    options: [
      "GenuineIntel",
      "VMwareVMware",
      "Microsoft",
      "KVMKVMKVM"
    ],
    correctAnswer: 1,
    explanation: "CPUID leaf 0x40000000 returns the hypervisor vendor string. VMware returns 'VMwareVMware', VirtualBox returns 'VBoxVBoxVBox'.",
    topic: "Anti-VM Detection"
  },
  {
    id: 53,
    question: "Why does malware sleep for extended periods?",
    options: [
      "To save power",
      "To outlast sandbox analysis timeouts (sandboxes typically run for minutes)",
      "To wait for user login",
      "To reduce CPU usage"
    ],
    correctAnswer: 1,
    explanation: "Automated sandboxes typically analyze samples for a few minutes. By sleeping longer, malware can avoid revealing its behavior during the analysis window.",
    topic: "Anti-VM Detection"
  },
  {
    id: 54,
    question: "What registry path reveals VM information on Windows?",
    options: [
      "HKEY_CURRENT_USER\\Desktop",
      "HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS",
      "HKEY_CLASSES_ROOT",
      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    ],
    correctAnswer: 1,
    explanation: "The BIOS registry key contains SystemManufacturer and SystemProductName values that reveal VM vendors like VMware or VirtualBox.",
    topic: "Anti-VM Detection"
  },
  {
    id: 55,
    question: "How can analysts harden their analysis VMs?",
    options: [
      "Use the default VM settings",
      "Remove VM artifacts, change MAC addresses, add realistic user data, modify registry",
      "Install more RAM",
      "Use wireless networking"
    ],
    correctAnswer: 1,
    explanation: "VM hardening involves removing/renaming VM tools, changing MAC prefixes, patching CPUID returns, adding realistic documents/history, and modifying registry entries.",
    topic: "Anti-VM Detection"
  },

  // Section 9: Linux Anti-Debugging (7 questions)
  {
    id: 56,
    question: "What is the primary debugging mechanism on Linux?",
    options: [
      "WinDbg",
      "ptrace system call",
      "Debug.Print",
      "Console.WriteLine"
    ],
    correctAnswer: 1,
    explanation: "ptrace (process trace) is the system call that enables debugging on Linux. GDB and other debuggers use ptrace to attach, set breakpoints, and read memory.",
    topic: "Linux Anti-Debugging"
  },
  {
    id: 57,
    question: "How does ptrace(PTRACE_TRACEME) detect debuggers?",
    options: [
      "It doesn't detect debuggers",
      "A process can only be traced by one tracer - if it fails, something is already tracing",
      "It reads memory",
      "It checks CPU registers"
    ],
    correctAnswer: 1,
    explanation: "PTRACE_TRACEME allows the parent to trace the process. If a debugger is already attached, this call fails because only one tracer is allowed.",
    topic: "Linux Anti-Debugging"
  },
  {
    id: 58,
    question: "What does /proc/self/status TracerPid field show?",
    options: [
      "CPU usage",
      "PID of the process tracing this one (0 if not traced)",
      "Memory usage",
      "File descriptors"
    ],
    correctAnswer: 1,
    explanation: "The TracerPid field in /proc/self/status contains the PID of the tracing process, or 0 if not being traced.",
    topic: "Linux Anti-Debugging"
  },
  {
    id: 59,
    question: "What is LD_PRELOAD used for in bypass techniques?",
    options: [
      "Loading device drivers",
      "Injecting a library that hooks functions like ptrace before the program loads",
      "Preloading web pages",
      "Loading configuration files"
    ],
    correctAnswer: 1,
    explanation: "LD_PRELOAD forces the dynamic linker to load a specified library first, allowing analysts to hook functions like ptrace to bypass anti-debugging.",
    topic: "Linux Anti-Debugging"
  },
  {
    id: 60,
    question: "How can a program detect LD_PRELOAD-based hooks?",
    options: [
      "Check network connections",
      "Check if LD_PRELOAD environment variable is set or inspect /proc/self/maps",
      "Measure CPU speed",
      "Check disk space"
    ],
    correctAnswer: 1,
    explanation: "Programs can read the LD_PRELOAD environment variable or check /proc/self/maps for unexpected libraries to detect injection.",
    topic: "Linux Anti-Debugging"
  },
  {
    id: 61,
    question: "What signal does a debugger typically use for breakpoints on Linux?",
    options: [
      "SIGKILL",
      "SIGTRAP",
      "SIGTERM",
      "SIGHUP"
    ],
    correctAnswer: 1,
    explanation: "SIGTRAP is generated by breakpoints (INT 3) and single-stepping. Debuggers catch this signal to implement breakpoint functionality.",
    topic: "Linux Anti-Debugging"
  },
  {
    id: 62,
    question: "What is the syscall number for ptrace on x86_64 Linux?",
    options: [
      "1",
      "101",
      "60",
      "0"
    ],
    correctAnswer: 1,
    explanation: "On x86_64 Linux, ptrace is syscall number 101. Malware might use direct syscalls to avoid library-level hooks.",
    topic: "Linux Anti-Debugging"
  },

  // Section 10: Android & Mobile Anti-Debugging (7 questions)
  {
    id: 63,
    question: "What is JDWP?",
    options: [
      "Java Development Web Portal",
      "Java Debug Wire Protocol - used for debugging Java/Android apps",
      "Joint Data Writing Process",
      "Java Driver Web Package"
    ],
    correctAnswer: 1,
    explanation: "JDWP (Java Debug Wire Protocol) is the protocol used to debug Java applications, including Android apps.",
    topic: "Android Anti-Debugging"
  },
  {
    id: 64,
    question: "What does android.os.Debug.isDebuggerConnected() check?",
    options: [
      "USB connection status",
      "Whether a Java debugger is currently attached to the app",
      "WiFi debugging status",
      "ADB status"
    ],
    correctAnswer: 1,
    explanation: "isDebuggerConnected() returns true if a Java debugger (JDWP) is currently attached to the application process.",
    topic: "Android Anti-Debugging"
  },
  {
    id: 65,
    question: "What is Frida used for?",
    options: [
      "Video editing",
      "Dynamic instrumentation - hooking functions at runtime on multiple platforms",
      "Photo editing",
      "Music production"
    ],
    correctAnswer: 1,
    explanation: "Frida is a dynamic instrumentation toolkit that injects JavaScript into processes, allowing function hooking and modification at runtime.",
    topic: "Android Anti-Debugging"
  },
  {
    id: 66,
    question: "What is the default port for Frida server?",
    options: [
      "8080",
      "27042",
      "443",
      "22"
    ],
    correctAnswer: 1,
    explanation: "Frida server listens on port 27042 by default. Anti-Frida checks often probe this port.",
    topic: "Android Anti-Debugging"
  },
  {
    id: 67,
    question: "How can root detection be implemented on Android?",
    options: [
      "Check screen brightness",
      "Check for su binary, root management apps (Magisk), or test-keys build tags",
      "Measure battery level",
      "Check GPS location"
    ],
    correctAnswer: 1,
    explanation: "Root detection checks for su binaries in common paths, root management apps like Magisk or SuperSU, and build tags indicating custom ROMs.",
    topic: "Android Anti-Debugging"
  },
  {
    id: 68,
    question: "What is Magisk Hide / Zygisk used for?",
    options: [
      "Speeding up the phone",
      "Hiding root status from apps that check for it",
      "Improving battery life",
      "Blocking advertisements"
    ],
    correctAnswer: 1,
    explanation: "Magisk Hide (and its successor in Zygisk) hides root from specific apps, making them believe the device is not rooted.",
    topic: "Android Anti-Debugging"
  },
  {
    id: 69,
    question: "What is Objection in mobile security?",
    options: [
      "A legal term",
      "A Frida-based toolkit that automates common mobile bypasses",
      "An Android app",
      "A type of malware"
    ],
    correctAnswer: 1,
    explanation: "Objection is a runtime mobile exploration toolkit powered by Frida, providing automated bypasses for SSL pinning, root detection, and more.",
    topic: "Android Anti-Debugging"
  },

  // Section 11: Bypass & Defeat Techniques (6 questions)
  {
    id: 70,
    question: "What is ScyllaHide?",
    options: [
      "A type of malware",
      "An anti-anti-debugging plugin that hides debuggers from detection",
      "A web browser",
      "An operating system"
    ],
    correctAnswer: 1,
    explanation: "ScyllaHide is an open-source anti-anti-debugging tool that hooks Windows APIs to hide debugger presence from protected software.",
    topic: "Bypass Techniques"
  },
  {
    id: 71,
    question: "What is binary patching?",
    options: [
      "Updating software through official channels",
      "Modifying executable bytes to change behavior, like NOPing out checks",
      "Compressing files",
      "Encrypting data"
    ],
    correctAnswer: 1,
    explanation: "Binary patching involves modifying the executable's bytes directly - replacing instructions with NOPs, changing jumps, or altering return values.",
    topic: "Bypass Techniques"
  },
  {
    id: 72,
    question: "What does NOPing out mean?",
    options: [
      "Deleting the entire program",
      "Replacing instructions with 0x90 (NOP - no operation) to disable them",
      "Compiling with optimization",
      "Running as administrator"
    ],
    correctAnswer: 1,
    explanation: "NOPing replaces instructions with NOP (0x90), which does nothing. This effectively disables anti-debugging checks without changing code size.",
    topic: "Bypass Techniques"
  },
  {
    id: 73,
    question: "What is TitanHide?",
    options: [
      "A game",
      "A kernel-mode driver that hides debuggers at ring 0",
      "A browser extension",
      "An Android app"
    ],
    correctAnswer: 1,
    explanation: "TitanHide is a kernel-mode (ring 0) anti-anti-debugging tool that hides debuggers more effectively than user-mode solutions like ScyllaHide.",
    topic: "Bypass Techniques"
  },
  {
    id: 74,
    question: "Why hook functions instead of patching them?",
    options: [
      "It's faster",
      "Hooks can be applied dynamically without modifying files, and can restore original behavior",
      "It uses less memory",
      "It's required by law"
    ],
    correctAnswer: 1,
    explanation: "Hooking intercepts calls at runtime without changing files. You can log calls, modify arguments/returns, and easily toggle the hook on/off.",
    topic: "Bypass Techniques"
  },
  {
    id: 75,
    question: "What is the recommended first step when encountering anti-debugging?",
    options: [
      "Give up",
      "Enable ScyllaHide/anti-anti-debug tools with common protections",
      "Restart the computer",
      "Contact the software vendor"
    ],
    correctAnswer: 1,
    explanation: "Start with anti-anti-debugging tools like ScyllaHide with common options enabled. This handles most standard checks automatically.",
    topic: "Bypass Techniques"
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
    if (score === 10) return "Perfect! You're an anti-debugging expert! 🏆";
    if (score >= 8) return "Excellent work! You have strong knowledge! 🌟";
    if (score >= 6) return "Good job! Keep studying to improve! 📚";
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
          border: `2px solid ${alpha("#f59e0b", 0.3)}`,
          background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.05)} 0%, ${alpha("#f97316", 0.05)} 100%)`,
        }}
      >
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              background: "linear-gradient(135deg, #f59e0b, #f97316)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <QuizIcon sx={{ color: "white", fontSize: 32 }} />
          </Box>
          Test Your Knowledge
        </Typography>

        <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8, fontSize: "1.05rem" }}>
          Ready to test what you've learned? Take this <strong>10-question quiz</strong> covering all aspects of 
          anti-debugging techniques. Questions are randomly selected from a pool of <strong>75 questions</strong>, 
          so each attempt is different!
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
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#8b5cf6" }}>12</Typography>
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
          sx={{
            background: "linear-gradient(135deg, #f59e0b, #f97316)",
            fontWeight: 700,
            px: 4,
            py: 1.5,
            fontSize: "1.1rem",
            "&:hover": {
              background: "linear-gradient(135deg, #d97706, #ea580c)",
            },
          }}
        >
          Start Quiz
        </Button>
      </Paper>
    );
  }

  if (showResults) {
    const score = calculateScore();
    return (
      <Paper
        id="quiz-section"
        sx={{
          p: 4,
          mb: 5,
          borderRadius: 4,
          bgcolor: alpha(theme.palette.background.paper, 0.6),
          border: `2px solid ${alpha(getScoreColor(score), 0.3)}`,
        }}
      >
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <EmojiEventsIcon sx={{ color: getScoreColor(score), fontSize: 40 }} />
          Quiz Results
        </Typography>

        <Box sx={{ textAlign: "center", mb: 4 }}>
          <Typography variant="h1" sx={{ fontWeight: 900, color: getScoreColor(score), mb: 1 }}>
            {score}/10
          </Typography>
          <Typography variant="h6" sx={{ color: "text.secondary", mb: 2 }}>
            {getScoreMessage(score)}
          </Typography>
          <Chip
            label={`${score * 10}%`}
            sx={{
              bgcolor: alpha(getScoreColor(score), 0.15),
              color: getScoreColor(score),
              fontWeight: 700,
              fontSize: "1rem",
              px: 2,
            }}
          />
        </Box>

        <Divider sx={{ my: 3 }} />

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Review Your Answers:</Typography>

        {currentQuestions.map((q, index) => {
          const isCorrect = userAnswers[q.id] === q.correctAnswer;
          return (
            <Paper
              key={q.id}
              sx={{
                p: 2,
                mb: 2,
                borderRadius: 2,
                bgcolor: alpha(isCorrect ? "#22c55e" : "#ef4444", 0.05),
                border: `1px solid ${alpha(isCorrect ? "#22c55e" : "#ef4444", 0.2)}`,
              }}
            >
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1 }}>
                <Chip
                  label={`Q${index + 1}`}
                  size="small"
                  sx={{
                    bgcolor: isCorrect ? "#22c55e" : "#ef4444",
                    color: "white",
                    fontWeight: 700,
                  }}
                />
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  {q.question}
                </Typography>
              </Box>
              <Typography variant="body2" sx={{ color: "text.secondary", ml: 4.5 }}>
                <strong>Your answer:</strong> {q.options[userAnswers[q.id]] || "Not answered"}
                {!isCorrect && (
                  <>
                    <br />
                    <strong style={{ color: "#22c55e" }}>Correct:</strong> {q.options[q.correctAnswer]}
                  </>
                )}
              </Typography>
              {!isCorrect && (
                <Alert severity="info" sx={{ mt: 1, ml: 4.5 }}>
                  <Typography variant="caption">{q.explanation}</Typography>
                </Alert>
              )}
            </Paper>
          );
        })}

        <Box sx={{ display: "flex", gap: 2, mt: 3 }}>
          <Button
            variant="contained"
            onClick={startQuiz}
            startIcon={<RefreshIcon />}
            sx={{
              background: "linear-gradient(135deg, #f59e0b, #f97316)",
              fontWeight: 700,
            }}
          >
            Try Again (New Questions)
          </Button>
          <Button
            variant="outlined"
            onClick={() => setQuizStarted(false)}
            sx={{ fontWeight: 600 }}
          >
            Back to Overview
          </Button>
        </Box>
      </Paper>
    );
  }

  const currentQuestion = currentQuestions[currentQuestionIndex];
  const answeredCount = Object.keys(userAnswers).length;

  return (
    <Paper
      id="quiz-section"
      sx={{
        p: 4,
        mb: 5,
        borderRadius: 4,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        border: `2px solid ${alpha("#f59e0b", 0.3)}`,
      }}
    >
      {/* Progress Bar */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
            Question {currentQuestionIndex + 1} of 10
          </Typography>
          <Chip
            label={currentQuestion.topic}
            size="small"
            sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }}
          />
        </Box>
        <Box sx={{ width: "100%", bgcolor: alpha("#f59e0b", 0.1), borderRadius: 1, height: 8 }}>
          <Box
            sx={{
              width: `${((currentQuestionIndex + 1) / 10) * 100}%`,
              bgcolor: "#f59e0b",
              borderRadius: 1,
              height: "100%",
              transition: "width 0.3s ease",
            }}
          />
        </Box>
      </Box>

      {/* Question */}
      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3, lineHeight: 1.6 }}>
        {currentQuestion.question}
      </Typography>

      {/* Options */}
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {currentQuestion.options.map((option, index) => {
          const isSelected = userAnswers[currentQuestion.id] === index;
          return (
            <Grid item xs={12} key={index}>
              <Paper
                onClick={() => handleAnswerSelect(currentQuestion.id, index)}
                sx={{
                  p: 2,
                  borderRadius: 2,
                  cursor: "pointer",
                  bgcolor: isSelected ? alpha("#3b82f6", 0.15) : alpha(theme.palette.background.paper, 0.5),
                  border: `2px solid ${isSelected ? "#3b82f6" : alpha(theme.palette.divider, 0.2)}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    borderColor: "#3b82f6",
                    bgcolor: alpha("#3b82f6", 0.08),
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box
                    sx={{
                      width: 32,
                      height: 32,
                      borderRadius: "50%",
                      bgcolor: isSelected ? "#3b82f6" : alpha(theme.palette.divider, 0.3),
                      color: isSelected ? "white" : "text.secondary",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontWeight: 700,
                      fontSize: "0.9rem",
                    }}
                  >
                    {String.fromCharCode(65 + index)}
                  </Box>
                  <Typography variant="body1" sx={{ fontWeight: isSelected ? 600 : 400 }}>
                    {option}
                  </Typography>
                </Box>
              </Paper>
            </Grid>
          );
        })}
      </Grid>

      {/* Navigation */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Button
          variant="outlined"
          disabled={currentQuestionIndex === 0}
          onClick={() => setCurrentQuestionIndex((prev) => prev - 1)}
        >
          Previous
        </Button>

        <Typography variant="body2" color="text.secondary">
          {answeredCount}/10 answered
        </Typography>

        {currentQuestionIndex < 9 ? (
          <Button
            variant="contained"
            onClick={() => setCurrentQuestionIndex((prev) => prev + 1)}
            sx={{
              background: "linear-gradient(135deg, #3b82f6, #2563eb)",
            }}
          >
            Next
          </Button>
        ) : (
          <Button
            variant="contained"
            onClick={() => setShowResults(true)}
            disabled={answeredCount < 10}
            sx={{
              background: answeredCount >= 10
                ? "linear-gradient(135deg, #22c55e, #16a34a)"
                : undefined,
              fontWeight: 700,
            }}
          >
            Submit Quiz
          </Button>
        )}
      </Box>

      {/* Quick Navigation */}
      <Box sx={{ mt: 3, pt: 3, borderTop: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
        <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: "block" }}>
          Quick Navigation:
        </Typography>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          {currentQuestions.map((_, index) => {
            const isAnswered = userAnswers[currentQuestions[index].id] !== undefined;
            const isCurrent = index === currentQuestionIndex;
            return (
              <Box
                key={index}
                onClick={() => setCurrentQuestionIndex(index)}
                sx={{
                  width: 32,
                  height: 32,
                  borderRadius: 1,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  cursor: "pointer",
                  fontWeight: 700,
                  fontSize: "0.85rem",
                  bgcolor: isCurrent
                    ? "#f59e0b"
                    : isAnswered
                    ? alpha("#22c55e", 0.2)
                    : alpha(theme.palette.divider, 0.1),
                  color: isCurrent ? "white" : isAnswered ? "#22c55e" : "text.secondary",
                  border: `1px solid ${isCurrent ? "#f59e0b" : isAnswered ? "#22c55e" : "transparent"}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    bgcolor: isCurrent ? "#f59e0b" : alpha("#f59e0b", 0.2),
                  },
                }}
              >
                {index + 1}
              </Box>
            );
          })}
        </Box>
      </Box>
    </Paper>
  );
}

// Outline sections for the page
const outlineSections = [
  {
    id: "what-is-anti-debugging",
    title: "What is Anti-Debugging?",
    icon: <SearchIcon />,
    color: "#3b82f6",
    status: "Complete",
    description: "Understanding the concept, why software uses it, and the cat-and-mouse game between analysts and malware",
  },
  {
    id: "windows-api-checks",
    title: "Windows API-Based Checks",
    icon: <ComputerIcon />,
    color: "#8b5cf6",
    status: "Complete",
    description: "IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess, and kernel32 tricks",
  },
  {
    id: "peb-flags",
    title: "PEB & TEB Flag Checks",
    icon: <MemoryIcon />,
    color: "#06b6d4",
    status: "Complete",
    description: "BeingDebugged flag, NtGlobalFlag, heap flags, and process environment block inspection",
  },
  {
    id: "timing-attacks",
    title: "Timing-Based Detection",
    icon: <TimerIcon />,
    color: "#f97316",
    status: "Complete",
    description: "RDTSC, QueryPerformanceCounter, GetTickCount, and detecting single-stepping delays",
  },
  {
    id: "exception-based",
    title: "Exception-Based Techniques",
    icon: <WarningIcon />,
    color: "#ef4444",
    status: "Complete",
    description: "INT 3 detection, structured exception handling (SEH), vectored exception handlers, and trap flags",
  },
  {
    id: "hardware-breakpoints",
    title: "Hardware Breakpoint Detection",
    icon: <SettingsIcon />,
    color: "#ec4899",
    status: "Complete",
    description: "Debug registers (DR0-DR7), GetThreadContext, and detecting hardware breakpoints",
  },
  {
    id: "software-breakpoints",
    title: "Software Breakpoint Detection",
    icon: <BugReportIcon />,
    color: "#14b8a6",
    status: "Complete",
    description: "INT 3 (0xCC) byte scanning, checksum verification, and self-modifying code",
  },
  {
    id: "anti-vm",
    title: "Anti-VM & Sandbox Detection",
    icon: <StorageIcon />,
    color: "#6366f1",
    status: "Complete",
    description: "VMware/VirtualBox artifacts, CPUID checks, MAC addresses, registry keys, and environment fingerprinting",
  },
  {
    id: "linux-anti-debug",
    title: "Linux Anti-Debugging Techniques",
    icon: <TerminalIcon />,
    color: "#22c55e",
    status: "Complete",
    description: "ptrace detection, /proc/self/status checks, signal handlers, and LD_PRELOAD detection",
  },
  {
    id: "android-anti-debug",
    title: "Android & Mobile Anti-Debugging",
    icon: <AndroidIcon />,
    color: "#a855f7",
    status: "Complete",
    description: "Java debugger detection, native anti-debug, Frida detection, root/jailbreak checks",
  },
  {
    id: "bypass-techniques",
    title: "Bypass & Defeat Techniques",
    icon: <BuildIcon />,
    color: "#dc2626",
    status: "Complete",
    description: "ScyllaHide, x64dbg plugins, Frida scripts, binary patching, and kernel-level bypasses",
  },
  {
    id: "tools-resources",
    title: "Tools & Practice Resources",
    icon: <ExtensionIcon />,
    color: "#0ea5e9",
    status: "Complete",
    description: "Debuggers, plugins, practice binaries, CTF challenges, and further reading",
  },
];

// Quick stats for visual impact
const quickStats = [
  { value: "12", label: "Topics Covered", color: "#ef4444" },
  { value: "Win/Lin", label: "Platforms", color: "#3b82f6" },
  { value: "20+", label: "Techniques", color: "#10b981" },
  { value: "Both", label: "Attack & Defense", color: "#8b5cf6" },
];

export default function AntiDebuggingGuidePage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Anti-Debugging & Anti-Analysis Techniques Learning Guide - Comprehensive course covering anti-debugging fundamentals, Windows API checks, PEB/TEB flags, timing attacks, exception-based detection, hardware and software breakpoint detection, anti-VM techniques, Linux and Android anti-debugging, bypass strategies, and tools for both red team (implementing protections) and blue team (defeating them) perspectives.`;

  return (
    <LearnPageLayout pageTitle="Anti-Debugging & Anti-Analysis Techniques" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
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
            background: `linear-gradient(135deg, ${alpha("#ef4444", 0.15)} 0%, ${alpha("#f97316", 0.15)} 50%, ${alpha("#8b5cf6", 0.15)} 100%)`,
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
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
              background: `radial-gradient(circle, ${alpha("#ef4444", 0.1)} 0%, transparent 70%)`,
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
                  background: `linear-gradient(135deg, #ef4444, #f97316)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#ef4444", 0.3)}`,
                }}
              >
                <VisibilityOffIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                  Anti-Debugging & Anti-Analysis
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                  Techniques to detect, evade, and defeat analysis environments
                </Typography>
              </Box>
            </Box>
            
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
              <Chip label="Intermediate" color="warning" />
              <Chip label="Reverse Engineering" sx={{ bgcolor: alpha("#dc2626", 0.15), color: "#dc2626", fontWeight: 600 }} />
              <Chip label="Malware Analysis" sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444", fontWeight: 600 }} />
              <Chip label="Software Protection" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
              <Chip label="Red & Blue Team" sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 600 }} />
            </Box>

            {/* Quick Stats */}
            <Grid container spacing={2}>
              {quickStats.map((stat) => (
                <Grid item xs={6} sm={3} key={stat.label}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      borderRadius: 2,
                      bgcolor: alpha(stat.color, 0.1),
                      border: `1px solid ${alpha(stat.color, 0.2)}`,
                    }}
                  >
                    <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                      {stat.value}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
                      {stat.label}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>
        </Paper>

        {/* ==================== DETAILED INTRODUCTION ==================== */}
        <Paper
          id="introduction"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #ef4444, #f97316)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <SchoolIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            What is Anti-Debugging?
          </Typography>
          
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Imagine you're a detective trying to figure out how a mysterious machine works. You open it up, poke around 
            with your tools, pause it mid-operation to see what's happening inside, and trace its every move. Now imagine 
            the machine was designed to <strong>detect when someone is investigating it</strong> and either shut down, 
            behave differently, or actively fight back. That's essentially what <strong>anti-debugging</strong> is—techniques 
            built into software to detect, evade, or disrupt analysis attempts.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Anti-debugging</strong> refers to a collection of techniques that software uses to detect if it's being 
            run inside a debugger (like x64dbg, GDB, or OllyDbg), a virtual machine, or other analysis environment. When 
            detected, the software might crash, exit silently, change its behavior, produce incorrect output, or even 
            corrupt itself to prevent further analysis. These techniques are used by both <strong>malicious software</strong> 
            (malware trying to avoid detection) and <strong>legitimate software</strong> (games with anti-cheat systems, 
            DRM-protected applications, or security software protecting itself from tampering).
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Why Should You Learn This?</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Understanding anti-debugging is essential for <strong>malware analysts</strong> who need to bypass protections 
              to understand threats, <strong>security researchers</strong> analyzing protected software, <strong>reverse engineers</strong> 
              working on CTF challenges or crackmes, and <strong>software developers</strong> who want to protect their own 
              applications from tampering. It's a critical skill that sits at the intersection of offense and defense—you 
              need to understand how these techniques work both to implement them and to defeat them.
            </Typography>
          </Alert>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#3b82f6" }}>
            The Cat-and-Mouse Game
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Anti-debugging is fundamentally a <strong>cat-and-mouse game</strong> between software authors and analysts. 
            Software authors implement detection techniques, analysts find ways to bypass them, authors add more sophisticated 
            checks, and the cycle continues. This has led to increasingly creative techniques on both sides:
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  bgcolor: alpha("#ef4444", 0.05),
                  border: `1px solid ${alpha("#ef4444", 0.2)}`,
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <ShieldIcon sx={{ fontSize: 32, color: "#ef4444" }} />
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>
                    Defense (Anti-Debugging)
                  </Typography>
                </Box>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  Software trying to <em>prevent</em> analysis uses techniques like:
                </Typography>
                <List dense>
                  {[
                    "Checking for debugger presence via OS APIs",
                    "Detecting breakpoints in memory",
                    "Measuring execution time (debuggers slow things down)",
                    "Looking for VM/sandbox artifacts",
                    "Using self-modifying or encrypted code",
                  ].map((item, idx) => (
                    <ListItem key={idx} sx={{ py: 0.25 }}>
                      <ListItemIcon><LockIcon sx={{ fontSize: 16, color: "#ef4444" }} /></ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  bgcolor: alpha("#10b981", 0.05),
                  border: `1px solid ${alpha("#10b981", 0.2)}`,
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <BuildIcon sx={{ fontSize: 32, color: "#10b981" }} />
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#10b981" }}>
                    Offense (Bypass Techniques)
                  </Typography>
                </Box>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  Analysts trying to <em>defeat</em> protections use techniques like:
                </Typography>
                <List dense>
                  {[
                    "Patching out detection checks",
                    "Hooking APIs to return fake values",
                    "Using anti-anti-debugging plugins (ScyllaHide)",
                    "Hardware-assisted debugging",
                    "Custom VMs that evade fingerprinting",
                  ].map((item, idx) => (
                    <ListItem key={idx} sx={{ py: 0.25 }}>
                      <ListItemIcon><CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} /></ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#8b5cf6" }}>
            How Debuggers Work (The Basics)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            To understand anti-debugging, you first need to understand how debuggers work. A <strong>debugger</strong> is 
            a program that controls the execution of another program (the "debuggee" or "target"). It can:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { title: "Pause Execution", desc: "Stop the program at any point to examine its state", icon: "⏸️" },
              { title: "Set Breakpoints", desc: "Mark locations where execution should pause", icon: "🔴" },
              { title: "Single-Step", desc: "Execute one instruction at a time", icon: "👣" },
              { title: "Inspect Memory", desc: "Read/write the program's memory and registers", icon: "🔍" },
              { title: "Modify State", desc: "Change register values, memory, or code", icon: "✏️" },
              { title: "Trace Execution", desc: "Log all instructions or API calls", icon: "📝" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} md={4} key={idx}>
                <Paper
                  sx={{
                    p: 2,
                    height: "100%",
                    borderRadius: 2,
                    bgcolor: alpha("#8b5cf6", 0.05),
                    border: `1px solid ${alpha("#8b5cf6", 0.15)}`,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Typography variant="h5">{item.icon}</Typography>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            On Windows, debuggers typically work through the <strong>Windows Debug API</strong> (functions like 
            <code style={{ background: alpha("#8b5cf6", 0.1), padding: "2px 6px", borderRadius: 4 }}>DebugActiveProcess</code>, 
            <code style={{ background: alpha("#8b5cf6", 0.1), padding: "2px 6px", borderRadius: 4 }}>WaitForDebugEvent</code>). 
            On Linux, the <strong>ptrace</strong> system call provides similar capabilities. The operating system maintains 
            information about whether a process is being debugged, and this information can be queried—which is exactly 
            what anti-debugging techniques exploit.
          </Typography>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#f97316" }}>
            Categories of Anti-Debugging Techniques
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Anti-debugging techniques can be broadly categorized based on <em>what</em> they detect or <em>how</em> they work:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              {
                category: "API-Based",
                color: "#3b82f6",
                desc: "Calling OS functions that reveal debugger presence",
                examples: "IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess",
              },
              {
                category: "Flag/Structure Inspection",
                color: "#8b5cf6",
                desc: "Directly reading OS data structures for debug flags",
                examples: "PEB.BeingDebugged, NtGlobalFlag, heap flags",
              },
              {
                category: "Timing-Based",
                color: "#f97316",
                desc: "Measuring execution time (debugging slows things down)",
                examples: "RDTSC, QueryPerformanceCounter, GetTickCount",
              },
              {
                category: "Exception-Based",
                color: "#ef4444",
                desc: "Using exceptions that behave differently under debuggers",
                examples: "INT 3, INT 2D, single-step exceptions, SEH tricks",
              },
              {
                category: "Breakpoint Detection",
                color: "#ec4899",
                desc: "Scanning for breakpoint bytes or debug registers",
                examples: "0xCC scanning, DR0-DR7 register checks, checksums",
              },
              {
                category: "Environment Detection",
                color: "#6366f1",
                desc: "Detecting VMs, sandboxes, or analysis tools",
                examples: "CPUID, MAC addresses, registry keys, process names",
              },
            ].map((item, idx) => (
              <Grid item xs={12} md={6} key={idx}>
                <Paper
                  sx={{
                    p: 2.5,
                    height: "100%",
                    borderRadius: 2,
                    bgcolor: alpha(item.color, 0.03),
                    border: `1px solid ${alpha(item.color, 0.15)}`,
                  }}
                >
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>
                    {item.category}
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>{item.desc}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    <strong>Examples:</strong> {item.examples}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#10b981" }}>
            Who Uses Anti-Debugging?
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                  🦠 Malware
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  Malware uses anti-debugging to evade analysis by security researchers and automated sandboxes. 
                  If malware detects it's being analyzed, it may refuse to run, delete itself, or behave innocently 
                  to avoid detection.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                  🎮 Game Anti-Cheat
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  Games use anti-debugging to prevent cheaters from using memory editors, trainers, or debuggers 
                  to modify game state. Systems like EasyAntiCheat, BattlEye, and Vanguard heavily rely on these 
                  techniques.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                  🔐 DRM & Licensing
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  Software protection systems (Denuvo, VMProtect, Themida) use anti-debugging to prevent 
                  reverse engineering of licensing checks and copy protection mechanisms.
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Alert severity="warning" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>⚠️ Legal & Ethical Considerations</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Bypassing anti-debugging protections may be illegal depending on your jurisdiction and intent. Analyzing 
              malware for defensive purposes is generally acceptable. Bypassing protections on software you own for 
              interoperability or security research may be protected under laws like DMCA §1201(f). However, bypassing 
              DRM for piracy or circumventing anti-cheat to gain unfair advantages violates terms of service and 
              potentially laws. Always ensure you have proper authorization before analyzing protected software.
            </Typography>
          </Alert>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>What You'll Learn</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              This guide will walk you through all major anti-debugging techniques, from simple API checks to 
              sophisticated timing attacks and VM detection. For each technique, you'll learn <strong>how it works</strong>, 
              <strong>how to detect it</strong> in binaries, and <strong>how to bypass it</strong>. By the end, you'll 
              be equipped to analyze heavily protected malware, understand game anti-cheat systems, and even implement 
              your own protections.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 2: WINDOWS API-BASED CHECKS ==================== */}
        <Paper
          id="windows-api-checks-content"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #8b5cf6, #a855f7)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <ComputerIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Windows API-Based Checks
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            The simplest and most common anti-debugging techniques involve calling Windows API functions that directly 
            tell you whether a debugger is attached. These are easy to implement but also easy to detect and bypass. 
            Despite their simplicity, they're still widely used because they catch basic debugging attempts and are 
            often combined with more sophisticated techniques.
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Why API Checks Still Matter</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Even though these checks are well-known and easily bypassed, they serve as the first line of defense. 
              They catch casual analysis attempts, force analysts to use anti-anti-debugging tools, and when combined 
              with multiple techniques, increase the overall protection level. Think of them as the "locks on your door"—
              they won't stop a determined attacker, but they deter opportunistic ones.
            </Typography>
          </Alert>

          {/* IsDebuggerPresent */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
              1. IsDebuggerPresent()
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              The most famous anti-debugging API. This function from <code style={{ background: alpha("#8b5cf6", 0.1), padding: "2px 6px", borderRadius: 4 }}>kernel32.dll</code> returns 
              <strong> TRUE</strong> if the calling process is being debugged by a user-mode debugger, and <strong>FALSE</strong> otherwise.
            </Typography>

            <Paper sx={{ p: 2, mb: 2, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// C/C++ Example
#include <windows.h>

if (IsDebuggerPresent()) {
    // Debugger detected!
    ExitProcess(0);  // Or more subtle: corrupt data, change behavior
}

// Assembly equivalent (what it actually does internally)
// mov eax, dword ptr fs:[0x30]  ; Get PEB address
// movzx eax, byte ptr [eax+2]   ; Read BeingDebugged flag
// ret`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    ✅ How to Detect in Binaries
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Search for import "IsDebuggerPresent" in IAT</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Look for call to kernel32.IsDebuggerPresent</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Search for fs:[0x30] followed by byte read at offset +2</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    🔓 Bypass Methods
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Patch return value to always return 0</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Hook the API and return FALSE</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Set PEB.BeingDebugged = 0 directly</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Use ScyllaHide or similar plugins</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* CheckRemoteDebuggerPresent */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
              2. CheckRemoteDebuggerPresent()
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Similar to IsDebuggerPresent, but can check if <em>any</em> process (including the current one) is being 
              debugged. The "remote" part is misleading—it can check the current process too. It's slightly harder to 
              bypass because it makes a system call rather than just reading a flag.
            </Typography>

            <Paper sx={{ p: 2, mb: 2, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// C/C++ Example
BOOL isDebuggerPresent = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);

if (isDebuggerPresent) {
    // Debugger detected!
    MessageBox(NULL, "Nice try!", "Debug Detected", MB_OK);
    TerminateProcess(GetCurrentProcess(), 0);
}`}
              </Typography>
            </Paper>

            <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8, bgcolor: alpha("#f59e0b", 0.1), p: 2, borderRadius: 2 }}>
              <strong>💡 Key Difference:</strong> While IsDebuggerPresent just reads a memory flag (easily spoofed), 
              CheckRemoteDebuggerPresent internally calls <code>NtQueryInformationProcess</code> with 
              <code>ProcessDebugPort</code> class, which queries the kernel. This makes it slightly more reliable 
              but still bypassable.
            </Typography>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* NtQueryInformationProcess */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
              3. NtQueryInformationProcess()
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              This is a <strong>native API</strong> from <code style={{ background: alpha("#8b5cf6", 0.1), padding: "2px 6px", borderRadius: 4 }}>ntdll.dll</code>—a 
              lower-level function that the kernel32 APIs call internally. It's more powerful because it can query 
              multiple types of debug-related information. Malware often calls this directly to avoid usermode hooks 
              on higher-level APIs.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Using NtQueryInformationProcess with different info classes
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// Method 1: ProcessDebugPort (0x07)
// Returns non-zero if debugger attached
DWORD_PTR debugPort = 0;
NtQueryInformationProcess(GetCurrentProcess(), 
    ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
if (debugPort != 0) { /* Debugger detected */ }

// Method 2: ProcessDebugObjectHandle (0x1E)
// Returns valid handle if debug object exists
HANDLE debugObject = NULL;
NtQueryInformationProcess(GetCurrentProcess(),
    ProcessDebugObjectHandle, &debugObject, sizeof(debugObject), NULL);
if (debugObject != NULL) { /* Debugger detected */ }

// Method 3: ProcessDebugFlags (0x1F)
// Returns 0 if being debugged, 1 if not (inverted logic!)
DWORD debugFlags = 0;
NtQueryInformationProcess(GetCurrentProcess(),
    ProcessDebugFlags, &debugFlags, sizeof(debugFlags), NULL);
if (debugFlags == 0) { /* Debugger detected */ }`}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                    ProcessDebugPort (0x07)
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.6 }}>
                    Returns the debug port handle. If non-zero, a debugger is attached. This is what 
                    CheckRemoteDebuggerPresent uses internally.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                    ProcessDebugObjectHandle (0x1E)
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.6 }}>
                    Returns a handle to the debug object. Only exists when being debugged. Harder to fake 
                    because it's a kernel object.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>
                    ProcessDebugFlags (0x1F)
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.6 }}>
                    <strong>Inverted logic!</strong> Returns 0 when debugged, 1 when not. Catches analysts 
                    who don't know about this quirk.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Other API Checks */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
              4. Other Notable API Checks
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                    OutputDebugString Trick
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7, mb: 2 }}>
                    <code>OutputDebugString</code> only succeeds if a debugger is attached to receive the message. 
                    By checking if the function "worked," you can detect a debugger.
                  </Typography>
                  <Paper sx={{ p: 1.5, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 1 }}>
                    <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#d4d4d4", m: 0 }}>
{`SetLastError(0);
OutputDebugStringA("test");
if (GetLastError() == 0) {
    // Debugger present!
}`}
                    </Typography>
                  </Paper>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>
                    FindWindow / EnumWindows
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7, mb: 2 }}>
                    Search for windows with debugger-related titles like "x64dbg", "OllyDbg", "IDA", "Ghidra", etc. 
                    Simple but effective against careless analysts.
                  </Typography>
                  <Paper sx={{ p: 1.5, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 1 }}>
                    <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#d4d4d4", m: 0 }}>
{`if (FindWindowA(NULL, "x64dbg") ||
    FindWindowA("OLLYDBG", NULL)) {
    // Debugger window found!
}`}
                    </Typography>
                  </Paper>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>
                    CreateToolhelp32Snapshot
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Enumerate all running processes looking for known debugger process names. Common targets: 
                    "x64dbg.exe", "ollydbg.exe", "ida.exe", "ida64.exe", "windbg.exe", "devenv.exe" (Visual Studio).
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    NtSetInformationThread
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Call with <code>ThreadHideFromDebugger (0x11)</code> to hide the current thread from the debugger. 
                    The debugger won't receive events from this thread—very effective for protecting critical code.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Practical Tip for Analysts</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              When analyzing malware, always use tools like <strong>ScyllaHide</strong> (x64dbg plugin) or 
              <strong>TitanHide</strong> that hook these APIs at the kernel level. Set breakpoints on 
              <code>IsDebuggerPresent</code>, <code>NtQueryInformationProcess</code>, and similar functions to identify 
              where the checks occur, then patch or bypass them. In IDA/Ghidra, search for these function imports 
              in the Import Address Table (IAT) to find all references.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 3: PEB & TEB FLAG CHECKS ==================== */}
        <Paper
          id="peb-flags-content"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#06b6d4", 0.2)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #06b6d4, #0891b2)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <MemoryIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            PEB & TEB Flag Checks
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Instead of calling Windows APIs (which can be hooked), sophisticated anti-debugging code directly reads 
            the <strong>Process Environment Block (PEB)</strong> and <strong>Thread Environment Block (TEB)</strong>—
            internal Windows data structures that contain debug-related flags. Since these are just memory reads, 
            they're faster and harder to hook than API calls.
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Understanding PEB and TEB</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Every Windows process has a <strong>PEB</strong> (Process Environment Block) containing process-wide 
              information. Every thread has a <strong>TEB</strong> (Thread Environment Block) containing thread-specific 
              data. Both are located in usermode memory and accessible without calling any APIs—you just need to know 
              where they are and how to read them. The TEB can be accessed via the <strong>FS</strong> register (32-bit) 
              or <strong>GS</strong> register (64-bit), and the PEB address is stored within the TEB.
            </Typography>
          </Alert>

          {/* PEB Structure Diagram */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
              The PEB Structure (Simplified)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#1e1e1e", 0.9), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Simplified PEB structure (Windows x64)
struct PEB {
    BYTE InheritedAddressSpace;        // 0x00
    BYTE ReadImageFileExecOptions;     // 0x01
    BYTE BeingDebugged;                // 0x02  ← KEY FLAG!
    BYTE BitField;                     // 0x03
    BYTE Padding[4];                   // 0x04-0x07
    PVOID Mutant;                      // 0x08
    PVOID ImageBaseAddress;            // 0x10
    PVOID Ldr;                         // 0x18
    PVOID ProcessParameters;           // 0x20
    // ... more fields ...
    DWORD NtGlobalFlag;                // 0xBC (x64)  ← KEY FLAG!
    // ... more fields ...
    PVOID ProcessHeap;                 // 0x30
    // The heap itself has debug flags too!
};

// Accessing PEB in assembly:
// x86: mov eax, fs:[0x30]   ; TEB.ProcessEnvironmentBlock
// x64: mov rax, gs:[0x60]   ; TEB.ProcessEnvironmentBlock`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* BeingDebugged Flag */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
              1. PEB.BeingDebugged Flag (Offset 0x02)
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              This is the flag that <code>IsDebuggerPresent()</code> reads. It's a single byte that's set to <strong>1</strong> 
              when a usermode debugger is attached and <strong>0</strong> otherwise. By reading it directly, you avoid 
              the API call that might be hooked.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// C++ - Direct PEB access
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

if (pPeb->BeingDebugged) {
    // Debugger detected!
}

// Inline assembly version (x86)
__asm {
    mov eax, fs:[0x30]    ; Get PEB address
    movzx eax, byte ptr [eax+0x02]  ; Read BeingDebugged
    test eax, eax
    jnz debugger_detected
}`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    ✅ Detecting in Disassembly
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Look for <code>fs:[0x30]</code> (x86) or <code>gs:[0x60]</code> (x64)</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Followed by read at offset +0x02</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Often followed by test/cmp and conditional jump</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    🔓 Bypass Methods
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Manually set PEB.BeingDebugged = 0</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• ScyllaHide patches this automatically</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Use x64dbg command: <code>peb.BeingDebugged = 0</code></Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* NtGlobalFlag */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
              2. PEB.NtGlobalFlag (Offset 0x68/0xBC)
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              The <strong>NtGlobalFlag</strong> field contains system debugging flags. When a process is created under 
              a debugger, Windows sets specific flags that indicate debug heap and other debugging features are enabled. 
              The key flags to look for are:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.08), borderRadius: 2, textAlign: "center" }}>
                  <Typography variant="h6" sx={{ fontFamily: "monospace", fontWeight: 700, color: "#06b6d4" }}>
                    FLG_HEAP_ENABLE_TAIL_CHECK
                  </Typography>
                  <Typography variant="caption" color="text.secondary">0x10</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.08), borderRadius: 2, textAlign: "center" }}>
                  <Typography variant="h6" sx={{ fontFamily: "monospace", fontWeight: 700, color: "#06b6d4" }}>
                    FLG_HEAP_ENABLE_FREE_CHECK
                  </Typography>
                  <Typography variant="caption" color="text.secondary">0x20</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.08), borderRadius: 2, textAlign: "center" }}>
                  <Typography variant="h6" sx={{ fontFamily: "monospace", fontWeight: 700, color: "#06b6d4" }}>
                    FLG_HEAP_VALIDATE_PARAMETERS
                  </Typography>
                  <Typography variant="caption" color="text.secondary">0x40</Typography>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              When combined (0x10 | 0x20 | 0x40 = <strong>0x70</strong>), these flags strongly indicate the process 
              was started under a debugger. Unlike BeingDebugged, this flag persists even if you detach the debugger!
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Checking NtGlobalFlag
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED      0x70

#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0xBC);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);
#endif

if (NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED) {
    // Process was STARTED under a debugger!
}`}
              </Typography>
            </Paper>

            <Alert severity="warning" sx={{ mb: 3, borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>⚠️ Important Distinction</AlertTitle>
              <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
                <strong>BeingDebugged</strong> = "Is a debugger currently attached?"<br />
                <strong>NtGlobalFlag</strong> = "Was this process created by a debugger?"<br /><br />
                If you attach a debugger to a running process, BeingDebugged becomes 1, but NtGlobalFlag stays 0. 
                If you start a process from a debugger, both are set. This is why sophisticated malware checks both!
              </Typography>
            </Alert>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Heap Flags */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
              3. Heap Flags (ProcessHeap)
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              When a process is created under a debugger, Windows enables <strong>debug heap</strong> features that 
              add extra checking and padding to heap allocations (to help find memory bugs). The heap structure itself 
              contains flags that reveal this, and these flags persist even after detaching the debugger.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Heap structure (simplified)
// The Flags and ForceFlags fields reveal debug heap

#define HEAP_GROWABLE              0x00000002
#define HEAP_TAIL_CHECKING_ENABLED 0x00000020
#define HEAP_FREE_CHECKING_ENABLED 0x00000040

// Get process heap
PVOID pHeap = (PVOID)*(PDWORD_PTR)((PBYTE)pPeb + 
    (sizeof(PVOID) == 8 ? 0x30 : 0x18));

// Read Flags (offset 0x40 x86, 0x70 x64)
// Read ForceFlags (offset 0x44 x86, 0x74 x64)
#ifdef _WIN64
    DWORD heapFlags = *(PDWORD)((PBYTE)pHeap + 0x70);
    DWORD forceFlags = *(PDWORD)((PBYTE)pHeap + 0x74);
#else
    DWORD heapFlags = *(PDWORD)((PBYTE)pHeap + 0x40);
    DWORD forceFlags = *(PDWORD)((PBYTE)pHeap + 0x44);
#endif

// Normal values: Flags=2 (GROWABLE), ForceFlags=0
// Debug values: Extra flags set
if (heapFlags != HEAP_GROWABLE || forceFlags != 0) {
    // Debug heap detected!
}`}
              </Typography>
            </Paper>

            <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8, bgcolor: alpha("#06b6d4", 0.1), p: 2, borderRadius: 2 }}>
              <strong>💡 Pro Tip:</strong> The heap flags check is particularly annoying because even if you patch 
              BeingDebugged and NtGlobalFlag, the heap was already created with debug features enabled. You need to 
              either start the process without a debugger and attach later, or use tools that patch these flags too.
            </Typography>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Other PEB/TEB Checks */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
              4. Other PEB/TEB-Based Checks
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>
                    PEB.Ldr (Loaded Modules)
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    The loader data contains a linked list of all loaded DLLs. Malware can scan for known debugger 
                    DLLs like <code>dbghelp.dll</code>, <code>dbgcore.dll</code>, or DLLs from analysis tools.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                    TEB.NtTib.ArbitraryUserPointer
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Some debuggers use this field for internal purposes. If it contains unexpected values, it might 
                    indicate a debugger is manipulating the thread state.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>
                    PEB.ProcessParameters.Flags
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Contains flags indicating how the process was started. The <code>BEING_DEBUGGED</code> flag 
                    (0x00000004) can also indicate debugger presence.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    LdrpDebugFlags Check
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    An internal ntdll variable that gets set during process initialization. Requires pattern scanning 
                    in ntdll.dll to locate, making it harder to detect and bypass.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Comprehensive Bypass Strategy</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              To fully bypass PEB/TEB checks, you need to patch <strong>all</strong> of the following: BeingDebugged (→0), 
              NtGlobalFlag (→0), Heap.Flags (→2), Heap.ForceFlags (→0). Tools like <strong>ScyllaHide</strong> and 
              <strong>TitanHide</strong> can do this automatically. In x64dbg, you can also use the "Hide Debugger (PEB)" 
              option. For persistent bypasses, consider writing a loader that creates the process without a debugger, 
              patches the flags, then attaches.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 4: TIMING-BASED DETECTION ==================== */}
        <Paper
          id="timing-attacks-content"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#f97316", 0.2)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #f97316, #ea580c)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <TimerIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Timing-Based Detection
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            One of the cleverest anti-debugging techniques exploits a fundamental truth: <strong>debugging slows things down</strong>. 
            When you single-step through code, set breakpoints, or inspect memory, everything takes longer than it would during 
            normal execution. Timing-based detection measures execution time and triggers if it's suspiciously long.
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Why Timing Checks Are Effective</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Even the fastest debugger adds overhead. Single-stepping executes one instruction then returns control to the 
              debugger—each step might take milliseconds instead of nanoseconds. Hardware breakpoints cause exceptions. 
              Memory inspection requires context switches. A code block that normally runs in microseconds might take seconds 
              under a debugger, and this difference is easily detectable.
            </Typography>
          </Alert>

          {/* RDTSC */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
              1. RDTSC (Read Time-Stamp Counter)
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              The <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>RDTSC</code> instruction 
              reads the processor's Time Stamp Counter—a 64-bit counter that increments every CPU cycle. By reading it before 
              and after a code block, you can measure exactly how many cycles elapsed. If the count is too high, someone's 
              stepping through your code.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// RDTSC anti-debugging
#include <intrin.h>  // For __rdtsc()

void check_timing() {
    unsigned __int64 start, end;
    
    start = __rdtsc();  // Read TSC before
    
    // Code block to time - intentionally simple
    volatile int x = 0;
    for (int i = 0; i < 100; i++) {
        x += i;
    }
    
    end = __rdtsc();    // Read TSC after
    
    // Normal execution: ~1000-5000 cycles
    // Under debugger (single-stepping): millions of cycles
    if ((end - start) > 100000) {
        // Debugger detected!
        ExitProcess(0);
    }
}

// Inline assembly version (x86)
__asm {
    rdtsc                 ; EDX:EAX = timestamp
    mov esi, eax          ; Save low 32 bits
    ; ... code to time ...
    rdtsc
    sub eax, esi          ; Calculate difference
    cmp eax, 100000
    ja debugger_detected
}`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    ✅ Detecting in Binaries
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Search for <code>0F 31</code> bytes (RDTSC opcode)</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Look for paired RDTSC calls with comparison</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Watch for large constant comparisons (&gt;10000)</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    🔓 Bypass Methods
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Use TitanHide to hook RDTSC at kernel level</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Patch the comparison to always pass</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Use VM with TSC offsetting (VMware)</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Run without breakpoints, trace with logging</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* QueryPerformanceCounter */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
              2. QueryPerformanceCounter / QueryPerformanceFrequency
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Windows API alternative to RDTSC. <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>QueryPerformanceCounter</code> 
              returns a high-resolution timestamp, and <code>QueryPerformanceFrequency</code> tells you the counter's frequency. 
              Together, they allow precise time measurement in a portable way.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`LARGE_INTEGER start, end, freq;
QueryPerformanceFrequency(&freq);
QueryPerformanceCounter(&start);

// Suspicious code block
for (volatile int i = 0; i < 1000; i++) { }

QueryPerformanceCounter(&end);

// Calculate elapsed time in milliseconds
double elapsed_ms = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;

if (elapsed_ms > 50.0) {  // Should take < 1ms normally
    // Debugger detected!
}`}
              </Typography>
            </Paper>

            <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8, bgcolor: alpha("#f97316", 0.1), p: 2, borderRadius: 2 }}>
              <strong>💡 Pro Tip:</strong> QueryPerformanceCounter is more "legitimate-looking" than RDTSC because many 
              applications use it for benchmarking and frame timing. Malware often uses it because it raises fewer red 
              flags during static analysis.
            </Typography>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* GetTickCount */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
              3. GetTickCount / GetTickCount64
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              The simplest timing check. <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>GetTickCount</code> returns 
              the number of milliseconds since system boot. While less precise than RDTSC (millisecond vs nanosecond resolution), 
              it's extremely easy to use and very common in malware.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`DWORD start = GetTickCount();

// Code to time
Sleep(0);  // Yield to OS, tiny delay normally
// ... more code ...

DWORD elapsed = GetTickCount() - start;

// Normal: 0-15ms (depends on scheduler)
// Debugging with stepping: seconds or more
if (elapsed > 1000) {
    // Either debugger or system is very slow
    exit(1);
}`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Other timing techniques */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
              4. Advanced Timing Techniques
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>
                    RDTSCP (Serializing RDTSC)
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    <code>RDTSCP</code> is a serializing version of RDTSC that waits for all previous instructions to 
                    complete. This prevents out-of-order execution from skewing measurements. More accurate but also 
                    more detectable.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>
                    Interrupt Timing (INT 2A)
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    <code>INT 2A</code> (KiGetTickCount) is an interrupt that returns the tick count. Measuring the 
                    time to execute an interrupt can reveal debugger presence due to exception handling overhead.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                    Thread Timing
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Create a watchdog thread that monitors the main thread's progress. If the main thread takes too 
                    long to reach certain checkpoints, the watchdog terminates the process. Hard to bypass because 
                    you'd need to debug both threads simultaneously.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    Cumulative Timing
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Instead of one timing check, spread many small checks throughout the code. Each measures a tiny 
                    delay that's imperceptible normally but accumulates under debugging. Harder to find and patch all 
                    of them.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Bypassing Timing Checks</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Timing checks are tricky to bypass because you can't easily "speed up" debugging. Best approaches: 
              <strong>1)</strong> Use kernel-level tools (TitanHide) that hook timing functions to return fake values. 
              <strong>2)</strong> Identify and patch all timing comparisons. <strong>3)</strong> Use conditional breakpoints 
              sparingly and let code run freely when possible. <strong>4)</strong> Use trace logging instead of stepping. 
              <strong>5)</strong> Run in a VM with time virtualization.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 5: EXCEPTION-BASED TECHNIQUES ==================== */}
        <Paper
          id="exception-based-content"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #ef4444, #dc2626)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <WarningIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Exception-Based Techniques
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Exception-based anti-debugging exploits a key difference: <strong>debuggers intercept exceptions before 
            your exception handlers do</strong>. By causing intentional exceptions and checking how they're handled, 
            code can detect if a debugger is interfering with normal exception flow.
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>How Windows Exception Handling Works</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              When an exception occurs: <strong>1)</strong> If a debugger is attached, it gets first chance to handle it. 
              <strong>2)</strong> If the debugger passes, Windows walks the SEH chain looking for a handler. 
              <strong>3)</strong> If no handler is found, the debugger gets a second chance. <strong>4)</strong> If still 
              unhandled, the process terminates. Anti-debugging code exploits step 1—if a debugger handles the exception, 
              your handler never runs.
            </Typography>
          </Alert>

          {/* INT 3 */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              1. INT 3 (Breakpoint Exception)
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              <code style={{ background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: 4 }}>INT 3</code> (opcode 0xCC) 
              is the software breakpoint instruction. When executed, it raises a BREAKPOINT_EXCEPTION. Without a debugger, 
              your exception handler runs. <em>With</em> a debugger, the debugger typically catches it and pauses execution—
              your handler never executes.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// INT 3 anti-debugging with SEH
BOOL g_debuggerDetected = TRUE;  // Assume debugger until proven otherwise

LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        g_debuggerDetected = FALSE;  // Handler ran = no debugger
        ep->ContextRecord->Eip++;    // Skip past INT 3
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void check_int3() {
    AddVectoredExceptionHandler(1, VectoredHandler);
    
    __try {
        __asm { int 3 }  // Or: __debugbreak();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        g_debuggerDetected = FALSE;  // SEH handler ran
    }
    
    if (g_debuggerDetected) {
        // Debugger swallowed the exception!
        TerminateProcess(GetCurrentProcess(), 0);
    }
}`}
              </Typography>
            </Paper>

            <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8, bgcolor: alpha("#ef4444", 0.1), p: 2, borderRadius: 2 }}>
              <strong>⚠️ Note:</strong> Most debuggers can be configured to pass INT 3 exceptions to the program. In x64dbg, 
              go to Options → Preferences → Exceptions and configure how breakpoint exceptions are handled. However, many 
              analysts forget to do this, making INT 3 checks still effective.
            </Typography>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* INT 2D */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              2. INT 2D (Kernel Debugger Check)
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              <code style={{ background: alpha("#ef4444", 0.1), padding: "2px 6px", borderRadius: 4 }}>INT 2D</code> is used 
              internally by Windows for kernel debugging. When executed in user mode with a kernel debugger attached, it 
              behaves differently. It also has a quirk: the instruction pointer after the exception might skip the next byte, 
              which can be used for detection.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// INT 2D trick - the byte after INT 2D may be skipped
BOOL detected = FALSE;

__try {
    __asm {
        int 2dh
        nop        ; This NOP might be skipped under debugger!
    }
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    // Exception handler ran - check EIP
}

// Alternative: Use INT 2D to detect kernel debuggers (WinDbg)
// If a kernel debugger is attached, behavior changes`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Single-Step Exception */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              3. Single-Step (Trap Flag) Exception
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              The CPU's <strong>Trap Flag (TF)</strong> in the EFLAGS register causes a SINGLE_STEP exception after each 
              instruction. Debuggers use this for single-stepping. By setting TF yourself and checking if your handler runs, 
              you can detect if a debugger is intercepting single-step exceptions.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`BOOL g_singleStepHandled = FALSE;

LONG CALLBACK SingleStepHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        g_singleStepHandled = TRUE;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void check_trap_flag() {
    AddVectoredExceptionHandler(1, SingleStepHandler);
    
    // Set the Trap Flag
    __asm {
        pushfd           ; Push EFLAGS
        or dword ptr [esp], 0x100  ; Set TF (bit 8)
        popfd            ; Pop back to EFLAGS
        nop              ; Single-step exception fires AFTER this
    }
    
    if (!g_singleStepHandled) {
        // Debugger ate the exception!
        ExitProcess(1);
    }
}`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Other exception techniques */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              4. Other Exception Techniques
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    EXCEPTION_GUARD_PAGE
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Mark a memory page as a guard page. First access raises an exception. Debuggers often access memory 
                    for inspection, potentially triggering the guard and revealing their presence.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>
                    INVALID_HANDLE Exception
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    <code>CloseHandle()</code> with an invalid handle raises an exception only when a debugger is attached. 
                    This is an undocumented behavior that serves as a simple debugger check.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                    RaiseException with DBG_PRINTEXCEPTION_C
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    <code>RaiseException(DBG_PRINTEXCEPTION_C, ...)</code> is used by OutputDebugString. Debuggers handle 
                    this specially. Checking if the exception is consumed can reveal debugger presence.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>
                    Unhandled Exception Filter
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    <code>SetUnhandledExceptionFilter</code> installs a last-resort handler. Under a debugger, this filter 
                    is often bypassed. Check if your filter was actually called when an exception occurs.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Bypassing Exception-Based Checks</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              <strong>1)</strong> Configure your debugger to pass exceptions to the program (x64dbg: Options → Preferences → Exceptions). 
              <strong>2)</strong> Use ScyllaHide's "Skip INT 3" and exception hiding options. 
              <strong>3)</strong> Set breakpoints after the exception handler, not inside it. 
              <strong>4)</strong> Use conditional logging instead of stepping through exception-heavy code. 
              <strong>5)</strong> Patch the exception-raising code directly.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 6: HARDWARE BREAKPOINT DETECTION ==================== */}
        <Paper
          id="hardware-breakpoints-content"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#ec4899", 0.2)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #ec4899, #db2777)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <SettingsIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Hardware Breakpoint Detection
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            x86/x64 CPUs have <strong>debug registers</strong> (DR0-DR7) specifically designed for debugging. They allow 
            setting up to 4 hardware breakpoints that trigger without modifying code (unlike software breakpoints). 
            Since they're CPU features, anti-debugging code can read these registers to detect if breakpoints are set.
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Understanding Debug Registers</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              <strong>DR0-DR3:</strong> Hold addresses of up to 4 breakpoints<br/>
              <strong>DR4-DR5:</strong> Reserved (alias to DR6-DR7 on older CPUs)<br/>
              <strong>DR6:</strong> Debug status register—shows which breakpoint fired<br/>
              <strong>DR7:</strong> Debug control register—enables breakpoints and sets conditions (execute, read, write)
            </Typography>
          </Alert>

          {/* GetThreadContext */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
              1. GetThreadContext - Reading Debug Registers
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              The <code style={{ background: alpha("#ec4899", 0.1), padding: "2px 6px", borderRadius: 4 }}>GetThreadContext</code> API 
              can retrieve the current thread's context, including debug registers. If DR0-DR3 contain non-zero values, 
              hardware breakpoints are set—a clear sign of debugging.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Detecting hardware breakpoints via GetThreadContext
BOOL CheckHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        return FALSE;  // Failed to get context
    }
    
    // Check if any hardware breakpoints are set
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || 
        ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        return TRUE;  // Hardware breakpoint detected!
    }
    
    // Also check DR7 control bits
    // Bits 0,2,4,6 enable local breakpoints for DR0-DR3
    if (ctx.Dr7 & 0x55) {  // 01010101 binary
        return TRUE;  // Breakpoints enabled in DR7
    }
    
    return FALSE;
}

// Usage
if (CheckHardwareBreakpoints()) {
    // Someone's debugging with hardware breakpoints!
    ExitProcess(0xDEAD);
}`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    ✅ Detecting in Binaries
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Look for GetThreadContext import</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• CONTEXT_DEBUG_REGISTERS (0x10010)</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Checks on Dr0, Dr1, Dr2, Dr3, Dr7 fields</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    🔓 Bypass Methods
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Hook GetThreadContext to zero DR registers</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Use software breakpoints instead</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• ScyllaHide hides debug registers</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Exception-based DR detection */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
              2. Exception-Based Debug Register Detection
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              A sneakier approach: cause an exception and check the debug registers in the exception handler. The CONTEXT 
              structure passed to exception handlers contains the debug registers. This avoids calling GetThreadContext 
              directly (which can be hooked).
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`BOOL g_hwbpDetected = FALSE;

LONG CALLBACK HWBPExceptionHandler(PEXCEPTION_POINTERS ep) {
    // Check debug registers in exception context
    PCONTEXT ctx = ep->ContextRecord;
    
    if (ctx->Dr0 || ctx->Dr1 || ctx->Dr2 || ctx->Dr3) {
        g_hwbpDetected = TRUE;
    }
    
    // Handle the exception and continue
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        ctx->Eip += 2;  // Skip past the faulting instruction
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void check_hwbp_via_exception() {
    AddVectoredExceptionHandler(1, HWBPExceptionHandler);
    
    // Cause an exception
    __try {
        *(volatile int*)0 = 0;  // Access violation
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    
    if (g_hwbpDetected) {
        // Hardware breakpoints found!
    }
}`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* SetThreadContext */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
              3. SetThreadContext - Clearing Debug Registers
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Instead of just detecting hardware breakpoints, aggressive anti-debugging code can <strong>clear them</strong>. 
              Using <code style={{ background: alpha("#ec4899", 0.1), padding: "2px 6px", borderRadius: 4 }}>SetThreadContext</code>, 
              malware can zero out the debug registers, removing any hardware breakpoints an analyst has set.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Clear all hardware breakpoints
void ClearHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    // Get current context
    GetThreadContext(GetCurrentThread(), &ctx);
    
    // Zero all debug registers
    ctx.Dr0 = 0;
    ctx.Dr1 = 0;
    ctx.Dr2 = 0;
    ctx.Dr3 = 0;
    ctx.Dr6 = 0;
    ctx.Dr7 = 0;
    
    // Apply the modified context
    SetThreadContext(GetCurrentThread(), &ctx);
    
    // Now no hardware breakpoints are set!
}`}
              </Typography>
            </Paper>

            <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8, bgcolor: alpha("#ec4899", 0.1), p: 2, borderRadius: 2 }}>
              <strong>💡 Defense Tip:</strong> If malware clears your hardware breakpoints, you can set them again using 
              your debugger. But if the malware does this repeatedly or in multiple threads, you may need to hook 
              SetThreadContext to prevent the clearing.
            </Typography>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Advanced techniques */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
              4. Advanced Debug Register Techniques
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#ec4899", 0.03), border: `1px solid ${alpha("#ec4899", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>
                    NtQueryInformationThread
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Lower-level alternative to GetThreadContext. With ThreadBasicInformation or ThreadWow64Context, 
                    you can retrieve thread context including debug registers. Harder to hook than kernel32 APIs.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>
                    Thread-Walking Detection
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Create multiple threads and check debug registers in each one. Analysts might set breakpoints 
                    only in the main thread, missing other threads. Enumerate all threads and check each one.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                    MOV DR Instruction (Ring 0 Only)
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Kernel drivers can directly read/write debug registers using <code>MOV DR</code> instructions. 
                    Anti-cheat systems like EasyAntiCheat use this to detect kernel debuggers.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>
                    Anti-Breakpoint via Checksums
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Some malware doesn't check debug registers directly but uses code checksums. If you set a hardware 
                    breakpoint that modifies memory (it doesn't, but some checks are paranoid), checksums would fail.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Practical Bypass Strategy</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              <strong>1)</strong> Use software breakpoints (INT 3) when possible—they don't use debug registers. 
              <strong>2)</strong> Hook GetThreadContext/SetThreadContext to hide or preserve debug registers. 
              <strong>3)</strong> Use conditional logging and trace instead of breakpoints. 
              <strong>4)</strong> ScyllaHide's "Protect DRx" option prevents clearing and hides values. 
              <strong>5)</strong> For critical breakpoints, set them in all threads and re-apply after any SetThreadContext call.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 7: SOFTWARE BREAKPOINT DETECTION ==================== */}
        <Paper
          id="software-breakpoints-content"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#14b8a6", 0.2)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #14b8a6, #0d9488)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <BugReportIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Software Breakpoint Detection
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Unlike hardware breakpoints (which use CPU debug registers), <strong>software breakpoints</strong> work by 
            modifying code in memory. The debugger replaces the first byte of an instruction with <code style={{ background: alpha("#14b8a6", 0.1), padding: "2px 6px", borderRadius: 4 }}>0xCC</code> 
            (INT 3), which triggers a breakpoint exception. Since this modifies the actual code, anti-debugging techniques 
            can detect it by scanning for 0xCC bytes or verifying code integrity.
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>How Software Breakpoints Work</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              When you set a breakpoint at address 0x401000, the debugger: <strong>1)</strong> Saves the original byte. 
              <strong>2)</strong> Writes 0xCC (INT 3) to that address. <strong>3)</strong> When execution reaches it, 
              CPU raises EXCEPTION_BREAKPOINT. <strong>4)</strong> Debugger catches exception, restores original byte, 
              lets you inspect. This modification is detectable!
            </Typography>
          </Alert>

          {/* 0xCC Scanning */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
              1. Scanning for 0xCC (INT 3) Bytes
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              The most direct approach: scan your own code for 0xCC bytes that shouldn't be there. If you find INT 3 
              instructions in places where you know there shouldn't be any, a debugger has set breakpoints.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Scan a function for software breakpoints (0xCC)
BOOL CheckForSoftwareBreakpoints(PVOID pFunction, SIZE_T size) {
    PBYTE pCode = (PBYTE)pFunction;
    
    for (SIZE_T i = 0; i < size; i++) {
        if (pCode[i] == 0xCC) {  // INT 3 opcode
            return TRUE;  // Breakpoint detected!
        }
    }
    return FALSE;
}

// Check specific functions
if (CheckForSoftwareBreakpoints(ImportantFunction, 0x100)) {
    // Someone set a breakpoint in our code!
    ExitProcess(0xDEAD);
}

// Can also check API functions for hooks/breakpoints
if (*(PBYTE)GetProcAddress(GetModuleHandle("ntdll"), 
    "NtQueryInformationProcess") == 0xCC) {
    // API has breakpoint - likely being monitored
}`}
              </Typography>
            </Paper>

            <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8, bgcolor: alpha("#14b8a6", 0.1), p: 2, borderRadius: 2 }}>
              <strong>⚠️ Limitation:</strong> Some legitimate code might contain 0xCC bytes (as immediate values, 
              not as instructions). Sophisticated detection should disassemble and check if 0xCC is at instruction 
              boundaries. Also, this only catches breakpoints set <em>before</em> the scan runs.
            </Typography>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Checksum Verification */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
              2. Code Checksum Verification
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Instead of looking for specific bytes, calculate a checksum of your code and compare it to a known-good 
              value. Any modification (breakpoints, patches, hooks) will change the checksum.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Calculate CRC32 checksum of code section
DWORD CalculateCodeChecksum(PVOID pStart, SIZE_T size) {
    DWORD checksum = 0xFFFFFFFF;
    PBYTE pCode = (PBYTE)pStart;
    
    for (SIZE_T i = 0; i < size; i++) {
        checksum ^= pCode[i];
        for (int j = 0; j < 8; j++) {
            checksum = (checksum >> 1) ^ (0xEDB88320 & -(checksum & 1));
        }
    }
    return ~checksum;
}

// Store expected checksum (calculated at build time)
#define EXPECTED_CHECKSUM 0x12345678

void VerifyCodeIntegrity() {
    DWORD currentChecksum = CalculateCodeChecksum(
        (PVOID)&CriticalFunction, 0x200);
    
    if (currentChecksum != EXPECTED_CHECKSUM) {
        // Code has been modified!
        // Could be breakpoints, patches, or hooks
        CorruptSensitiveData();  // Make analysis harder
    }
}`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    ✅ Advantages
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Detects ANY code modification</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Works against patches and hooks too</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Can verify multiple code regions</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    🔓 Bypass Methods
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Find and patch the checksum comparison</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Use hardware breakpoints instead</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Hook checksum function to return expected value</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Self-Modifying Code */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
              3. Self-Modifying Code
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Advanced protection: code that modifies itself at runtime. If a breakpoint is set, the modification either 
              changes the breakpoint or the breakpoint corrupts the self-modification, causing crashes or incorrect behavior.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Self-modifying code example
// The function decrypts itself before execution
void __declspec(naked) SelfModifyingFunction() {
    __asm {
        // XOR-decrypt the next 10 bytes with key 0x55
        mov ecx, 10
        lea esi, encrypted_code
    decrypt_loop:
        xor byte ptr [esi], 0x55
        inc esi
        loop decrypt_loop
        
    encrypted_code:
        // This code is XOR-encrypted at rest
        // If breakpoint is here, XOR will corrupt it
        _emit 0x55  // Encrypted: mov eax, 1
        _emit 0xB8  // These bytes make sense after XOR
        // ...
    }
}

// If analyst sets breakpoint in encrypted region:
// 0xCC XOR 0x55 = 0x99 (garbage instruction)
// Code crashes or behaves unexpectedly`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Other techniques */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
              4. Other Software Breakpoint Techniques
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#14b8a6", 0.03), border: `1px solid ${alpha("#14b8a6", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#14b8a6", mb: 1 }}>
                    API First-Byte Check
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Check if common APIs start with 0xCC. Analysts often set breakpoints on APIs like 
                    <code>VirtualAlloc</code>, <code>CreateFile</code>, etc. to monitor behavior.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>
                    PAGE_GUARD Detection
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Check page protection flags. Debuggers might set PAGE_GUARD on code pages for memory breakpoints. 
                    Use <code>VirtualQuery</code> to detect unusual protection flags.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                    Continuous Integrity Checks
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Run checksum verification in a loop or separate thread. Even if analyst removes breakpoint 
                    after being detected once, continuous checking will catch re-applied breakpoints.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    Import Table Verification
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Verify that imported function addresses match expected values. Hooks often redirect imports, 
                    which changes the IAT entries. Compare against known-good addresses.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Analyst Tips</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Against software breakpoint detection: <strong>1)</strong> Use hardware breakpoints exclusively. 
              <strong>2)</strong> Set breakpoints outside the checked regions. <strong>3)</strong> Use tracing/logging 
              instead of breakpoints. <strong>4)</strong> Find and disable the checking code first. 
              <strong>5)</strong> For self-modifying code, dump after decryption or use memory breakpoints.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 8: ANTI-VM & SANDBOX DETECTION ==================== */}
        <Paper
          id="anti-vm-content"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#6366f1", 0.2)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #6366f1, #4f46e5)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <StorageIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Anti-VM & Sandbox Detection
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Security researchers often analyze malware in <strong>virtual machines</strong> (VMware, VirtualBox, Hyper-V) 
            or automated <strong>sandboxes</strong> (Cuckoo, Any.Run, Joe Sandbox). Malware has evolved to detect these 
            environments and behave innocently when observed—only revealing malicious behavior on "real" systems.
          </Typography>

          <Alert severity="warning" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Why This Matters</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Anti-VM techniques are <strong>extremely common</strong> in modern malware. Studies show 50-80% of malware 
              samples include some form of VM detection. If your analysis VM is easily detected, you'll miss the actual 
              malicious behavior. Hardening your analysis environment is essential.
            </Typography>
          </Alert>

          {/* CPUID Checks */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
              1. CPUID Instruction Checks
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              The <code style={{ background: alpha("#6366f1", 0.1), padding: "2px 6px", borderRadius: 4 }}>CPUID</code> instruction 
              returns information about the CPU. Hypervisors set a specific bit to indicate virtualization, and the 
              vendor string might reveal the hypervisor type.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// CPUID-based VM detection
BOOL IsVirtualMachine_CPUID() {
    int cpuInfo[4] = {0};
    
    // Check hypervisor present bit (CPUID.1:ECX bit 31)
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        // Hypervisor bit set - definitely in VM
        return TRUE;
    }
    
    // Get hypervisor vendor string (CPUID leaf 0x40000000)
    __cpuid(cpuInfo, 0x40000000);
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 12);
    
    // Check for known hypervisor signatures
    if (strstr(vendor, "VMwareVMware") ||
        strstr(vendor, "Microsoft Hv") ||  // Hyper-V
        strstr(vendor, "KVMKVMKVM") ||     // KVM
        strstr(vendor, "XenVMMXenVMM") ||  // Xen
        strstr(vendor, "VBoxVBoxVBox")) {  // VirtualBox
        return TRUE;
    }
    
    return FALSE;
}`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Hardware Artifacts */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
              2. Hardware & Driver Artifacts
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              VMs have characteristic hardware identifiers. The MAC address, disk names, BIOS strings, and device 
              drivers all contain fingerprints that reveal virtualization.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#6366f1", 0.03), border: `1px solid ${alpha("#6366f1", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#6366f1", mb: 1 }}>
                    MAC Address Prefixes
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7, fontFamily: "monospace", fontSize: "0.8rem" }}>
                    VMware: 00:0C:29, 00:50:56<br/>
                    VirtualBox: 08:00:27<br/>
                    Hyper-V: 00:15:5D<br/>
                    Parallels: 00:1C:42
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>
                    Disk & Device Names
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Look for "VBOX", "VMWARE", "QEMU", "Virtual" in disk names, SCSI device strings, 
                    or device descriptions. WMI queries reveal this information.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Check for VM-specific drivers and files
BOOL CheckVMDrivers() {
    // VMware tools
    if (GetFileAttributes("C:\\\\Windows\\\\System32\\\\drivers\\\\vmhgfs.sys") 
        != INVALID_FILE_ATTRIBUTES) return TRUE;
    if (GetFileAttributes("C:\\\\Windows\\\\System32\\\\drivers\\\\vmmouse.sys") 
        != INVALID_FILE_ATTRIBUTES) return TRUE;
        
    // VirtualBox
    if (GetFileAttributes("C:\\\\Windows\\\\System32\\\\drivers\\\\VBoxMouse.sys") 
        != INVALID_FILE_ATTRIBUTES) return TRUE;
        
    // Check for VM processes
    if (FindProcess("vmtoolsd.exe")) return TRUE;  // VMware Tools
    if (FindProcess("VBoxService.exe")) return TRUE;  // VirtualBox
    
    return FALSE;
}`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Registry Checks */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
              3. Registry & WMI Checks
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Virtual machines leave traces in the Windows registry. BIOS information, hardware descriptions, and 
              installed software all provide detection opportunities.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Registry-based VM detection
BOOL CheckVMRegistry() {
    HKEY hKey;
    char value[256];
    DWORD size = sizeof(value);
    
    // Check BIOS vendor
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "HARDWARE\\\\DESCRIPTION\\\\System\\\\BIOS", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        RegQueryValueExA(hKey, "SystemManufacturer", 
            NULL, NULL, (LPBYTE)value, &size);
        
        if (strstr(value, "VMware") || 
            strstr(value, "innotek") ||  // VirtualBox
            strstr(value, "Microsoft Corporation")) {  // Hyper-V
            RegCloseKey(hKey);
            return TRUE;
        }
        RegCloseKey(hKey);
    }
    
    // Check for VirtualBox Guest Additions
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Sandbox Detection */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
              4. Sandbox-Specific Detection
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Automated sandboxes have unique characteristics: short execution time, limited user interaction, 
              specific usernames, low file counts, and analysis tool processes.
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    Common Sandbox Indicators
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Username: "sandbox", "malware", "virus", "analysis"</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Computer name: "SANDBOX", "CUCKOO", "ANYRUN"</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Few files in Documents/Desktop</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Recently installed OS (uptime check)</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                    Behavioral Evasion
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Sleep for extended periods (sandboxes timeout)</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Require user interaction (clicks, typing)</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Check for recent user activity</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Wait for specific date/time</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Hardening Your Analysis VM</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              <strong>1)</strong> Remove/rename VM tools after installation. <strong>2)</strong> Change MAC address prefixes. 
              <strong>3)</strong> Modify registry keys that reveal VM. <strong>4)</strong> Use realistic username and files. 
              <strong>5)</strong> Add fake browser history and documents. <strong>6)</strong> Patch CPUID returns with 
              tools like VMMDetector. <strong>7)</strong> Use nested virtualization or bare-metal when necessary.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 9: LINUX ANTI-DEBUGGING ==================== */}
        <Paper
          id="linux-anti-debug-content"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#22c55e", 0.2)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #22c55e, #16a34a)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <TerminalIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Linux Anti-Debugging Techniques
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            While Windows anti-debugging gets most attention, Linux has its own ecosystem of techniques. The 
            <code style={{ background: alpha("#22c55e", 0.1), padding: "2px 6px", borderRadius: 4 }}>ptrace</code> system call 
            is the foundation of Linux debugging, and detecting it is the primary anti-debugging strategy. The 
            <code>/proc</code> filesystem also exposes debugging information.
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Linux Debugging Basics</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              On Linux, debugging is done via <strong>ptrace()</strong>—a system call that allows one process to control 
              another. Debuggers like GDB use ptrace to attach, set breakpoints, and read memory. A process can only be 
              traced by one tracer at a time, which creates the primary detection opportunity.
            </Typography>
          </Alert>

          {/* ptrace Detection */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
              1. ptrace Self-Attach Detection
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              The classic Linux anti-debugging technique: try to ptrace yourself. If a debugger is already attached, 
              this will fail because a process can only have one tracer. This is simple, effective, and extremely common.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Classic ptrace anti-debugging
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>

void check_ptrace() {
    // Try to trace ourselves
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        // If this fails, someone is already tracing us!
        printf("Debugger detected!\\n");
        exit(1);
    }
    // Note: After PTRACE_TRACEME, parent becomes tracer
    // This can affect process behavior
}

// Alternative: Fork and trace child
void check_ptrace_fork() {
    pid_t child = fork();
    if (child == 0) {
        // Child: try to trace parent
        if (ptrace(PTRACE_ATTACH, getppid(), NULL, NULL) == -1) {
            // Parent is being traced by someone else
            exit(1);  // Signal to parent
        }
        ptrace(PTRACE_DETACH, getppid(), NULL, NULL);
        exit(0);
    } else {
        int status;
        waitpid(child, &status, 0);
        if (WEXITSTATUS(status) == 1) {
            printf("Debugger detected!\\n");
            exit(1);
        }
    }
}`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    ✅ Detecting in Binaries
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Search for ptrace in imports/strings</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Look for syscall 101 (ptrace on x64)</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• PTRACE_TRACEME = 0, check for this constant</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    🔓 Bypass Methods
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• LD_PRELOAD to hook ptrace and return 0</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Patch the ptrace call in binary</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Use GDB's "catch syscall ptrace"</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* /proc Checks */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
              2. /proc/self/status Checks
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              The <code>/proc</code> filesystem exposes process information. The <code>TracerPid</code> field in 
              <code>/proc/self/status</code> contains the PID of the tracing process (0 if not being traced).
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Check TracerPid in /proc/self/status
#include <stdio.h>
#include <string.h>

int check_tracer_pid() {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            fclose(f);
            
            if (tracer_pid != 0) {
                printf("Being traced by PID: %d\\n", tracer_pid);
                return 1;  // Debugger detected
            }
            return 0;
        }
    }
    fclose(f);
    return 0;
}

// Also check /proc/self/stat (field 6 is tracer PID)
// Or /proc/self/wchan for debugging wait channels`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Other Linux Techniques */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
              3. Other Linux Anti-Debugging Techniques
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    LD_PRELOAD Detection
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Check if LD_PRELOAD environment variable is set. Analysts use it to hook functions. Also check 
                    <code>/proc/self/maps</code> for injected libraries.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>
                    Signal Handlers
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Set custom handlers for SIGTRAP, SIGSTOP, SIGINT. Debuggers use these signals. Check if signals 
                    are delivered as expected or intercepted by a debugger.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                    /proc/self/fd Analysis
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Debuggers often keep extra file descriptors open. Check for unusual FDs or FDs pointing to 
                    debugger-related files or pipes.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>
                    Timing Checks (Linux)
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Use <code>clock_gettime()</code>, <code>gettimeofday()</code>, or read <code>/proc/uptime</code>. 
                    Measure execution time of code blocks to detect single-stepping.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Linux Bypass Toolkit</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              <strong>1)</strong> Create a ptrace hook with LD_PRELOAD that always returns success. 
              <strong>2)</strong> Modify /proc/self/status with FUSE or kernel module. 
              <strong>3)</strong> Use <code>strace -f</code> with <code>-e inject=ptrace:retval=0</code>. 
              <strong>4)</strong> Patch binary to NOP out anti-debug calls. 
              <strong>5)</strong> Use <code>gdb -ex 'catch syscall ptrace'</code> to intercept and modify results.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 10: ANDROID & MOBILE ANTI-DEBUGGING ==================== */}
        <Paper
          id="android-anti-debug-content"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#a855f7", 0.2)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #a855f7, #9333ea)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <AndroidIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Android & Mobile Anti-Debugging
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Mobile applications face unique challenges: attackers can root/jailbreak devices, use tools like 
            <strong> Frida</strong> for dynamic instrumentation, and attach debuggers to both Java and native code. 
            Android apps must defend against the <strong>Android Debug Bridge (ADB)</strong>, Java debuggers (JDWP), 
            and native debuggers (ptrace-based).
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Mobile Threat Landscape</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Mobile apps are particularly vulnerable because users have physical access to devices. Rooting/jailbreaking 
              removes OS protections. Tools like <strong>Frida</strong>, <strong>Objection</strong>, and <strong>Magisk</strong> make 
              bypassing protections accessible even to beginners. Defense-in-depth is essential.
            </Typography>
          </Alert>

          {/* Java/JDWP Detection */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>
              1. Java Debugger Detection (JDWP)
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Android apps can check if the Java Debug Wire Protocol is enabled or if a debugger is connected. 
              The <code style={{ background: alpha("#a855f7", 0.1), padding: "2px 6px", borderRadius: 4 }}>android:debuggable</code> flag 
              and runtime checks are the first line of defense.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Java-level debugger detection (Kotlin/Java)
fun isDebuggerDetected(): Boolean {
    // Check if debuggable flag is set
    val isDebuggable = (applicationContext.applicationInfo.flags 
        and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    
    // Check if debugger is connected right now
    val isDebuggerConnected = android.os.Debug.isDebuggerConnected()
    
    // Check for debug waiting (debugger will attach)
    val waitingForDebugger = android.os.Debug.waitingForDebugger()
    
    return isDebuggable || isDebuggerConnected || waitingForDebugger
}

// Check for USB debugging enabled
fun isUsbDebuggingEnabled(context: Context): Boolean {
    return Settings.Global.getInt(context.contentResolver, 
        Settings.Global.ADB_ENABLED, 0) == 1
}

// Detect JDWP port (5005 is default debug port)
fun checkJdwpPort(): Boolean {
    try {
        ServerSocket(5005).close()  // If this succeeds, port is free
        return false
    } catch (e: Exception) {
        return true  // Port in use - possibly debugger
    }
}`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Frida Detection */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>
              2. Frida Detection
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              <strong>Frida</strong> is the most popular dynamic instrumentation toolkit for mobile. It injects a JavaScript 
              engine into the target process. Detection focuses on Frida's artifacts: server process, injected libraries, 
              named pipes, and memory patterns.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Native Frida detection (C/C++ in JNI)
#include <stdio.h>
#include <string.h>
#include <dirent.h>

// Check for frida-server process
int check_frida_server() {
    DIR *dir = opendir("/data/local/tmp");
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, "frida") || 
            strstr(entry->d_name, "gum-js-loop")) {
            closedir(dir);
            return 1;  // Frida detected!
        }
    }
    closedir(dir);
    return 0;
}

// Check /proc/self/maps for Frida libraries
int check_frida_maps() {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || 
            strstr(line, "gadget") ||
            strstr(line, "gum-js-loop")) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

// Check for Frida's default port (27042)
int check_frida_port() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27042);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        close(sock);
        return 1;  // Something listening on Frida port
    }
    close(sock);
    return 0;
}`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#a855f7", mb: 1 }}>
                    Frida Artifacts to Detect
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• frida-server process</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• frida-agent*.so in memory maps</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Port 27042 (default Frida port)</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• D-Bus interface strings</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    Frida Bypass Methods
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Rename frida-server binary</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Use non-default port</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Hook detection functions with Frida itself</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Use Frida Gadget instead of server</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Root Detection */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>
              3. Root/Jailbreak Detection
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Rooted Android devices and jailbroken iOS devices allow users to bypass app sandboxing, run debugging 
              tools, and modify app behavior. Detection focuses on root management apps, su binaries, and system modifications.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Root detection checks
fun isDeviceRooted(): Boolean {
    // Check for su binary
    val suPaths = arrayOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/data/local/su"
    )
    for (path in suPaths) {
        if (File(path).exists()) return true
    }
    
    // Check for root management apps
    val rootApps = arrayOf(
        "com.topjohnwu.magisk",      // Magisk
        "eu.chainfire.supersu",       // SuperSU
        "com.koushikdutta.superuser", // Superuser
        "com.noshufou.android.su"     // Another Superuser
    )
    for (pkg in rootApps) {
        try {
            packageManager.getPackageInfo(pkg, 0)
            return true
        } catch (e: Exception) { }
    }
    
    // Check system properties
    val buildTags = android.os.Build.TAGS
    if (buildTags != null && buildTags.contains("test-keys")) {
        return true  // Custom ROM indicator
    }
    
    return false
}`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Native ptrace on Android */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>
              4. Native Anti-Debug (ptrace on Android)
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Android's native layer uses the same ptrace mechanism as Linux. Native libraries (.so files) can implement 
              ptrace-based anti-debugging identical to Linux techniques.
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#a855f7", 0.03), border: `1px solid ${alpha("#a855f7", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 1 }}>
                    Native Techniques
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• ptrace(PTRACE_TRACEME) in JNI_OnLoad</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Check /proc/self/status TracerPid</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Fork watchdog process</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Signal handler tricks (SIGTRAP)</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>
                    iOS Specific
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• sysctl() to check P_TRACED flag</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Check for Cydia/Sileo (jailbreak)</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Detect Substrate/Substitute hooks</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Check for /private/var/lib/apt</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Mobile Analysis Tips</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              <strong>1)</strong> Use Frida with objection for quick bypasses. <strong>2)</strong> Magisk Hide/Zygisk can hide root from apps. 
              <strong>3)</strong> Patch APK with apktool to remove checks. <strong>4)</strong> Use Xposed/LSPosed modules for system-wide hooks. 
              <strong>5)</strong> For heavily protected apps, combine static analysis (jadx/Ghidra) with dynamic (Frida) for best results.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 11: BYPASS & DEFEAT TECHNIQUES ==================== */}
        <Paper
          id="bypass-techniques-content"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#dc2626", 0.2)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #dc2626, #b91c1c)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <BuildIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Bypass & Defeat Techniques
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Now that we've covered anti-debugging techniques, let's focus on the other side: <strong>defeating them</strong>. 
            As a security analyst, you need to understand both sides. This section covers the tools, plugins, and 
            techniques used to bypass anti-debugging protections systematically.
          </Typography>

          <Alert severity="error" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Important Notice</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              These techniques are for <strong>legitimate security research only</strong>. Always ensure you have 
              authorization to analyze software. Bypassing protections on software you don't own or have permission 
              to test may violate laws and terms of service.
            </Typography>
          </Alert>

          {/* ScyllaHide */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
              1. ScyllaHide (Windows)
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              <strong>ScyllaHide</strong> is the most comprehensive anti-anti-debugging plugin for Windows debuggers. 
              It hooks Windows APIs and modifies their behavior to hide the debugger. Works with x64dbg, OllyDbg, 
              IDA Pro, and TitanEngine.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#dc2626", 0.03), border: `1px solid ${alpha("#dc2626", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>
                    ScyllaHide Features
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Hide PEB flags (BeingDebugged, NtGlobalFlag)</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Hook NtQueryInformationProcess</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Protect debug registers (DRx)</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Hide debugger windows/processes</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• Block anti-debug timing checks</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    Recommended Settings
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">✓ PEB - BeingDebugged</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">✓ PEB - NtGlobalFlag</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">✓ PEB - Heap Flags</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">✓ NtQueryInformationProcess</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">✓ NtSetInformationThread (HideFromDebugger)</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Binary Patching */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
              2. Binary Patching
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Sometimes the cleanest approach is to permanently remove anti-debugging code from the binary. This involves 
              finding the checks and patching them with NOPs or changing conditional jumps.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Common patching patterns

// 1. NOP out the call to anti-debug function
// Before: E8 xx xx xx xx    call AntiDebug
// After:  90 90 90 90 90    nop nop nop nop nop

// 2. Change conditional jump to always/never jump
// Before: 74 xx    je  detected     (jump if equal)
// After:  EB xx    jmp detected     (always jump)
// Or:     90 90    nop nop          (never jump)

// 3. Change return value
// Before: mov eax, 1    (return true = detected)
//         ret
// After:  xor eax, eax  (return false = not detected)
//         ret

// 4. For IsDebuggerPresent, patch the import
// Find IAT entry for IsDebuggerPresent
// Redirect to stub that returns 0

// x64dbg patching workflow:
// 1. Find anti-debug call with breakpoint
// 2. Right-click instruction -> Assemble
// 3. Enter "nop" or new instruction
// 4. Patches -> Patch File to save`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Frida Scripts */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
              3. Frida Bypass Scripts
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              <strong>Frida</strong> can hook any function and modify its behavior at runtime. This is powerful for 
              bypassing anti-debugging because you can intercept checks and return fake results without modifying the binary.
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`// Frida script to bypass common Windows anti-debug

// Hook IsDebuggerPresent
Interceptor.attach(Module.getExportByName('kernel32.dll', 'IsDebuggerPresent'), {
    onLeave: function(retval) {
        retval.replace(0);  // Always return FALSE
        console.log('[+] IsDebuggerPresent bypassed');
    }
});

// Hook CheckRemoteDebuggerPresent
Interceptor.attach(Module.getExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent'), {
    onLeave: function(retval) {
        // Set output parameter to FALSE
        this.context.rdx.writeU32(0);  // x64: second param
        console.log('[+] CheckRemoteDebuggerPresent bypassed');
    }
});

// Hook NtQueryInformationProcess
var ntdll = Module.getExportByName('ntdll.dll', 'NtQueryInformationProcess');
Interceptor.attach(ntdll, {
    onEnter: function(args) {
        this.infoClass = args[1].toInt32();
        this.buffer = args[2];
    },
    onLeave: function(retval) {
        if (this.infoClass === 7) {  // ProcessDebugPort
            this.buffer.writeU64(0);
            console.log('[+] ProcessDebugPort bypassed');
        } else if (this.infoClass === 0x1f) {  // ProcessDebugFlags
            this.buffer.writeU32(1);
            console.log('[+] ProcessDebugFlags bypassed');
        }
    }
});`}
              </Typography>
            </Paper>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Strategy */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
              4. Systematic Bypass Strategy
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                    Step 1: Identify
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Run with ScyllaHide. Note crashes and suspicious behavior. Search for anti-debug API imports.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    Step 2: Locate
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Set breakpoints on anti-debug APIs. Trace back to find the checking code and decision points.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>
                    Step 3: Bypass
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Hook with Frida, patch binary, or configure ScyllaHide. Test each bypass individually.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#a855f7", mb: 1 }}>
                    Step 4: Verify
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    Confirm bypass works. Check for secondary checks. Document for future reference.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Pro Tips</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              <strong>1)</strong> Start with ScyllaHide on maximum settings—it catches most common checks. 
              <strong>2)</strong> Use x64dbg's trace feature to find where checks happen. 
              <strong>3)</strong> Combine approaches: ScyllaHide + selective patching for stubborn checks. 
              <strong>4)</strong> Keep notes on what works—protections often repeat patterns.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 12: TOOLS & PRACTICE RESOURCES ==================== */}
        <Paper
          id="tools-resources-content"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#0ea5e9", 0.2)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #0ea5e9, #0284c7)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <SettingsIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Tools & Practice Resources
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Mastering anti-debugging requires hands-on practice. Here are the essential tools for your toolkit 
            and resources where you can practice these techniques safely and legally.
          </Typography>

          {/* Debuggers */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
              1. Essential Debuggers
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>
                    x64dbg (Windows)
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7, mb: 1 }}>
                    Free, open-source, actively maintained. Best choice for Windows reversing. Great plugin ecosystem including ScyllaHide.
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    x64dbg.com
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    GDB + GEF (Linux)
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7, mb: 1 }}>
                    GNU Debugger with GEF (GDB Enhanced Features) extension. Essential for Linux and embedded. Powerful scripting with Python.
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    github.com/hugsy/gef
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#a855f7", 0.03), border: `1px solid ${alpha("#a855f7", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 1 }}>
                    WinDbg (Windows)
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7, mb: 1 }}>
                    Microsoft's debugger. Essential for kernel debugging and crash dump analysis. Steeper learning curve but very powerful.
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    Windows SDK
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Anti-Anti-Debug Tools */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
              2. Anti-Anti-Debug Tools
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#dc2626", 0.03), border: `1px solid ${alpha("#dc2626", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>
                    ScyllaHide
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7, mb: 1 }}>
                    The gold standard for Windows. Hides debugger from most protections. Works with x64dbg, OllyDbg, IDA. Open source.
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    github.com/x64dbg/ScyllaHide
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>
                    Frida
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7, mb: 1 }}>
                    Dynamic instrumentation toolkit. Works on Windows, macOS, Linux, iOS, Android. JavaScript-based hooks. Incredibly versatile.
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    frida.re
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                    Objection (Mobile)
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7, mb: 1 }}>
                    Built on Frida. Automates common mobile bypass tasks: SSL pinning, root detection, anti-debug. Great for beginners.
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    github.com/sensepost/objection
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>
                    TitanHide
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7, mb: 1 }}>
                    Kernel-level anti-anti-debug. Hides debugger at ring0. More powerful but requires driver signing or test mode.
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    github.com/mrexodia/TitanHide
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Practice Resources */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
              3. Practice & Learning Resources
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    🎯 Practice Binaries
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• <strong>crackmes.one</strong> - Thousands of reverse engineering challenges</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• <strong>malwareunicorn.org</strong> - RE101/102 workshops</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• <strong>challenges.re</strong> - Reverse engineering challenges</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• <strong>OALABS</strong> - Malware analysis samples (YouTube)</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.15)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                    📚 Learning Materials
                  </Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• <strong>"Practical Malware Analysis"</strong> - Sikorski & Honig</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• <strong>"The Art of Memory Forensics"</strong> - Advanced analysis</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• <strong>OpenSecurityTraining2</strong> - Free courses</Typography>} />
                    </ListItem>
                    <ListItem sx={{ py: 0.25, px: 0 }}>
                      <ListItemText primary={<Typography variant="body2">• <strong>hasherezade's 1001 nights</strong> - Blog with great writeups</Typography>} />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Box>

          <Divider sx={{ my: 4 }} />

          {/* Quick Reference */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
              4. Quick Reference Cheat Sheet
            </Typography>

            <Paper sx={{ p: 2, mb: 3, bgcolor: alpha("#1e1e1e", 0.8), borderRadius: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#d4d4d4", whiteSpace: "pre-wrap", m: 0 }}>
{`╔═══════════════════════════════════════════════════════════════╗
║           ANTI-DEBUGGING QUICK REFERENCE                  ║
╠═══════════════════════════════════════════════════════════════╣
║ TECHNIQUE               │ BYPASS                          ║
╠═════════════════════════╪═════════════════════════════════════╣
║ IsDebuggerPresent       │ Hook to return 0 / ScyllaHide   ║
║ PEB.BeingDebugged       │ Set to 0 / ScyllaHide           ║
║ NtGlobalFlag            │ Clear debug heap flags          ║
║ NtQueryInformationProc  │ Hook / ScyllaHide               ║
║ RDTSC timing            │ Patch / VM with TSC scaling     ║
║ INT 2D                  │ Set EIP to skip / ScyllaHide    ║
║ Hardware breakpoints    │ Hook GetThreadContext           ║
║ Software breakpoints    │ Use hardware BPs instead        ║
║ VM detection            │ Harden VM / bare metal          ║
║ ptrace (Linux)          │ LD_PRELOAD hook                 ║
║ Frida detection         │ Rename server / hook checks     ║
╚═════════════════════════╧═════════════════════════════════════╝`}
              </Typography>
            </Paper>
          </Box>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Congratulations!</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              You've completed the Anti-Debugging guide! You now understand the major techniques used to detect 
              and evade debuggers on Windows, Linux, and mobile platforms. <strong>Next steps:</strong> Practice 
              on crackmes, analyze real malware samples (safely!), and experiment with writing your own anti-debug code.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION OUTLINE ==================== */}
        <Typography 
          variant="h4" 
          sx={{ fontWeight: 800, mb: 4, display: "flex", alignItems: "center", gap: 2 }}
          id="topics"
        >
          <AccountTreeIcon sx={{ color: "#ef4444", fontSize: 36 }} />
          Course Outline
        </Typography>

        <Typography variant="body1" color="text.secondary" sx={{ mb: 4, maxWidth: 800 }}>
          This comprehensive guide covers anti-debugging techniques across Windows, Linux, and mobile platforms. 
          Sections marked "Placeholder" will be expanded with detailed content, code examples, and hands-on exercises.
        </Typography>

        <Grid container spacing={3} sx={{ mb: 6 }}>
          {outlineSections.map((section, index) => (
            <Grid item xs={12} sm={6} md={4} key={section.id}>
              <Paper
                id={section.id}
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  bgcolor: alpha(section.color, 0.03),
                  border: `2px solid ${alpha(section.color, 0.15)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    boxShadow: `0 8px 24px ${alpha(section.color, 0.2)}`,
                    borderColor: alpha(section.color, 0.4),
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, mb: 2 }}>
                  <Box
                    sx={{
                      width: 48,
                      height: 48,
                      borderRadius: 2,
                      bgcolor: alpha(section.color, 0.15),
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: section.color,
                      flexShrink: 0,
                    }}
                  >
                    {section.icon}
                  </Box>
                  <Box sx={{ flex: 1 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                      <Chip 
                        label={`${index + 1}`}
                        size="small"
                        sx={{ 
                          minWidth: 28,
                          height: 22,
                          fontSize: "0.7rem",
                          fontWeight: 800,
                          bgcolor: section.color,
                          color: "white",
                        }}
                      />
                      <Chip 
                        label={section.status}
                        size="small"
                        icon={section.status === "Complete" ? <CheckCircleIcon /> : <RadioButtonUncheckedIcon />}
                        sx={{ 
                          fontSize: "0.65rem",
                          height: 22,
                          bgcolor: section.status === "Complete" 
                            ? alpha("#22c55e", 0.15) 
                            : alpha("#f59e0b", 0.15),
                          color: section.status === "Complete" ? "#22c55e" : "#f59e0b",
                          "& .MuiChip-icon": { 
                            fontSize: 14,
                            color: section.status === "Complete" ? "#22c55e" : "#f59e0b",
                          },
                        }}
                      />
                    </Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, lineHeight: 1.3 }}>
                      {section.title}
                    </Typography>
                  </Box>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>
                  {section.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== PLACEHOLDER SECTIONS ==================== */}
        {outlineSections.filter(s => s.status === "Placeholder").map((section, index) => (
          <Paper
            key={section.id}
            id={`${section.id}-content`}
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 3,
              bgcolor: alpha(section.color, 0.02),
              border: `1px solid ${alpha(section.color, 0.1)}`,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 56,
                  height: 56,
                  borderRadius: 2,
                  bgcolor: alpha(section.color, 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: section.color,
                }}
              >
                {React.cloneElement(section.icon, { sx: { fontSize: 32 } })}
              </Box>
              <Box>
                <Typography variant="h5" sx={{ fontWeight: 800, color: section.color }}>
                  {index + 2}. {section.title}
                </Typography>
                <Chip 
                  label="Coming Soon" 
                  size="small" 
                  sx={{ mt: 0.5, bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} 
                />
              </Box>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              {section.description}
            </Typography>

            <Alert severity="info" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Content Coming Soon</AlertTitle>
              <Typography variant="body2">
                This section will cover detailed explanations, code examples, detection methods, and bypass techniques 
                for {section.title.toLowerCase()}. Check back soon for comprehensive coverage of this topic.
              </Typography>
            </Alert>
          </Paper>
        ))}

        {/* ==================== QUIZ SECTION ==================== */}
        <QuizSection />

        {/* ==================== RELATED TOPICS ==================== */}
        <Paper
          sx={{
            p: 4,
            borderRadius: 3,
            bgcolor: alpha(theme.palette.info.main, 0.03),
            border: `1px solid ${alpha(theme.palette.info.main, 0.1)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <TipsAndUpdatesIcon sx={{ color: theme.palette.info.main }} />
            Related Learning Topics
          </Typography>
          
          <Grid container spacing={2}>
            {[
              { title: "Intro to Reverse Engineering", path: "/learn/intro-to-re", color: "#dc2626", desc: "Start here if you're new to RE" },
              { title: "Debugging 101", path: "/learn/debugging-101", color: "#3b82f6", desc: "Learn the fundamentals of debugging" },
              { title: "Malware Analysis", path: "/learn/malware-analysis", color: "#ef4444", desc: "Analyze malicious software" },
              { title: "Windows Internals", path: "/learn/windows-internals", color: "#8b5cf6", desc: "PEB, TEB, and Windows APIs" },
              { title: "Linux Internals", path: "/learn/linux-internals", color: "#f97316", desc: "ELF, ptrace, and Linux debugging" },
              { title: "Ghidra Guide", path: "/learn/ghidra", color: "#14b8a6", desc: "Disassembly and decompilation" },
            ].map((topic) => (
              <Grid item xs={12} sm={6} md={4} key={topic.path}>
                <Paper
                  onClick={() => navigate(topic.path)}
                  sx={{
                    p: 2,
                    borderRadius: 2,
                    cursor: "pointer",
                    bgcolor: alpha(topic.color, 0.05),
                    border: `1px solid ${alpha(topic.color, 0.15)}`,
                    transition: "all 0.2s ease",
                    "&:hover": {
                      transform: "translateY(-2px)",
                      boxShadow: `0 4px 12px ${alpha(topic.color, 0.2)}`,
                      borderColor: topic.color,
                    },
                  }}
                >
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: topic.color }}>
                    {topic.title}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {topic.desc}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

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
}
