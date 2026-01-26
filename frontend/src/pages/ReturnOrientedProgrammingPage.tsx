import React, { useEffect, useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Typography,
  Paper,
  Chip,
  Button,
  Accordion,
  AccordionSummary,
  AccordionDetails,
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
  Drawer,
  Fab,
  Divider,
  LinearProgress,
  alpha,
  useTheme,
  useMediaQuery,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import MemoryIcon from "@mui/icons-material/Memory";
import BugReportIcon from "@mui/icons-material/BugReport";
import WarningIcon from "@mui/icons-material/Warning";
import ShieldIcon from "@mui/icons-material/Shield";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SearchIcon from "@mui/icons-material/Search";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import LockIcon from "@mui/icons-material/Lock";
import TuneIcon from "@mui/icons-material/Tune";
import QuizIcon from "@mui/icons-material/Quiz";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import TerminalIcon from "@mui/icons-material/Terminal";
import SecurityIcon from "@mui/icons-material/Security";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import { Link, useNavigate } from "react-router-dom";

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
        bgcolor: "#101626",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(37, 99, 235, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#2563eb", color: "#0b1020" }} />
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
          fontFamily: "monospace",
          fontSize: "0.85rem",
          color: "#e2e8f0",
          pt: 2,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#2563eb";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "ROP stands for:",
    options: ["Return-Oriented Programming", "Register Optimization Path", "Runtime Object Policy", "Remote Operation Protocol"],
    correctAnswer: 0,
    explanation: "ROP is Return-Oriented Programming.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "ROP is commonly used to bypass:",
    options: ["NX/DEP", "TLS", "DNSSEC", "MFA"],
    correctAnswer: 0,
    explanation: "ROP reuses executable code to bypass non-executable memory.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "A ROP gadget is:",
    options: ["A short instruction sequence ending in ret", "A kernel module", "A compiler flag", "A runtime patch"],
    correctAnswer: 0,
    explanation: "Gadgets are small code snippets ending in a return.",
  },
  {
    id: 4,
    topic: "Fundamentals",
    question: "ROP chains are typically stored on the:",
    options: ["Stack", "GPU", "Disk", "Network interface"],
    correctAnswer: 0,
    explanation: "ROP chains are usually placed on the stack.",
  },
  {
    id: 5,
    topic: "Entry Points",
    question: "ROP usually requires control over:",
    options: ["The return address", "CPU temperature", "Log rotation", "DNS cache"],
    correctAnswer: 0,
    explanation: "ROP needs control of the return address to start the chain.",
  },
  {
    id: 6,
    topic: "Addressing",
    question: "ASLR makes ROP harder by:",
    options: ["Randomizing gadget addresses", "Removing gadgets", "Encrypting the stack", "Disabling syscalls"],
    correctAnswer: 0,
    explanation: "ASLR randomizes memory layout so gadget addresses change.",
  },
  {
    id: 7,
    topic: "Addressing",
    question: "A common ROP prerequisite is:",
    options: ["An information leak", "A bigger buffer", "A faster CPU", "A new kernel"],
    correctAnswer: 0,
    explanation: "Leaks reveal addresses needed to build the chain.",
  },
  {
    id: 8,
    topic: "Addressing",
    question: "PIE helps because it:",
    options: ["Randomizes the main binary base", "Disables canaries", "Enables JOP", "Removes relocations"],
    correctAnswer: 0,
    explanation: "PIE makes the main binary relocatable under ASLR.",
  },
  {
    id: 9,
    topic: "Gadgets",
    question: "A common gadget to set the first argument on x86-64 is:",
    options: ["pop rdi; ret", "pop rsp; ret", "syscall; ret", "int3; ret"],
    correctAnswer: 0,
    explanation: "The first argument is passed in RDI.",
  },
  {
    id: 10,
    topic: "Calling Conventions",
    question: "SysV x86-64 argument order starts with:",
    options: ["RDI, RSI, RDX", "RAX, RBX, RCX", "RSP, RBP, RDI", "RCX, R8, R9"],
    correctAnswer: 0,
    explanation: "Arguments use RDI, RSI, RDX, RCX, R8, R9.",
  },
  {
    id: 11,
    topic: "Technique",
    question: "ret2libc is a technique that:",
    options: ["Reuses libc functions like system()", "Uses only inline shellcode", "Disables ASLR", "Rewrites binaries"],
    correctAnswer: 0,
    explanation: "ret2libc redirects execution into libc.",
  },
  {
    id: 12,
    topic: "Technique",
    question: "A common ROP goal is to call:",
    options: ["mprotect to make memory executable", "chmod to hide files", "fsync to flush logs", "chdir to change directories"],
    correctAnswer: 0,
    explanation: "mprotect can mark a page as executable for payloads.",
  },
  {
    id: 13,
    topic: "Technique",
    question: "ROP differs from shellcode injection because it:",
    options: ["Uses existing code in memory", "Requires new executable pages", "Uses only network packets", "Does not require a bug"],
    correctAnswer: 0,
    explanation: "ROP reuses code that already exists.",
  },
  {
    id: 14,
    topic: "Tools",
    question: "A tool commonly used to find gadgets is:",
    options: ["ROPgadget", "tcpdump", "rsync", "systemctl"],
    correctAnswer: 0,
    explanation: "ROPgadget scans binaries for gadgets.",
  },
  {
    id: 15,
    topic: "Tools",
    question: "Another gadget finder is:",
    options: ["ropper", "curl", "tar", "uname"],
    correctAnswer: 0,
    explanation: "ropper is a popular gadget finding tool.",
  },
  {
    id: 16,
    topic: "Stack",
    question: "A stack pivot changes:",
    options: ["The stack pointer to attacker-controlled data", "The heap allocator", "The syscall table", "The kernel version"],
    correctAnswer: 0,
    explanation: "Stack pivots redirect RSP to a controlled buffer.",
  },
  {
    id: 17,
    topic: "Stack",
    question: "Stack alignment is important because:",
    options: ["Some ABI calls require 16-byte alignment", "It disables ASLR", "It removes canaries", "It prevents syscalls"],
    correctAnswer: 0,
    explanation: "Misaligned stacks can crash or break function calls.",
  },
  {
    id: 18,
    topic: "Variants",
    question: "JOP stands for:",
    options: ["Jump-Oriented Programming", "Java Object Protocol", "Join Operations Plan", "Kernel Object Policy"],
    correctAnswer: 0,
    explanation: "JOP chains gadgets with jumps instead of returns.",
  },
  {
    id: 19,
    topic: "Variants",
    question: "SROP stands for:",
    options: ["Sigreturn-Oriented Programming", "Stack Return Optimization", "Symbol Resolution Override", "Secure ROP"],
    correctAnswer: 0,
    explanation: "SROP abuses sigreturn to control registers.",
  },
  {
    id: 20,
    topic: "Variants",
    question: "SROP relies on:",
    options: ["A sigreturn frame on the stack", "A writable kernel module", "A disabled NX bit", "A static binary only"],
    correctAnswer: 0,
    explanation: "SROP crafts a signal frame to load registers.",
  },
  {
    id: 21,
    topic: "Mitigations",
    question: "CFI mitigates ROP by:",
    options: ["Restricting indirect control flow targets", "Removing the stack", "Disabling syscalls", "Encrypting memory"],
    correctAnswer: 0,
    explanation: "CFI blocks invalid jumps and calls.",
  },
  {
    id: 22,
    topic: "Mitigations",
    question: "Intel CET helps prevent ROP using:",
    options: ["A shadow stack", "A new heap allocator", "A bigger stack", "A custom linker"],
    correctAnswer: 0,
    explanation: "CET uses a shadow stack to protect return addresses.",
  },
  {
    id: 23,
    topic: "Mitigations",
    question: "Stack canaries primarily protect against:",
    options: ["Stack smashing", "Heap spraying", "ASLR bypass", "Symbol stripping"],
    correctAnswer: 0,
    explanation: "Canaries detect stack corruption.",
  },
  {
    id: 24,
    topic: "Mitigations",
    question: "A canary bypass usually needs:",
    options: ["A leak of the canary value", "A new compiler", "A shorter buffer", "A kernel module"],
    correctAnswer: 0,
    explanation: "Without the canary value, the check fails.",
  },
  {
    id: 25,
    topic: "Mitigations",
    question: "Full RELRO helps ROP by:",
    options: ["Preventing GOT overwrites", "Disabling ASLR", "Enabling JOP", "Removing symbols"],
    correctAnswer: 0,
    explanation: "Full RELRO makes the GOT read-only after relocation.",
  },
  {
    id: 26,
    topic: "Chains",
    question: "A ROP chain is a series of:",
    options: ["Gadget addresses and data", "Kernel modules", "Threads", "Passwords"],
    correctAnswer: 0,
    explanation: "Chains are gadget addresses with arguments on the stack.",
  },
  {
    id: 27,
    topic: "Chains",
    question: "A common first step in building a chain is:",
    options: ["Finding a control-flow overwrite", "Disabling the network", "Removing logs", "Reinstalling libc"],
    correctAnswer: 0,
    explanation: "You need control of RIP before building a chain.",
  },
  {
    id: 28,
    topic: "Chains",
    question: "Leaking libc addresses allows you to:",
    options: ["Compute the libc base", "Disable NX", "Remove CFI", "Increase entropy"],
    correctAnswer: 0,
    explanation: "You can calculate gadget addresses from the base.",
  },
  {
    id: 29,
    topic: "Chains",
    question: "ret2plt is used to:",
    options: ["Call a PLT entry for a function", "Patch the kernel", "Encrypt payloads", "Disable ASLR"],
    correctAnswer: 0,
    explanation: "ret2plt uses PLT stubs to call functions.",
  },
  {
    id: 30,
    topic: "Chains",
    question: "ret2csu refers to:",
    options: ["Using __libc_csu_init gadgets to set registers", "Turning off canaries", "Randomizing stacks", "Using only syscalls"],
    correctAnswer: 0,
    explanation: "ret2csu uses common gadgets in __libc_csu_init.",
  },
  {
    id: 31,
    topic: "Gadgets",
    question: "A gadget ending in ret is useful because:",
    options: ["ret pops the next address from the stack", "ret encrypts memory", "ret clears the heap", "ret disables ASLR"],
    correctAnswer: 0,
    explanation: "ret uses the stack to chain execution.",
  },
  {
    id: 32,
    topic: "Gadgets",
    question: "Gadgets are often found in:",
    options: ["libc and the main binary", "Only the kernel", "Only the network stack", "Only scripts"],
    correctAnswer: 0,
    explanation: "libc is a rich source of gadgets.",
  },
  {
    id: 33,
    topic: "Gadgets",
    question: "A gadget chain typically avoids:",
    options: ["Bad bytes in addresses", "All memory reads", "All registers", "All syscalls"],
    correctAnswer: 0,
    explanation: "Bad bytes can break string-based payloads.",
  },
  {
    id: 34,
    topic: "Execution",
    question: "ROP can execute a syscall by:",
    options: ["Setting registers and using a syscall gadget", "Editing the kernel", "Modifying ASLR", "Disabling NX"],
    correctAnswer: 0,
    explanation: "Chains can set registers and invoke syscall.",
  },
  {
    id: 35,
    topic: "Execution",
    question: "execve('/bin/sh') is often used to:",
    options: ["Spawn a shell", "List files", "Rotate logs", "Update packages"],
    correctAnswer: 0,
    explanation: "execve launches a new process like a shell.",
  },
  {
    id: 36,
    topic: "Execution",
    question: "A ROP chain can call system() if it:",
    options: ["Sets up arguments in the correct registers", "Changes file permissions only", "Writes to disk only", "Updates libc only"],
    correctAnswer: 0,
    explanation: "The correct calling convention is required.",
  },
  {
    id: 37,
    topic: "Detection",
    question: "A detection clue for ROP is:",
    options: ["Repeated returns into non-call sites", "Normal HTTP traffic", "Stable stack traces", "Regular file reads"],
    correctAnswer: 0,
    explanation: "ROP can show unusual return patterns.",
  },
  {
    id: 38,
    topic: "Detection",
    question: "CFI violations often produce:",
    options: ["Security exceptions or crashes", "Successful logins", "Faster performance", "Lower memory usage"],
    correctAnswer: 0,
    explanation: "CFI detects invalid control flow and can terminate.",
  },
  {
    id: 39,
    topic: "Detection",
    question: "Unexpected syscalls after a crash may indicate:",
    options: ["A ROP chain", "A normal shutdown", "A compiler update", "A network issue"],
    correctAnswer: 0,
    explanation: "ROP chains often invoke syscalls after hijacking control.",
  },
  {
    id: 40,
    topic: "Response",
    question: "A good response step after a ROP alert is to:",
    options: ["Collect crash dumps and logs", "Ignore the event", "Disable ASLR", "Remove patches"],
    correctAnswer: 0,
    explanation: "Crash data helps confirm exploitation paths.",
  },
  {
    id: 41,
    topic: "Hardening",
    question: "PIE and ASLR together:",
    options: ["Randomize the main binary and libraries", "Disable stack canaries", "Prevent all bugs", "Remove relocations"],
    correctAnswer: 0,
    explanation: "PIE enables ASLR for the main binary.",
  },
  {
    id: 42,
    topic: "Hardening",
    question: "Disabling symbol stripping helps defenders by:",
    options: ["Providing better crash backtraces", "Increasing exploitability", "Removing debug data", "Reducing logs"],
    correctAnswer: 0,
    explanation: "Symbols improve debugging and analysis.",
  },
  {
    id: 43,
    topic: "Hardening",
    question: "Memory-safe languages help prevent ROP because they:",
    options: ["Reduce memory corruption bugs", "Disable ASLR", "Remove syscalls", "Ignore bounds checks"],
    correctAnswer: 0,
    explanation: "ROP needs memory corruption to control flow.",
  },
  {
    id: 44,
    topic: "Hardening",
    question: "The best long-term fix for ROP risk is:",
    options: ["Eliminate memory corruption bugs", "Disable logging", "Remove ASLR", "Block all traffic"],
    correctAnswer: 0,
    explanation: "ROP is a symptom of memory safety bugs.",
  },
  {
    id: 45,
    topic: "ROP Basics",
    question: "ROP is considered a form of:",
    options: ["Code-reuse attack", "SQL injection", "Authentication bypass", "Phishing"],
    correctAnswer: 0,
    explanation: "ROP reuses existing code instead of injecting new code.",
  },
  {
    id: 46,
    topic: "ROP Basics",
    question: "A typical ROP chain ends by:",
    options: ["Returning into a function or syscall", "Erasing the stack", "Closing the terminal", "Changing file ownership"],
    correctAnswer: 0,
    explanation: "Chains often end by calling a target function.",
  },
  {
    id: 47,
    topic: "ROP Basics",
    question: "A ret instruction does what?",
    options: ["Pops an address from the stack and jumps", "Pushes a value to the stack", "Clears registers", "Allocates memory"],
    correctAnswer: 0,
    explanation: "ret uses the stack to continue execution.",
  },
  {
    id: 48,
    topic: "ROP Basics",
    question: "A typical ROP chain uses:",
    options: ["Existing executable pages", "Injected new code pages", "Only data pages", "Only kernel pages"],
    correctAnswer: 0,
    explanation: "ROP uses existing executable code.",
  },
  {
    id: 49,
    topic: "ROP Basics",
    question: "Gadget addresses are often relative to:",
    options: ["A module base (like libc base)", "The DNS server", "The CPU cache", "The NIC driver"],
    correctAnswer: 0,
    explanation: "Gadgets are found within modules like libc.",
  },
  {
    id: 50,
    topic: "ROP Basics",
    question: "A ROP chain can be constructed to:",
    options: ["Call functions with chosen arguments", "Only print text", "Only crash", "Only exit immediately"],
    correctAnswer: 0,
    explanation: "ROP chains can set registers and call functions.",
  },
  {
    id: 51,
    topic: "Mitigations",
    question: "SafeStack aims to:",
    options: ["Separate safe and unsafe stack data", "Disable ASLR", "Remove canaries", "Stop syscalls"],
    correctAnswer: 0,
    explanation: "SafeStack isolates unsafe stack objects.",
  },
  {
    id: 52,
    topic: "Mitigations",
    question: "Stack unwinding for CFI relies on:",
    options: ["Valid return addresses", "Large buffers", "Disabled NX", "Missing symbols"],
    correctAnswer: 0,
    explanation: "CFI checks ensure return targets are valid.",
  },
  {
    id: 53,
    topic: "Mitigations",
    question: "A shadow stack stores:",
    options: ["Protected copies of return addresses", "Heap metadata", "Kernel logs", "TLS secrets"],
    correctAnswer: 0,
    explanation: "Shadow stacks protect return addresses from tampering.",
  },
  {
    id: 54,
    topic: "Mitigations",
    question: "A common ROP defense is:",
    options: ["Fine-grained CFI", "Disabling updates", "Removing patches", "Increasing buffer sizes"],
    correctAnswer: 0,
    explanation: "CFI limits allowed control-flow targets.",
  },
  {
    id: 55,
    topic: "Mitigations",
    question: "ASLR entropy is higher on:",
    options: ["64-bit systems", "16-bit systems", "DOS", "Microcontrollers"],
    correctAnswer: 0,
    explanation: "64-bit address space provides more randomization.",
  },
  {
    id: 56,
    topic: "Operations",
    question: "A reliable ROP chain requires:",
    options: ["Stable gadget addresses", "Only slower CPUs", "Disabled logging", "No debugging"],
    correctAnswer: 0,
    explanation: "Address stability or leaks are needed for reliable chains.",
  },
  {
    id: 57,
    topic: "Operations",
    question: "A ROP chain is usually built after:",
    options: ["Finding a memory corruption bug", "Changing DNS", "Installing updates", "Enabling logging"],
    correctAnswer: 0,
    explanation: "ROP is a post-exploitation technique.",
  },
  {
    id: 58,
    topic: "Operations",
    question: "A common early step is to:",
    options: ["Find the overflow offset to RIP", "Disable ASLR permanently", "Strip symbols", "Remove protections"],
    correctAnswer: 0,
    explanation: "You must locate the offset to control RIP.",
  },
  {
    id: 59,
    topic: "Operations",
    question: "A ROP chain can be used to:",
    options: ["Call write() to leak addresses", "Only reboot systems", "Only change themes", "Only read config files"],
    correctAnswer: 0,
    explanation: "Leaking addresses is common to bypass ASLR.",
  },
  {
    id: 60,
    topic: "Operations",
    question: "A ret sled is often used to:",
    options: ["Align the stack before a call", "Disable canaries", "Encrypt payloads", "Remove logs"],
    correctAnswer: 0,
    explanation: "Ret sleds can fix alignment issues.",
  },
  {
    id: 61,
    topic: "Variants",
    question: "Call-Oriented Programming (COP) chains:",
    options: ["Use call instructions and call-preceded gadgets", "Use only syscalls", "Use only returns", "Use only jumps"],
    correctAnswer: 0,
    explanation: "COP uses call-based gadget chains.",
  },
  {
    id: 62,
    topic: "Variants",
    question: "A ROP chain that uses syscall directly is called:",
    options: ["Syscall-oriented ROP", "Heap spraying", "Format string abuse", "Pointer authentication"],
    correctAnswer: 0,
    explanation: "Chains can end in a syscall gadget.",
  },
  {
    id: 63,
    topic: "Debugging",
    question: "GDB helps ROP analysis by:",
    options: ["Inspecting registers and stack state", "Encrypting memory", "Disabling ASLR permanently", "Changing CPU microcode"],
    correctAnswer: 0,
    explanation: "GDB shows registers and memory needed for chain building.",
  },
  {
    id: 64,
    topic: "Debugging",
    question: "A crash after a gadget may indicate:",
    options: ["Incorrect stack alignment or bad addresses", "Successful exploit", "No bug present", "Only a UI issue"],
    correctAnswer: 0,
    explanation: "Bad addresses or alignment often cause crashes.",
  },
  {
    id: 65,
    topic: "Debugging",
    question: "If a gadget address contains a null byte, it may:",
    options: ["Break string-based payloads", "Increase reliability", "Bypass canaries", "Disable ASLR"],
    correctAnswer: 0,
    explanation: "Null bytes terminate strings in many payloads.",
  },
  {
    id: 66,
    topic: "Defense",
    question: "The strongest defense against ROP is:",
    options: ["Memory-safe coding and bug elimination", "Only logging", "Only WAF rules", "Only antivirus"],
    correctAnswer: 0,
    explanation: "ROP depends on memory corruption bugs.",
  },
  {
    id: 67,
    topic: "Defense",
    question: "Keeping libc updated helps because:",
    options: ["It changes gadget layouts and fixes bugs", "It disables ASLR", "It removes stack canaries", "It avoids syscalls"],
    correctAnswer: 0,
    explanation: "Updates can fix vulnerabilities and alter gadget offsets.",
  },
  {
    id: 68,
    topic: "Defense",
    question: "Removing unused libraries helps by:",
    options: ["Reducing available gadgets", "Increasing gadget count", "Disabling ASLR", "Breaking logs"],
    correctAnswer: 0,
    explanation: "Fewer libraries means fewer gadgets.",
  },
  {
    id: 69,
    topic: "Defense",
    question: "Hardening flags like -fstack-protector help by:",
    options: ["Detecting stack corruption", "Creating gadgets", "Disabling CFI", "Removing PIE"],
    correctAnswer: 0,
    explanation: "Canaries detect stack smashing before control flow hijack.",
  },
  {
    id: 70,
    topic: "Defense",
    question: "Using full RELRO helps mitigate:",
    options: ["GOT overwrite attacks", "DNS poisoning", "SQL injection", "Phishing"],
    correctAnswer: 0,
    explanation: "Full RELRO makes the GOT read-only.",
  },
  {
    id: 71,
    topic: "ROP Basics",
    question: "ROP typically follows a bug like:",
    options: ["Stack buffer overflow", "XSS only", "SQL injection only", "CSRF only"],
    correctAnswer: 0,
    explanation: "ROP requires memory corruption like a buffer overflow.",
  },
  {
    id: 72,
    topic: "ROP Basics",
    question: "A gadget chain must respect:",
    options: ["Calling conventions and stack layout", "Only DNS records", "Only UI state", "Only file permissions"],
    correctAnswer: 0,
    explanation: "ROP must follow ABI rules to work.",
  },
  {
    id: 73,
    topic: "ROP Basics",
    question: "ROP is more feasible when:",
    options: ["Address randomization is weak or leaked", "All symbols are removed", "All libraries are stripped", "All inputs are validated"],
    correctAnswer: 0,
    explanation: "Weak ASLR or leaks make gadget addresses predictable.",
  },
  {
    id: 74,
    topic: "ROP Basics",
    question: "A typical ROP chain uses data from:",
    options: ["The stack and memory pages", "Only registers", "Only CPU cache", "Only BIOS"],
    correctAnswer: 0,
    explanation: "ROP uses stack data and gadget addresses in memory.",
  },
  {
    id: 75,
    topic: "ROP Basics",
    question: "ROP is best described as:",
    options: ["Chaining existing code to perform attacker-chosen actions", "Writing new code into the kernel", "Only a denial-of-service technique", "A network protocol"],
    correctAnswer: 0,
    explanation: "ROP reuses existing code to execute attacker logic.",
  },
];

const quickStats = [
  { value: "12", label: "Sections", color: "#2563eb" },
  { value: "15+", label: "Techniques", color: "#22c55e" },
  { value: "5", label: "Defense Layers", color: "#f59e0b" },
  { value: "75", label: "Quiz Bank", color: "#8b5cf6" },
];

const ReturnOrientedProgrammingPage: React.FC = () => {
  const navigate = useNavigate();
  const theme = useTheme();
  const accent = "#2563eb";
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const objectives = [
    "Explain Return-Oriented Programming (ROP) in simple terms.",
    "Show why memory bugs can lead to control-flow abuse.",
    "Identify common entry points and real-world risk areas.",
    "Recognize detection signals and safe triage steps.",
    "Apply prevention and hardening practices for ROP risks.",
  ];
  const beginnerPath = [
    "1) Read the beginner explanation and glossary.",
    "2) Learn the basics of the stack and return addresses.",
    "3) Review how ROP chains reuse existing code.",
    "4) Study detection signals and response steps.",
    "5) Apply the mitigation and hardening checklist.",
  ];
  const keyIdeas = [
    "ROP reuses existing code fragments instead of injecting new code.",
    "It usually appears when memory safety bugs allow control of returns.",
    "Modern defenses raise the cost, but do not replace safe coding.",
    "The best fix is to prevent memory corruption in the first place.",
  ];
  const glossary = [
    { term: "Stack", desc: "A memory region that stores function call data." },
    { term: "Return address", desc: "Where execution continues after a function ends." },
    { term: "Gadget", desc: "A short code sequence ending in a return instruction." },
    { term: "DEP/NX", desc: "Marks memory as non-executable to block injected code." },
    { term: "ASLR", desc: "Randomizes memory locations to make addresses harder to guess." },
    { term: "CFI", desc: "Control-flow integrity, restricts invalid jumps." },
  ];
  const misconceptions = [
    {
      myth: "ROP only matters to experts.",
      reality: "It is a common outcome of basic memory bugs.",
    },
    {
      myth: "DEP/NX stops all code execution attacks.",
      reality: "ROP can reuse existing executable code.",
    },
    {
      myth: "ASLR alone prevents ROP.",
      reality: "Address leaks or weak randomization can bypass it.",
    },
  ];

  const memoryBasics = [
    "Functions store a return address on the stack.",
    "If a buffer overflow overwrites that address, execution changes.",
    "DEP/NX blocks new code from running in data memory.",
    "ROP chains small instruction sequences that already exist in memory.",
    "Each return jumps to the next gadget, forming a chain.",
  ];
  const coreConcepts = [
    {
      concept: "Return addresses",
      meaning: "Saved locations that tell the CPU where to go next.",
      whyItMatters: "If overwritten, control flow can be hijacked.",
    },
    {
      concept: "Gadgets",
      meaning: "Existing code snippets ending in a return.",
      whyItMatters: "They can be chained to perform complex actions.",
    },
    {
      concept: "Calling convention",
      meaning: "Rules for passing arguments and using the stack.",
      whyItMatters: "ROP chains must align with these rules.",
    },
    {
      concept: "Non-executable memory",
      meaning: "Data pages cannot be executed as code.",
      whyItMatters: "Forces attackers to reuse existing code.",
    },
    {
      concept: "Address randomization",
      meaning: "Memory locations change between runs.",
      whyItMatters: "Harder to predict gadget addresses.",
    },
  ];
  const whereItShowsUp = [
    "C/C++ services handling untrusted input.",
    "Legacy libraries without modern compiler flags.",
    "Custom network parsers or binary protocols.",
    "Device firmware or IoT services with limited updates.",
    "Plugin ecosystems that load third-party code.",
  ];
  const attackFlow = [
    "A memory bug allows overwriting data on the stack or heap.",
    "The return address is corrupted to redirect execution.",
    "The program begins executing short existing code sequences.",
    "Each gadget ends in a return, moving to the next gadget.",
    "The chain completes a goal like calling a function safely.",
  ];
  const impactAreas = [
    "Remote code execution in vulnerable services.",
    "Bypass of memory protections like DEP/NX.",
    "Privilege escalation in low-level components.",
    "Denial of service from crashes or corrupted state.",
  ];

  const detectionSignals = [
    "Crashes with instruction pointers inside unexpected modules.",
    "Return addresses that land on small instruction sequences.",
    "Repeated crashes with similar stack patterns.",
    "Unusual fault addresses near executable memory regions.",
    "Spike in access violations after malformed input.",
  ];
  const telemetrySources = [
    "Crash reports and minidumps.",
    "EDR alerts for exploit-like behavior.",
    "Application logs around parsing failures.",
    "System logs for access violations.",
    "Vulnerability scanners highlighting unsafe code paths.",
  ];
  const baselineMetrics = [
    {
      metric: "Crash rate by endpoint",
      normal: "Low and stable across typical inputs.",
      investigate: "Sudden spikes after new traffic patterns.",
    },
    {
      metric: "Parser error rate",
      normal: "Stable within expected ranges.",
      investigate: "Large jump in malformed input errors.",
    },
    {
      metric: "Memory fault types",
      normal: "Occasional benign crashes only.",
      investigate: "New access violation patterns.",
    },
  ];
  const triageSteps = [
    "Identify the endpoint and input that triggered the crash.",
    "Collect crash dumps and stack traces.",
    "Check for overwrites of return addresses.",
    "Confirm whether DEP/NX and ASLR are enabled.",
    "Search for known vulnerable functions in the code path.",
  ];
  const responseSteps = [
    "Disable or rate limit the vulnerable endpoint.",
    "Patch the memory bug and add bounds checks.",
    "Rebuild with hardening flags enabled.",
    "Roll out updated binaries and verify mitigations.",
    "Add regression tests for the offending inputs.",
  ];

  const preventionChecklist = [
    "Fix memory safety bugs (bounds checks and safe APIs).",
    "Enable DEP/NX, ASLR, and stack canaries.",
    "Use compiler hardening flags consistently.",
    "Adopt Control-Flow Integrity where possible.",
    "Reduce attack surface by removing unused code.",
    "Prefer memory-safe languages for new components.",
  ];
  const secureCodingPatterns = [
    "Prefer length-checked functions and safe wrappers.",
    "Validate input size before copying or parsing.",
    "Avoid manual memory management when possible.",
    "Use fuzzing to catch crashes early.",
  ];
  const mitigationsTable = [
    {
      mitigation: "DEP/NX",
      purpose: "Prevents executing code in data memory.",
      limitation: "Does not stop reuse of existing code.",
    },
    {
      mitigation: "ASLR",
      purpose: "Randomizes memory layout.",
      limitation: "Leaks can reveal addresses.",
    },
    {
      mitigation: "Stack canaries",
      purpose: "Detects stack buffer overwrites.",
      limitation: "May be bypassed in some cases.",
    },
    {
      mitigation: "CFI",
      purpose: "Restricts invalid control-flow transitions.",
      limitation: "Coverage varies by compiler and runtime.",
    },
    {
      mitigation: "Shadow stack",
      purpose: "Separates real return addresses from writable stack.",
      limitation: "Requires hardware or OS support.",
    },
  ];
  const buildFlags = `# Linux hardening flags (example)
-fstack-protector-strong
-D_FORTIFY_SOURCE=2
-fPIE -pie
-Wl,-z,relro,-z,now
-Wl,-z,noexecstack`;
  const platformDefenses = [
    {
      platform: "Windows",
      controls: "DEP, ASLR, CFG (/guard:cf), CET Shadow Stack",
    },
    {
      platform: "Linux",
      controls: "ASLR, NX, PIE, RELRO, stack canaries",
    },
    {
      platform: "macOS",
      controls: "ASLR, hardened runtime, pointer authentication",
    },
  ];

  const codeReviewChecklist = [
    "Search for unsafe C functions and manual buffer copies.",
    "Check for missing bounds checks in parsers.",
    "Verify build flags and linker options.",
    "Ensure crash reports are collected and reviewed.",
    "Review third-party libraries for memory safety issues.",
  ];
  const codeReviewCommands = `# Search for risky C functions
rg -n "strcpy|strcat|gets\\(|sprintf|scanf\\(|memcpy|memmove" src

# Search for manual buffer arithmetic
rg -n "\\+\\+|--|\\[.*\\]" src`;

  const labSteps = [
    "Use a safe demo app or test binary in a lab.",
    "Trigger a controlled crash with oversized input.",
    "Inspect the stack trace and note the fault address.",
    "Check if DEP/NX and ASLR are enabled.",
    "Document mitigations and rebuild with hardening flags.",
  ];
  const verificationChecklist = [
    "Memory bugs are fixed and tested.",
    "Binaries are built with stack protection and PIE.",
    "DEP/NX and ASLR are enabled in production.",
    "Crash handling and reporting are in place.",
    "Fuzzing is part of the release process.",
  ];
  const safeBoundaries = [
    "Only test in a lab or with written authorization.",
    "Avoid exploit development in production environments.",
    "Use non-sensitive sample inputs and data.",
    "Focus on detection and mitigation improvements.",
  ];

  const pageContext = `This page explains Return-Oriented Programming (ROP), a technique that exploits memory corruption vulnerabilities by chaining existing code fragments (gadgets) to perform malicious actions. Topics include understanding the stack and return addresses, how ROP bypasses DEP/NX protections, detection signals and triage steps, and mitigation strategies like ASLR, stack canaries, CFI, and shadow stacks. The guide focuses on defensive learning and prevention practices.`;

  const sectionNavItems = [
    { id: "intro", label: "Intro", icon: <MemoryIcon /> },
    { id: "overview", label: "Overview", icon: <TuneIcon /> },
    { id: "foundations", label: "Foundations", icon: <CodeIcon /> },
    { id: "attack-flow", label: "Attack Flow", icon: <BugReportIcon /> },
    { id: "detection", label: "Detection", icon: <SearchIcon /> },
    { id: "defenses", label: "Defenses", icon: <ShieldIcon /> },
    { id: "gadgets-detail", label: "Gadgets", icon: <CodeIcon /> },
    { id: "techniques-detail", label: "Techniques", icon: <BugReportIcon /> },
    { id: "practical-defense", label: "Implementation", icon: <BuildIcon /> },
    { id: "real-world", label: "Real World", icon: <SecurityIcon /> },
    { id: "safe-lab", label: "Safe Lab", icon: <BuildIcon /> },
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
        border: `1px solid ${alpha(accent, 0.2)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha(accent, 0.35),
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
              bgcolor: alpha(accent, 0.15),
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
                bgcolor: activeSection === item.id ? alpha(accent, 0.18) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha(accent, 0.1),
                },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, color: activeSection === item.id ? accent : "text.secondary" }}>
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
      </Box>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="Return-Oriented Programming (ROP)" pageContext={pageContext}>
      <Box sx={{ minHeight: "100vh", bgcolor: "background.default" }}>
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
              "&:hover": { bgcolor: "#1d4ed8" },
              boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
              display: { xs: "flex", lg: "none" },
            }}
          >
            <ListAltIcon />
          </Fab>
        </Tooltip>

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

            <List dense sx={{ mx: -1 }}>
              {sectionNavItems.map((item) => (
                <ListItem
                  key={item.id}
                  onClick={() => scrollToSection(item.id)}
                  sx={{
                    borderRadius: 2,
                    mb: 0.5,
                    cursor: "pointer",
                    bgcolor: activeSection === item.id ? alpha(accent, 0.2) : "transparent",
                    borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                    "&:hover": {
                      bgcolor: alpha(accent, 0.12),
                    },
                    transition: "all 0.2s ease",
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
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2, mb: 3, borderColor: alpha(accent, 0.4), color: accent }}
        />

        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha(accent, 0.2)} 0%, ${alpha("#38bdf8", 0.18)} 50%, ${alpha("#22c55e", 0.12)} 100%)`,
            border: `1px solid ${alpha(accent, 0.3)}`,
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
              background: `radial-gradient(circle, ${alpha(accent, 0.18)} 0%, transparent 70%)`,
            }}
          />
          <Box
            sx={{
              position: "absolute",
              bottom: -30,
              left: "30%",
              width: 160,
              height: 160,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#38bdf8", 0.12)} 0%, transparent 70%)`,
            }}
          />
          <Box sx={{ position: "relative", zIndex: 1 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3, flexWrap: "wrap" }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, ${accent}, #38bdf8)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha(accent, 0.35)}`,
                }}
              >
                <MemoryIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                  Return-Oriented Programming (ROP)
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                  A defensive guide to code reuse attacks and mitigation strategies
                </Typography>
              </Box>
            </Box>

            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
              <Chip label="Defensive Focus" sx={{ bgcolor: alpha(accent, 0.2), color: accent, fontWeight: 600 }} />
              <Chip
                label="Memory Safety"
                sx={{ bgcolor: alpha("#22c55e", 0.2), color: "#22c55e", fontWeight: 600 }}
              />
              <Chip
                label="Code Reuse"
                sx={{ bgcolor: alpha("#38bdf8", 0.2), color: "#38bdf8", fontWeight: 600 }}
              />
              <Chip
                label="Mitigations"
                sx={{ bgcolor: alpha("#f59e0b", 0.2), color: "#f59e0b", fontWeight: 600 }}
              />
            </Box>

            <Grid container spacing={2}>
              {quickStats.map((stat) => (
                <Grid item xs={6} sm={3} key={stat.label}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      borderRadius: 2,
                      bgcolor: alpha(stat.color, 0.12),
                      border: `1px solid ${alpha(stat.color, 0.25)}`,
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
              label="Learning Hub"
              size="small"
              clickable
              onClick={() => navigate("/learn")}
              sx={{
                fontWeight: 700,
                fontSize: "0.75rem",
                bgcolor: alpha(accent, 0.15),
                color: accent,
                "&:hover": {
                  bgcolor: alpha(accent, 0.25),
                },
              }}
            />
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.secondary" }}>
              Quick Navigation
            </Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {[
              { label: "Intro", id: "intro" },
              { label: "Overview", id: "overview" },
              { label: "Foundations", id: "foundations" },
              { label: "Attack Flow", id: "attack-flow" },
              { label: "Detection", id: "detection" },
              { label: "Defenses", id: "defenses" },
              { label: "Gadgets", id: "gadgets-detail" },
              { label: "Techniques", id: "techniques-detail" },
              { label: "Implementation", id: "practical-defense" },
              { label: "Real World", id: "real-world" },
              { label: "Safe Lab", id: "safe-lab" },
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

        <Box sx={{ mb: 6 }}>
          <Typography id="intro" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Introduction
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            A beginner-friendly walkthrough of how ROP works and how defenders reduce the risk.
          </Typography>

          <Alert severity="warning" sx={{ mb: 3 }}>
            <AlertTitle>Defensive Learning Only</AlertTitle>
            This content focuses on prevention, detection, and safe engineering practices.
          </Alert>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              <strong>Return-Oriented Programming (ROP)</strong> is an advanced exploitation technique that fundamentally changed how we think about memory safety and code execution. To understand ROP, imagine you're watching a movie on a DVD player with a special remote control. Instead of playing the movie from start to finish, you can use the remote to jump to any scene you want. Now imagine a malicious person gets control of that remote and starts jumping between tiny fragments of different scenes to create an entirely new sequence that was never intended by the filmmakers. That's essentially what ROP does with computer programs.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              In traditional buffer overflow attacks before the mid-2000s, attackers would inject their own malicious code into a program's memory and then redirect execution to run that code. But as security researchers and operating system vendors became aware of these attacks, they implemented a crucial defense called <strong>DEP (Data Execution Prevention)</strong> on Windows or <strong>NX (No-eXecute)</strong> on Linux/Unix systems. This defense marked certain areas of memory—specifically the areas where data like the stack and heap live—as non-executable. It's like putting a lock on certain rooms in a house: you can store things there, but you can't use those rooms for certain activities. With DEP/NX enabled, even if an attacker successfully injects malicious code into memory, the processor will refuse to execute it because it's in a data-only region.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              This is where Return-Oriented Programming comes into the picture. <strong>ROP is the ingenious workaround that attackers developed in response to DEP/NX protections.</strong> Instead of injecting new code, ROP reuses code that already exists in the program's memory—code that's legitimately marked as executable. When a program is running, it loads not just your application code but also system libraries (like libc on Linux or kernel32.dll on Windows) that contain thousands of instructions. ROP works by carefully selecting tiny fragments of these existing instructions, called <strong>"gadgets,"</strong> and chaining them together in a specific sequence to achieve the attacker's goals. Each gadget is just a few instructions long and must end with a "return" instruction (hence "Return-Oriented"). When one gadget finishes executing and hits its return instruction, control transfers to the next gadget in the chain, and so on, like dominoes falling in sequence.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
              Here's the crucial part for beginners to understand: <strong>ROP itself is not a vulnerability or bug.</strong> Rather, it's an exploitation technique that requires an underlying memory corruption vulnerability to work. Think of it this way: if your house has a broken window (the memory bug), a burglar might use various techniques to climb through that window (ROP is one of those techniques). Fixing the broken window (eliminating memory corruption bugs) is the fundamental solution. ROP typically appears after a buffer overflow vulnerability allows an attacker to overwrite the <strong>return address</strong> on the stack—the memory location that tells the program where to resume execution after a function completes. By carefully crafting the overwritten data, an attacker can redirect execution to their chosen gadgets and build a complete ROP chain that performs malicious actions like spawning a shell, reading sensitive files, or escalating privileges.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              The evolution of ROP is a fascinating example of the ongoing cat-and-mouse game in computer security. As defenders create new protections like <strong>ASLR (Address Space Layout Randomization)</strong> which randomizes where code is loaded in memory, attackers develop information leak techniques to defeat ASLR. As defenders implement <strong>Control-Flow Integrity (CFI)</strong> which restricts what gadgets can be chained together, attackers search for ways to find CFI-compliant gadgets or bypass CFI checks. This page focuses on the defensive perspective: understanding how ROP works, recognizing warning signs, implementing robust mitigations, and most importantly, writing memory-safe code that eliminates the root cause. While ROP chains can be remarkably sophisticated, <strong>they all share a common dependency: they need a memory corruption bug to gain initial control.</strong> Eliminate that bug through secure coding practices, comprehensive input validation, memory-safe language choices, and thorough testing, and ROP becomes irrelevant. The mitigations we'll discuss—stack canaries, ASLR, CFI, shadow stacks—are important layers of defense, but they're the second line of defense. The first and most critical defense is writing code that doesn't have exploitable memory corruption vulnerabilities in the first place.
            </Typography>
          </Paper>

          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip icon={<MemoryIcon />} label="Stack" size="small" />
            <Chip icon={<CodeIcon />} label="Gadgets" size="small" />
            <Chip icon={<SearchIcon />} label="Detection" size="small" />
            <Chip icon={<ShieldIcon />} label="Mitigations" size="small" />
            <Chip icon={<BuildIcon />} label="Hardening" size="small" />
          </Box>
        </Box>

        <Box sx={{ mb: 6 }}>
          <Typography id="overview" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Overview and Objectives
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Use this section to orient your learning path and vocabulary before diving into the technical details.
          </Typography>
          <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Learning Objectives
                </Typography>
                <List dense>
                  {objectives.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Beginner Path
                </Typography>
                <List dense>
                  {beginnerPath.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Key Ideas
                </Typography>
                <List dense>
                  {keyIdeas.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Quick Glossary
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Term</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Meaning</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {glossary.map((item) => (
                        <TableRow key={item.term}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.term}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Common Misconceptions
                </Typography>
                <Grid container spacing={2}>
                  {misconceptions.map((item) => (
                    <Grid item xs={12} md={4} key={item.myth}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: "#0b1020",
                          borderRadius: 2,
                          border: "1px solid rgba(37, 99, 235, 0.25)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#2563eb", mb: 1 }}>
                          Myth
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>
                          {item.myth}
                        </Typography>
                        <Typography variant="subtitle2" sx={{ color: "#38bdf8", mb: 0.5 }}>
                          Reality
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>
                          {item.reality}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Box>
          </Box>

          <Box sx={{ mb: 6 }}>
            <Typography id="foundations" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
              Foundations
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Build intuition for the stack, gadgets, and where ROP appears in real systems.
            </Typography>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  To truly understand Return-Oriented Programming, you need to grasp how computers manage function calls and memory at a fundamental level. When you write a program with multiple functions calling each other, the computer needs a systematic way to keep track of where to return after each function completes. This is where <strong>the stack</strong> comes in—a special region of memory that operates like a stack of plates in a cafeteria: you can add (push) new plates on top, and you can remove (pop) plates from the top, but you always work with the topmost plate first. This "Last-In, First-Out" (LIFO) behavior makes stacks perfect for managing nested function calls.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Here's what happens when your program calls a function: First, the program pushes the <strong>return address</strong>—the memory location of the instruction that should execute after the function finishes—onto the stack. Then it pushes any necessary parameters and local variables. The function does its work, modifies its local variables, and when it's ready to finish, it executes a "return" instruction. This return instruction pops the return address off the stack and jumps to that address, resuming execution right where the function was originally called. <strong>This return address is the Achilles' heel that ROP exploits.</strong>
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Now consider what happens if a program has a buffer overflow vulnerability—perhaps a function copies user input into a fixed-size buffer without checking the input length. If the input is too large, it overflows the buffer boundaries and starts overwriting adjacent memory on the stack. Since return addresses are stored on the stack right after local variables, <strong>a buffer overflow can overwrite the return address with an attacker-controlled value.</strong> When the function tries to return, instead of jumping back to the legitimate caller, it jumps to whatever address the attacker wrote—and that's where ROP chains begin. The attacker carefully crafts this overflow to overwrite the return address with the address of their first gadget, and then places a sequence of additional addresses on the stack that form the complete ROP chain.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  The genius of ROP is that <strong>it weaponizes the program's own code against itself.</strong> Every program and library contains countless small instruction sequences that happen to end with a return instruction. These weren't intentionally designed as gadgets—they're just fragments of normal code that happen to have useful side effects. For example, you might find a sequence like "pop rdi; ret" which pops a value from the stack into the RDI register and then returns. By itself, that's harmless. But when an attacker chains dozens of these gadgets together, each one performing a small operation, they can accomplish complex tasks: moving values into specific registers, performing arithmetic operations, calling system functions, changing memory permissions, or spawning a command shell. Modern operating systems' DEP/NX protections prevent executing code from writable memory regions, but they can't prevent executing legitimate code that's already marked as executable—which is exactly what ROP gadgets are.
                </Typography>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1, mt: 2 }}>
                  Memory Basics for ROP (Quick Summary)
                </Typography>
                <List dense>
                  {memoryBasics.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Core Concepts
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Concept</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Meaning</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Why It Matters</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {coreConcepts.map((item) => (
                        <TableRow key={item.concept}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.concept}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.meaning}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.whyItMatters}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Where ROP Shows Up
                </Typography>
                <List dense>
                  {whereItShowsUp.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </Box>

          <Box sx={{ mb: 6 }}>
            <Typography id="attack-flow" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
              Attack Flow
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              A conceptual view of how ROP chains are assembled from a memory corruption bug.
            </Typography>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Understanding the attack flow of a Return-Oriented Programming exploit helps defenders recognize suspicious patterns and implement effective countermeasures. <strong>The ROP attack lifecycle has several distinct phases,</strong> each presenting opportunities for detection and prevention. Let's walk through what actually happens when an attacker builds and executes a ROP chain, breaking down each step so even beginners can follow the progression.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  The attack begins with <strong>reconnaissance and vulnerability discovery.</strong> The attacker needs to find a memory corruption vulnerability—typically a buffer overflow in a function that handles user input without proper bounds checking. This might be in a network service parsing incoming requests, a file format parser processing untrusted documents, or any code path where external data can overflow a fixed-size buffer. Once they've identified this vulnerability, the attacker can trigger it by sending specially crafted input that exceeds the buffer's capacity. At this point, the attacker has the ability to overwrite memory on the stack, including the critical return address that determines where execution will jump when the vulnerable function completes.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Next comes <strong>gadget hunting</strong>—the process of finding useful instruction sequences in the executable code. The attacker uses specialized tools like ROPgadget or ropper to scan through the program's binary and all loaded libraries (like libc), searching for sequences that end with a return instruction. A gadget might be as simple as "pop rax; ret" (which pops a value into the RAX register) or more complex like "mov [rdi], rax; ret" (which writes the value in RAX to the memory address pointed to by RDI). <strong>The attacker needs to find gadgets that match the operations required for their goal,</strong> whether that's setting up arguments for a function call, manipulating memory permissions, or performing arithmetic calculations. On modern 64-bit Linux systems, for example, the x86-64 calling convention requires specific registers (RDI, RSI, RDX, RCX, R8, R9) to hold function arguments, so the attacker needs gadgets that can populate those registers with the correct values.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  With gadgets identified, the attacker <strong>constructs the ROP chain</strong>—a carefully ordered sequence of gadget addresses interspersed with data values. This chain is embedded in the malicious input that triggers the buffer overflow. Here's how it works: When the vulnerable function tries to return, it pops the return address from the stack—but that address now points to the first gadget. The first gadget executes, performs its operation (perhaps popping a value into a register), and then hits its own return instruction, which pops the next address from the stack. That next address points to the second gadget, which executes and returns to the third gadget, and so on. <strong>The stack essentially becomes a script of instructions, with each gadget acting as a single line in that script.</strong> Between gadget addresses, the attacker places data values that gadgets will pop into registers or use in calculations—these are the "arguments" to the gadget operations.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  The ultimate goal of most ROP chains is <strong>gaining code execution privileges</strong>—specifically, calling a powerful function that the attacker controls. Common targets include the "system()" function (which executes shell commands), the "execve()" system call (which launches a new program), or "mprotect()" (which can change memory permissions to make a data region executable, after which the attacker can run traditional shellcode). The ROP chain meticulously sets up the necessary registers and stack values to call one of these functions with attacker-controlled arguments. For example, to call system("/bin/sh"), the chain needs to place a pointer to the string "/bin/sh" in the RDI register (the first argument position in the x86-64 calling convention) and then transfer control to the system() function. <strong>Each gadget in the chain performs one small piece of this setup,</strong> like finding where "/bin/sh" exists in memory (often searching the loaded libc library), moving that address through registers, and finally calling the system() function. When successful, this gives the attacker an interactive shell with the same privileges as the vulnerable program—which might be root/administrator if the program runs with elevated privileges.
                </Typography>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1, mt: 2 }}>
                  High-Level Attack Flow (Conceptual Summary)
                </Typography>
                <List dense>
                  {attackFlow.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Impact Areas
                </Typography>
                <List dense>
                  {impactAreas.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <BugReportIcon color="error" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </Box>

          <Box sx={{ mb: 6 }}>
            <Typography id="detection" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
              Detection and Triage
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Indicators, telemetry, and response steps to confirm and contain suspected ROP activity.
            </Typography>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Detecting Return-Oriented Programming attacks in production systems is challenging but absolutely critical</strong> for maintaining security posture and responding quickly to incidents. Unlike traditional attacks that might leave obvious traces like new files or network connections, ROP attacks often operate entirely within the memory space of a legitimate process, making them stealthy and hard to spot with conventional monitoring tools. However, ROP attacks do leave distinctive behavioral patterns and anomalies that defenders can watch for if they know what to look for.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  One of the most valuable sources of ROP detection intelligence comes from <strong>crash dumps and application crashes.</strong> When a ROP exploit is being developed or when it fails due to incorrect addresses, defensive mitigations, or environmental differences, the program often crashes. But these aren't ordinary crashes—they have specific characteristics. The instruction pointer (EIP on 32-bit systems, RIP on 64-bit) might be pointing to an unusual location: not the beginning of a function as you'd normally expect, but instead to the middle of a function at a gadget location, or even into the middle of an instruction (what's called an "unaligned" address). The stack trace might show impossible call sequences—functions that would never normally call each other suddenly appearing in the same call stack. <strong>These are strong indicators that something has hijacked the normal control flow of the program.</strong>
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Another key detection signal is <strong>abnormal memory access patterns.</strong> ROP chains often need to read from or write to unusual memory regions as they set up their payload. You might see access violations when the chain attempts to dereference a null pointer or invalid address, or when it tries to write to read-only memory. Security monitoring tools and endpoint detection and response (EDR) solutions can flag processes that suddenly start accessing memory regions they've never touched before, especially if those accesses fail. Additionally, <strong>stack anomalies</strong> are common indicators—if you examine a crash dump and see the stack filled with patterns that look like addresses rather than normal data, or if you see the stack pointer (ESP/RSP) suddenly jumping to unexpected locations, these suggest stack manipulation consistent with ROP.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Modern defensive technologies provide additional telemetry specifically designed to catch ROP attacks. <strong>Control-Flow Integrity (CFI)</strong> implementations will generate alerts or terminate processes when they detect illegal control-flow transfers—like jumping to a gadget address instead of a proper function entry point. <strong>Shadow stack</strong> implementations (part of Intel CET—Control-flow Enforcement Technology) maintain a separate, protected copy of return addresses; if a return instruction uses an address that doesn't match the shadow stack, the processor raises an exception. These technologies specifically target ROP's core mechanism, making them highly effective at detection. Similarly, stack canaries—random values placed on the stack between local variables and return addresses—will be corrupted if a buffer overflow overwrites the return address, triggering a stack smashing detection error before the ROP chain can execute.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  For incident response teams, <strong>behavioral analysis</strong> is crucial. A process that suddenly spawns a shell (like cmd.exe, powershell.exe, or /bin/bash) without going through normal application logic should raise immediate red flags. A network service that has no legitimate reason to execute shell commands starting to do so is a classic indicator of successful exploitation. Similarly, watch for unexpected child processes, unusual network connections to external IPs, attempts to escalate privileges, or access to sensitive files that the application normally doesn't touch. <strong>These post-exploitation behaviors often follow successful ROP attacks</strong> and represent the moment when you can still contain the damage by killing the process, isolating the system, and beginning forensic analysis. The key is establishing strong baselines of normal behavior for each application and service, then using automated monitoring to flag deviations from those baselines—because manual detection of these subtle signals is nearly impossible at scale.
                </Typography>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1, mt: 2 }}>
                  Detection Signals (Quick Reference)
                </Typography>
                <List dense>
                  {detectionSignals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Telemetry Sources
                </Typography>
                <List dense>
                  {telemetrySources.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Baseline Metrics
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Metric</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Normal</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Investigate When</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {baselineMetrics.map((item) => (
                        <TableRow key={item.metric}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.metric}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.normal}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.investigate}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Quick Triage Steps
                </Typography>
                <List dense>
                  {triageSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Response Steps (Defensive)
                </Typography>
                <List dense>
                  {responseSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </Box>

          <Box sx={{ mb: 6 }}>
            <Typography id="defenses" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
              Defenses and Hardening
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Practical ways to reduce exploitability and harden builds against code reuse attacks.
            </Typography>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Defending against Return-Oriented Programming requires a defense-in-depth approach</strong>—multiple layers of security controls working together, because no single mitigation is foolproof. The good news for defenders is that the security industry has developed a robust set of countermeasures over the past two decades, each targeting different aspects of the ROP attack chain. While sophisticated attackers have found ways around individual mitigations, combining multiple defenses raises the bar significantly, often making attacks impractical or impossible within the attacker's resource constraints.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Let's start with <strong>the most fundamental defense: eliminating memory corruption vulnerabilities in the first place.</strong> This cannot be overstated—if your code doesn't have buffer overflows, use-after-free bugs, or other memory corruption issues, ROP becomes irrelevant because attackers have no way to gain control of the return address. Modern secure coding practices include: using length-checked functions (like strncpy instead of strcpy, snprintf instead of sprintf), validating all input sizes before processing, leveraging compiler warnings (treating them as errors), employing static analysis tools to catch potential overflows, and most importantly, <strong>considering memory-safe languages for new projects.</strong> Languages like Rust, Go, and modern managed languages (C#, Java, Python) provide memory safety guarantees that make entire classes of vulnerabilities impossible. When you must use C or C++, modern language features like smart pointers, bounds-checked containers (std::vector instead of raw arrays), and safe string classes (std::string) dramatically reduce risk.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Address Space Layout Randomization (ASLR)</strong> is one of the most important operating system-level mitigations against ROP. ASLR randomizes the memory addresses where the program, its libraries, stack, and heap are loaded each time the process starts. Without ASLR, an attacker can look up gadget addresses once and use them reliably in their exploit. With ASLR enabled, those addresses change every time—the gadget that was at 0x7ffff7a52123 in one run might be at 0x7ffff79ed123 in the next run. <strong>This means attackers can't hardcode gadget addresses in their ROP chain;</strong> instead, they need to somehow leak an address from the running process first, then calculate where the gadgets are relative to that leak. This significantly increases exploit complexity and creates opportunities for detection. However, ASLR has limitations: it's only effective if <strong>everything</strong> is randomized (position-independent executables with PIE, randomized libraries, randomized stack/heap), and it can be defeated by information leak vulnerabilities that disclose addresses to the attacker.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Stack canaries</strong> provide a runtime defense specifically against stack buffer overflows. The compiler inserts a random value (the "canary") on the stack between local variables and the saved return address when a function starts. Before the function returns, it checks whether the canary value has been modified. If a buffer overflow overwrote the return address, it almost certainly also overwrote the canary in the process. When the canary check fails, the program terminates immediately with a stack smashing detection error, preventing the ROP chain from executing. Modern compilers like GCC and Clang enable stack canaries by default for functions with vulnerable characteristics (string buffers, char arrays). The limitation is that canaries can sometimes be bypassed if an attacker can read the canary value through an information leak, or if they can exploit vulnerabilities in other memory regions (heap) that don't have canary protection.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Control-Flow Integrity (CFI)</strong> and <strong>shadow stacks</strong> represent the cutting edge of anti-ROP defenses. CFI works by enforcing a policy of legal control-flow transitions—the program maintains a list of valid targets for each indirect call or return, and any attempt to jump to an address not on that list is blocked. This directly counters ROP because gadgets are generally not valid return targets according to the program's original control flow. Shadow stacks go further by maintaining a separate, protected copy of all return addresses. When a function returns, the processor compares the return address from the normal stack with the value from the shadow stack; if they don't match (because an attacker overwrote the stack copy), the processor raises an exception. <strong>Intel's Control-flow Enforcement Technology (CET) implements shadow stacks in hardware,</strong> making them extremely difficult to bypass. These technologies are becoming more widespread in modern operating systems (Windows 10/11, recent Linux kernels) and represent a significant barrier to ROP attacks. However, deployment is gradual because they require recompilation of programs and can have performance impacts.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Finally, <strong>reducing the attack surface</strong> is an often-overlooked but highly effective defensive strategy. Each library your program loads potentially contains thousands of gadgets that could be used in ROP chains. By removing or disabling unnecessary libraries, features, and code paths, you reduce the gadget pool available to attackers. Use linker options like RELRO (RELocation Read-Only) to make certain sections of memory read-only, preventing attacks that try to overwrite function pointers in the Global Offset Table (GOT). Enable compiler hardening flags consistently across all builds: -fstack-protector-strong for stack canaries, -fPIE -pie for position-independent code, -D_FORTIFY_SOURCE=2 for additional runtime checks. <strong>Regular security updates are critical</strong>—not just to patch vulnerabilities, but also because updates change the layout of system libraries, invalidating any gadget addresses an attacker might have discovered. A well-maintained, hardened system with all these defenses enabled makes ROP exploitation exponentially more difficult, often pushing it beyond the capability of all but the most sophisticated attackers.
                </Typography>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1, mt: 2 }}>
                  Prevention Checklist (Quick Reference)
                </Typography>
                <List dense>
                  {preventionChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Secure Coding Patterns
                </Typography>
                <List dense>
                  {secureCodingPatterns.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Mitigations Overview
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Mitigation</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Purpose</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Limitations</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {mitigationsTable.map((item) => (
                        <TableRow key={item.mitigation}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.mitigation}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.purpose}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.limitation}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Build Hardening Flags (Example)
                </Typography>
                <CodeBlock code={buildFlags} language="text" />
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Platform Defenses
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Platform</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Controls</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {platformDefenses.map((item) => (
                        <TableRow key={item.platform}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.platform}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.controls}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Extra Hardening Tips
                </Typography>
                <List dense>
                  {[
                    "Turn on crash reporting and monitor for anomalies.",
                    "Harden third-party libraries or replace them.",
                    "Segment high-risk parsers into separate processes.",
                    "Remove unused features to reduce gadget surface.",
                    "Practice secure patching and regular updates.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <LockIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </Box>

          <Box sx={{ mb: 6 }}>
            <Typography id="real-world" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
              Real-World Context and Case Studies
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Understanding how ROP appears in actual security incidents and vulnerability disclosures.
            </Typography>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>ROP techniques have been used in countless real-world security incidents,</strong> from targeted attacks on high-value systems to widespread exploitation of common software vulnerabilities. Understanding these real-world contexts helps defenders appreciate why ROP matters and how it fits into the broader threat landscape. While this guide focuses on defensive learning rather than providing exploitation recipes, examining actual case studies (with appropriate ethical boundaries) reveals important lessons about where defenses succeed or fail.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Browser exploits</strong> represent one of the most common contexts where ROP techniques appear. Modern web browsers like Chrome, Firefox, and Safari are enormous codebases written primarily in C++, handling untrusted content from the internet. When researchers discover memory corruption vulnerabilities in JavaScript engines, HTML parsers, or media codec handlers, they frequently develop ROP chains to achieve code execution. <strong>Browser vendors respond by implementing aggressive mitigations:</strong> fine-grained ASLR, site isolation (running different websites in separate processes), and Control-Flow Integrity. This ongoing arms race drives innovation in both attack and defense techniques.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Operating system kernels</strong> are another critical attack surface. Kernel vulnerabilities are particularly valuable because exploiting them provides complete system control. ROP techniques adapted for kernel space face unique challenges: defensive mechanisms like SMEP (Supervisor Mode Execution Prevention) prevent the kernel from executing userspace code. Attackers respond with kernel ROP chains using only kernel gadgets, often targeting vulnerable system call handlers or device drivers.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Embedded systems and IoT devices</strong> present a different challenge. Many devices run with limited security features—ASLR disabled, no stack canaries, ancient library versions. This makes ROP exploitation easier. <strong>The defensive lesson: never assume a device is "too small" to deserve proper security hardening.</strong> As these devices proliferate and connect to networks, they become attractive targets.
                </Typography>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 2 }}>
                  Historical Evolution of ROP
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>The history of Return-Oriented Programming illustrates the continuous evolution of both attack and defense techniques.</strong> In the early 2000s, buffer overflow attacks were relatively straightforward—attackers would inject shellcode (malicious machine instructions) directly into program memory and redirect execution to run it. This "code injection" approach worked because memory regions were typically both writable and executable. The security community recognized this fundamental weakness and developed Data Execution Prevention (DEP), also known as W^X ("Write XOR Execute"), which enforced a simple but powerful rule: a memory page can be either writable or executable, but never both simultaneously. This defense was deployed widely by 2004-2006 across Windows (DEP), Linux (NX bit support), and other operating systems.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>The academic breakthrough came in 2007 when Hovav Shacham published the seminal paper "The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls."</strong> This work formalized Return-Oriented Programming and demonstrated that it was Turing-complete—meaning attackers could perform any computation using only gadgets, without any injected code. The paper showed that even with DEP enabled, attackers could achieve arbitrary code execution by carefully chaining together existing instruction sequences. This was a watershed moment because it proved that DEP alone was insufficient against sophisticated adversaries. The security community had to develop entirely new defensive approaches.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>The years following 2007 saw an explosion of ROP-related research and real-world exploitation.</strong> Address Space Layout Randomization (ASLR) became the next major defense, randomizing where code was loaded in memory to make gadget addresses unpredictable. But attackers responded with information leak vulnerabilities that disclosed memory addresses, allowing them to calculate gadget locations at runtime. The Pwn2Own competitions demonstrated this arms race dramatically: each year, researchers would demonstrate new browser exploits using increasingly sophisticated ROP chains that bypassed the latest mitigations. These competitions drove both attack innovation and defensive improvements, leading to technologies like Control-Flow Integrity (CFI) and Intel CET (Control-flow Enforcement Technology) that specifically target ROP's core mechanism.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Today, ROP remains relevant but has become significantly harder to exploit successfully.</strong> Modern systems typically require attackers to chain together multiple vulnerabilities: an initial memory corruption bug, an information leak to defeat ASLR, techniques to bypass CFI or shadow stacks, and finally the ROP chain itself. This "exploitation complexity" is a defensive win—while it doesn't eliminate attacks entirely, it dramatically raises the cost and skill required, reducing the pool of potential attackers. The most sophisticated ROP attacks now appear primarily in targeted operations by well-resourced adversaries, while opportunistic attacks have largely moved to other techniques like social engineering, credential theft, or exploitation of unpatched known vulnerabilities.
                </Typography>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 2 }}>
                  Industry Applications and Career Relevance
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Understanding ROP is valuable across multiple cybersecurity career paths.</strong> Security researchers and vulnerability analysts need ROP knowledge to assess the exploitability of discovered bugs and write accurate severity assessments. A buffer overflow that can be leveraged into a ROP chain for code execution is far more critical than one that only causes a crash. Penetration testers and red team operators use ROP techniques when testing hardened systems that have traditional exploit mitigations enabled. Blue team defenders and incident responders must recognize ROP indicators in crash dumps, EDR alerts, and memory forensics to accurately triage and investigate potential compromises.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Software developers and security engineers benefit from ROP knowledge by understanding why certain coding practices and compiler flags matter.</strong> When you understand how a buffer overflow leads to ROP exploitation, you're more likely to take bounds checking seriously, use safe string functions, and enable security-hardening compiler options. Threat modeling becomes more accurate when you understand the full exploitation chain. Security architects designing systems can make better decisions about memory-safe language choices, sandboxing strategies, and defense-in-depth layering when they understand what ROP attackers need to succeed.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Certifications and training programs increasingly cover ROP concepts.</strong> The OSCP (Offensive Security Certified Professional) and OSED (Offensive Security Exploit Developer) certifications include buffer overflow and ROP topics. CTF (Capture The Flag) competitions frequently feature "pwn" challenges that require constructing ROP chains. Academic security courses at major universities dedicate significant time to code-reuse attacks. Understanding this material puts you ahead of peers who only understand vulnerabilities at a surface level, enabling you to speak intelligently about exploitation risks, defensive investments, and security architecture decisions.
                </Typography>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 2 }}>
                  Common Vulnerable Patterns in Code
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Vulnerable Pattern</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Why It's Dangerous</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Secure Alternative</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontFamily: "monospace", fontSize: "0.85rem" }}>strcpy(dest, user_input)</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>No bounds checking</TableCell>
                        <TableCell sx={{ color: "grey.400", fontFamily: "monospace", fontSize: "0.85rem" }}>strncpy with size check</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontFamily: "monospace", fontSize: "0.85rem" }}>sprintf(buf, fmt, input)</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>No size limit</TableCell>
                        <TableCell sx={{ color: "grey.400", fontFamily: "monospace", fontSize: "0.85rem" }}>snprintf with buffer size</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontFamily: "monospace", fontSize: "0.85rem" }}>gets(buffer)</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Inherently unsafe</TableCell>
                        <TableCell sx={{ color: "grey.400", fontFamily: "monospace", fontSize: "0.85rem" }}>fgets with size parameter</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontFamily: "monospace", fontSize: "0.85rem" }}>memcpy(dest, src, user_len)</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>User-controlled length</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Validate length first</TableCell>
                      </TableRow>
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Box>
          </Box>

          <Box sx={{ mb: 6 }}>
            <Typography id="safe-lab" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
              Safe Lab Workflow
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Practice in controlled environments and validate fixes with disciplined checklists.
            </Typography>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Safe Lab Walkthrough
                </Typography>
                <List dense>
                  {labSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Code Review Checklist
                </Typography>
                <List dense>
                  {codeReviewChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Accordion sx={{ bgcolor: "#0f1422", borderRadius: 2, mb: 3 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Safe Code Search Commands</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={codeReviewCommands} language="bash" />
                </AccordionDetails>
              </Accordion>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Verification Checklist
                </Typography>
                <List dense>
                  {verificationChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Safe Boundaries
                </Typography>
                <List dense>
                  {safeBoundaries.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </Box>

          <Box sx={{ mb: 6 }}>
            <Typography id="gadgets-detail" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
              Understanding Gadgets in Depth
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              A comprehensive look at what gadgets are, how they're found, and how they're chained together.
            </Typography>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Gadgets are the fundamental building blocks of Return-Oriented Programming,</strong> and understanding them deeply is essential for both attackers trying to exploit systems and defenders trying to protect them. At its core, a gadget is simply a sequence of machine code instructions that already exists in an executable region of memory and ends with a return instruction. What makes gadgets powerful is that they weren't designed to be gadgets—they're just fragments of legitimate program code that happen to have useful side effects when taken out of their original context and executed independently.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  To understand how gadgets form, you need to know that <strong>machine code is just bytes,</strong> and the processor interprets those bytes as instructions starting from wherever the instruction pointer (IP) is currently pointing. In normal program execution, the IP advances through code in a predictable way, following the program's intended flow. But in ROP, the attacker deliberately redirects the IP to land in the middle of legitimate code, often not even at the intended instruction boundaries. This technique, called <strong>"instruction misalignment,"</strong> can reveal entirely different instructions than what the programmer intended. For example, a multi-byte instruction like "mov [rbp+8], eax" (which moves a value from the EAX register to a memory location) contains several bytes. If you jump to the second or third byte of that instruction instead of the first, the processor might interpret those bytes as completely different instructions—perhaps a "pop rdx; ret" sequence. This is why even small binaries can contain hundreds or thousands of potential gadgets: every byte is a potential starting point for interpretation.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Gadget categories</strong> help organize the types of operations you can perform in a ROP chain. <strong>Data movement gadgets</strong> like "pop rdi; ret" or "mov rax, rbx; ret" let you load values from the stack into registers or move values between registers. These are crucial for setting up function arguments and preparing data. <strong>Arithmetic gadgets</strong> like "add rax, rbx; ret" or "xor rdi, rdi; ret" perform calculations, which might be needed to compute addresses or manipulate values. <strong>Memory access gadgets</strong> like "mov [rdi], rax; ret" (write) or "mov rax, [rdi]; ret" (read) allow you to read from or write to arbitrary memory addresses, essential for modifying program state. <strong>Control flow gadgets</strong> include conditional jumps or gadgets that end with "jmp rax" instead of "ret", allowing more complex chain structures. And finally, <strong>system call gadgets</strong> like "syscall; ret" or gadgets that call library functions directly let you invoke operating system functionality—the ultimate goal of most ROP chains.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Finding gadgets is both an art and a science, powered by specialized tools. <strong>ROPgadget</strong> and <strong>ropper</strong> are the two most popular open-source tools for automated gadget discovery. They work by disassembling binary files and scanning for instruction sequences that end with return instructions, cataloging each sequence by its operations and registers affected. You run these tools against your target binary and all its dependent libraries (especially libc, the standard C library, which is loaded by almost every program and contains an enormous variety of useful gadgets). The tools output a database of available gadgets with their addresses and assembly code. For example: "0x00007ffff7a52123 : pop rdi ; ret" tells you that at address 0x7ffff7a52123, there's a gadget that pops a value into RDI and returns.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Chaining gadgets together</strong> is where the real complexity emerges. Each gadget performs one small operation, so achieving something meaningful like calling system("/bin/sh") might require a chain of 10-20 gadgets or more. The chain needs to respect the <strong>calling convention</strong> of the target platform—on Linux x86-64, that means placing function arguments in specific registers (RDI for the first argument, RSI for the second, RDX for the third, and so on). So a typical chain might start with gadgets that pop values into these registers, then include a gadget that calls the desired function. The stack layout becomes critical: after the initial return address overwrite, you place the address of your first gadget, then any data values that gadget needs to pop, then the address of your second gadget, more data, and so forth. When the first gadget returns, the return instruction pops the next address off the stack and jumps to the second gadget. Each gadget advances the stack pointer, moving through your prepared chain like reading a script.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  One of the biggest challenges in ROP exploitation is dealing with <strong>bad bytes</strong> and <strong>stack alignment</strong> requirements. Bad bytes are characters that break your exploit—most commonly null bytes (0x00), which terminate strings if you're exploiting a string-handling function like strcpy, or newline characters (0x0a) that might stop input parsing. If a gadget address contains a bad byte, you can't use that gadget, forcing you to find alternatives. Stack alignment is another constraint: many modern functions expect the stack pointer to be aligned to 16-byte boundaries (on x86-64), and calling them with a misaligned stack causes crashes. <strong>This means your ROP chain might need to include padding gadgets or "stack pivot" operations</strong> that adjust the stack pointer to meet alignment requirements before calling critical functions. These practical constraints are why ROP exploitation, despite the conceptual simplicity, often requires considerable trial and error and expertise.
                </Typography>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Common Gadget Types and Their Uses
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Gadget Type</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Example</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Purpose</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>Register Pop</TableCell>
                        <TableCell sx={{ color: "grey.400", fontFamily: "monospace" }}>pop rdi; ret</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Load value from stack into register for function arguments</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>Register Move</TableCell>
                        <TableCell sx={{ color: "grey.400", fontFamily: "monospace" }}>mov rax, rbx; ret</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Transfer values between registers</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>Memory Write</TableCell>
                        <TableCell sx={{ color: "grey.400", fontFamily: "monospace" }}>mov [rdi], rax; ret</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Write register value to memory address</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>Memory Read</TableCell>
                        <TableCell sx={{ color: "grey.400", fontFamily: "monospace" }}>mov rax, [rdi]; ret</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Read value from memory into register</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>Arithmetic</TableCell>
                        <TableCell sx={{ color: "grey.400", fontFamily: "monospace" }}>add rax, rbx; ret</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Perform calculations for address computation</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>System Call</TableCell>
                        <TableCell sx={{ color: "grey.400", fontFamily: "monospace" }}>syscall; ret</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Invoke operating system functionality</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>Stack Pivot</TableCell>
                        <TableCell sx={{ color: "grey.400", fontFamily: "monospace" }}>xchg rsp, rax; ret</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Move stack pointer to attacker-controlled memory</TableCell>
                      </TableRow>
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Finding Gadgets with Tools
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Modern exploitation frameworks and tools automate gadget discovery:
                </Typography>
                <CodeBlock code={`# Using ROPgadget to find all gadgets in a binary
ROPgadget --binary ./vulnerable_program

# Find specific gadgets (e.g., pop rdi)
ROPgadget --binary ./vulnerable_program --only "pop|ret"

# Find gadgets in libc (the gold mine for most exploits)
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret"

# Using ropper for more advanced searching
ropper --file ./vulnerable_program --search "pop rdi"

# Find gadgets that don't contain bad bytes
ropper --file ./vulnerable_program --badbytes "000a0d"

# Find gadgets for specific operations
ROPgadget --binary ./vulnerable_program --ropchain`} language="bash" />
              </Paper>
            </Box>
          </Box>

          <Box sx={{ mb: 6 }}>
            <Typography id="techniques-detail" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
              Common ROP Techniques Explained
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Detailed explanations of popular ROP techniques like ret2libc, ret2plt, and ret2csu.
            </Typography>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 2 }}>
                  ret2libc (Return-to-libc)
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>ret2libc is one of the oldest and most fundamental ROP techniques,</strong> predating the formalization of ROP itself. The idea is elegantly simple: instead of injecting your own code, you redirect execution to powerful functions that already exist in the C standard library (libc). The system() function is the classic target—it takes a string argument and passes it to the shell for execution. If you can call system("/bin/sh"), you've spawned a shell with the privileges of the vulnerable program. The challenge is setting up the function call correctly according to the calling convention.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  On older 32-bit x86 systems, ret2libc was relatively straightforward because function arguments were passed on the stack. You'd overflow a buffer to overwrite the return address with the address of system(), then place your arguments on the stack right after that. On modern 64-bit x86-64 systems, it's more complex because arguments are passed in registers (RDI holds the first argument). <strong>This means you need gadgets to pop values into those registers before calling the function.</strong> A typical ret2libc chain might look like: [address of "pop rdi; ret" gadget] [address of "/bin/sh" string] [address of system()]. When the vulnerable function returns, it jumps to the pop gadget, which pops the string address into RDI, then returns to system(), which reads its argument from RDI and spawns a shell.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  The main complications with ret2libc are <strong>ASLR</strong> (which randomizes where libc is loaded, requiring an information leak to find function addresses) and <strong>finding the "/bin/sh" string</strong> (which often exists somewhere in libc itself, so tools can search for it). Despite these challenges, ret2libc remains highly effective because libc is loaded in virtually every program, providing a consistent attack surface.
                </Typography>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 2 }}>
                  ret2plt (Return-to-PLT)
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>The Procedure Linkage Table (PLT) is a mechanism used in dynamically linked binaries</strong> to resolve function addresses at runtime. When your program calls a library function like puts() or system(), it actually calls through a PLT stub that handles the dynamic linking. The beauty of ret2plt for attackers is that <strong>PLT addresses are not randomized by ASLR</strong>—they're part of the main executable, which typically loads at a fixed address (unless PIE is enabled).
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  This technique involves directing execution to a PLT entry for a useful function. For example, if the program uses puts() somewhere in its legitimate code, there will be a PLT entry for puts(). An attacker can call puts() through its PLT entry to leak memory contents (like libc addresses), then use that information in a second-stage attack. <strong>ret2plt is especially powerful for defeating ASLR:</strong> you can call puts() to print out the GOT (Global Offset Table) entry for a resolved function, which reveals where libc is loaded in memory. With that information, you can calculate the addresses of other libc functions and build a complete ROP chain.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  A typical ret2plt information leak looks like: [pop rdi gadget] [GOT address of puts] [PLT address of puts] [main function address]. This calls puts() to print the address stored in the GOT, which reveals libc's location. The chain then returns to main() to trigger the vulnerability again, but now with knowledge of libc addresses for a full exploit.
                </Typography>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 2 }}>
                  ret2csu (Return-to-csu)
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>ret2csu exploits code in the C runtime startup routines</strong> that's present in nearly every dynamically linked binary. Specifically, it targets a function called __libc_csu_init that contains a convenient gadget sequence for populating multiple registers at once. This code is part of the initialization process that runs before main(), and it contains instruction sequences that move values into RBX, RBP, R12, R13, R14, and R15, then performs function calls with controlled arguments.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  The reason ret2csu is so valuable is that <strong>it provides "universal gadgets"</strong> that exist in nearly every binary, even when other useful gadgets are scarce. The typical ret2csu chain uses two stages: first, a gadget that pops values into the six registers, then a gadget that moves those values into the argument registers (RDI, RSI, RDX) and makes a function call. This gives you fine-grained control over function arguments even in stripped binaries with limited gadget availability.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  ret2csu is particularly useful when you need to call functions with multiple arguments, like mprotect(addr, size, permissions), which requires three arguments and is often used to make memory regions executable so traditional shellcode can run. The technique is complex to set up correctly but extremely powerful once mastered.
                </Typography>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 2 }}>
                  Advanced Variants: JOP, SROP, and Others
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Jump-Oriented Programming (JOP)</strong> is a variant that uses jump instructions instead of return instructions to chain gadgets. Instead of relying on the stack-based control flow of returns, JOP uses indirect jumps (like "jmp rax") where the destination register is attacker-controlled. This can bypass some CFI implementations that specifically target return instructions. JOP is less common because suitable gadgets are harder to find, but it represents the adaptability of code reuse attacks.
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Sigreturn-Oriented Programming (SROP)</strong> exploits the sigreturn system call, which is used to restore program state after a signal handler executes. sigreturn reads a structure from the stack that contains all register values and restores them, essentially giving the attacker complete control over all registers with a single system call. SROP is particularly powerful on systems where gadgets are very limited because a single "syscall; ret" gadget combined with a crafted sigreturn frame can set up any register state you need.
                </Typography>
              </Paper>
            </Box>
          </Box>

          <Box sx={{ mb: 6 }}>
            <Typography id="practical-defense" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
              Practical Defense Implementation
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Step-by-step guide to implementing ROP defenses in your development workflow.
            </Typography>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 2 }}>
                  Compiler and Linker Hardening
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Modern compilers provide numerous security flags that enable critical defenses.</strong> These should be enabled in all production builds and preferably in development builds as well to catch issues early. Here's what each flag does and why it matters:
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircleIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary={<span style={{ color: "#e0e0e0", fontFamily: "monospace" }}>-fstack-protector-strong</span>}
                      secondary={<span style={{ color: "#b0b0b0" }}>Enables stack canaries for functions with vulnerable characteristics (arrays, alloca, address-taken locals). This catches stack-based buffer overflows before they can overwrite return addresses.</span>}
                      sx={{ "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircleIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary={<span style={{ color: "#e0e0e0", fontFamily: "monospace" }}>-D_FORTIFY_SOURCE=2</span>}
                      secondary={<span style={{ color: "#b0b0b0" }}>Enables compile-time and runtime checks for buffer overflows in functions like strcpy, memcpy, sprintf. Replaces dangerous functions with safer versions that check bounds.</span>}
                      sx={{ "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircleIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary={<span style={{ color: "#e0e0e0", fontFamily: "monospace" }}>-fPIE -pie</span>}
                      secondary={<span style={{ color: "#b0b0b0" }}>Generates Position Independent Executable, allowing the main program to be loaded at randomized addresses with ASLR. Without PIE, only libraries are randomized, leaving the main executable at predictable addresses.</span>}
                      sx={{ "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircleIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary={<span style={{ color: "#e0e0e0", fontFamily: "monospace" }}>-Wl,-z,relro,-z,now</span>}
                      secondary={<span style={{ color: "#b0b0b0" }}>RELRO (RELocation Read-Only) makes the GOT read-only after dynamic linking completes, preventing attackers from overwriting function pointers. "now" forces all symbols to resolve at load time.</span>}
                      sx={{ "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircleIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary={<span style={{ color: "#e0e0e0", fontFamily: "monospace" }}>-Wl,-z,noexecstack</span>}
                      secondary={<span style={{ color: "#b0b0b0" }}>Marks the stack as non-executable (DEP/NX), preventing direct code injection. This is often enabled by default but should be explicit in build configs.</span>}
                      sx={{ "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 2 }}>
                  Example Hardened Makefile Configuration
                </Typography>
                <CodeBlock code={`# Compiler flags for maximum security
CC = gcc
CFLAGS = -Wall -Wextra -Werror \\
         -fstack-protector-strong \\
         -D_FORTIFY_SOURCE=2 \\
         -fPIE \\
         -O2

# Linker flags
LDFLAGS = -pie \\
          -Wl,-z,relro,-z,now \\
          -Wl,-z,noexecstack

# Example build
vulnerable_program: main.c utils.c
\t$(CC) $(CFLAGS) $(LDFLAGS) -o vulnerable_program main.c utils.c

# Verify protections are enabled
check-security:
\t@echo "Checking security properties..."
\t@checksec --file=vulnerable_program
\t@echo "Stack canaries: "; readelf -s vulnerable_program | grep stack_chk
\t@echo "PIE enabled: "; readelf -h vulnerable_program | grep "Type:"
\t@echo "RELRO: "; readelf -l vulnerable_program | grep GNU_RELRO`} language="makefile" />
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 2 }}>
                  Runtime Environment Configuration
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Beyond compile-time protections, ensure your runtime environment has security features enabled:
                </Typography>
                <CodeBlock code={`# Linux: Verify ASLR is enabled (should return 2)
cat /proc/sys/kernel/randomize_va_space
# 0 = disabled, 1 = conservative, 2 = full randomization

# Enable ASLR if disabled
sudo sysctl -w kernel.randomize_va_space=2

# Windows: Verify DEP and ASLR via PowerShell
Get-ProcessMitigation -System

# Enable additional protections for specific executables
Set-ProcessMitigation -Name vulnerable_program.exe -Enable DEP,ASLR,BottomUp,HighEntropy

# Check if Intel CET is available (modern CPUs)
grep cet /proc/cpuinfo

# Verify shadow stack support
cat /proc/self/status | grep shadow`} language="bash" />
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 2 }}>
                  Security Testing Integration
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Build security testing into your CI/CD pipeline to catch issues before deployment:</strong>
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon>
                      <SecurityIcon color="info" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Static Analysis"
                      secondary="Run tools like Clang Static Analyzer, Coverity, or SonarQube to detect potential buffer overflows and unsafe function usage during code review."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <SecurityIcon color="info" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Fuzzing"
                      secondary="Use AFL++, libFuzzer, or Honggfuzz to automatically generate test inputs that trigger crashes. Fuzzing is incredibly effective at finding memory corruption bugs."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <SecurityIcon color="info" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Dynamic Analysis"
                      secondary="Run binaries under Valgrind or AddressSanitizer (ASan) to detect memory errors at runtime. ASan catches use-after-free, buffer overflows, and other issues with minimal performance overhead."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <SecurityIcon color="info" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Binary Hardening Verification"
                      secondary="Use checksec.sh or hardening-check to verify all security flags are properly enabled in released binaries. Automate this check in your build pipeline."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 2 }}>
                  CI/CD Pipeline Integration Example
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Integrate security checks directly into your continuous integration pipeline:</strong>
                </Typography>
                <CodeBlock code={`# .github/workflows/security.yml - GitHub Actions example
name: Security Checks

on: [push, pull_request]

jobs:
  security-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install security tools
        run: |
          sudo apt-get update
          sudo apt-get install -y clang clang-tools valgrind checksec
          
      - name: Static analysis with Clang
        run: |
          scan-build --status-bugs make all
          
      - name: Build with AddressSanitizer
        run: |
          make clean
          CFLAGS="-fsanitize=address -g" make all
          
      - name: Run tests under ASan
        run: |
          ASAN_OPTIONS=detect_leaks=1 ./run_tests
          
      - name: Verify binary hardening
        run: |
          checksec --file=./vulnerable_program --output=json > security.json
          # Fail if stack canaries or PIE disabled
          python3 -c "
          import json
          with open('security.json') as f:
              data = json.load(f)
              assert data['canary'] == 'yes', 'Stack canaries not enabled!'
              assert data['pie'] == 'yes', 'PIE not enabled!'
              assert data['nx'] == 'yes', 'NX not enabled!'
              print('All security checks passed!')
          "`} language="yaml" />
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 2 }}>
                  Incident Response Preparation
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Prepare your team to respond effectively if a ROP attack is suspected:</strong>
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon>
                      <WarningIcon color="warning" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Preserve crash dumps immediately"
                      secondary="Configure automatic crash dump collection and ensure they're stored securely for forensic analysis. Include full memory dumps, not just minidumps."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <WarningIcon color="warning" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Capture network traffic"
                      secondary="Enable packet capture on critical services so you can analyze the exploit payload if an attack occurs. Tools like tcpdump or Wireshark in ring-buffer mode work well."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <WarningIcon color="warning" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Document baseline behavior"
                      secondary="Know what normal looks like: typical process trees, network connections, memory usage. Deviations from baseline are your first indicator of compromise."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <WarningIcon color="warning" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Have rollback procedures ready"
                      secondary="Maintain the ability to quickly roll back to known-good configurations and binaries. Test your rollback procedures regularly—don't wait for an incident to discover they don't work."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                </List>
              </Paper>
            </Box>
          </Box>

          <Box sx={{ mb: 6 }}>
            <Typography id="further-learning" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
              Further Learning Resources
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Curated resources to deepen your understanding of ROP and memory safety.
            </Typography>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 2 }}>
                  Foundational Reading
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Understanding the academic and practical foundations of ROP:</strong>
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon>
                      <MenuBookIcon color="info" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="'The Geometry of Innocent Flesh on the Bone' by Hovav Shacham (2007)"
                      secondary="The seminal academic paper that formalized Return-Oriented Programming. Dense but essential reading for understanding ROP's theoretical foundations."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <MenuBookIcon color="info" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="'Hacking: The Art of Exploitation' by Jon Erickson"
                      secondary="Comprehensive book covering memory corruption, buffer overflows, and exploitation techniques. Excellent for understanding the vulnerabilities that enable ROP."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <MenuBookIcon color="info" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="'The Shellcoder's Handbook' by Koziol et al."
                      secondary="Detailed guide covering shell coding, exploit development, and mitigation bypass. Includes ROP-specific chapters and practical examples."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 2 }}>
                  Hands-On Practice Platforms
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Safe environments to practice defensive skills and understanding:</strong>
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon>
                      <TerminalIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="pwn.college"
                      secondary="Free, educational platform with structured challenges covering memory corruption, ROP, and modern mitigations. Designed for learners at all levels."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <TerminalIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="ROP Emporium"
                      secondary="Dedicated ROP training platform with progressive challenges. Excellent for learning gadget chaining without needing to find initial vulnerabilities."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <TerminalIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Exploit Education (Phoenix, Protostar)"
                      secondary="Virtual machines designed for learning exploitation. Progressive difficulty from basic buffer overflows to advanced ROP techniques."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <TerminalIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="CTFtime.org (Capture The Flag competitions)"
                      secondary="Repository of past CTF challenges including 'pwn' categories with ROP problems. Great for practice after mastering fundamentals."
                      sx={{ "& .MuiListItemText-primary": { color: "grey.200", fontWeight: 600 }, "& .MuiListItemText-secondary": { color: "grey.400" } }}
                    />
                  </ListItem>
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 2 }}>
                  Tools for Defenders
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>Essential tools for security analysis and hardening verification:</strong>
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Tool</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Purpose</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Key Use Case</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600, fontFamily: "monospace" }}>checksec</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Binary security analysis</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Verify ASLR, DEP, stack canaries, RELRO enabled</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600, fontFamily: "monospace" }}>pwntools</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>CTF/exploit development framework</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Understanding exploit mechanics for better defense</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600, fontFamily: "monospace" }}>AFL++</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Coverage-guided fuzzing</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Finding memory corruption bugs before attackers</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600, fontFamily: "monospace" }}>AddressSanitizer</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Runtime memory error detection</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Catching buffer overflows during testing</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600, fontFamily: "monospace" }}>Ghidra/IDA</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Reverse engineering</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Analyzing crash dumps and suspicious binaries</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600, fontFamily: "monospace" }}>ROPgadget/ropper</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Gadget discovery</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>Assessing exploitability of your own binaries</TableCell>
                      </TableRow>
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 2 }}>
                  Advanced Topics to Explore
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  <strong>After mastering the fundamentals, explore these advanced areas:</strong>
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: "#0b1020", borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#2563eb", mb: 1 }}>
                        JIT-ROP (Just-In-Time ROP)
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>
                        Advanced technique that reads memory at runtime to discover gadgets dynamically, defeating traditional ASLR. Understanding this helps evaluate the strength of your mitigations.
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: "#0b1020", borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#2563eb", mb: 1 }}>
                        BROP (Blind ROP)
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>
                        Technique for exploiting remote services without access to the binary. Attackers probe the service to discover gadgets through crash oracles. Important for understanding remote threats.
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: "#0b1020", borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#2563eb", mb: 1 }}>
                        SROP (Sigreturn-Oriented Programming)
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>
                        Uses the sigreturn system call to set all registers at once, simplifying ROP chains. Understanding SROP helps you implement appropriate kernel-level defenses.
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: "#0b1020", borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#2563eb", mb: 1 }}>
                        CFI/CET Internals
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>
                        Deep understanding of Control-Flow Integrity and Intel CET's shadow stacks. Essential for evaluating your platform's effectiveness against modern ROP techniques.
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Paper>
            </Box>
          </Box>

          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
            <Divider sx={{ flex: 1 }} />
            <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
              TEST YOUR KNOWLEDGE
            </Typography>
            <Divider sx={{ flex: 1 }} />
          </Box>

          <Typography id="quiz" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
            Knowledge Check
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Take a quick quiz to reinforce the defensive ROP concepts from this page.
          </Typography>

          <Paper
            id="quiz-section"
            sx={{
              mb: 5,
              p: 4,
              borderRadius: 3,
              border: `1px solid ${QUIZ_ACCENT_COLOR}33`,
            }}
          >
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
              Return-Oriented Programming Quiz
            </Typography>
            <QuizSection
              questions={quizQuestions}
              accentColor={QUIZ_ACCENT_COLOR}
              title="Return-Oriented Programming Knowledge Check"
              description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
              questionsPerQuiz={QUIZ_QUESTION_COUNT}
            />
          </Paper>

          <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
            <Button
              variant="outlined"
              size="large"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{
                borderRadius: 2,
                px: 4,
                py: 1.5,
                fontWeight: 600,
                borderColor: alpha(accent, 0.3),
                color: accent,
                "&:hover": {
                  borderColor: accent,
                  bgcolor: alpha(accent, 0.08),
                },
              }}
            >
              Return to Learning Hub
            </Button>
          </Box>
        </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default ReturnOrientedProgrammingPage;
