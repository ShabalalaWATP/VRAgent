import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Container,
  Typography,
  Paper,
  Tabs,
  Tab,
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
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import MemoryIcon from "@mui/icons-material/Memory";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import ShieldIcon from "@mui/icons-material/Shield";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SearchIcon from "@mui/icons-material/Search";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import LockIcon from "@mui/icons-material/Lock";
import TuneIcon from "@mui/icons-material/Tune";
import QuizIcon from "@mui/icons-material/Quiz";
import { Link, useNavigate } from "react-router-dom";

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

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

const ReturnOrientedProgrammingPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

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

  return (
    <LearnPageLayout pageTitle="Return-Oriented Programming (ROP)" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="lg">
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2, mb: 2 }}
        />

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <MemoryIcon sx={{ fontSize: 42, color: "#2563eb" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #2563eb 0%, #38bdf8 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Return-Oriented Programming (ROP)
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          A beginner-friendly deep dive into how ROP works and how to reduce the risk.
        </Typography>

        <Alert severity="warning" sx={{ mb: 3 }}>
          <AlertTitle>Defensive Learning Only</AlertTitle>
          This content focuses on prevention, detection, and safe engineering practices.
        </Alert>

        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            Return-Oriented Programming, or ROP, is a technique that abuses how programs return from functions.
            When a function finishes, it jumps back to a return address stored on the stack. If a memory bug lets
            an attacker overwrite that address, the program can be redirected to run other pieces of code.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            Modern systems often block running new code inside data memory using protections like DEP or NX.
            ROP works around that by reusing code that already exists in the program or its libraries. Think of
            it like cutting a movie into tiny clips and then splicing those clips together to create a new scene.
            Each clip is a small sequence of instructions that ends with a return.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            For beginners, the key idea is simple: ROP is not a separate bug, it is a way to exploit memory bugs.
            If you prevent buffer overflows and other memory corruption issues, you prevent ROP. Mitigations like
            ASLR, stack canaries, and CFI raise the difficulty, but safe coding remains the real fix.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            This page explains the concept, where it shows up in real systems, how to detect warning signs, and
            how to apply practical hardening steps that reduce ROP risk.
          </Typography>
        </Paper>

        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<MemoryIcon />} label="Stack" size="small" />
          <Chip icon={<CodeIcon />} label="Gadgets" size="small" />
          <Chip icon={<SearchIcon />} label="Detection" size="small" />
          <Chip icon={<ShieldIcon />} label="Mitigations" size="small" />
          <Chip icon={<BuildIcon />} label="Hardening" size="small" />
        </Box>

        <Paper sx={{ bgcolor: "#111826", borderRadius: 2 }}>
          <Tabs
            value={tabValue}
            onChange={(_, v) => setTabValue(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              borderBottom: "1px solid rgba(255,255,255,0.08)",
              "& .MuiTab-root": { color: "grey.400" },
              "& .Mui-selected": { color: "#2563eb" },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Overview" />
            <Tab icon={<TuneIcon />} label="Foundations" />
            <Tab icon={<MemoryIcon />} label="Attack Flow" />
            <Tab icon={<SearchIcon />} label="Detection" />
            <Tab icon={<ShieldIcon />} label="Defenses" />
            <Tab icon={<BuildIcon />} label="Safe Lab" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
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
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Memory Basics for ROP
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
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  High-Level Attack Flow (Conceptual)
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
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Detection Signals
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

              <Paper sx={{ p: 2.5, mt: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
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
          </TabPanel>

          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#2563eb", mb: 1 }}>
                  Prevention Checklist
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
          </TabPanel>

          <TabPanel value={tabValue} index={5}>
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
          </TabPanel>
        </Paper>

        <Paper
          id="quiz-section"
          sx={{
            mt: 4,
            p: 4,
            borderRadius: 3,
            border: `1px solid ${QUIZ_ACCENT_COLOR}33`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
            Knowledge Check
          </Typography>
          <QuizSection
            questions={quizQuestions}
            accentColor={QUIZ_ACCENT_COLOR}
            title="Return-Oriented Programming Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
        </Paper>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#2563eb", color: "#2563eb" }}
          >
            Back to Learning Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default ReturnOrientedProgrammingPage;
