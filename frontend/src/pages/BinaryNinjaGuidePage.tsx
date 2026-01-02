import React, { useState } from "react";
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
  Divider,
  alpha,
  useTheme,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import MemoryIcon from "@mui/icons-material/Memory";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import BugReportIcon from "@mui/icons-material/BugReport";
import TerminalIcon from "@mui/icons-material/Terminal";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SearchIcon from "@mui/icons-material/Search";
import SecurityIcon from "@mui/icons-material/Security";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";

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
  language = "python",
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
        bgcolor: "#0b1f1e",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(20, 184, 166, 0.35)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#14b8a6", color: "#041815" }} />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: "#d1fae5" }}>
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
          color: "#d1fae5",
          pt: 2,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

const questionBank: QuizQuestion[] = [
  // Binary Ninja Basics (1-8)
  {
    id: 1,
    question: "What is Binary Ninja primarily used for?",
    options: ["Video editing", "Binary reverse engineering and analysis", "Packet capture", "Web browsing"],
    correctAnswer: 1,
    explanation: "Binary Ninja is a reverse engineering platform used to analyze compiled binaries.",
    topic: "Binary Ninja Basics",
  },
  {
    id: 2,
    question: "In reverse engineering, what is a binary?",
    options: ["A text file with source code", "Compiled machine code executed by the CPU", "A network packet", "A database"],
    correctAnswer: 1,
    explanation: "A binary is compiled machine code that the CPU executes directly.",
    topic: "Binary Ninja Basics",
  },
  {
    id: 3,
    question: "What should you confirm right after importing a file?",
    options: ["Your favorite theme", "Architecture and file format", "Internet connectivity", "Antivirus version"],
    correctAnswer: 1,
    explanation: "Verifying architecture and file format ensures correct disassembly and analysis.",
    topic: "Binary Ninja Basics",
  },
  {
    id: 4,
    question: "Why start practice with a small, known-safe binary?",
    options: ["It looks nicer", "It reduces risk and speeds learning", "It is required by law", "It uses less RAM only"],
    correctAnswer: 1,
    explanation: "Small, safe samples are easier to understand and reduce risk for beginners.",
    topic: "Binary Ninja Basics",
  },
  {
    id: 5,
    question: "What does auto-analysis typically do?",
    options: ["Deletes unknown functions", "Identifies functions, data, and references", "Disables strings view", "Encrypts the binary"],
    correctAnswer: 1,
    explanation: "Auto-analysis detects functions and data references to jump-start your investigation.",
    topic: "Binary Ninja Basics",
  },
  {
    id: 6,
    question: "What is an entry point?",
    options: ["A string value", "The first instruction the loader executes", "A comment in the code", "A debug symbol"],
    correctAnswer: 1,
    explanation: "The entry point is where execution begins when the program starts.",
    topic: "Binary Ninja Basics",
  },
  {
    id: 7,
    question: "Why are projects useful in Binary Ninja?",
    options: ["They compress binaries", "They organize analysis files and metadata", "They patch code automatically", "They disable ASLR"],
    correctAnswer: 1,
    explanation: "Projects help organize analysis databases, notes, and related artifacts.",
    topic: "Binary Ninja Basics",
  },
  {
    id: 8,
    question: "Why rename functions and variables early?",
    options: ["It makes the binary smaller", "It improves readability and understanding", "It increases execution speed", "It removes obfuscation"],
    correctAnswer: 1,
    explanation: "Naming gives meaning to code and makes the HLIL easier to follow.",
    topic: "Binary Ninja Basics",
  },

  // Intermediate Languages (9-16)
  {
    id: 9,
    question: "Which IL is closest to raw assembly?",
    options: ["HLIL", "MLIL", "LLIL", "None of them"],
    correctAnswer: 2,
    explanation: "LLIL is the low-level IL and is closest to assembly semantics.",
    topic: "Intermediate Languages",
  },
  {
    id: 10,
    question: "Which IL is most C-like for reading logic?",
    options: ["HLIL", "LLIL", "MLIL", "SSA only"],
    correctAnswer: 0,
    explanation: "HLIL provides the highest-level, most C-like representation.",
    topic: "Intermediate Languages",
  },
  {
    id: 11,
    question: "Why use MLIL during analysis?",
    options: ["It is only for UI themes", "It clarifies data flow and operations", "It hides function calls", "It disables comments"],
    correctAnswer: 1,
    explanation: "MLIL simplifies operations and helps understand how values move through code.",
    topic: "Intermediate Languages",
  },
  {
    id: 12,
    question: "What does it mean to lift instructions into IL?",
    options: ["Compressing instructions", "Translating machine code into an intermediate representation", "Encrypting the binary", "Removing symbols"],
    correctAnswer: 1,
    explanation: "Lifting converts low-level instructions into a structured IL form.",
    topic: "Intermediate Languages",
  },
  {
    id: 13,
    question: "When HLIL looks confusing, what should you do?",
    options: ["Ignore it", "Switch to MLIL or LLIL for clarity", "Delete the function", "Only read strings"],
    correctAnswer: 1,
    explanation: "Dropping to a lower IL can clarify exact operations and control flow.",
    topic: "Intermediate Languages",
  },
  {
    id: 14,
    question: "What is a key benefit of IL for reverse engineering?",
    options: ["It removes all obfuscation", "It normalizes semantics across compilers", "It patches binaries", "It replaces debugging"],
    correctAnswer: 1,
    explanation: "ILs make compiler-specific output easier to compare and reason about.",
    topic: "Intermediate Languages",
  },
  {
    id: 15,
    question: "Which IL should you use to confirm a tricky arithmetic operation?",
    options: ["HLIL only", "LLIL to verify the exact operations", "Strings view", "Imports view"],
    correctAnswer: 1,
    explanation: "LLIL is closest to the machine instructions and clarifies precise operations.",
    topic: "Intermediate Languages",
  },
  {
    id: 16,
    question: "Why does Binary Ninja provide multiple IL levels?",
    options: ["To reduce file size", "To support different levels of abstraction", "To hide functions", "To disable analysis"],
    correctAnswer: 1,
    explanation: "Multiple IL levels let you shift between high-level intent and low-level detail.",
    topic: "Intermediate Languages",
  },

  // Navigation and Views (17-24)
  {
    id: 17,
    question: "Which view is best for understanding control flow and branches?",
    options: ["Graph view", "Strings view", "Hex view only", "Comments view"],
    correctAnswer: 0,
    explanation: "Graph view visualizes basic blocks and branches clearly.",
    topic: "Navigation and Views",
  },
  {
    id: 18,
    question: "Which view is fastest for scanning a long function top-to-bottom?",
    options: ["Graph view", "Linear view", "Imports view", "Symbols view"],
    correctAnswer: 1,
    explanation: "Linear view shows a continuous listing that is easier to scan quickly.",
    topic: "Navigation and Views",
  },
  {
    id: 19,
    question: "What does the Strings view help you find?",
    options: ["Only integers", "Human-readable strings embedded in the binary", "Network packets", "Source code comments"],
    correctAnswer: 1,
    explanation: "Strings view lists readable strings that often reveal functionality.",
    topic: "Navigation and Views",
  },
  {
    id: 20,
    question: "What does the Imports view reveal?",
    options: ["External libraries and APIs used", "CPU temperature", "File permissions", "Stack size"],
    correctAnswer: 0,
    explanation: "Imports show which external functions the binary relies on.",
    topic: "Navigation and Views",
  },
  {
    id: 21,
    question: "Why use the Symbols or Functions list?",
    options: ["To delete functions", "To jump quickly to named locations", "To encrypt the binary", "To start networking"],
    correctAnswer: 1,
    explanation: "Symbol and function lists provide fast navigation across the program.",
    topic: "Navigation and Views",
  },
  {
    id: 22,
    question: "What does the Go To action help with?",
    options: ["Changing themes", "Jumping to a specific address or symbol", "Running a debugger", "Editing imports"],
    correctAnswer: 1,
    explanation: "Go To lets you jump to an address or symbol immediately.",
    topic: "Navigation and Views",
  },
  {
    id: 23,
    question: "Why add bookmarks or notes?",
    options: ["They make the binary smaller", "They preserve important context for later", "They disable analysis", "They hide functions"],
    correctAnswer: 1,
    explanation: "Notes and bookmarks capture context and speed future sessions.",
    topic: "Navigation and Views",
  },
  {
    id: 24,
    question: "What is a useful first view after import?",
    options: ["Strings and Imports", "Themes panel", "Help menu", "Debugger window"],
    correctAnswer: 0,
    explanation: "Strings and Imports quickly reveal capabilities and likely entry points.",
    topic: "Navigation and Views",
  },

  // Types and Data (25)
  {
    id: 25,
    question: "Why apply types to variables?",
    options: ["To change CPU speed", "To improve decompilation readability", "To disable analysis", "To compress the binary"],
    correctAnswer: 1,
    explanation: "Types clarify intent and improve how HLIL is displayed.",
    topic: "Types and Data",
  },
  {
    id: 26,
    question: "What is a struct?",
    options: ["A loop", "A grouped collection of fields", "A debugger", "A stack frame"],
    correctAnswer: 1,
    explanation: "Structs group related fields to model data structures.",
    topic: "Types and Data",
  },
  {
    id: 27,
    question: "When should you define a struct?",
    options: ["Before understanding fields", "After you identify data layout", "Only after dynamic analysis", "Never"],
    correctAnswer: 1,
    explanation: "Define a struct once you understand the data layout and usage.",
    topic: "Types and Data",
  },
  {
    id: 28,
    question: "What is type propagation?",
    options: ["Deleting variables", "Spreading types through data flow", "Encrypting function names", "Creating comments"],
    correctAnswer: 1,
    explanation: "Type propagation carries known types through operations and references.",
    topic: "Types and Data",
  },
  {
    id: 29,
    question: "What is a pointer?",
    options: ["A loop counter", "An address that refers to data", "A file name", "A CPU core"],
    correctAnswer: 1,
    explanation: "Pointers store addresses to other data or code.",
    topic: "Types and Data",
  },
  {
    id: 30,
    question: "Why define arrays in analysis?",
    options: ["To hide data", "To represent buffers and repeated elements", "To break the decompiler", "To remove strings"],
    correctAnswer: 1,
    explanation: "Arrays model buffers and repeated data structures accurately.",
    topic: "Types and Data",
  },
  {
    id: 31,
    question: "What is a function signature?",
    options: ["A file hash", "Parameter and return type information", "A UI theme", "A debugger setting"],
    correctAnswer: 1,
    explanation: "Signatures describe input parameters and return types for functions.",
    topic: "Types and Data",
  },
  {
    id: 32,
    question: "What happens when types are wrong?",
    options: ["No impact", "HLIL can become misleading", "Imports disappear", "Strings are deleted"],
    correctAnswer: 1,
    explanation: "Incorrect types can distort logic and lead to wrong conclusions.",
    topic: "Types and Data",
  },

  // Cross References (33-39)
  {
    id: 33,
    question: "What is a cross reference (Xref)?",
    options: ["A patch", "A link showing where something is used", "A data type", "A debugger option"],
    correctAnswer: 1,
    explanation: "Xrefs show where symbols, addresses, or data are referenced in code.",
    topic: "Cross References",
  },
  {
    id: 34,
    question: "Why use Xrefs on a string?",
    options: ["To delete it", "To find code that uses it", "To encrypt it", "To change its length"],
    correctAnswer: 1,
    explanation: "String Xrefs reveal the functions that reference or use that string.",
    topic: "Cross References",
  },
  {
    id: 35,
    question: "What do inbound Xrefs typically show?",
    options: ["Functions called by this function", "Functions that call into this function", "Only comments", "Only imports"],
    correctAnswer: 1,
    explanation: "Inbound Xrefs indicate call sites that reference the function.",
    topic: "Cross References",
  },
  {
    id: 36,
    question: "What do outbound Xrefs help you find?",
    options: ["Who calls the function", "What the function calls or references", "Only strings", "Only types"],
    correctAnswer: 1,
    explanation: "Outbound Xrefs show which functions or data this function references.",
    topic: "Cross References",
  },
  {
    id: 37,
    question: "Why are Xrefs useful in config extraction?",
    options: ["They change the config", "They show where config values are used", "They remove encryption", "They hide data"],
    correctAnswer: 1,
    explanation: "Xrefs show how and where config data is used in code.",
    topic: "Cross References",
  },
  {
    id: 38,
    question: "What is a data Xref?",
    options: ["A reference to a data address", "A reference to a function call only", "A network link", "A log entry"],
    correctAnswer: 0,
    explanation: "Data Xrefs refer to static data addresses or constants.",
    topic: "Cross References",
  },
  {
    id: 39,
    question: "A good Xref workflow starts with:",
    options: ["Random functions", "High-signal strings or imports", "Changing themes", "Disabling analysis"],
    correctAnswer: 1,
    explanation: "High-signal strings or imports provide the fastest lead into relevant code.",
    topic: "Cross References",
  },

  // Triage and Strings (40-46)
  {
    id: 40,
    question: "Why is the Strings view useful during triage?",
    options: ["It shows the stack", "It reveals clues like URLs, file paths, and errors", "It patches code", "It runs tests"],
    correctAnswer: 1,
    explanation: "Strings often reveal functions, file paths, URLs, or commands.",
    topic: "Triage and Strings",
  },
  {
    id: 41,
    question: "What does high entropy in a section suggest?",
    options: ["It is plain text", "Packing or encryption", "A debug build", "No code present"],
    correctAnswer: 1,
    explanation: "High entropy often suggests compressed or encrypted data.",
    topic: "Triage and Strings",
  },
  {
    id: 42,
    question: "What can suspicious imports indicate?",
    options: ["UI rendering only", "Networking, crypto, or persistence behavior", "No external usage", "Disk defragmentation"],
    correctAnswer: 1,
    explanation: "Imports like socket, crypto, or registry APIs often indicate behavior areas.",
    topic: "Triage and Strings",
  },
  {
    id: 43,
    question: "What can a mutex name hint at?",
    options: ["CPU speed", "Single-instance behavior or malware family", "Monitor size", "Compiler version"],
    correctAnswer: 1,
    explanation: "Mutex names can indicate single-instance behavior or known families.",
    topic: "Triage and Strings",
  },
  {
    id: 44,
    question: "Which is a good early triage step?",
    options: ["Skip analysis", "Check strings and imports", "Only review UI", "Ignore architecture"],
    correctAnswer: 1,
    explanation: "Strings and imports are fast ways to identify program capabilities.",
    topic: "Triage and Strings",
  },
  {
    id: 45,
    question: "What is an IOC?",
    options: ["An index of comments", "An indicator of compromise like a hash or domain", "A compiler flag", "An OS service"],
    correctAnswer: 1,
    explanation: "IOCs are indicators such as hashes, domains, or file paths used in detection.",
    topic: "Triage and Strings",
  },
  {
    id: 46,
    question: "What is a risk of relying only on strings?",
    options: ["Strings are always correct", "Strings may be encrypted or obfuscated", "Strings show full logic", "Strings replace analysis"],
    correctAnswer: 1,
    explanation: "Many binaries hide or encrypt strings, so you must validate with code.",
    topic: "Triage and Strings",
  },

  // Scripting (47-50)
  {
    id: 47,
    question: "What is the primary scripting language for Binary Ninja?",
    options: ["Ruby", "Python", "C#", "Lua"],
    correctAnswer: 1,
    explanation: "Binary Ninja exposes a Python API for scripting and automation.",
    topic: "Scripting",
  },
  {
    id: 48,
    question: "In Binary Ninja scripts, what does `bv` usually represent?",
    options: ["A debugger", "The current BinaryView", "The build system", "The network stack"],
    correctAnswer: 1,
    explanation: "`bv` is commonly used to refer to the current BinaryView.",
    topic: "Scripting",
  },
  {
    id: 49,
    question: "What is a common use of scripting?",
    options: ["Changing CPU speed", "Automating renames and searches", "Encrypting binaries", "Disabling strings"],
    correctAnswer: 1,
    explanation: "Scripts automate repetitive tasks like renaming and searching.",
    topic: "Scripting",
  },
  {
    id: 50,
    question: "Why use scripts instead of manual steps?",
    options: ["Scripts are always faster in runtime", "Scripts make analysis repeatable and consistent", "Scripts disable analysis", "Scripts add errors"],
    correctAnswer: 1,
    explanation: "Scripts improve repeatability and reduce manual mistakes.",
    topic: "Scripting",
  },
  {
    id: 51,
    question: "What does `bv.functions` provide?",
    options: ["A list of functions detected in the binary", "Only strings", "Only imports", "Only memory blocks"],
    correctAnswer: 0,
    explanation: "`bv.functions` returns the list of detected functions.",
    topic: "Scripting",
  },
  {
    id: 52,
    question: "What does `bv.strings` provide?",
    options: ["Network connections", "A list of strings in the binary", "Thread IDs", "Compiled source code"],
    correctAnswer: 1,
    explanation: "`bv.strings` yields the strings found during analysis.",
    topic: "Scripting",
  },
  {
    id: 53,
    question: "What should you do before running a large script?",
    options: ["Disable analysis", "Make sure the binary and analysis are loaded", "Delete the project", "Turn off UI"],
    correctAnswer: 1,
    explanation: "Ensure analysis is loaded so the script has consistent data to work with.",
    topic: "Scripting",
  },

  // Workflow (54-60)
  {
    id: 54,
    question: "Why iterate between static and dynamic analysis?",
    options: ["To avoid learning", "To confirm behavior and reveal hidden data", "To delete code", "To change file format"],
    correctAnswer: 1,
    explanation: "Static analysis gives structure, while dynamic analysis confirms runtime behavior.",
    topic: "Workflow",
  },
  {
    id: 55,
    question: "After finding the entry point, what is a good next step?",
    options: ["Exit the tool", "Identify key subsystems like network or crypto", "Disable strings", "Remove symbols"],
    correctAnswer: 1,
    explanation: "Tagging major subsystems helps map program behavior.",
    topic: "Workflow",
  },
  {
    id: 56,
    question: "Why add notes during analysis?",
    options: ["To slow down analysis", "To preserve context and findings", "To hide evidence", "To reset HLIL"],
    correctAnswer: 1,
    explanation: "Notes capture context so you can resume or share results later.",
    topic: "Workflow",
  },
  {
    id: 57,
    question: "What does it mean to scope analysis?",
    options: ["Analyze everything at once", "Focus on a single feature or subsystem first", "Disable scripts", "Skip documentation"],
    correctAnswer: 1,
    explanation: "Scoping helps you make steady progress without getting overwhelmed.",
    topic: "Workflow",
  },
  {
    id: 58,
    question: "When should you switch to MLIL or LLIL?",
    options: ["When HLIL is unclear or misleading", "Only after finishing the report", "Never", "When strings are missing"],
    correctAnswer: 0,
    explanation: "Lower IL levels provide clarity when HLIL hides details.",
    topic: "Workflow",
  },
  {
    id: 59,
    question: "What is a good beginner goal for a session?",
    options: ["Reverse the entire binary", "Understand one feature or behavior end-to-end", "Ignore the entry point", "Skip notes"],
    correctAnswer: 1,
    explanation: "Small, focused goals build confidence and momentum.",
    topic: "Workflow",
  },
  {
    id: 60,
    question: "Why label functions early in the workflow?",
    options: ["To hide data", "To make later passes faster and clearer", "To change architecture", "To disable analysis"],
    correctAnswer: 1,
    explanation: "Even rough labels reduce confusion and speed later analysis.",
    topic: "Workflow",
  },

  // Analysis Tips (61-67)
  {
    id: 61,
    question: "Which is a common pitfall for beginners?",
    options: ["Renaming functions", "Not renaming or typing anything", "Checking imports", "Taking notes"],
    correctAnswer: 1,
    explanation: "Skipping renames and types makes the analysis much harder.",
    topic: "Analysis Tips",
  },
  {
    id: 62,
    question: "Why check imports early?",
    options: ["They show compile flags", "They hint at capabilities like networking or crypto", "They are always safe", "They show UI colors"],
    correctAnswer: 1,
    explanation: "Imports reveal the external APIs the binary relies on.",
    topic: "Analysis Tips",
  },
  {
    id: 63,
    question: "Why validate with Xrefs?",
    options: ["To delete code", "To confirm how data is actually used", "To skip analysis", "To speed up execution"],
    correctAnswer: 1,
    explanation: "Xrefs confirm whether a string or function is truly used.",
    topic: "Analysis Tips",
  },
  {
    id: 64,
    question: "Why confirm endianness and architecture?",
    options: ["It changes UI colors", "Wrong settings lead to incorrect disassembly", "It is optional for all binaries", "It only affects strings"],
    correctAnswer: 1,
    explanation: "Incorrect architecture settings can make disassembly meaningless.",
    topic: "Analysis Tips",
  },
  {
    id: 65,
    question: "Why keep a notes template?",
    options: ["To waste time", "To capture consistent evidence and decisions", "To remove symbols", "To break the decompiler"],
    correctAnswer: 1,
    explanation: "A consistent template helps you document findings and decisions.",
    topic: "Analysis Tips",
  },
  {
    id: 66,
    question: "What is a false positive in analysis?",
    options: ["A confirmed bug", "A misinterpreted behavior that looks real", "A correct function name", "A valid hash"],
    correctAnswer: 1,
    explanation: "A false positive is a mistaken conclusion based on weak evidence.",
    topic: "Analysis Tips",
  },
  {
    id: 67,
    question: "Which is a safe practice for beginners?",
    options: ["Analyze unknown malware on host", "Use known-safe samples in a VM", "Disable snapshots", "Skip documentation"],
    correctAnswer: 1,
    explanation: "Working in a VM with safe samples reduces risk and keeps your host clean.",
    topic: "Analysis Tips",
  },

  // Reporting and Sharing (68-75)
  {
    id: 68,
    question: "What should a basic reverse engineering report include?",
    options: ["Only screenshots", "Summary, key findings, and IOCs", "No evidence", "Only raw disassembly"],
    correctAnswer: 1,
    explanation: "Reports should summarize behavior and include supporting evidence and IOCs.",
    topic: "Reporting and Sharing",
  },
  {
    id: 69,
    question: "Why include file hashes in your report?",
    options: ["They speed up execution", "They uniquely identify the sample", "They remove symbols", "They change architecture"],
    correctAnswer: 1,
    explanation: "Hashes help uniquely identify the exact sample analyzed.",
    topic: "Reporting and Sharing",
  },
  {
    id: 70,
    question: "Why record addresses or offsets?",
    options: ["For reproducibility and verification", "To increase file size", "To change execution speed", "To delete data"],
    correctAnswer: 0,
    explanation: "Addresses allow others to verify findings in the same binary.",
    topic: "Reporting and Sharing",
  },
  {
    id: 71,
    question: "What is a good naming convention for functions?",
    options: ["Random names", "Descriptive names based on behavior", "Only numbers", "Leave all as sub_"],
    correctAnswer: 1,
    explanation: "Descriptive names make your analysis and reports much clearer.",
    topic: "Reporting and Sharing",
  },
  {
    id: 72,
    question: "Why export notes or analysis data?",
    options: ["To forget findings", "To share results with teammates", "To disable analysis", "To modify the binary"],
    correctAnswer: 1,
    explanation: "Exports help collaborators review and build on your work.",
    topic: "Reporting and Sharing",
  },
  {
    id: 73,
    question: "What is a call graph useful for?",
    options: ["Measuring CPU speed", "Understanding high-level function relationships", "Encrypting data", "Changing file format"],
    correctAnswer: 1,
    explanation: "Call graphs show how functions interact and reveal program structure.",
    topic: "Reporting and Sharing",
  },
  {
    id: 74,
    question: "Why document assumptions?",
    options: ["To hide mistakes", "So reviewers can validate or challenge them", "To remove evidence", "To skip testing"],
    correctAnswer: 1,
    explanation: "Clear assumptions help others verify and refine your conclusions.",
    topic: "Reporting and Sharing",
  },
  {
    id: 75,
    question: "What is a strong next step after static analysis?",
    options: ["Delete the project", "Plan a focused dynamic test to confirm behavior", "Ignore findings", "Only change themes"],
    correctAnswer: 1,
    explanation: "Dynamic checks validate findings and reveal runtime-only behavior.",
    topic: "Reporting and Sharing",
  },
];

function QuizSection() {
  const theme = useTheme();
  const [quizStarted, setQuizStarted] = useState(false);
  const [currentQuestions, setCurrentQuestions] = useState<QuizQuestion[]>([]);
  const [userAnswers, setUserAnswers] = useState<{ [key: number]: number }>({});
  const [showResults, setShowResults] = useState(false);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);

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
    if (score === 10) return "Perfect. Strong command of Binary Ninja essentials.";
    if (score >= 8) return "Excellent work. You have solid Binary Ninja fundamentals.";
    if (score >= 6) return "Good progress. Review a few sections and try again.";
    if (score >= 4) return "Keep going. Revisit the IL and workflow sections.";
    return "Start with the basics section and try again.";
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
          border: `2px solid ${alpha("#14b8a6", 0.3)}`,
          background: `linear-gradient(135deg, ${alpha("#14b8a6", 0.06)} 0%, ${alpha("#22d3ee", 0.06)} 100%)`,
        }}
      >
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              background: "linear-gradient(135deg, #14b8a6, #22d3ee)",
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
          Ready to test what you learned? Take this <strong>10-question quiz</strong> covering Binary Ninja essentials.
          Questions are randomly selected from a pool of <strong>75 questions</strong>, so each attempt is different.
        </Typography>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#14b8a6", 0.12), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#14b8a6" }}>10</Typography>
              <Typography variant="caption" color="text.secondary">Questions</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#22c55e", 0.12), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#22c55e" }}>75</Typography>
              <Typography variant="caption" color="text.secondary">Question Pool</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#0ea5e9", 0.12), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#0ea5e9" }}>10</Typography>
              <Typography variant="caption" color="text.secondary">Topics Covered</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#f97316", 0.12), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#f97316" }}>Unlimited</Typography>
              <Typography variant="caption" color="text.secondary">Retakes</Typography>
            </Paper>
          </Grid>
        </Grid>

        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          startIcon={<QuizIcon />}
          sx={{
            background: "linear-gradient(135deg, #14b8a6, #22d3ee)",
            fontWeight: 700,
            px: 4,
            py: 1.5,
            fontSize: "1.1rem",
            "&:hover": {
              background: "linear-gradient(135deg, #0f766e, #0891b2)",
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
              background: "linear-gradient(135deg, #14b8a6, #22d3ee)",
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
        border: `2px solid ${alpha("#14b8a6", 0.3)}`,
      }}
    >
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
            Question {currentQuestionIndex + 1} of 10
          </Typography>
          <Chip
            label={currentQuestion.topic}
            size="small"
            sx={{ bgcolor: alpha("#0ea5e9", 0.15), color: "#0ea5e9", fontWeight: 600 }}
          />
        </Box>
        <Box sx={{ width: "100%", bgcolor: alpha("#14b8a6", 0.1), borderRadius: 1, height: 8 }}>
          <Box
            sx={{
              width: `${((currentQuestionIndex + 1) / 10) * 100}%`,
              bgcolor: "#14b8a6",
              borderRadius: 1,
              height: "100%",
              transition: "width 0.3s ease",
            }}
          />
        </Box>
      </Box>

      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3, lineHeight: 1.6 }}>
        {currentQuestion.question}
      </Typography>

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
                  bgcolor: isSelected ? alpha("#14b8a6", 0.15) : alpha(theme.palette.background.paper, 0.5),
                  border: `2px solid ${isSelected ? "#14b8a6" : alpha(theme.palette.divider, 0.2)}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    borderColor: "#14b8a6",
                    bgcolor: alpha("#14b8a6", 0.08),
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box
                    sx={{
                      width: 32,
                      height: 32,
                      borderRadius: "50%",
                      bgcolor: isSelected ? "#14b8a6" : alpha(theme.palette.divider, 0.3),
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
              background: "linear-gradient(135deg, #14b8a6, #22d3ee)",
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
                    ? "#14b8a6"
                    : isAnswered
                    ? alpha("#22c55e", 0.2)
                    : alpha(theme.palette.divider, 0.1),
                  color: isCurrent ? "white" : isAnswered ? "#22c55e" : "text.secondary",
                  border: `1px solid ${isCurrent ? "#14b8a6" : isAnswered ? "#22c55e" : "transparent"}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    bgcolor: isCurrent ? "#14b8a6" : alpha("#14b8a6", 0.2),
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

const BinaryNinjaGuidePage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const keyIdeas = [
    "Binary Ninja centers analysis around multiple intermediate languages (LLIL, MLIL, HLIL).",
    "Typed variables and data types greatly improve decompilation and readability.",
    "Scripting with the built-in Python API helps automate repetitive analysis tasks.",
    "Graph and linear views let you switch between structure and flow quickly.",
    "A few high-signal views (Strings, Imports, HLIL) cover most beginner use cases.",
    "Small naming and typing improvements compound into much clearer decompilation.",
  ];

  const coreWorkflow = [
    "Create a new project and import the binary.",
    "Let analysis run, then confirm file type and architecture.",
    "Start with strings and imports to map capabilities.",
    "Find main or entry, then label key functions.",
    "Apply types and rename variables to clean up HLIL.",
    "Use cross references to follow data and call chains.",
    "Write a small script to extract patterns or rename helpers.",
    "Document findings and export notes as you go.",
  ];

  const gettingStarted = [
    "Open Binary Ninja and create a new project folder for your analysis.",
    "Drag in a small, known-safe binary (crackme or sample app).",
    "Let auto-analysis finish, then verify architecture and platform.",
    "Open the Strings and Imports views to identify likely functionality.",
    "Jump to main/entry, then rename 3-5 functions you understand.",
    "Switch between HLIL and MLIL when logic looks unclear.",
    "Add notes as you learn; the goal is clarity, not speed.",
  ];

  const bnStrengths = [
    { title: "IL-Centric Analysis", desc: "LLIL, MLIL, and HLIL reduce compiler noise and make intent easier to see." },
    { title: "Modern UI", desc: "Fast navigation with graph and linear views, plus side-by-side panes." },
    { title: "Scripting First", desc: "Python API makes it easy to automate function tagging and searches." },
    { title: "Type Recovery", desc: "Type propagation improves readability of decompiled output." },
    { title: "Binary Views", desc: "Multiple synchronized views make it easier to confirm findings." },
  ];

  const useCaseTable = [
    { goal: "Malware triage", focus: "Strings, imports, entry flow", view: "Linear + Strings view" },
    { goal: "Vuln research", focus: "HLIL control flow and types", view: "HLIL + Type views" },
    { goal: "Protocol RE", focus: "Parsing functions and structs", view: "MLIL + Structure view" },
    { goal: "Patch review", focus: "Diff behavior across versions", view: "Function graph + notes" },
  ];

  const ilLevels = [
    { level: "LLIL", purpose: "Low-level, close to assembly with simplified semantics." },
    { level: "MLIL", purpose: "Medium-level, lifted operations with better control flow." },
    { level: "HLIL", purpose: "High-level, C-like representation with types and variables." },
  ];

  const navigationShortcuts = [
    { key: "G", action: "Go to address or symbol" },
    { key: "N", action: "Rename symbol" },
    { key: "X", action: "Show cross references" },
    { key: "Tab", action: "Toggle graph or linear view" },
    { key: "Shift+F", action: "Find strings" },
    { key: "U", action: "Undefine/clear analysis at selection" },
  ];

  const triageSignals = [
    { signal: "High entropy sections", meaning: "Packing or encryption", action: "Look for unpacking stubs" },
    { signal: "Suspicious imports", meaning: "Networking, crypto, persistence", action: "Tag related functions" },
    { signal: "Config strings", meaning: "C2, file paths, mutexes", action: "Trace references in XRefs" },
    { signal: "Large switch tables", meaning: "Protocol or command handler", action: "Map case values" },
  ];

  const scriptingTasks = [
    "Rename common library wrappers automatically.",
    "Find string references for suspicious keywords.",
    "Extract call graphs for specific subsystems.",
    "Export function lists with hashes and sizes.",
    "Identify functions with high cyclomatic complexity.",
  ];

  const pitfalls = [
    "Trusting HLIL before applying types or renaming variables.",
    "Ignoring data flow and focusing only on control flow.",
    "Not using cross references to confirm string usage.",
    "Skipping notes and losing context across sessions.",
    "Trying to reverse everything at once instead of scoping focus.",
  ];

  const practicePath = [
    "Reverse a small crackme without packing.",
    "Identify main, then locate the password check in HLIL.",
    "Rename key functions and add types until HLIL reads cleanly.",
    "Write a script to list all string references to the check.",
    "Document the logic and verify with a test input.",
  ];

  const pythonExample = `# Binary Ninja Python example
# List functions and rename simple wrappers
for func in bv.functions:
    if func.name.startswith("sub_") and func.high_level_il:
        if "memcpy" in str(func.high_level_il):
            func.name = "wrap_memcpy"

# Find strings containing "http"
for s in bv.strings:
    if "http" in s.value:
        print(hex(s.start), s.value)
        for xref in bv.get_code_refs(s.start):
            print("  xref:", xref.function.name, hex(xref.address))`;

  const analysisChecklist = [
    "Confirm architecture, endianness, and entry point.",
    "Review imports and exports for suspicious APIs.",
    "Tag crypto, network, and persistence functions.",
    "Apply types and rename variables to stabilize HLIL.",
    "Trace config extraction to locate runtime data.",
    "Record open questions to revisit after dynamic analysis.",
  ];

  const pageContext = `Binary Ninja Essentials guide covering installation and project setup, navigation and views, LLIL/MLIL/HLIL concepts, typing and renaming, cross references, scripting with the Python API, and practical workflows for malware analysis and vulnerability research.`;

  return (
    <LearnPageLayout pageTitle="Binary Ninja Essentials" pageContext={pageContext}>
      <Box sx={{ minHeight: "100vh", bgcolor: "#080d12", py: 4 }}>
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
            <MemoryIcon sx={{ fontSize: 42, color: "#14b8a6" }} />
            <Typography
              variant="h3"
              sx={{
                fontWeight: 700,
                background: "linear-gradient(135deg, #14b8a6 0%, #22d3ee 100%)",
                backgroundClip: "text",
                WebkitBackgroundClip: "text",
                color: "transparent",
              }}
            >
              Binary Ninja Essentials
            </Typography>
          </Box>
          <Typography variant="h6" sx={{ color: "grey.400", mb: 3 }}>
            Modern IL-first reverse engineering with powerful analysis, scripting, and visualization
          </Typography>

          {/* Comprehensive Introduction Section */}
          <Paper sx={{ p: 4, mb: 4, bgcolor: "#0f1422", borderRadius: 3, border: "1px solid rgba(20, 184, 166, 0.2)" }}>
            <Typography variant="h5" sx={{ color: "#14b8a6", mb: 2, fontWeight: 700 }}>
              🔬 What is Binary Ninja?
            </Typography>
            
            <Typography variant="body1" sx={{ color: "grey.200", mb: 2, fontSize: "1.1rem", lineHeight: 1.8 }}>
              <strong>Binary Ninja</strong> is a modern reverse engineering platform developed by Vector 35. Think of it as a 
              sophisticated translator that helps you understand what compiled programs actually do. When software developers 
              write code in languages like C, C++, or Rust, that code gets compiled into machine instructions — raw binary 
              data that computers can execute but humans cannot easily read. Binary Ninja takes those cryptic machine 
              instructions and transforms them into progressively more human-readable forms, allowing you to analyze, 
              understand, and document what a program does without ever seeing its original source code.
            </Typography>

            <Typography variant="body1" sx={{ color: "grey.200", mb: 2, fontSize: "1.1rem", lineHeight: 1.8 }}>
              <strong>Why would you need this?</strong> Reverse engineering is essential in many fields: security researchers 
              analyze malware to understand threats and develop defenses; vulnerability researchers examine software for 
              security flaws; game modders understand game mechanics; compatibility engineers figure out how to make 
              different systems work together; and developers maintain legacy software where source code has been lost. 
              Whether you're defending against cyber threats, hunting for bugs in bug bounty programs, or just curious 
              about how your favorite software works, reverse engineering gives you the ability to peek under the hood.
            </Typography>

            <Typography variant="body1" sx={{ color: "grey.200", mb: 2, fontSize: "1.1rem", lineHeight: 1.8 }}>
              <strong>What makes Binary Ninja different?</strong> Unlike older tools that show you raw assembly code and 
              expect you to figure everything out yourself, Binary Ninja was built from the ground up around the concept 
              of <em>intermediate languages (ILs)</em>. When you load a program, Binary Ninja doesn't just show you assembly — 
              it automatically lifts that assembly through three progressively cleaner representations: Low Level IL (LLIL), 
              Medium Level IL (MLIL), and High Level IL (HLIL). Each level removes more complexity and noise, so by the 
              time you reach HLIL, you're looking at something that resembles C code. This layered approach means you can 
              work at whatever level of abstraction makes sense for your task.
            </Typography>

            <Typography variant="body1" sx={{ color: "grey.200", mb: 2, fontSize: "1.1rem", lineHeight: 1.8 }}>
              <strong>Is this tool for beginners?</strong> Absolutely! While reverse engineering has a reputation for being 
              difficult (and it does require patience and practice), Binary Ninja's modern interface and IL system make it 
              more approachable than ever. You don't need to memorize every x86 instruction or understand every calling 
              convention before you can start. The tool handles much of that complexity for you. You can start by loading 
              simple programs, examining strings and function names, and gradually work your way up to more complex analysis. 
              The key is to start with small, known programs where you can verify your understanding.
            </Typography>

            <Divider sx={{ my: 3, borderColor: "rgba(20, 184, 166, 0.2)" }} />

            <Typography variant="h6" sx={{ color: "#22d3ee", mb: 2, fontWeight: 600 }}>
              📊 Understanding the Three IL Levels
            </Typography>

            <Typography variant="body1" sx={{ color: "grey.300", mb: 2, lineHeight: 1.7 }}>
              Binary Ninja's signature feature is its multi-level intermediate language system. Here's what each level means 
              and when to use it:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: "rgba(20, 184, 166, 0.1)", borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ color: "#14b8a6", fontWeight: 700, mb: 1 }}>
                    LLIL (Low Level IL)
                  </Typography>
                  <Typography variant="body2" sx={{ color: "grey.300" }}>
                    Very close to assembly but with simplified semantics. Useful when you need to understand exactly what 
                    the CPU is doing, like analyzing anti-tampering code or obfuscated instructions.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: "rgba(34, 211, 238, 0.1)", borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ color: "#22d3ee", fontWeight: 700, mb: 1 }}>
                    MLIL (Medium Level IL)
                  </Typography>
                  <Typography variant="body2" sx={{ color: "grey.300" }}>
                    Lifts operations into cleaner expressions with better control flow. Great for understanding function 
                    logic without assembly-level noise. Often the sweet spot for detailed analysis.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: "rgba(168, 85, 247, 0.1)", borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ color: "#a855f7", fontWeight: 700, mb: 1 }}>
                    HLIL (High Level IL)
                  </Typography>
                  <Typography variant="body2" sx={{ color: "grey.300" }}>
                    C-like pseudocode with variables, types, and control structures. Best for getting a quick overview 
                    of what a function does. Start here, then dive deeper if needed.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Alert severity="success" sx={{ bgcolor: "rgba(34, 197, 94, 0.1)", mb: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Pro Tip for Beginners</AlertTitle>
              Start with HLIL to understand what a function is trying to accomplish, then switch to MLIL or LLIL 
              when something doesn't make sense. The ability to seamlessly move between abstraction levels is 
              Binary Ninja's superpower.
            </Alert>

            <Typography variant="h6" sx={{ color: "#22d3ee", mb: 2, fontWeight: 600 }}>
              🎯 Common Use Cases
            </Typography>

            <Grid container spacing={2} sx={{ mb: 2 }}>
              {[
                { title: "Malware Analysis", desc: "Understand how viruses, trojans, and ransomware work to develop defenses", icon: <BugReportIcon />, color: "#ef4444" },
                { title: "Vulnerability Research", desc: "Find security bugs in closed-source software for bug bounties or security audits", icon: <SecurityIcon />, color: "#f59e0b" },
                { title: "CTF Competitions", desc: "Solve reverse engineering challenges in Capture The Flag competitions", icon: <EmojiEventsIcon />, color: "#22c55e" },
                { title: "Software Analysis", desc: "Understand how programs work, analyze protocols, or study compiler output", icon: <CodeIcon />, color: "#3b82f6" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Paper sx={{ p: 2, bgcolor: alpha(item.color, 0.1), borderRadius: 2, border: `1px solid ${alpha(item.color, 0.2)}` }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box sx={{ color: item.color }}>{item.icon}</Box>
                      <Typography variant="subtitle2" sx={{ color: item.color, fontWeight: 700 }}>{item.title}</Typography>
                    </Box>
                    <Typography variant="body2" sx={{ color: "grey.300" }}>{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          <Alert severity="info" sx={{ mb: 3 }}>
            <AlertTitle>About This Guide</AlertTitle>
            This guide focuses on practical, repeatable workflows in Binary Ninja. You'll learn navigation, IL analysis, 
            typing, and small scripts that automate common tasks — everything you need to start analyzing binaries confidently.
          </Alert>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#22d3ee", mb: 1 }}>
              Getting Started (10 Minutes)
            </Typography>
            <List dense>
              {gettingStarted.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <CheckCircleIcon color="success" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
            <Chip icon={<CodeIcon />} label="HLIL/MLIL/LLIL" size="small" />
            <Chip icon={<TerminalIcon />} label="Python API" size="small" />
            <Chip icon={<SearchIcon />} label="XRefs" size="small" />
            <Chip icon={<BuildIcon />} label="Type Recovery" size="small" />
          </Box>

          <Paper sx={{ bgcolor: "#111827", borderRadius: 2 }}>
            <Tabs
              value={tabValue}
              onChange={handleTabChange}
              variant="scrollable"
              scrollButtons="auto"
              sx={{
                borderBottom: "1px solid rgba(255,255,255,0.1)",
                "& .MuiTab-root": { color: "grey.400" },
                "& .Mui-selected": { color: "#14b8a6" },
              }}
            >
              <Tab icon={<MemoryIcon />} label="Overview" />
              <Tab icon={<BuildIcon />} label="Workflow" />
              <Tab icon={<CodeIcon />} label="IL & Views" />
              <Tab icon={<TerminalIcon />} label="Scripting" />
              <Tab icon={<BugReportIcon />} label="Tips & Practice" />
            </Tabs>

            <TabPanel value={tabValue} index={0}>
              <Box sx={{ p: 3 }}>
                <Typography variant="h5" sx={{ color: "#14b8a6", mb: 2 }}>
                  Why Binary Ninja
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  Binary Ninja is built for clarity: it lifts machine code into structured intermediate languages and
                  keeps your analysis organized with consistent naming, types, and notes. For beginners, this means
                  you can start by scanning strings and imports, then gradually move into HLIL and data flow as you
                  build confidence. The tool rewards small, steady improvements, not one-time leaps.
                </Typography>
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  {bnStrengths.map((item) => (
                    <Grid item xs={12} md={6} key={item.title}>
                      <Paper sx={{ p: 2.5, bgcolor: "#0f172a", borderRadius: 2 }}>
                        <Typography variant="h6" sx={{ color: "#22d3ee", mb: 1 }}>
                          {item.title}
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>
                          {item.desc}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>

                <Typography variant="h6" sx={{ color: "#22d3ee", mb: 1 }}>
                  Use Cases
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  Most analysis sessions start with questions like: "Where does it connect?" or "How does it parse
                  input?" Use the table below to pick the most helpful view first, then pivot to IL layers for deeper
                  reasoning.
                </Typography>
                <TableContainer sx={{ mb: 2 }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#22d3ee" }}>Goal</TableCell>
                        <TableCell sx={{ color: "#22d3ee" }}>Focus</TableCell>
                        <TableCell sx={{ color: "#22d3ee" }}>Best View</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {useCaseTable.map((row) => (
                        <TableRow key={row.goal}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{row.goal}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{row.focus}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{row.view}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>

                <Typography variant="h6" sx={{ color: "#14b8a6", mb: 1 }}>
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
              </Box>
            </TabPanel>

            <TabPanel value={tabValue} index={1}>
              <Box sx={{ p: 3 }}>
                <Typography variant="h5" sx={{ color: "#14b8a6", mb: 2 }}>
                  Core Workflow
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  Treat the workflow as a loop. Each pass gives you more context: you label a function, the HLIL
                  improves, and new relationships become obvious. When you are stuck, go back to strings, imports,
                  or MLIL for a more literal view.
                </Typography>
                <List>
                  {coreWorkflow.map((step, idx) => (
                    <ListItem key={step}>
                      <ListItemIcon>
                        <Chip label={idx + 1} size="small" sx={{ bgcolor: "#14b8a6", color: "#041815" }} />
                      </ListItemIcon>
                      <ListItemText primary={step} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>

                <Typography variant="h6" sx={{ color: "#22d3ee", mt: 2, mb: 1 }}>
                  Triage Signals
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#22d3ee" }}>Signal</TableCell>
                        <TableCell sx={{ color: "#22d3ee" }}>Meaning</TableCell>
                        <TableCell sx={{ color: "#22d3ee" }}>Action</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {triageSignals.map((row) => (
                        <TableRow key={row.signal}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{row.signal}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{row.meaning}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{row.action}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>

                <Alert severity="info" sx={{ mt: 2 }}>
                  Tag functions early. Even rough names make HLIL easier to reason about during deep dives.
                </Alert>
              </Box>
            </TabPanel>

            <TabPanel value={tabValue} index={2}>
              <Box sx={{ p: 3 }}>
                <Typography variant="h5" sx={{ color: "#14b8a6", mb: 2 }}>
                  IL Levels and Views
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  Think of IL layers like zoom levels. HLIL reads like structured code and is great for logic, MLIL
                  clarifies how values move, and LLIL shows the closest translation from assembly. Switching layers
                  lets you confirm assumptions without losing context.
                </Typography>
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  {ilLevels.map((item) => (
                    <Grid item xs={12} md={4} key={item.level}>
                      <Paper sx={{ p: 2.5, bgcolor: "#0f172a", borderRadius: 2 }}>
                        <Typography variant="h6" sx={{ color: "#22d3ee", mb: 1 }}>
                          {item.level}
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>
                          {item.purpose}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>

                <Accordion sx={{ bgcolor: "#0f172a", borderRadius: 2, mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle1">Graph vs Linear Views</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      <ListItem>
                        <ListItemIcon>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText
                          primary="Graph view is best for control flow and branching."
                          sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }}
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText
                          primary="Linear view is faster for scanning long sequences and data access."
                          sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }}
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText
                          primary="Switch between HLIL and MLIL when data flow is unclear."
                          sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }}
                        />
                      </ListItem>
                    </List>
                  </AccordionDetails>
                </Accordion>

                <Typography variant="h6" sx={{ color: "#22d3ee", mt: 2, mb: 1 }}>
                  Navigation Shortcuts
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  Learn a small set of shortcuts and reuse them. Fast navigation reduces fatigue and helps you stay
                  focused on logic instead of UI hunting.
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#22d3ee" }}>Key</TableCell>
                        <TableCell sx={{ color: "#22d3ee" }}>Action</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {navigationShortcuts.map((row) => (
                        <TableRow key={row.key}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{row.key}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{row.action}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Box>
            </TabPanel>

            <TabPanel value={tabValue} index={3}>
              <Box sx={{ p: 3 }}>
                <Typography variant="h5" sx={{ color: "#14b8a6", mb: 2 }}>
                  Scripting Basics
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300" }}>
                  The Binary Ninja API is designed for quick automation. Start with small scripts that rename
                  wrappers or export metadata, then build more focused analysis helpers.
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mt: 1 }}>
                  You can run scripts in the Python console or as saved plugins. Scripts are useful for making
                  consistent naming decisions and turning repeated manual steps into a single command.
                </Typography>
                <CodeBlock code={pythonExample} language="python" />

                <Typography variant="h6" sx={{ color: "#22d3ee", mt: 2, mb: 1 }}>
                  Script Ideas
                </Typography>
                <List dense>
                  {scriptingTasks.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>

                <Alert severity="info" sx={{ mt: 2 }}>
                  Keep scripts small and specific. Store outputs in notes or exports for easy sharing.
                </Alert>
              </Box>
            </TabPanel>

            <TabPanel value={tabValue} index={4}>
              <Box sx={{ p: 3 }}>
                <Typography variant="h5" sx={{ color: "#14b8a6", mb: 2 }}>
                  Tips and Practice
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                  Beginners progress fastest when they work on small binaries and focus on just one subsystem at a
                  time. Use the checklist and practice path below to build confidence before tackling packed or
                  heavily optimized targets.
                </Typography>
                <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f172a", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ color: "#22d3ee", mb: 1 }}>
                    Analysis Checklist
                  </Typography>
                  <List dense>
                    {analysisChecklist.map((item) => (
                      <ListItem key={item}>
                        <ListItemIcon>
                          <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>

                <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f172a", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ color: "#22d3ee", mb: 1 }}>
                    Common Pitfalls
                  </Typography>
                  <List dense>
                    {pitfalls.map((item) => (
                      <ListItem key={item}>
                        <ListItemIcon>
                          <BugReportIcon color="warning" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>

                <Paper sx={{ p: 2.5, bgcolor: "#0f172a", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ color: "#22d3ee", mb: 1 }}>
                    Practice Path
                  </Typography>
                  <List dense>
                    {practicePath.map((item) => (
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
          </Paper>

          <QuizSection />

          <Box sx={{ mt: 4, textAlign: "center" }}>
            <Button
              variant="outlined"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ borderColor: "#14b8a6", color: "#14b8a6" }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Container>
      </Box>
    </LearnPageLayout>
  );
};

export default BinaryNinjaGuidePage;
