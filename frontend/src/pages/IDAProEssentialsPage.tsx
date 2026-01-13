import React, { useEffect, useMemo, useRef, useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
  Typography,
  Paper,
  Grid,
  Button,
  Chip,
  Divider,
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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  AlertTitle,
  IconButton,
  Tooltip,
  alpha,
  useTheme,
  Drawer,
  Fab,
  LinearProgress,
  useMediaQuery,
} from "@mui/material";
import { useNavigate, Link } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import MemoryIcon from "@mui/icons-material/Memory";
import SearchIcon from "@mui/icons-material/Search";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import BugReportIcon from "@mui/icons-material/BugReport";
import TerminalIcon from "@mui/icons-material/Terminal";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import KeyboardIcon from "@mui/icons-material/Keyboard";
import FitnessCenterIcon from "@mui/icons-material/FitnessCenter";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";

interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

const questionBank: QuizQuestion[] = [
  {
    id: 1,
    question: "What does IDA stand for in IDA Pro?",
    options: ["Interactive Disassembler", "Integrated Debugging Assistant", "Instruction Data Analyzer", "Internal Driver Analyzer"],
    correctAnswer: 0,
    explanation: "IDA is short for Interactive Disassembler, highlighting that analysts guide the analysis.",
    topic: "Basics",
  },
  {
    id: 2,
    question: "IDA Pro is primarily used for:",
    options: ["Writing source code", "Reverse engineering compiled binaries", "Network packet capture", "Database administration"],
    correctAnswer: 1,
    explanation: "IDA Pro helps analysts understand compiled programs when source code is unavailable.",
    topic: "Basics",
  },
  {
    id: 3,
    question: "Why is IDA called interactive?",
    options: ["It only runs in a browser", "You can guide analysis with names, types, and comments", "It requires internet access", "It runs games"],
    correctAnswer: 1,
    explanation: "You actively rename symbols, add comments, and correct code/data to steer the analysis.",
    topic: "Basics",
  },
  {
    id: 4,
    question: "Where does IDA store your analysis progress?",
    options: ["A temporary cache only", "An IDB or I64 database file", "The system registry", "Only in RAM"],
    correctAnswer: 1,
    explanation: "IDA saves work in a database so you can resume later without losing changes.",
    topic: "Basics",
  },
  {
    id: 5,
    question: "What does auto-analysis in IDA do?",
    options: ["Deletes functions", "Identifies code, data, and cross-references automatically", "Only changes the theme", "Encrypts the binary"],
    correctAnswer: 1,
    explanation: "Auto-analysis builds an initial map of code and data to speed up investigation.",
    topic: "Basics",
  },
  {
    id: 6,
    question: "What is the entry point of a program?",
    options: ["First instruction the loader executes", "Last function called", "A comment block", "A debug symbol"],
    correctAnswer: 0,
    explanation: "Execution begins at the entry point when the OS loader starts the program.",
    topic: "Basics",
  },
  {
    id: 7,
    question: "Why do analysts open the Strings window early?",
    options: ["To view human-readable clues and messages", "To change CPU registers", "To compile code", "To view network traffic"],
    correctAnswer: 0,
    explanation: "Strings often reveal file paths, error messages, or feature names that hint at behavior.",
    topic: "Basics",
  },
  {
    id: 8,
    question: "What does Graph View show?",
    options: ["Control flow between basic blocks", "Disk usage", "Only hex bytes", "Symbol imports only"],
    correctAnswer: 0,
    explanation: "Graph View provides a visual map of branches, loops, and control flow.",
    topic: "Basics",
  },
  {
    id: 9,
    question: "What is the Hex-Rays decompiler output?",
    options: ["C-like pseudocode", "Exact source code", "Bytecode", "Network logs"],
    correctAnswer: 0,
    explanation: "The decompiler produces readable pseudocode that approximates the original logic.",
    topic: "Basics",
  },
  {
    id: 10,
    question: "Which capability is part of IDA Pro Essentials?",
    options: ["Hex-Rays decompiler integration", "Package manager", "Web server", "Browser extension"],
    correctAnswer: 0,
    explanation: "IDA Pro integrates with the Hex-Rays decompiler to provide C-like pseudocode.",
    topic: "Basics",
  },
  {
    id: 11,
    question: "When loading a binary, the most important first choice is:",
    options: ["Favorite theme", "Correct processor architecture and bitness", "Window size", "Font color"],
    correctAnswer: 1,
    explanation: "Choosing the correct architecture and bitness ensures accurate disassembly.",
    topic: "Loading and Formats",
  },
  {
    id: 12,
    question: "What does the loader in IDA do?",
    options: ["Interprets the file format and maps segments", "Writes new code", "Encrypts the binary", "Uploads to the cloud"],
    correctAnswer: 0,
    explanation: "The loader understands the executable format and lays it out in memory.",
    topic: "Loading and Formats",
  },
  {
    id: 13,
    question: "In IDA, a segment represents:",
    options: ["A memory range with a base address and attributes", "A comment", "A function prototype", "A debugger breakpoint"],
    correctAnswer: 0,
    explanation: "Segments describe contiguous memory areas such as code or data.",
    topic: "Loading and Formats",
  },
  {
    id: 14,
    question: "A section is best described as:",
    options: ["A named region inside a segment defined by the file format", "A UI tab", "A network session", "A CPU register"],
    correctAnswer: 0,
    explanation: "Sections are file-format-defined regions like .text or .data.",
    topic: "Loading and Formats",
  },
  {
    id: 15,
    question: "What does rebasing an IDA database mean?",
    options: ["Adjusting addresses to a new base address", "Deleting the database", "Compressing the binary", "Turning on debugging"],
    correctAnswer: 0,
    explanation: "Rebasing updates addresses when a binary is loaded at a new base.",
    topic: "Loading and Formats",
  },
  {
    id: 16,
    question: "PE, ELF, and Mach-O are:",
    options: ["Executable file formats", "Database engines", "Network protocols", "Virtual machines"],
    correctAnswer: 0,
    explanation: "They are common executable formats for Windows, Linux, and macOS.",
    topic: "Loading and Formats",
  },
  {
    id: 17,
    question: "Why are imports useful during analysis?",
    options: ["They reveal which APIs or libraries are called", "They hide strings", "They improve performance", "They remove obfuscation"],
    correctAnswer: 0,
    explanation: "Imports show external functions the program relies on.",
    topic: "Loading and Formats",
  },
  {
    id: 18,
    question: "What does the export table describe?",
    options: ["Functions or symbols a module exposes", "Local variables", "User accounts", "Compiler warnings"],
    correctAnswer: 0,
    explanation: "Exports are functions other programs can call from the module.",
    topic: "Loading and Formats",
  },
  {
    id: 19,
    question: "High entropy and a small import table often suggest:",
    options: ["Packing or heavy obfuscation", "Clear text configuration", "Open source license", "Low risk"],
    correctAnswer: 0,
    explanation: "Packed samples compress or encrypt data, raising entropy and hiding imports.",
    topic: "Loading and Formats",
  },
  {
    id: 20,
    question: "If IDA mislabels code as data, you should:",
    options: ["Convert it to code and reanalyze", "Ignore it permanently", "Delete the function", "Only change the theme"],
    correctAnswer: 0,
    explanation: "Mark the region as code and re-run analysis to correct it.",
    topic: "Loading and Formats",
  },
  {
    id: 21,
    question: "Cross-references (xrefs) help you:",
    options: ["See where a function or data is used", "Change CPU speed", "Encrypt strings", "Generate reports automatically"],
    correctAnswer: 0,
    explanation: "Xrefs connect callers and references to data or functions.",
    topic: "Navigation",
  },
  {
    id: 22,
    question: "The Functions window is useful for:",
    options: ["Listing discovered functions and jumping to them", "Editing the registry", "Changing OS settings", "Viewing network packets"],
    correctAnswer: 0,
    explanation: "It gives a quick index of all known functions.",
    topic: "Navigation",
  },
  {
    id: 23,
    question: "The Names window shows:",
    options: ["All named symbols", "Only raw bytes", "Only decompiler output", "Only debugger logs"],
    correctAnswer: 0,
    explanation: "Names include functions, globals, and labels.",
    topic: "Navigation",
  },
  {
    id: 24,
    question: "Why use Graph View during analysis?",
    options: ["It highlights branches, loops, and control flow", "It increases file size", "It disables analysis", "It shows only strings"],
    correctAnswer: 0,
    explanation: "Graph View makes complex flow easier to follow.",
    topic: "Navigation",
  },
  {
    id: 25,
    question: "What is the benefit of renaming functions?",
    options: ["Improves readability and your mental model", "Shrinks binary size", "Increases execution speed", "Removes imports"],
    correctAnswer: 0,
    explanation: "Good names turn raw assembly into understandable logic.",
    topic: "Navigation",
  },
  {
    id: 26,
    question: "Comments in IDA are used to:",
    options: ["Record observations and hypotheses", "Execute code", "Change file format", "Compile source"],
    correctAnswer: 0,
    explanation: "Comments document your reasoning and save time later.",
    topic: "Navigation",
  },
  {
    id: 27,
    question: "Bookmarks or color tags help you:",
    options: ["Mark important locations for quick return", "Fix broken binaries", "Encrypt a file", "Change CPU mode"],
    correctAnswer: 0,
    explanation: "They help you track key places across large programs.",
    topic: "Navigation",
  },
  {
    id: 28,
    question: "Xrefs to strings can help you:",
    options: ["Find code paths that use a message or check", "Optimize compiler flags", "Detect network routes", "Upgrade the OS"],
    correctAnswer: 0,
    explanation: "String references often point to logging, errors, or UI code.",
    topic: "Navigation",
  },
  {
    id: 29,
    question: "Why is the Imports window helpful for malware analysis?",
    options: ["It shows API usage like file, registry, or network calls", "It only shows comments", "It lists user passwords", "It removes obfuscation"],
    correctAnswer: 0,
    explanation: "Imports reveal capabilities before you dive deep.",
    topic: "Navigation",
  },
  {
    id: 30,
    question: "A fast way to jump to a known address or symbol is to use:",
    options: ["Go to address command", "Restart IDA", "Change font size", "Export to PDF"],
    correctAnswer: 0,
    explanation: "Go to address lets you jump directly to an address or name.",
    topic: "Navigation",
  },
  {
    id: 31,
    question: "What is a function prototype in IDA?",
    options: ["Return type and parameter types", "Only the function name", "The raw bytes", "A breakpoint list"],
    correctAnswer: 0,
    explanation: "Prototypes define how a function is called and what it returns.",
    topic: "Analysis and Types",
  },
  {
    id: 32,
    question: "Why add structure types to data?",
    options: ["It makes fields readable and helps the decompiler", "It reduces binary size", "It hides data", "It disables xrefs"],
    correctAnswer: 0,
    explanation: "Structures turn raw bytes into meaningful fields.",
    topic: "Analysis and Types",
  },
  {
    id: 33,
    question: "Type propagation helps by:",
    options: ["Spreading known types through data flow", "Removing comments", "Clearing symbols", "Encrypting strings"],
    correctAnswer: 0,
    explanation: "Type propagation improves readability and analysis accuracy.",
    topic: "Analysis and Types",
  },
  {
    id: 34,
    question: "The stack frame window primarily shows:",
    options: ["Local variables and function arguments", "Network sockets", "Disk usage", "Only global variables"],
    correctAnswer: 0,
    explanation: "It displays how the function uses stack space.",
    topic: "Analysis and Types",
  },
  {
    id: 35,
    question: "What is a thunk function?",
    options: ["Small stub that forwards to another function", "Large data table", "A decompiler error", "An encrypted string"],
    correctAnswer: 0,
    explanation: "Thunks often forward to imported or wrapped functions.",
    topic: "Analysis and Types",
  },
  {
    id: 36,
    question: "Why identify calling conventions?",
    options: ["Clarifies how arguments are passed and stack cleaned", "Changes UI colors", "Improves network speed", "Deletes symbols"],
    correctAnswer: 0,
    explanation: "Calling conventions define argument passing and stack cleanup rules.",
    topic: "Analysis and Types",
  },
  {
    id: 37,
    question: "What does FLIRT do?",
    options: ["Matches known library functions to signatures", "Encrypts the binary", "Runs the program", "Deletes comments"],
    correctAnswer: 0,
    explanation: "FLIRT signatures help identify library code automatically.",
    topic: "Analysis and Types",
  },
  {
    id: 38,
    question: "What does Lumina provide?",
    options: ["Cloud-based sharing of function metadata and names", "Disk defragmentation", "Malware sandboxing", "Source control"],
    correctAnswer: 0,
    explanation: "Lumina shares function metadata to speed up analysis.",
    topic: "Analysis and Types",
  },
  {
    id: 39,
    question: "Why load PDB or debug symbols?",
    options: ["Recover accurate function and variable names", "Speed up CPU", "Reduce file size", "Disable analysis"],
    correctAnswer: 0,
    explanation: "Symbols improve naming and type information dramatically.",
    topic: "Analysis and Types",
  },
  {
    id: 40,
    question: "Switching a region from code to data is useful when:",
    options: ["Bytes represent a table or constant data", "You want to remove a segment", "You want to debug faster", "You want to change themes"],
    correctAnswer: 0,
    explanation: "Not all bytes are instructions; some are data tables.",
    topic: "Analysis and Types",
  },
  {
    id: 41,
    question: "What should you remember about decompiler output?",
    options: ["It is an approximation and may be wrong", "It is exact source code", "It runs the program", "It is a hex dump"],
    correctAnswer: 0,
    explanation: "Decompiler output is helpful but not guaranteed to be exact.",
    topic: "Decompiler",
  },
  {
    id: 42,
    question: "Why do better types improve the decompiler?",
    options: ["They produce clearer variables and logic", "They delete functions", "They disable xrefs", "They change file format"],
    correctAnswer: 0,
    explanation: "Types guide the decompiler toward accurate variable usage.",
    topic: "Decompiler",
  },
  {
    id: 43,
    question: "What does the decompiler do with indirect calls?",
    options: ["May show them as function pointers until resolved", "Always resolves them perfectly", "Removes them", "Turns them into comments only"],
    correctAnswer: 0,
    explanation: "Indirect calls often remain as pointers until more context is available.",
    topic: "Decompiler",
  },
  {
    id: 44,
    question: "If pseudocode looks wrong, you should:",
    options: ["Check the assembly and control flow", "Ignore it", "Delete the function", "Only print the file"],
    correctAnswer: 0,
    explanation: "The disassembly is the ground truth for behavior.",
    topic: "Decompiler",
  },
  {
    id: 45,
    question: "Renaming a variable in the decompiler will:",
    options: ["Update the name across the decompiler view", "Delete the function", "Rename the binary file", "Change CPU architecture"],
    correctAnswer: 0,
    explanation: "Renames propagate through decompiler output for clarity.",
    topic: "Decompiler",
  },
  {
    id: 46,
    question: "Which view is best for confirming instruction-level behavior?",
    options: ["Disassembly listing", "Strings window", "Output console", "Project settings"],
    correctAnswer: 0,
    explanation: "The listing view shows the real instructions being executed.",
    topic: "Decompiler",
  },
  {
    id: 47,
    question: "What is a common reason the decompiler misses a function?",
    options: ["Obfuscation or unusual control flow", "Too many comments", "Large font size", "No internet"],
    correctAnswer: 0,
    explanation: "Obfuscation can hide typical function boundaries.",
    topic: "Decompiler",
  },
  {
    id: 48,
    question: "Why compare decompiler and graph view?",
    options: ["Graph view reveals branches and loops visually", "Graph view deletes code", "Decompiler is always wrong", "It changes file format"],
    correctAnswer: 0,
    explanation: "Graph view helps validate structure that pseudocode might obscure.",
    topic: "Decompiler",
  },
  {
    id: 49,
    question: "IDAPython is used to:",
    options: ["Automate tasks and extend IDA", "Compile C code", "Scan networks", "Manage Docker"],
    correctAnswer: 0,
    explanation: "IDAPython lets you script the database and build custom tooling.",
    topic: "Scripting",
  },
  {
    id: 50,
    question: "IDC is:",
    options: ["IDA's legacy scripting language", "A network protocol", "A debugger breakpoint", "A file system"],
    correctAnswer: 0,
    explanation: "IDC is the older scripting language still supported in IDA.",
    topic: "Scripting",
  },
  {
    id: 51,
    question: "A script can access:",
    options: ["Functions, names, bytes, and comments", "Only images", "Only network packets", "Only UI themes"],
    correctAnswer: 0,
    explanation: "Scripts can read and modify most analysis artifacts.",
    topic: "Scripting",
  },
  {
    id: 52,
    question: "Scripting is most useful when:",
    options: ["Repeating the same task across many functions", "You want to change the OS", "You only read one string", "You never save the database"],
    correctAnswer: 0,
    explanation: "Automation saves time on repetitive analysis work.",
    topic: "Scripting",
  },
  {
    id: 53,
    question: "Plugins in IDA are:",
    options: ["Extensions that add features or integrations", "Only theme packs", "Only antivirus tools", "Temporary files"],
    correctAnswer: 0,
    explanation: "Plugins extend IDA to support new workflows or tooling.",
    topic: "Scripting",
  },
  {
    id: 54,
    question: "Where do you run scripts inside IDA?",
    options: ["Script Manager or the built-in console", "The Windows registry", "Command prompt only", "External web site"],
    correctAnswer: 0,
    explanation: "IDA provides a script manager and console for running scripts.",
    topic: "Scripting",
  },
  {
    id: 55,
    question: "A simple automation example is:",
    options: ["Renaming all functions that call a specific API", "Replace all hex bytes with zeros", "Disable analysis", "Start a web server"],
    correctAnswer: 0,
    explanation: "Scripting can automatically label functions based on API usage.",
    topic: "Scripting",
  },
  {
    id: 56,
    question: "Why keep scripts small and focused?",
    options: ["Easier to reuse and debug", "They run slower", "They hide errors", "They require admin access"],
    correctAnswer: 0,
    explanation: "Small scripts are easier to maintain and share.",
    topic: "Scripting",
  },
  {
    id: 57,
    question: "Scripting helps collaboration by:",
    options: ["Letting teammates reproduce analysis steps", "Deleting other users work", "Hiding file formats", "Changing the architecture"],
    correctAnswer: 0,
    explanation: "Reusable scripts document how results were produced.",
    topic: "Scripting",
  },
  {
    id: 58,
    question: "IDAPython can help extract:",
    options: ["Call graphs, strings, and constants", "Printer settings", "Wi-Fi keys", "Browser history"],
    correctAnswer: 0,
    explanation: "Scripts can export useful data for reports or further analysis.",
    topic: "Scripting",
  },
  {
    id: 59,
    question: "IDA Pro's debugger can:",
    options: ["Attach to a running process or launch a program", "Only view logs", "Only edit text", "Only rename functions"],
    correctAnswer: 0,
    explanation: "IDA Pro supports attaching and debugging executables directly.",
    topic: "Debugging and Patching",
  },
  {
    id: 60,
    question: "A breakpoint lets you:",
    options: ["Pause execution at a specific instruction", "Encrypt memory", "Change CPU model", "Compile source code"],
    correctAnswer: 0,
    explanation: "Breakpoints stop execution so you can inspect state.",
    topic: "Debugging and Patching",
  },
  {
    id: 61,
    question: "Step over vs step into means:",
    options: ["Step over runs called functions; step into enters them", "Step over deletes code; step into saves files", "Step over adds comments; step into removes comments", "Step over turns on graph; step into turns off graph"],
    correctAnswer: 0,
    explanation: "Step into goes inside a call, step over runs it without entering.",
    topic: "Debugging and Patching",
  },
  {
    id: 62,
    question: "Why debug in a VM?",
    options: ["Isolate and safely observe suspicious code", "Make CPU faster", "Disable security", "Increase screen size"],
    correctAnswer: 0,
    explanation: "VMs isolate the sample and reduce risk to the host system.",
    topic: "Debugging and Patching",
  },
  {
    id: 63,
    question: "Patching in IDA is used to:",
    options: ["Modify instructions or data for testing", "Change the OS", "Compile C code", "Generate key pairs"],
    correctAnswer: 0,
    explanation: "Patching is useful to test hypotheses or bypass checks.",
    topic: "Debugging and Patching",
  },
  {
    id: 64,
    question: "After patching, you should:",
    options: ["Apply or export patches to a new file", "Delete the database", "Turn off auto-analysis", "Reinstall IDA"],
    correctAnswer: 0,
    explanation: "Export a patched copy instead of modifying the original file.",
    topic: "Debugging and Patching",
  },
  {
    id: 65,
    question: "What is a safe practice before patching?",
    options: ["Keep a copy of the original binary", "Never save the database", "Disable backups", "Delete imports"],
    correctAnswer: 0,
    explanation: "Always keep the original sample intact for reference.",
    topic: "Debugging and Patching",
  },
  {
    id: 66,
    question: "Function diffing tools help you:",
    options: ["Compare binaries and find code changes", "Encrypt the file", "Add new functions", "Increase entropy"],
    correctAnswer: 0,
    explanation: "Diffing highlights what changed between versions.",
    topic: "Workflow",
  },
  {
    id: 67,
    question: "A call graph view is helpful to:",
    options: ["See how functions call each other", "Show disk usage", "Edit the registry", "Change debugger settings"],
    correctAnswer: 0,
    explanation: "Call graphs reveal high-level architecture and dependencies.",
    topic: "Workflow",
  },
  {
    id: 68,
    question: "Why label library functions?",
    options: ["Focus on custom code", "Hide APIs", "Disable xrefs", "Change architecture"],
    correctAnswer: 0,
    explanation: "Labeling libraries helps you focus on the unique logic.",
    topic: "Workflow",
  },
  {
    id: 69,
    question: "Why save the IDA database often?",
    options: ["Preserve analysis progress and recover from mistakes", "Reduce file size", "Increase CPU speed", "Hide strings"],
    correctAnswer: 0,
    explanation: "Frequent saves prevent losing valuable analysis work.",
    topic: "Workflow",
  },
  {
    id: 70,
    question: "A good early workflow step is to:",
    options: ["Scan strings and imports for quick context", "Delete all comments", "Disable analysis", "Patch the binary"],
    correctAnswer: 0,
    explanation: "Strings and imports provide fast clues about behavior.",
    topic: "Workflow",
  },
  {
    id: 71,
    question: "Trusting decompiler output without checking assembly can lead to:",
    options: ["Incorrect conclusions about behavior", "Better performance", "Automatic fixes", "Smaller files"],
    correctAnswer: 0,
    explanation: "The assembly is the real execution path; always verify.",
    topic: "Workflow",
  },
  {
    id: 72,
    question: "Leaving functions with default names makes analysis harder because:",
    options: ["You lose semantic clues", "It speeds up debugging", "It reduces file size", "It improves decompiler output"],
    correctAnswer: 0,
    explanation: "Meaningful names make logic easier to follow.",
    topic: "Workflow",
  },
  {
    id: 73,
    question: "Ignoring data types usually results in:",
    options: ["Confusing decompiler output and unclear structures", "More accurate graphs", "Better string detection", "Smaller database"],
    correctAnswer: 0,
    explanation: "Types clarify variables and how data is used.",
    topic: "Workflow",
  },
  {
    id: 74,
    question: "If a function name is misleading, you should:",
    options: ["Rename it to reflect observed behavior", "Delete it", "Change file format", "Disable xrefs"],
    correctAnswer: 0,
    explanation: "Correct names make analysis and reports accurate.",
    topic: "Workflow",
  },
  {
    id: 75,
    question: "When starting a new sample, the best first goal is to:",
    options: ["Build a rough map of what the program does", "Write exploit code", "Publish results immediately", "Skip to patching"],
    correctAnswer: 0,
    explanation: "Start by understanding overall behavior before diving deep.",
    topic: "Workflow",
  },
];

const quickStartSteps = [
  {
    title: "Load the binary safely",
    description: "Open the file, confirm the architecture, and let auto-analysis complete. If the file is untrusted, work in a VM.",
  },
  {
    title: "Get fast context",
    description: "Check the Strings, Imports, and Entry Point. These often reveal major features and key APIs.",
  },
  {
    title: "Map the main flow",
    description: "Find the entry function, main function, or exported APIs, then follow xrefs to build a top-level map.",
  },
  {
    title: "Rename and comment early",
    description: "Rename functions and add short notes as soon as you understand a block. It prevents confusion later.",
  },
  {
    title: "Validate with assembly",
    description: "Use the decompiler for speed, but confirm important logic in the disassembly view.",
  },
];

const workspaceMap = [
  {
    pane: "IDA View (Disassembly)",
    purpose: "Shows assembly instructions with addresses, bytes, and comments.",
    tip: "Treat this as ground truth when decompiler output is unclear.",
  },
  {
    pane: "Graph View",
    purpose: "Visual control flow of a function using basic blocks.",
    tip: "Great for loops, branches, and understanding execution paths.",
  },
  {
    pane: "Decompiler View",
    purpose: "C-like pseudocode for the current function.",
    tip: "Rename variables and types here to improve readability quickly.",
  },
  {
    pane: "Functions Window",
    purpose: "List of detected functions with addresses and names.",
    tip: "Sort by name or address to quickly jump around.",
  },
  {
    pane: "Strings Window",
    purpose: "Extracted strings that can hint at behavior and features.",
    tip: "Use xrefs on interesting strings to find relevant code.",
  },
  {
    pane: "Imports/Exports",
    purpose: "Lists imported and exported APIs or symbols.",
    tip: "Imports show capabilities; exports show module interfaces.",
  },
  {
    pane: "Hex View",
    purpose: "Raw bytes of the binary with highlighting.",
    tip: "Useful for patches and verifying data layout.",
  },
  {
    pane: "Structures/Types",
    purpose: "Manage structs, enums, and typedefs for clarity.",
    tip: "Define structures for complex data to improve decompiler output.",
  },
];

const coreFeatures = [
  {
    title: "Auto-Analysis + Signatures",
    description: "Identify functions, references, and standard library code quickly.",
    icon: <SearchIcon />,
    color: "#2563eb",
  },
  {
    title: "Decompiler (Hex-Rays)",
    description: "Readable pseudocode to speed up logic discovery and note-taking.",
    icon: <CodeIcon />,
    color: "#7c3aed",
  },
  {
    title: "Cross-References (Xrefs)",
    description: "Jump between callers, callees, and data references with confidence.",
    icon: <BuildIcon />,
    color: "#10b981",
  },
  {
    title: "Types and Structures",
    description: "Turn raw bytes into meaningful structs, enums, and function prototypes.",
    icon: <MemoryIcon />,
    color: "#f59e0b",
  },
  {
    title: "Scripting (IDAPython)",
    description: "Automate boring steps and extract data for reports.",
    icon: <TerminalIcon />,
    color: "#0ea5e9",
  },
  {
    title: "Debugging and Patching",
    description: "Run, step, and test ideas by modifying instructions safely.",
    icon: <BugReportIcon />,
    color: "#ef4444",
  },
];
const commonTasks = [
  {
    title: "Find the main control flow",
    steps: [
      "Start at the entry point or exported function list.",
      "Follow xrefs into large dispatcher or main routines.",
      "Rename key functions as you confirm their roles.",
    ],
  },
  {
    title: "Trace a suspicious string",
    steps: [
      "Open the Strings window and search for the message.",
      "Jump to xrefs to find where it is used.",
      "Inspect the nearby logic in Graph View.",
    ],
  },
  {
    title: "Identify file or network activity",
    steps: [
      "Check imports for file or socket APIs.",
      "Use xrefs on those APIs to find call sites.",
      "Label wrapper functions to map higher-level behavior.",
    ],
  },
  {
    title: "Locate crypto usage",
    steps: [
      "Search for known crypto library imports or strings.",
      "Look for large constants or tables near suspicious functions.",
      "Rename suspected crypto routines and verify with assembly.",
    ],
  },
];

const keyboardShortcuts = [
  { shortcut: "G", action: "Go to address or symbol" },
  { shortcut: "X", action: "Show cross-references" },
  { shortcut: "N", action: "Rename a symbol" },
  { shortcut: ";", action: "Add a comment" },
  { shortcut: "Space", action: "Toggle graph and text view" },
  { shortcut: "Shift+F12", action: "Open Strings window" },
  { shortcut: "C", action: "Define code at cursor" },
  { shortcut: "D", action: "Define data at cursor" },
  { shortcut: "F5", action: "Open the decompiler view (Hex-Rays)" },
];

const checklist = [
  "Confirm architecture, bitness, and file format.",
  "Review imports and exports for quick capability hints.",
  "Scan strings and follow xrefs to key messages.",
  "Identify entry, main, or dispatcher logic.",
  "Rename functions and variables as soon as you understand them.",
  "Verify critical logic in the disassembly view.",
  "Save the database often and keep notes consistent.",
];

const pitfalls = [
  "Trusting pseudocode without checking assembly.",
  "Leaving important functions with default names.",
  "Ignoring data types and structures.",
  "Forgetting to save the IDB/I64 database.",
  "Analyzing malware outside of a safe environment.",
];

const practiceDrills = [
  {
    title: "10-minute warmup",
    description: "Open a small binary, list the top 5 functions, and rename them based on behavior.",
  },
  {
    title: "String trace drill",
    description: "Pick one string and follow xrefs until you understand where it is used.",
  },
  {
    title: "API map",
    description: "Create a short list of high-risk APIs (file, registry, network) and mark their callers.",
  },
  {
    title: "Type cleanup",
    description: "Add a structure and apply it to a data region to improve decompiler output.",
  },
];

const CodeBlock: React.FC<{ code: string; language?: string; title?: string }> = ({
  code,
  language = "python",
  title,
}) => {
  const [copied, setCopied] = useState(false);
  const theme = useTheme();

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper
      sx={{
        bgcolor: "#0b1120",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: `1px solid ${alpha(theme.palette.primary.main, 0.3)}`,
        overflow: "hidden",
      }}
    >
      {title && (
        <Box
          sx={{
            px: 2,
            py: 1,
            bgcolor: alpha("#2563eb", 0.2),
            borderBottom: `1px solid ${alpha("#2563eb", 0.3)}`,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <Typography variant="subtitle2" sx={{ color: "#93c5fd", fontWeight: 600 }}>
            {title}
          </Typography>
          <Tooltip title={copied ? "Copied!" : "Copy"}>
            <IconButton size="small" onClick={handleCopy} sx={{ color: "#93c5fd" }}>
              <ContentCopyIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      )}
      <Box sx={{ position: "absolute", top: title ? 40 : 8, right: 8 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#2563eb", color: "white" }} />
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          p: 2,
          pt: title ? 3 : 2,
          overflow: "auto",
          fontFamily: "'Fira Code', 'Consolas', monospace",
          fontSize: "0.85rem",
          color: "#e2e8f0",
          lineHeight: 1.6,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};
function QuizSection() {
  const theme = useTheme();
  const [quizStarted, setQuizStarted] = useState(false);
  const [quizSession, setQuizSession] = useState(0);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);
  const [showResults, setShowResults] = useState(false);
  const [answers, setAnswers] = useState<(number | null)[]>([]);

  const quizQuestions = useMemo(() => {
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, 10);
  }, [quizSession]);

  const startQuiz = () => {
    setCurrentQuestionIndex(0);
    setSelectedAnswer(null);
    setShowResults(false);
    setQuizStarted(true);
    setAnswers([]);
    setQuizSession((prev) => prev + 1);
  };

  const handleSubmitAnswer = () => {
    if (selectedAnswer === null) return;

    setAnswers((prev) => [...prev, selectedAnswer]);

    if (currentQuestionIndex + 1 >= quizQuestions.length) {
      setShowResults(true);
    } else {
      setCurrentQuestionIndex((prev) => prev + 1);
      setSelectedAnswer(null);
    }
  };

  const getScoreColor = (value: number, total: number) => {
    const percentage = (value / total) * 100;
    if (percentage >= 80) return "#22c55e";
    if (percentage >= 60) return "#f59e0b";
    return "#ef4444";
  };

  const getScoreMessage = (value: number, total: number) => {
    const percentage = (value / total) * 100;
    if (percentage === 100) return "Perfect score! You nailed the essentials.";
    if (percentage >= 80) return "Great job! You know the essentials well.";
    if (percentage >= 60) return "Good attempt. Review a few sections and try again.";
    return "Keep practicing. Review the guide and try again.";
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
          border: `2px solid ${alpha("#2563eb", 0.3)}`,
          background: `linear-gradient(135deg, ${alpha("#2563eb", 0.06)} 0%, ${alpha("#7c3aed", 0.06)} 100%)`,
        }}
      >
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              background: "linear-gradient(135deg, #2563eb, #7c3aed)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <QuizIcon sx={{ color: "white", fontSize: 32 }} />
          </Box>
          IDA Pro Essentials Quiz
        </Typography>

        <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8, fontSize: "1.05rem" }}>
          Ready to test what you learned? This quiz presents <strong>10 random questions</strong> selected
          from a bank of <strong>75 questions</strong>, so every attempt is different.
        </Typography>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#2563eb", 0.1), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#2563eb" }}>10</Typography>
              <Typography variant="caption" color="text.secondary">Questions</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#7c3aed", 0.1), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#7c3aed" }}>75</Typography>
              <Typography variant="caption" color="text.secondary">Question Pool</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#22c55e", 0.1), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#22c55e" }}>8</Typography>
              <Typography variant="caption" color="text.secondary">Topics</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#f59e0b", 0.1), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#f59e0b" }}>Unlimited</Typography>
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
            background: "linear-gradient(135deg, #2563eb, #7c3aed)",
            fontWeight: 700,
            px: 4,
            py: 1.5,
            fontSize: "1.1rem",
            "&:hover": {
              background: "linear-gradient(135deg, #1d4ed8, #6d28d9)",
            },
          }}
        >
          Start Quiz
        </Button>
      </Paper>
    );
  }

  const currentQuestion = quizQuestions[currentQuestionIndex];
  if (!currentQuestion) {
    return null;
  }
  if (showResults) {
    const totalQuestions = quizQuestions.length;
    const score = answers.reduce<number>((total, answer, index) => {
      if (answer !== null && answer === quizQuestions[index]?.correctAnswer) {
        return total + 1;
      }
      return total;
    }, 0);
    const scoreColor = getScoreColor(score, totalQuestions);
    return (
      <Paper
        id="quiz-section"
        sx={{
          p: 4,
          mb: 5,
          borderRadius: 4,
          bgcolor: alpha(theme.palette.background.paper, 0.6),
          border: `2px solid ${alpha(scoreColor, 0.3)}`,
        }}
      >
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <EmojiEventsIcon sx={{ color: scoreColor, fontSize: 40 }} />
          Quiz Results
        </Typography>

        <Box sx={{ textAlign: "center", mb: 4 }}>
          <Typography variant="h1" sx={{ fontWeight: 900, color: scoreColor, mb: 1 }}>
            {score}/{totalQuestions}
          </Typography>
          <Typography variant="h6" sx={{ color: "text.secondary", mb: 2 }}>
            {getScoreMessage(score, totalQuestions)}
          </Typography>
          <Chip
            label={`${Math.round((score / totalQuestions) * 100)}%`}
            sx={{
              bgcolor: alpha(scoreColor, 0.15),
              color: scoreColor,
              fontWeight: 700,
              fontSize: "1rem",
              px: 2,
            }}
          />
        </Box>

        <Divider sx={{ my: 3 }} />

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Review Your Answers:</Typography>

        <Box>
          {quizQuestions.map((question, index) => {
            const answer = answers[index];
            const isCorrect = answer === question.correctAnswer;
            return (
              <Paper
                key={question.id}
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
                    {question.question}
                  </Typography>
                </Box>
                <Typography variant="body2" sx={{ color: "text.secondary", ml: 4.5 }}>
                  <strong>Your answer:</strong> {answer !== null && answer !== undefined ? question.options[answer] : "Not answered"}
                  {!isCorrect && (
                    <>
                      <br />
                      <strong style={{ color: "#22c55e" }}>Correct:</strong> {question.options[question.correctAnswer]}
                    </>
                  )}
                </Typography>
                <Typography variant="caption" sx={{ display: "block", mt: 1, ml: 4.5, fontStyle: "italic" }}>
                  {question.explanation}
                </Typography>
              </Paper>
            );
          })}
        </Box>

        <Box sx={{ display: "flex", gap: 2, mt: 3 }}>
          <Button
            variant="contained"
            onClick={startQuiz}
            startIcon={<RefreshIcon />}
            sx={{
              background: "linear-gradient(135deg, #2563eb, #7c3aed)",
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

  const answeredCount = answers.length + (selectedAnswer !== null ? 1 : 0);
  const progressValue = quizQuestions.length
    ? ((currentQuestionIndex + 1) / quizQuestions.length) * 100
    : 0;
  const isLastQuestion = currentQuestionIndex + 1 >= quizQuestions.length;

  return (
    <Paper
      id="quiz-section"
      sx={{
        p: 4,
        mb: 5,
        borderRadius: 4,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        border: `2px solid ${alpha("#2563eb", 0.3)}`,
      }}
    >
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
            Question {currentQuestionIndex + 1} of {quizQuestions.length}
          </Typography>
          <Chip
            label={currentQuestion.topic}
            size="small"
            sx={{ bgcolor: alpha("#7c3aed", 0.15), color: "#7c3aed", fontWeight: 600 }}
          />
        </Box>
        <Box sx={{ width: "100%", bgcolor: alpha("#2563eb", 0.1), borderRadius: 1, height: 8 }}>
          <Box
            sx={{
              width: `${progressValue}%`,
              bgcolor: "#2563eb",
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
          const isSelected = selectedAnswer === index;
          return (
            <Grid item xs={12} key={option}>
              <Paper
                onClick={() => setSelectedAnswer(index)}
                sx={{
                  p: 2,
                  borderRadius: 2,
                  cursor: "pointer",
                  bgcolor: isSelected ? alpha("#2563eb", 0.15) : alpha(theme.palette.background.paper, 0.5),
                  border: `2px solid ${isSelected ? "#2563eb" : alpha(theme.palette.divider, 0.2)}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    borderColor: "#2563eb",
                    bgcolor: alpha("#2563eb", 0.08),
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box
                    sx={{
                      width: 32,
                      height: 32,
                      borderRadius: "50%",
                      bgcolor: isSelected ? "#2563eb" : alpha(theme.palette.divider, 0.3),
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
        <Typography variant="body2" color="text.secondary">
          {answeredCount}/{quizQuestions.length} answered
        </Typography>

        <Button
          variant="contained"
          onClick={handleSubmitAnswer}
          disabled={selectedAnswer === null}
          sx={{
            background: selectedAnswer !== null
              ? "linear-gradient(135deg, #22c55e, #16a34a)"
              : undefined,
            fontWeight: 700,
          }}
        >
          {isLastQuestion ? "Finish Quiz" : "Next Question"}
        </Button>
      </Box>
    </Paper>
  );
}
export default function IDAProEssentialsPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [showScrollTop, setShowScrollTop] = useState(false);
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const mainContentRef = useRef<HTMLDivElement>(null);

  const pageContext = `IDA Pro Essentials learning page covering the IDA Pro interface, auto-analysis, navigation, 
  cross-references, types and structures, decompiler usage, IDAPython scripting, debugging and patching basics, 
  and beginner-friendly workflows for reverse engineering.`;

  // Navigation sections
  const sectionNavItems = [
    { id: "intro-section", label: "Introduction", icon: <MemoryIcon fontSize="small" /> },
    { id: "quickstart-section", label: "Quick Start", icon: <PlayArrowIcon fontSize="small" /> },
    { id: "workspace-section", label: "Workspace Map", icon: <SearchIcon fontSize="small" /> },
    { id: "capabilities-section", label: "Core Capabilities", icon: <BuildIcon fontSize="small" /> },
    { id: "tasks-section", label: "Common Tasks", icon: <CodeIcon fontSize="small" /> },
    { id: "checklist-section", label: "Checklist & Pitfalls", icon: <CheckCircleIcon fontSize="small" /> },
    { id: "scripting-section", label: "IDAPython", icon: <TerminalIcon fontSize="small" /> },
    { id: "shortcuts-section", label: "Keyboard Shortcuts", icon: <KeyboardIcon fontSize="small" /> },
    { id: "practice-section", label: "Practice Routine", icon: <FitnessCenterIcon fontSize="small" /> },
    { id: "quiz-section", label: "Knowledge Quiz", icon: <QuizIcon fontSize="small" /> },
  ];

  useEffect(() => {
    const handleScroll = () => {
      setShowScrollTop(window.scrollY > 400);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const handleNavClick = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    setNavDrawerOpen(false);
  };

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const sidebarNav = (
    <Paper
      sx={{
        position: "sticky",
        top: 80,
        p: 2,
        borderRadius: 3,
        bgcolor: alpha("#0f1422", 0.95),
        border: `1px solid ${alpha("#6366f1", 0.2)}`,
        maxHeight: "calc(100vh - 100px)",
        overflow: "auto",
      }}
    >
      <Typography variant="subtitle2" sx={{ color: "#6366f1", fontWeight: 700, mb: 2, px: 1 }}>
        📍 Page Navigation
      </Typography>
      <LinearProgress
        variant="determinate"
        value={100}
        sx={{
          mb: 2,
          mx: 1,
          height: 4,
          borderRadius: 2,
          bgcolor: alpha("#6366f1", 0.1),
          "& .MuiLinearProgress-bar": { bgcolor: "#6366f1" },
        }}
      />
      <List dense sx={{ py: 0 }}>
        {sectionNavItems.map((item) => (
          <ListItem
            key={item.id}
            onClick={() => handleNavClick(item.id)}
            sx={{
              borderRadius: 2,
              mb: 0.5,
              cursor: "pointer",
              "&:hover": {
                bgcolor: alpha("#6366f1", 0.1),
              },
            }}
          >
            <ListItemIcon sx={{ minWidth: 32, color: "#6366f1" }}>{item.icon}</ListItemIcon>
            <ListItemText
              primary={item.label}
              primaryTypographyProps={{
                fontSize: "0.85rem",
                fontWeight: 500,
                color: "grey.300",
              }}
            />
          </ListItem>
        ))}
      </List>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="IDA Pro Essentials" pageContext={pageContext}>
      <Box sx={{ minHeight: "100vh", py: 4 }}>
        <Container maxWidth="xl">
          <Box sx={{ display: "flex", gap: 3 }}>
            {/* Sidebar Navigation - Desktop Only */}
            {!isMobile && (
              <Box sx={{ width: 260, flexShrink: 0 }}>
                {sidebarNav}
              </Box>
            )}

            {/* Main Content */}
            <Box ref={mainContentRef} sx={{ flex: 1, minWidth: 0 }}>
        <Paper
          id="intro-section"
          sx={{
            p: { xs: 3, md: 4 },
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#0ea5e9", 0.14)} 0%, ${alpha("#6366f1", 0.14)} 50%, ${alpha("#7c3aed", 0.14)} 100%)`,
            border: `1px solid ${alpha("#2563eb", 0.25)}`,
          }}
        >
          <Typography variant="h3" sx={{ fontWeight: 900, mb: 3 }}>
            IDA Pro Essentials
          </Typography>

          {/* Comprehensive Introduction */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
            🔬 What is IDA Pro?
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>IDA Pro</strong> (Interactive Disassembler Professional) is the gold standard in reverse engineering tools, 
            trusted by security researchers, malware analysts, and software engineers worldwide since 1991. Developed by Hex-Rays, 
            IDA Pro has been the industry-leading disassembler for over three decades, and for good reason: it transforms compiled 
            binary programs into human-readable assembly code, allowing you to understand what software does when you don't have 
            access to the original source code.
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Why is reverse engineering necessary?</strong> Every program you run — from your web browser to your operating 
            system — started as human-readable source code written by programmers. That code was then <em>compiled</em> into machine 
            instructions (ones and zeros) that your computer's processor can execute. Unfortunately, this compilation process is 
            largely one-way: the compiler throws away most of the helpful information like variable names, comments, and high-level 
            structure. IDA Pro works backwards from this compiled code to reconstruct a readable representation of what the program does.
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>The "Interactive" in IDA is key.</strong> Unlike automated tools that just dump assembly code, IDA Pro is 
            designed to be a collaborative partner in your analysis. It makes smart guesses about function boundaries, data types, 
            and control flow — but it expects you to refine those guesses. As you analyze a program, you rename functions to reflect 
            their purpose (like changing <code>sub_401000</code> to <code>decrypt_config</code>), add comments explaining tricky logic, 
            and define data structures. All of this work is saved in an IDA database (IDB file), so your analysis accumulates over 
            time and you never lose progress.
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>The Hex-Rays Decompiler</strong> is IDA Pro's superpower. While disassembly shows you the raw assembly instructions 
            (like <code>MOV EAX, [EBP+8]</code>), the decompiler goes further — it reconstructs C-like pseudocode that's much easier 
            to read. Instead of dozens of assembly instructions, you see familiar constructs like <code>if</code> statements, 
            <code>for</code> loops, and function calls. This dramatically speeds up analysis, especially for complex programs. 
            However, decompiled code isn't perfect — it's a best-guess reconstruction, so experienced analysts often verify 
            critical logic in the assembly view.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Who uses IDA Pro?</strong> Security researchers analyzing malware to understand threats. Vulnerability hunters 
            searching for exploitable bugs in commercial software. Game modders understanding game engines. Embedded systems 
            engineers reverse-engineering firmware. Intelligence agencies (it was originally developed for such use cases). 
            And increasingly, anyone curious about how software really works under the hood. While IDA Pro is commercial software 
            with a significant price tag, there's also a free version (IDA Free) that's excellent for learning.
          </Typography>

          <Alert severity="info" sx={{ mb: 3 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>For Beginners</AlertTitle>
            If you're new to reverse engineering, IDA Pro might seem overwhelming at first — there are dozens of windows, menus, 
            and keyboard shortcuts. Don't panic! Start with the basics: load a simple program, explore the Strings window to see 
            readable text, follow cross-references to understand how functions connect, and gradually build your mental model. 
            The learning curve is steep but rewarding. This guide will walk you through a structured approach.
          </Alert>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
            🎯 Core Capabilities at a Glance
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { title: "Multi-Architecture Support", desc: "Analyze x86, x64, ARM, MIPS, PowerPC, and dozens of other processor architectures", color: "#2563eb" },
              { title: "Hex-Rays Decompiler", desc: "Transform assembly into readable C-like pseudocode for faster comprehension", color: "#7c3aed" },
              { title: "Cross-References (XRefs)", desc: "See everywhere a function is called or a variable is used — essential for tracing execution", color: "#10b981" },
              { title: "IDAPython Scripting", desc: "Automate repetitive tasks and extend IDA's capabilities with Python scripts", color: "#f59e0b" },
            ].map((feature) => (
              <Grid item xs={12} sm={6} key={feature.title}>
                <Paper sx={{ p: 2, bgcolor: alpha(feature.color, 0.08), borderRadius: 2, border: `1px solid ${alpha(feature.color, 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: feature.color, mb: 0.5 }}>{feature.title}</Typography>
                  <Typography variant="body2" sx={{ color: "text.secondary" }}>{feature.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
            📚 What You'll Learn in This Guide
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.8, mb: 2 }}>
            This page focuses on the essentials you need to become productive with IDA Pro: understanding the workspace layout 
            and the purpose of each pane, navigation techniques to move efficiently through code, leveraging cross-references 
            to trace program flow, working with types and structures to improve decompiler output, basic IDAPython scripting 
            for automation, and a clean beginner workflow that keeps your analysis organized. We'll also cover common mistakes 
            and safe analysis habits so your first sessions are structured and productive.
          </Typography>

          <Divider sx={{ my: 3 }} />

          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#2563eb", 0.1), borderRadius: 2 }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#2563eb" }}>
                  Disassembly
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Instruction-level view
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#7c3aed", 0.1), borderRadius: 2 }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#7c3aed" }}>
                  Decompiler
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  C-like pseudocode
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#10b981", 0.1), borderRadius: 2 }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#10b981" }}>
                  Xrefs
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Map relationships
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#f59e0b", 0.1), borderRadius: 2 }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#f59e0b" }}>
                  IDAPython
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Automate tasks
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2, mb: 3 }}
        />
        <Paper id="quickstart-section" sx={{ p: 4, mb: 4, borderRadius: 3 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
            Quick Start Workflow
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, color: "text.secondary" }}>
            A simple, repeatable flow to keep your early analysis structured.
          </Typography>
          <List>
            {quickStartSteps.map((step) => (
              <ListItem key={step.title} alignItems="flex-start" sx={{ px: 0 }}>
                <ListItemIcon sx={{ minWidth: 36 }}>
                  <CheckCircleIcon sx={{ color: "#22c55e" }} />
                </ListItemIcon>
                <ListItemText
                  primary={<Typography sx={{ fontWeight: 700 }}>{step.title}</Typography>}
                  secondary={<Typography variant="body2" color="text.secondary">{step.description}</Typography>}
                />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Paper id="workspace-section" sx={{ p: 4, mb: 4, borderRadius: 3 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
            IDA Workspace Map
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, color: "text.secondary" }}>
            These panes appear in most IDA layouts. Learning what each one does will speed up your navigation.
          </Typography>
          <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.08) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Pane</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Beginner Tip</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {workspaceMap.map((row) => (
                  <TableRow key={row.pane}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.pane}</TableCell>
                    <TableCell>{row.purpose}</TableCell>
                    <TableCell>{row.tip}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        <Paper id="capabilities-section" sx={{ p: 4, mb: 4, borderRadius: 3 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
            Core Capabilities You Should Master
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, color: "text.secondary" }}>
            These are the essentials that turn IDA from a viewer into a real analysis workspace.
          </Typography>
          <Grid container spacing={2}>
            {coreFeatures.map((feature) => (
              <Grid item xs={12} md={6} key={feature.title}>
                <Paper
                  sx={{
                    p: 3,
                    borderRadius: 2,
                    border: `1px solid ${alpha(feature.color, 0.3)}`,
                    bgcolor: alpha(feature.color, 0.06),
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <Box
                      sx={{
                        width: 40,
                        height: 40,
                        borderRadius: 2,
                        bgcolor: feature.color,
                        color: "white",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      {feature.icon}
                    </Box>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>
                      {feature.title}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {feature.description}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Paper id="tasks-section" sx={{ p: 4, mb: 4, borderRadius: 3 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
            Common Tasks in IDA
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, color: "text.secondary" }}>
            These mini playbooks keep you focused on practical goals when the binary feels overwhelming.
          </Typography>
          {commonTasks.map((task) => (
            <Accordion key={task.title} sx={{ mb: 1.5 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 700 }}>{task.title}</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <List dense>
                  {task.steps.map((step) => (
                    <ListItem key={step} sx={{ px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <TipsAndUpdatesIcon sx={{ color: "#f59e0b" }} />
                      </ListItemIcon>
                      <ListItemText primary={step} />
                    </ListItem>
                  ))}
                </List>
              </AccordionDetails>
            </Accordion>
          ))}
        </Paper>

        <Paper id="checklist-section" sx={{ p: 4, mb: 4, borderRadius: 3 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
            Analysis Checklist and Pitfalls
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                Checklist
              </Typography>
              <List dense>
                {checklist.map((item) => (
                  <ListItem key={item} sx={{ px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon sx={{ color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                Common Pitfalls
              </Typography>
              <List dense>
                {pitfalls.map((item) => (
                  <ListItem key={item} sx={{ px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <BuildIcon sx={{ color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>

          <Alert severity="info" sx={{ mt: 3 }}>
            <AlertTitle>Safety Reminder</AlertTitle>
            Always analyze untrusted binaries in an isolated environment, and only reverse engineer software
            you are authorized to inspect. Keep original samples intact when testing patches or edits.
          </Alert>
        </Paper>

        <Paper id="scripting-section" sx={{ p: 4, mb: 4, borderRadius: 3 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
            IDAPython Starter Snippet
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, color: "text.secondary" }}>
            This short script lists functions and prints their addresses. It is a simple way to learn the
            IDAPython API and verify that you can access the database programmatically.
          </Typography>
          <CodeBlock
            title="List functions and names"
            code={`import idautils
import idc

count = 0
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    print(hex(ea), name)
    count += 1

print("Total functions:", count)`}
          />
        </Paper>

        <Paper id="shortcuts-section" sx={{ p: 4, mb: 4, borderRadius: 3 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
            Essential Keyboard Shortcuts
          </Typography>
          <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.08) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Shortcut</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Action</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {keyboardShortcuts.map((row) => (
                  <TableRow key={row.shortcut}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.shortcut}</TableCell>
                    <TableCell>{row.action}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        <Paper id="practice-section" sx={{ p: 4, mb: 5, borderRadius: 3 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
            Practice Routine for Beginners
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, color: "text.secondary" }}>
            Short, repeatable drills help build muscle memory without getting lost.
          </Typography>
          <Grid container spacing={2}>
            {practiceDrills.map((drill) => (
              <Grid item xs={12} md={6} key={drill.title}>
                <Paper
                  sx={{
                    p: 3,
                    borderRadius: 2,
                    border: `1px solid ${alpha("#0ea5e9", 0.25)}`,
                    bgcolor: alpha("#0ea5e9", 0.06),
                  }}
                >
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
                    {drill.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {drill.description}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        <QuizSection />

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
            </Box>
          </Box>
        </Container>
      </Box>

      {/* Mobile Navigation Drawer */}
      <Drawer
        anchor="left"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: {
            bgcolor: "#0f1422",
            width: 280,
          },
        }}
      >
        <Box sx={{ p: 2, borderBottom: "1px solid rgba(255,255,255,0.1)" }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <Typography variant="h6" sx={{ color: "#6366f1", fontWeight: 700 }}>
              Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} sx={{ color: "grey.400" }}>
              <CloseIcon />
            </IconButton>
          </Box>
        </Box>
        {sidebarNav}
      </Drawer>

      {/* Mobile Navigation FAB */}
      {isMobile && (
        <Fab
          color="primary"
          size="medium"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: 80,
            right: 16,
            bgcolor: "#6366f1",
            "&:hover": { bgcolor: "#4f46e5" },
          }}
        >
          <ListAltIcon />
        </Fab>
      )}

      {/* Scroll to Top FAB */}
      {showScrollTop && (
        <Fab
          size="small"
          onClick={scrollToTop}
          sx={{
            position: "fixed",
            bottom: 16,
            right: 16,
            bgcolor: "rgba(99, 102, 241, 0.8)",
            "&:hover": { bgcolor: "#6366f1" },
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      )}
    </LearnPageLayout>
  );
}
