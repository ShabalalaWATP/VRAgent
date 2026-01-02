import React, { useState } from "react";
import {
  Box,
  Typography,
  Container,
  Paper,
  Tabs,
  Tab,
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
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  alpha,
  useTheme,
  Button,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import MemoryIcon from "@mui/icons-material/Memory";
import SearchIcon from "@mui/icons-material/Search";
import CodeIcon from "@mui/icons-material/Code";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import BuildIcon from "@mui/icons-material/Build";
import SchoolIcon from "@mui/icons-material/School";
import SpeedIcon from "@mui/icons-material/Speed";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import FunctionsIcon from "@mui/icons-material/Functions";
import SettingsIcon from "@mui/icons-material/Settings";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import QuizIcon from "@mui/icons-material/Quiz";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import RefreshIcon from "@mui/icons-material/Refresh";
import LearnPageLayout from "../components/LearnPageLayout";

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
  // Section 1: Ghidra Basics (8 questions)
  {
    id: 1,
    question: "Who developed Ghidra?",
    options: ["Microsoft", "Google", "NSA (National Security Agency)", "MIT"],
    correctAnswer: 2,
    explanation: "Ghidra was developed by the NSA and released as open-source in 2019.",
    topic: "Ghidra Basics"
  },
  {
    id: 2,
    question: "What programming language is Ghidra primarily written in?",
    options: ["Python", "C++", "Java", "Rust"],
    correctAnswer: 2,
    explanation: "Ghidra is primarily written in Java, which allows it to run on multiple platforms.",
    topic: "Ghidra Basics"
  },
  {
    id: 3,
    question: "What is the main advantage of Ghidra over many commercial tools?",
    options: ["It's faster", "It's free and open-source", "It has better graphics", "It only works on Windows"],
    correctAnswer: 1,
    explanation: "Ghidra is completely free and open-source, unlike commercial tools like IDA Pro.",
    topic: "Ghidra Basics"
  },
  {
    id: 4,
    question: "What file formats does Ghidra support?",
    options: ["Only PE files", "Only ELF files", "Multiple formats including PE, ELF, Mach-O, DEX, and more", "Only raw binaries"],
    correctAnswer: 2,
    explanation: "Ghidra supports many formats including PE, ELF, Mach-O, DEX, APK, firmware, and more.",
    topic: "Ghidra Basics"
  },
  {
    id: 5,
    question: "What is the keyboard shortcut to open the decompiler view in Ghidra?",
    options: ["Ctrl+D", "Ctrl+E", "F5", "Alt+D"],
    correctAnswer: 1,
    explanation: "Ctrl+E opens the decompiler window in Ghidra.",
    topic: "Ghidra Basics"
  },
  {
    id: 6,
    question: "What is a Ghidra project?",
    options: ["A single binary file", "A container that holds one or more programs for analysis", "A Python script", "A configuration file"],
    correctAnswer: 1,
    explanation: "A Ghidra project is a container that can hold multiple programs/binaries for analysis.",
    topic: "Ghidra Basics"
  },
  {
    id: 7,
    question: "How do you navigate to a specific address in Ghidra?",
    options: ["Press A", "Press G and type the address", "Double-click anywhere", "Press Ctrl+A"],
    correctAnswer: 1,
    explanation: "Press G to open the 'Go To' dialog and enter the address you want to navigate to.",
    topic: "Ghidra Basics"
  },
  {
    id: 8,
    question: "What is auto-analysis in Ghidra?",
    options: ["Manual function detection", "Automatic initial analysis that identifies functions, strings, and data", "A plugin system", "A debugging feature"],
    correctAnswer: 1,
    explanation: "Auto-analysis automatically analyzes the binary to identify functions, strings, references, and more.",
    topic: "Ghidra Basics"
  },

  // Section 2: Code Browser & Views (8 questions)
  {
    id: 9,
    question: "What is the Listing View in Ghidra?",
    options: ["A file browser", "The main disassembly view showing assembly code", "A log window", "A plugin manager"],
    correctAnswer: 1,
    explanation: "The Listing View is the main disassembly window showing assembly instructions with addresses and bytes.",
    topic: "Code Browser & Views"
  },
  {
    id: 10,
    question: "What does the Symbol Tree show?",
    options: ["Only imported functions", "All symbols including functions, labels, namespaces, and classes", "Only strings", "Only variables"],
    correctAnswer: 1,
    explanation: "The Symbol Tree shows all symbols in the program including functions, labels, namespaces, and classes.",
    topic: "Code Browser & Views"
  },
  {
    id: 11,
    question: "How do you view cross-references (XRefs) to a function or address?",
    options: ["Press X", "Press R", "Press C", "Press F"],
    correctAnswer: 0,
    explanation: "Press X to show all cross-references to the current address or symbol.",
    topic: "Code Browser & Views"
  },
  {
    id: 12,
    question: "What is the Function Graph view?",
    options: ["A list of all functions", "A visual representation of control flow with basic blocks", "A call graph", "A memory map"],
    correctAnswer: 1,
    explanation: "The Function Graph shows the control flow of a function with basic blocks connected by edges.",
    topic: "Code Browser & Views"
  },
  {
    id: 13,
    question: "How do you access the Function Graph in Ghidra?",
    options: ["Press G", "Press Space while in the Listing view", "Press F", "Press Tab"],
    correctAnswer: 1,
    explanation: "Press Space while in the Listing view to toggle the Function Graph display.",
    topic: "Code Browser & Views"
  },
  {
    id: 14,
    question: "What does the Bytes view display?",
    options: ["Only ASCII strings", "Raw hexadecimal bytes of the binary", "Only code bytes", "Encrypted data only"],
    correctAnswer: 1,
    explanation: "The Bytes view shows the raw hexadecimal representation of the binary file.",
    topic: "Code Browser & Views"
  },
  {
    id: 15,
    question: "What is the Data Type Manager?",
    options: ["A file manager", "A tool to define and manage data types and structures", "A debugging tool", "A memory analyzer"],
    correctAnswer: 1,
    explanation: "The Data Type Manager lets you create, modify, and apply data types and structures to the binary.",
    topic: "Code Browser & Views"
  },
  {
    id: 16,
    question: "What does the Defined Strings window show?",
    options: ["All bytes in the file", "Strings that Ghidra has identified in the binary", "Function names only", "Comments only"],
    correctAnswer: 1,
    explanation: "The Defined Strings window lists all strings Ghidra has found and defined in the binary.",
    topic: "Code Browser & Views"
  },

  // Section 3: Decompiler (9 questions)
  {
    id: 17,
    question: "What does the decompiler do?",
    options: ["Compiles source code", "Converts assembly back to pseudo-C code", "Encrypts code", "Debugs the binary"],
    correctAnswer: 1,
    explanation: "The decompiler converts low-level assembly code into higher-level pseudo-C for easier analysis.",
    topic: "Decompiler"
  },
  {
    id: 18,
    question: "How do you rename a variable in the decompiler view?",
    options: ["Press R", "Press L or right-click and rename", "Press N", "Press V"],
    correctAnswer: 1,
    explanation: "Press L or right-click on a variable and select 'Rename Variable' to give it a meaningful name.",
    topic: "Decompiler"
  },
  {
    id: 19,
    question: "How do you change a variable's type in the decompiler?",
    options: ["Press T or right-click and retype", "Press C", "Press D", "Press Y"],
    correctAnswer: 0,
    explanation: "Press T or right-click on a variable to change its data type.",
    topic: "Decompiler"
  },
  {
    id: 20,
    question: "What happens when you make changes in the decompiler?",
    options: ["Changes only affect the decompiler view", "Changes are synchronized with the Listing view", "Changes are lost on exit", "Nothing happens"],
    correctAnswer: 1,
    explanation: "Changes made in the decompiler (renaming, retyping) are synchronized with the Listing view and saved.",
    topic: "Decompiler"
  },
  {
    id: 21,
    question: "What is the purpose of the 'Commit Locals' action?",
    options: ["Save the project", "Apply inferred variable types and locations from decompiler to the function", "Delete local variables", "Export the function"],
    correctAnswer: 1,
    explanation: "Commit Locals applies the decompiler's inferred variable information to the function definition.",
    topic: "Decompiler"
  },
  {
    id: 22,
    question: "How does Ghidra handle optimized code in decompilation?",
    options: ["It cannot decompile optimized code", "It attempts to reconstruct logic but may show less readable output", "It automatically deoptimizes", "It refuses to open optimized binaries"],
    correctAnswer: 1,
    explanation: "Ghidra can decompile optimized code but the output may be harder to read due to inlining and other optimizations.",
    topic: "Decompiler"
  },
  {
    id: 23,
    question: "What is the 'Edit Function Signature' option used for?",
    options: ["Changing the function's address", "Correcting the function's return type and parameters", "Deleting the function", "Encrypting the function"],
    correctAnswer: 1,
    explanation: "Edit Function Signature lets you correct or define the return type, calling convention, and parameters.",
    topic: "Decompiler"
  },
  {
    id: 24,
    question: "What does the decompiler parameter ID analysis do?",
    options: ["Encrypts parameters", "Attempts to identify function parameters and their types", "Deletes parameters", "Exports parameters to a file"],
    correctAnswer: 1,
    explanation: "Parameter ID analysis tries to determine the number and types of function parameters.",
    topic: "Decompiler"
  },
  {
    id: 25,
    question: "How do you navigate from decompiler back to assembly?",
    options: ["Press Escape", "Click on code in decompiler to sync with Listing", "Press Home", "Close the decompiler"],
    correctAnswer: 1,
    explanation: "Clicking on code in the decompiler will highlight the corresponding assembly in the Listing view.",
    topic: "Decompiler"
  },

  // Section 4: Functions & Analysis (9 questions)
  {
    id: 26,
    question: "How do you create a function at an address in Ghidra?",
    options: ["Press C", "Press F", "Press D", "Press A"],
    correctAnswer: 1,
    explanation: "Press F to create a function at the current address.",
    topic: "Functions & Analysis"
  },
  {
    id: 27,
    question: "What does 'Undefined' mean in Ghidra?",
    options: ["Corrupted data", "Bytes that haven't been analyzed or defined as code/data", "Encrypted bytes", "Empty bytes"],
    correctAnswer: 1,
    explanation: "Undefined bytes haven't been analyzed or defined as code, data, or any other type.",
    topic: "Functions & Analysis"
  },
  {
    id: 28,
    question: "How do you disassemble undefined bytes as code?",
    options: ["Press D", "Press C (or right-click and Disassemble)", "Press X", "Press L"],
    correctAnswer: 1,
    explanation: "Press C to disassemble undefined bytes as code at the current address.",
    topic: "Functions & Analysis"
  },
  {
    id: 29,
    question: "What does 'D' do in the Listing view?",
    options: ["Deletes code", "Defines data at the current address", "Disassembles code", "Duplicates the line"],
    correctAnswer: 1,
    explanation: "D defines data (like a DWORD, string, etc.) at the current address.",
    topic: "Functions & Analysis"
  },
  {
    id: 30,
    question: "What is a thunk function?",
    options: ["A deleted function", "A small function that just jumps to another function (often for imports)", "An encrypted function", "A recursive function"],
    correctAnswer: 1,
    explanation: "A thunk is a small wrapper function that typically just jumps to another function, common for imports.",
    topic: "Functions & Analysis"
  },
  {
    id: 31,
    question: "How do you add a comment in Ghidra?",
    options: ["Press C", "Press ; for EOL comment, Ctrl+; for pre-comment", "Press N", "Press Tab"],
    correctAnswer: 1,
    explanation: "Press ; for end-of-line comment, or Ctrl+; for pre-comment (comment before the instruction).",
    topic: "Functions & Analysis"
  },
  {
    id: 32,
    question: "What is the purpose of creating bookmarks?",
    options: ["To delete code", "To mark important locations for easy navigation", "To encrypt sections", "To export functions"],
    correctAnswer: 1,
    explanation: "Bookmarks let you mark important locations and quickly navigate back to them later.",
    topic: "Functions & Analysis"
  },
  {
    id: 33,
    question: "How do you create a bookmark?",
    options: ["Press B", "Press Ctrl+D", "Press M", "Press K"],
    correctAnswer: 1,
    explanation: "Press Ctrl+D to create a bookmark at the current address.",
    topic: "Functions & Analysis"
  },
  {
    id: 34,
    question: "What is the Function Call Graph?",
    options: ["A list of functions", "A graph showing which functions call which other functions", "A memory map", "A string list"],
    correctAnswer: 1,
    explanation: "The Function Call Graph visualizes the calling relationships between functions.",
    topic: "Functions & Analysis"
  },

  // Section 5: Scripting & Automation (8 questions)
  {
    id: 35,
    question: "What scripting languages does Ghidra support?",
    options: ["Only Python", "Only Java", "Java and Python (via Jython)", "JavaScript only"],
    correctAnswer: 2,
    explanation: "Ghidra supports both Java and Python (via Jython) for scripting and automation.",
    topic: "Scripting & Automation"
  },
  {
    id: 36,
    question: "How do you access the Script Manager in Ghidra?",
    options: ["File menu", "Window > Script Manager", "Help menu", "Edit menu"],
    correctAnswer: 1,
    explanation: "Open the Script Manager from Window > Script Manager to browse and run scripts.",
    topic: "Scripting & Automation"
  },
  {
    id: 37,
    question: "What is 'currentProgram' in a Ghidra script?",
    options: ["The script itself", "A reference to the currently open program/binary", "A Python module", "A configuration object"],
    correctAnswer: 1,
    explanation: "currentProgram is a built-in variable that provides access to the currently open binary.",
    topic: "Scripting & Automation"
  },
  {
    id: 38,
    question: "What does 'currentAddress' represent in a script?",
    options: ["The entry point", "The address where the cursor is currently located", "The first byte of the file", "The last address"],
    correctAnswer: 1,
    explanation: "currentAddress is the address where the cursor is positioned in the Listing view.",
    topic: "Scripting & Automation"
  },
  {
    id: 39,
    question: "How do you get all functions in a program via script?",
    options: ["getSymbols()", "currentProgram.getFunctionManager().getFunctions(True)", "listFunctions()", "getAllFunctions()"],
    correctAnswer: 1,
    explanation: "Use currentProgram.getFunctionManager().getFunctions(True) to iterate over all functions.",
    topic: "Scripting & Automation"
  },
  {
    id: 40,
    question: "What is headless analysis in Ghidra?",
    options: ["Analysis without the GUI for batch processing", "Analysis of header files only", "Analysis with reduced features", "Analysis without decompilation"],
    correctAnswer: 0,
    explanation: "Headless analysis runs Ghidra without the GUI, enabling automated batch analysis of many files.",
    topic: "Scripting & Automation"
  },
  {
    id: 41,
    question: "How do you run headless analysis?",
    options: ["ghidra --headless", "Use analyzeHeadless script in support directory", "ghidra -nogui", "ghidra --batch"],
    correctAnswer: 1,
    explanation: "Use the analyzeHeadless script (analyzeHeadless.bat on Windows) from the support directory.",
    topic: "Scripting & Automation"
  },
  {
    id: 42,
    question: "What is the FlatProgramAPI?",
    options: ["A REST API", "A simplified API for common scripting tasks in Ghidra", "A file format API", "A network API"],
    correctAnswer: 1,
    explanation: "FlatProgramAPI provides simplified methods for common tasks like finding functions, getting bytes, etc.",
    topic: "Scripting & Automation"
  },

  // Section 6: Data Types & Structures (8 questions)
  {
    id: 43,
    question: "How do you apply a structure to memory in Ghidra?",
    options: ["Press S", "Press T and select the structure type", "Press D", "Press C"],
    correctAnswer: 1,
    explanation: "Press T to open the data type dialog and select a structure to apply at the current address.",
    topic: "Data Types & Structures"
  },
  {
    id: 44,
    question: "Where do you create custom structures in Ghidra?",
    options: ["In the Listing view", "In the Data Type Manager", "In the Script Manager", "In the Console"],
    correctAnswer: 1,
    explanation: "Use the Data Type Manager to create, edit, and organize custom data types and structures.",
    topic: "Data Types & Structures"
  },
  {
    id: 45,
    question: "What is a Data Type Archive in Ghidra?",
    options: ["A compressed file", "A collection of data types that can be shared between projects", "A backup file", "A log file"],
    correctAnswer: 1,
    explanation: "Data Type Archives (.gdt files) contain data types that can be shared across multiple projects.",
    topic: "Data Types & Structures"
  },
  {
    id: 46,
    question: "How do you import Windows API data types?",
    options: ["They're always included", "Open the windows.gdt archive from the Ghidra installation", "Download from Microsoft", "Create them manually"],
    correctAnswer: 1,
    explanation: "Ghidra includes windows.gdt archive with Windows API types - open it via the Data Type Manager.",
    topic: "Data Types & Structures"
  },
  {
    id: 47,
    question: "What is an enum in Ghidra?",
    options: ["A function type", "A data type with named integer constants", "A string type", "A pointer type"],
    correctAnswer: 1,
    explanation: "An enum (enumeration) is a data type consisting of named integer constants (like error codes).",
    topic: "Data Types & Structures"
  },
  {
    id: 48,
    question: "How do you create an array in the Listing view?",
    options: ["Press A", "Press [ and specify the count", "Right-click > Data > Create Array", "Press R"],
    correctAnswer: 2,
    explanation: "Right-click on defined data and select Data > Create Array, then specify the element count.",
    topic: "Data Types & Structures"
  },
  {
    id: 49,
    question: "What is a typedef in Ghidra?",
    options: ["A new type", "An alias for an existing data type", "A function definition", "A variable declaration"],
    correctAnswer: 1,
    explanation: "A typedef creates an alias or alternative name for an existing data type.",
    topic: "Data Types & Structures"
  },
  {
    id: 50,
    question: "How do you define a string at an address?",
    options: ["Press S", "Place cursor and choose Data > string type (or use keyboard shortcut for specific string type)", "Press Q", "Press W"],
    correctAnswer: 1,
    explanation: "Select the address, then use Data menu or shortcuts to define the string type (ASCII, Unicode, etc.).",
    topic: "Data Types & Structures"
  },

  // Section 7: Patching & Modifying (7 questions)
  {
    id: 51,
    question: "Can you patch (modify) bytes in Ghidra?",
    options: ["No, Ghidra is read-only", "Yes, using the Patch Instruction or Patch Data features", "Only in the decompiler", "Only with plugins"],
    correctAnswer: 1,
    explanation: "Ghidra supports patching via Patch Instruction (Ctrl+Shift+G) and direct byte modification.",
    topic: "Patching & Modifying"
  },
  {
    id: 52,
    question: "How do you patch an instruction in Ghidra?",
    options: ["Press P", "Press Ctrl+Shift+G", "Press M", "Press E"],
    correctAnswer: 1,
    explanation: "Press Ctrl+Shift+G to open the Patch Instruction dialog where you can modify assembly.",
    topic: "Patching & Modifying"
  },
  {
    id: 53,
    question: "Where can you directly edit bytes in Ghidra?",
    options: ["Only in the Listing", "In the Bytes view using the edit mode", "Only in scripts", "You cannot edit bytes"],
    correctAnswer: 1,
    explanation: "Enable edit mode in the Bytes view to directly modify hexadecimal values.",
    topic: "Patching & Modifying"
  },
  {
    id: 54,
    question: "How do you export a patched binary?",
    options: ["Save Project", "File > Export Program and choose format", "Copy and paste", "Use the Console"],
    correctAnswer: 1,
    explanation: "Use File > Export Program to save the modified binary in various formats (original, ELF, PE, etc.).",
    topic: "Patching & Modifying"
  },
  {
    id: 55,
    question: "What is NOPing out code?",
    options: ["Deleting code", "Replacing instructions with NOP (no operation) to disable functionality", "Encrypting code", "Commenting code"],
    correctAnswer: 1,
    explanation: "NOPing replaces instructions with NOP (0x90 on x86) to effectively disable that code path.",
    topic: "Patching & Modifying"
  },
  {
    id: 56,
    question: "Why might you patch a conditional jump to an unconditional jump?",
    options: ["To make code faster", "To bypass a check (like license validation) by always taking one path", "To add new features", "To compress the binary"],
    correctAnswer: 1,
    explanation: "Changing a conditional jump (JZ/JNZ) to unconditional (JMP) bypasses checks by forcing one code path.",
    topic: "Patching & Modifying"
  },
  {
    id: 57,
    question: "What should you be careful about when patching?",
    options: ["Color scheme", "Instruction length must match or be adjusted for, and not breaking relative references", "Font size", "Window position"],
    correctAnswer: 1,
    explanation: "Patches must account for instruction sizes and not break relative jumps/calls or corrupt other code.",
    topic: "Patching & Modifying"
  },

  // Section 8: Debugging Integration (6 questions)
  {
    id: 58,
    question: "Does Ghidra have a built-in debugger?",
    options: ["No debugging support", "Yes, Ghidra has integrated debugging capabilities", "Only for Java", "Only for Python"],
    correctAnswer: 1,
    explanation: "Ghidra includes debugging capabilities for analyzing running programs (introduced in version 10+).",
    topic: "Debugging Integration"
  },
  {
    id: 59,
    question: "What debuggers can Ghidra connect to?",
    options: ["Only GDB", "Only WinDbg", "GDB, WinDbg, LLDB, and others via connectors", "No external debuggers"],
    correctAnswer: 2,
    explanation: "Ghidra can connect to various debuggers including GDB, WinDbg, and LLDB through its debugger connectors.",
    topic: "Debugging Integration"
  },
  {
    id: 60,
    question: "What is the advantage of debugging in Ghidra?",
    options: ["Faster execution", "Combines static analysis with dynamic debugging in one tool", "Better graphics", "Smaller memory usage"],
    correctAnswer: 1,
    explanation: "Ghidra's debugging integration allows you to use your static analysis alongside dynamic debugging.",
    topic: "Debugging Integration"
  },
  {
    id: 61,
    question: "How do you set a breakpoint in Ghidra's debugger?",
    options: ["Press B", "Right-click in Listing and select toggle breakpoint, or use the Breakpoints window", "Press F9", "Press P"],
    correctAnswer: 1,
    explanation: "Set breakpoints by right-clicking in the Listing view or using the Breakpoints tool window.",
    topic: "Debugging Integration"
  },
  {
    id: 62,
    question: "What is the Registers window in debugging mode?",
    options: ["Shows file registers", "Displays CPU register values during debugging", "Shows memory regions", "Lists all variables"],
    correctAnswer: 1,
    explanation: "The Registers window shows current CPU register values (EAX, EBX, RIP, etc.) during debugging.",
    topic: "Debugging Integration"
  },
  {
    id: 63,
    question: "Can you modify registers while debugging in Ghidra?",
    options: ["No", "Yes, you can modify register values during debugging", "Only in scripts", "Only on Linux"],
    correctAnswer: 1,
    explanation: "You can modify register values in the Registers window to alter program execution.",
    topic: "Debugging Integration"
  },

  // Section 9: Collaboration & Server (6 questions)
  {
    id: 64,
    question: "What is Ghidra Server?",
    options: ["A web interface", "A server for collaborative reverse engineering with shared projects", "A malware database", "A file server"],
    correctAnswer: 1,
    explanation: "Ghidra Server enables teams to work together on the same project with version control.",
    topic: "Collaboration & Server"
  },
  {
    id: 65,
    question: "What is the default port for Ghidra Server?",
    options: ["8080", "443", "13100", "22"],
    correctAnswer: 2,
    explanation: "Ghidra Server uses port 13100 by default for client connections.",
    topic: "Collaboration & Server"
  },
  {
    id: 66,
    question: "How do you connect to a shared Ghidra project?",
    options: ["Open a local file", "File > New Project > Shared Project", "Import from URL", "Use FTP"],
    correctAnswer: 1,
    explanation: "Create a new Shared Project and provide the server address and credentials to connect.",
    topic: "Collaboration & Server"
  },
  {
    id: 67,
    question: "What happens when multiple people edit the same function?",
    options: ["It crashes", "Ghidra uses version control with checkouts and merging", "Only one person can work at a time", "Changes are lost"],
    correctAnswer: 1,
    explanation: "Ghidra Server uses version control - users check out files and can merge or resolve conflicts.",
    topic: "Collaboration & Server"
  },
  {
    id: 68,
    question: "How do you add a user to Ghidra Server?",
    options: ["Through the GUI", "Using svrAdmin command-line tool", "Edit a text file", "Via web interface"],
    correctAnswer: 1,
    explanation: "Use the svrAdmin command-line tool to add, remove, and manage users on the server.",
    topic: "Collaboration & Server"
  },
  {
    id: 69,
    question: "Can you undo changes in a shared project?",
    options: ["No", "Yes, using version history", "Only the admin can", "Only before saving"],
    correctAnswer: 1,
    explanation: "Shared projects maintain version history, allowing you to review and revert changes.",
    topic: "Collaboration & Server"
  },

  // Section 10: Advanced Features & Tips (6 questions)
  {
    id: 70,
    question: "What is the Entropy view useful for?",
    options: ["Showing code quality", "Identifying encrypted, compressed, or packed sections", "Measuring CPU usage", "Counting functions"],
    correctAnswer: 1,
    explanation: "The Entropy view helps identify encrypted, compressed, or packed data by showing randomness levels.",
    topic: "Advanced Features"
  },
  {
    id: 71,
    question: "What is Version Tracking in Ghidra?",
    options: ["Project version control", "Comparing and matching functions between different program versions", "Tracking Ghidra updates", "User activity logging"],
    correctAnswer: 1,
    explanation: "Version Tracking compares two binaries to identify matching functions (useful for patch diffing).",
    topic: "Advanced Features"
  },
  {
    id: 72,
    question: "How do you import function signatures from a header file?",
    options: ["Copy and paste", "File > Parse C Source", "Use a plugin", "It's not possible"],
    correctAnswer: 1,
    explanation: "Use File > Parse C Source to import function signatures and data types from C header files.",
    topic: "Advanced Features"
  },
  {
    id: 73,
    question: "What are Ghidra extensions?",
    options: ["File extensions Ghidra supports", "Plugins that add new features and capabilities to Ghidra", "Processor definitions", "Memory extensions"],
    correctAnswer: 1,
    explanation: "Extensions are plugins that extend Ghidra with new analyzers, exporters, loaders, and features.",
    topic: "Advanced Features"
  },
  {
    id: 74,
    question: "Where can you find community Ghidra scripts and plugins?",
    options: ["Only from NSA", "GitHub repositories like ghidra-scripts and ghidra-contrib", "Microsoft Store", "App Store"],
    correctAnswer: 1,
    explanation: "The community shares scripts and plugins on GitHub - search for 'ghidra scripts' or 'ghidra plugins'.",
    topic: "Advanced Features"
  },
  {
    id: 75,
    question: "What is SLEIGH in Ghidra?",
    options: ["A debugging tool", "The processor specification language used to define instruction sets", "A scripting language", "A file format"],
    correctAnswer: 1,
    explanation: "SLEIGH is Ghidra's language for defining processor specifications and instruction semantics.",
    topic: "Advanced Features"
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
    if (score === 10) return "Perfect! You're a Ghidra master! 🏆";
    if (score >= 8) return "Excellent work! Strong Ghidra skills! 🌟";
    if (score >= 6) return "Good job! Keep practicing with Ghidra! 📚";
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
          border: `2px solid ${alpha("#10b981", 0.3)}`,
          background: `linear-gradient(135deg, ${alpha("#10b981", 0.05)} 0%, ${alpha("#059669", 0.05)} 100%)`,
        }}
      >
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <Box sx={{ width: 56, height: 56, borderRadius: 2, background: "linear-gradient(135deg, #10b981, #059669)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <QuizIcon sx={{ color: "white", fontSize: 32 }} />
          </Box>
          Test Your Ghidra Knowledge
        </Typography>

        <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8, fontSize: "1.05rem" }}>
          Ready to test what you've learned? Take this <strong>10-question quiz</strong> covering all aspects of 
          Ghidra. Questions are randomly selected from a pool of <strong>75 questions</strong>, so each attempt is different!
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
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#8b5cf6" }}>10</Typography>
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
          sx={{ background: "linear-gradient(135deg, #10b981, #059669)", fontWeight: 700, px: 4, py: 1.5, fontSize: "1.1rem", "&:hover": { background: "linear-gradient(135deg, #059669, #047857)" } }}
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
          <Button variant="contained" onClick={startQuiz} startIcon={<RefreshIcon />} sx={{ background: "linear-gradient(135deg, #10b981, #059669)", fontWeight: 700 }}>Try Again</Button>
          <Button variant="outlined" onClick={() => setQuizStarted(false)} sx={{ fontWeight: 600 }}>Back to Overview</Button>
        </Box>
      </Paper>
    );
  }

  const currentQuestion = currentQuestions[currentQuestionIndex];
  const answeredCount = Object.keys(userAnswers).length;

  return (
    <Paper id="quiz-section" sx={{ p: 4, mb: 5, borderRadius: 4, bgcolor: alpha(theme.palette.background.paper, 0.6), border: `2px solid ${alpha("#10b981", 0.3)}` }}>
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Question {currentQuestionIndex + 1} of 10</Typography>
          <Chip label={currentQuestion.topic} size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
        </Box>
        <Box sx={{ width: "100%", bgcolor: alpha("#10b981", 0.1), borderRadius: 1, height: 8 }}>
          <Box sx={{ width: `${((currentQuestionIndex + 1) / 10) * 100}%`, bgcolor: "#10b981", borderRadius: 1, height: "100%", transition: "width 0.3s ease" }} />
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

// TabPanel component
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

// Code block component with copy
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
    <Paper
      sx={{
        mt: 2,
        mb: 2,
        overflow: "hidden",
        border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
      }}
    >
      {title && (
        <Box
          sx={{
            px: 2,
            py: 1,
            bgcolor: alpha(theme.palette.primary.main, 0.1),
            borderBottom: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <Typography variant="caption" fontWeight="bold" color="primary">
            {title}
          </Typography>
          <Tooltip title={copied ? "Copied!" : "Copy"}>
            <IconButton size="small" onClick={handleCopy}>
              <ContentCopyIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      )}
      <Box
        component="pre"
        sx={{
          m: 0,
          p: 2,
          overflow: "auto",
          bgcolor: theme.palette.mode === "dark" ? "#1a1a2e" : "#f8f9fa",
          fontSize: "0.85rem",
          fontFamily: "monospace",
          "& code": { fontFamily: "inherit" },
        }}
      >
        <code>{children}</code>
      </Box>
    </Paper>
  );
}

// Data arrays for expandable content
const ghidraWindows = [
  {
    name: "Listing View",
    shortcut: "L",
    description: "Main disassembly view showing assembly instructions with addresses, bytes, and comments",
  },
  {
    name: "Decompiler",
    shortcut: "Ctrl+E",
    description: "Converts assembly to pseudo-C code, making it easier to understand program logic",
  },
  {
    name: "Function Graph",
    shortcut: "Space (in Listing)",
    description: "Visual control flow graph showing basic blocks and their connections",
  },
  {
    name: "Symbol Tree",
    shortcut: "Ctrl+Shift+E",
    description: "Browse all functions, labels, classes, namespaces, and data types",
  },
  {
    name: "Data Type Manager",
    shortcut: "Ctrl+Shift+T",
    description: "Manage structs, enums, unions, and typedefs for better type analysis",
  },
  {
    name: "Bytes View",
    shortcut: "",
    description: "Raw hex dump of the binary with highlighting for selected regions",
  },
  {
    name: "Program Trees",
    shortcut: "",
    description: "View memory segments, sections, and organizational structure",
  },
];

const keyboardShortcuts = [
  { shortcut: "G", action: "Go to address/label" },
  { shortcut: "L", action: "Edit label/rename symbol" },
  { shortcut: "T", action: "Set data type" },
  { shortcut: ";", action: "Add comment (EOL)" },
  { shortcut: "Ctrl+;", action: "Add plate comment" },
  { shortcut: "D", action: "Define data at cursor" },
  { shortcut: "C", action: "Clear code/data definition" },
  { shortcut: "F", action: "Create function" },
  { shortcut: "X", action: "Show cross-references (XRefs)" },
  { shortcut: "N", action: "Next occurrence of selected text" },
  { shortcut: "Ctrl+Shift+F", action: "Search for strings" },
  { shortcut: "Ctrl+B", action: "Search for bytes" },
  { shortcut: "Alt+Left", action: "Go back in navigation history" },
  { shortcut: "Alt+Right", action: "Go forward in navigation history" },
];

const analysisFeatures = [
  {
    feature: "Auto Analysis",
    description: "Automatic disassembly, function detection, and type propagation",
    category: "Core",
  },
  {
    feature: "Decompilation",
    description: "High-quality C-like decompilation with variable recovery",
    category: "Core",
  },
  {
    feature: "Cross-References",
    description: "Track all references to/from any address, function, or data",
    category: "Navigation",
  },
  {
    feature: "Type Propagation",
    description: "Automatically propagate types through code analysis",
    category: "Analysis",
  },
  {
    feature: "Script Manager",
    description: "Java and Python scripting for automation and custom analysis",
    category: "Extensibility",
  },
  {
    feature: "Version Tracking",
    description: "Compare different versions of binaries to track changes",
    category: "Advanced",
  },
  {
    feature: "Collaborative Mode",
    description: "Multi-user analysis with Ghidra Server for team projects",
    category: "Advanced",
  },
  {
    feature: "PDB Support",
    description: "Load Windows debug symbols for better function/type names",
    category: "Symbols",
  },
];

const commonTasks = [
  {
    task: "Find main() or entry point",
    steps: ["Open Symbol Tree", "Look under 'Functions' for 'main' or 'entry'", "Or use Go To (G) and type 'main'"],
  },
  {
    task: "Rename a function",
    steps: ["Click on function name", "Press L (Label)", "Enter new meaningful name", "Press Enter"],
  },
  {
    task: "Add a comment",
    steps: ["Position cursor at instruction", "Press ; for end-of-line comment", "Or Ctrl+; for plate comment above"],
  },
  {
    task: "Follow a cross-reference",
    steps: ["Select function/variable", "Press X to see all XRefs", "Double-click to navigate"],
  },
  {
    task: "Define a structure",
    steps: ["Open Data Type Manager", "Right-click Archive → New → Structure", "Add fields with types and names"],
  },
  {
    task: "Search for strings",
    steps: ["Search → For Strings", "Set minimum length", "Filter results as needed"],
  },
];

const supportedProcessors = [
  { arch: "x86/x64", desc: "Intel/AMD desktop and server processors", common: true },
  { arch: "ARM/ARM64", desc: "Mobile devices, embedded systems, Apple Silicon", common: true },
  { arch: "MIPS", desc: "Networking equipment, older consoles, embedded", common: true },
  { arch: "PowerPC", desc: "Game consoles (Wii, Xbox 360), older Macs", common: false },
  { arch: "SPARC", desc: "Oracle/Sun servers and workstations", common: false },
  { arch: "AVR", desc: "Arduino and other microcontrollers", common: false },
  { arch: "68000", desc: "Classic Motorola processors, retro systems", common: false },
  { arch: "RISC-V", desc: "Open-source ISA, growing embedded use", common: false },
];

// Extended data arrays for detailed content
const analysisOptions = [
  { analyzer: "Aggressive Instruction Finder", desc: "Finds code that wasn't found through normal means", when: "Firmware, packed binaries" },
  { analyzer: "ASCII Strings", desc: "Finds and defines ASCII string data", when: "Always recommended" },
  { analyzer: "Create Address Tables", desc: "Searches for tables of addresses (vtables, etc.)", when: "C++ binaries, firmware" },
  { analyzer: "Data Reference", desc: "Creates data references from pointer tables", when: "Always recommended" },
  { analyzer: "Decompiler Parameter ID", desc: "Uses decompiler to identify function parameters", when: "After initial analysis" },
  { analyzer: "Demangler", desc: "Demangles C++ symbol names to readable form", when: "C++ binaries" },
  { analyzer: "Embedded Media", desc: "Finds embedded images, audio, etc.", when: "GUI applications" },
  { analyzer: "External Entry References", desc: "Creates refs to external entry points", when: "DLLs, shared libraries" },
  { analyzer: "Function Start Search", desc: "Looks for function prologues", when: "Stripped binaries" },
  { analyzer: "GCC Exception Handlers", desc: "Analyzes GCC exception handling structures", when: "Linux C++ binaries" },
  { analyzer: "Non-Returning Functions", desc: "Identifies functions that don't return (exit, abort)", when: "Always recommended" },
  { analyzer: "Stack", desc: "Analyzes stack frames and local variables", when: "Always recommended" },
  { analyzer: "Windows x86 PE Exception Handling", desc: "Analyzes SEH/VEH handlers", when: "Windows PE binaries" },
  { analyzer: "Windows x86 PE RTTI Analyzer", desc: "Recovers C++ RTTI type information", when: "Windows C++ binaries" },
];

const decompilerOptions = [
  { option: "Simplify predication", desc: "Simplifies conditional expressions" },
  { option: "Simplify register pairs", desc: "Combines register pairs into single variables" },
  { option: "Eliminate dead code", desc: "Removes code that doesn't affect output" },
  { option: "Max function size", desc: "Limit on decompiled function size (default 50MB)" },
  { option: "Analysis.Decompiler timeout", desc: "Timeout for decompilation (default 30s)" },
  { option: "Prototype evaluation", desc: "How to handle unknown function signatures" },
];

const dataTypeCategories = [
  { category: "BuiltIn", desc: "Primitive types (byte, word, dword, qword, float, etc.)", example: "dword, float, pointer" },
  { category: "Structures", desc: "User-defined composite types with named fields", example: "struct Person { char* name; int age; }" },
  { category: "Unions", desc: "Types where all fields share the same memory", example: "union { int i; float f; }" },
  { category: "Enums", desc: "Named integer constants", example: "enum Color { RED=0, GREEN=1, BLUE=2 }" },
  { category: "Typedefs", desc: "Aliases for existing types", example: "typedef unsigned long DWORD" },
  { category: "Function Definitions", desc: "Function pointer types with signatures", example: "int (*callback)(void*, int)" },
  { category: "Arrays", desc: "Fixed-size sequences of elements", example: "char[256], int[10]" },
  { category: "Pointers", desc: "References to other data types", example: "char*, DWORD*, struct Person*" },
];

const functionCallConventions = [
  { convention: "__cdecl", platform: "x86 Windows/Linux", desc: "Caller cleans stack, args right-to-left", registers: "EAX return" },
  { convention: "__stdcall", platform: "x86 Windows API", desc: "Callee cleans stack, args right-to-left", registers: "EAX return" },
  { convention: "__fastcall", platform: "x86", desc: "First 2 args in ECX/EDX, rest on stack", registers: "ECX, EDX, EAX return" },
  { convention: "__thiscall", platform: "x86 C++", desc: "Like cdecl but 'this' in ECX", registers: "ECX=this, EAX return" },
  { convention: "x64 Windows", platform: "x64 Windows", desc: "First 4 args in RCX,RDX,R8,R9", registers: "Shadow space required" },
  { convention: "System V AMD64", platform: "x64 Linux/Mac", desc: "First 6 args in RDI,RSI,RDX,RCX,R8,R9", registers: "Red zone (128 bytes)" },
  { convention: "ARM AAPCS", platform: "ARM 32-bit", desc: "First 4 args in R0-R3, rest on stack", registers: "R0 return, LR=return addr" },
  { convention: "ARM64", platform: "AArch64", desc: "First 8 args in X0-X7", registers: "X0 return, X30=LR" },
];

const patternRecognition = [
  { pattern: "Switch Table", desc: "Jump table for switch statements", indicators: "JMP [base + reg*4], table of addresses" },
  { pattern: "Virtual Function Table", desc: "C++ vtable for polymorphism", indicators: "Array of function pointers, RTTI nearby" },
  { pattern: "String XOR Decode", desc: "Obfuscated strings using XOR", indicators: "Loop with XOR, single key byte" },
  { pattern: "Stack Canary", desc: "Buffer overflow protection", indicators: "Check value against __stack_chk_fail" },
  { pattern: "PIC/PIE Code", desc: "Position-independent code", indicators: "GOT/PLT usage, RIP-relative addressing" },
  { pattern: "Tail Call", desc: "Optimized function call at return", indicators: "JMP instead of CALL+RET" },
  { pattern: "Loop Unrolling", desc: "Compiler optimization", indicators: "Repeated similar instructions" },
  { pattern: "Inline Function", desc: "Compiler-inlined code", indicators: "No CALL, duplicated code patterns" },
];

const scriptCategories = [
  { category: "Analysis", scripts: ["AnalyzeStackReferences", "CreateStructure", "FindPotentialDecompilerProblems"] },
  { category: "Data", scripts: ["ApplyDataArchive", "CreateArrayFromSelection", "DefineDataAt"] },
  { category: "Functions", scripts: ["FindFunctionsWithNoCallers", "FixupNoReturnFunctions", "SplitFunction"] },
  { category: "Memory", scripts: ["AddMemoryBlock", "MergeMemoryBlocks", "SplitMemoryBlock"] },
  { category: "Program", scripts: ["ComparePrograms", "DiffPrograms", "VersionTrackingDiff"] },
  { category: "Search", scripts: ["FindByteSequence", "FindInstructionPattern", "SearchForStringReferences"] },
  { category: "Selection", scripts: ["MakeSelection", "SelectByFlowFrom", "SelectByFlowTo"] },
  { category: "Headless", scripts: ["ExportCSV", "GenerateFunctionReport", "HeadlessAnalyzer"] },
];

const malwareAnalysisTips = [
  { tip: "Use a VM", desc: "Always analyze malware in an isolated virtual machine with snapshots" },
  { tip: "Check imports", desc: "Look at imported functions - networking, crypto, registry APIs are suspicious" },
  { tip: "Find C2 addresses", desc: "Search for IP addresses, URLs, and domain strings" },
  { tip: "Identify packing", desc: "High entropy sections, few imports, or known packer signatures indicate packing" },
  { tip: "Look for anti-analysis", desc: "IsDebuggerPresent, VM detection, timing checks" },
  { tip: "String decryption", desc: "Find XOR loops or crypto functions that decode strings at runtime" },
  { tip: "API hashing", desc: "Malware often resolves APIs by hash - look for hash constants" },
  { tip: "Persistence mechanisms", desc: "Registry keys, scheduled tasks, service creation" },
];

const ghidraExtensions = [
  { name: "ghidra-nsis", desc: "Support for NSIS installer scripts", category: "Loader" },
  { name: "ghidra-firmware-utils", desc: "Analysis tools for firmware (UEFI, etc.)", category: "Analysis" },
  { name: "GhiHorn", desc: "Binary analysis using SMT solvers", category: "Analysis" },
  { name: "ghidra-findcrypt", desc: "Identify cryptographic constants", category: "Analysis" },
  { name: "ret-sync", desc: "Sync Ghidra with debuggers (x64dbg, WinDbg)", category: "Integration" },
  { name: "ghidra-scripts", desc: "Community script collections", category: "Scripts" },
  { name: "Ghidra2Dwarf", desc: "Export Ghidra analysis to DWARF format", category: "Export" },
  { name: "ghidra-nodejs", desc: "Node.js analysis support", category: "Loader" },
];

const GhidraGuidePage: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const navigate = useNavigate();
  const theme = useTheme();

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const pageContext = `Ghidra Reverse Engineering Guide - Complete NSA-developed reverse engineering tool reference. Covers: installation and project setup, code browser interface, disassembly and decompilation, function analysis and renaming, cross-references (XREFs), data types and structures, Python scripting (Ghidra API), Java scripting, headless analysis, memory mapping, symbol management, function graphs, patch diffing, debugging integration, keyboard shortcuts, and community extensions. Essential for malware analysis, vulnerability research, and binary reverse engineering.`;

  return (
    <LearnPageLayout pageTitle="Ghidra Reverse Engineering Guide" pageContext={pageContext}>
    <Container maxWidth="xl" sx={{ py: 4 }}>
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

      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <MemoryIcon sx={{ fontSize: 40, color: "primary.main" }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              Ghidra Reverse Engineering Guide
            </Typography>
            <Typography variant="subtitle1" color="text.secondary">
              NSA's powerful open-source software reverse engineering framework
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* Introduction Section */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 2 }}>
        <Typography variant="h5" gutterBottom color="primary" fontWeight="bold">
          What is Ghidra?
        </Typography>
        
        <Typography paragraph sx={{ fontSize: "1.1rem", lineHeight: 1.8 }}>
          <strong>Ghidra</strong> (pronounced "GEE-dra") is a free, open-source software reverse engineering (SRE) tool 
          developed by the National Security Agency (NSA). Released to the public in 2019, Ghidra has quickly become 
          one of the most popular tools for analyzing compiled programs - competing directly with expensive commercial 
          tools like IDA Pro that can cost thousands of dollars.
        </Typography>

        <Typography paragraph sx={{ fontSize: "1.1rem", lineHeight: 1.8 }}>
          <strong>What does "reverse engineering" mean?</strong> When programmers write code, they use human-readable 
          languages like C, Python, or Java. This code is then <em>compiled</em> into machine code (binary) that computers 
          can execute. Reverse engineering is the process of taking that compiled binary and working backwards to understand 
          what it does - essentially trying to reconstruct the original logic and behavior of the program.
        </Typography>

        <Typography paragraph sx={{ fontSize: "1.1rem", lineHeight: 1.8 }}>
          <strong>Why would you need to do this?</strong> There are many legitimate reasons:
        </Typography>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          {[
            { icon: <BugReportIcon />, title: "Malware Analysis", desc: "Understanding how viruses, ransomware, and other threats work to develop defenses" },
            { icon: <SecurityIcon />, title: "Vulnerability Research", desc: "Finding security bugs in software when source code isn't available" },
            { icon: <BuildIcon />, title: "Legacy Software", desc: "Maintaining or updating old programs where the original source code is lost" },
            { icon: <SchoolIcon />, title: "Learning", desc: "Understanding how compilers work and how high-level code becomes machine instructions" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={3} key={item.title}>
              <Card variant="outlined" sx={{ height: "100%" }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, color: "primary.main" }}>
                    {item.icon}
                    <Typography variant="subtitle2" fontWeight="bold">{item.title}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        <Alert severity="info" sx={{ mt: 2 }}>
          <AlertTitle>Ghidra vs IDA Pro</AlertTitle>
          Ghidra is often compared to IDA Pro, the industry standard for reverse engineering. While IDA Pro has 
          decades of refinement, Ghidra offers comparable features for free, has excellent decompilation, and 
          supports collaborative analysis. For most tasks, Ghidra is an excellent choice.
        </Alert>
      </Paper>

      {/* Tabs */}
      <Paper sx={{ borderRadius: 2 }}>
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ borderBottom: 1, borderColor: "divider", px: 2 }}
        >
          <Tab icon={<PlayArrowIcon />} label="Getting Started" />
          <Tab icon={<AccountTreeIcon />} label="Interface" />
          <Tab icon={<SearchIcon />} label="Analysis" />
          <Tab icon={<CodeIcon />} label="Scripting" />
          <Tab icon={<LightbulbIcon />} label="Tips & Tricks" />
        </Tabs>

        {/* Tab 0: Getting Started */}
        <TabPanel value={tabValue} index={0}>
          <Typography variant="h5" gutterBottom>Getting Started with Ghidra</Typography>

          <Alert severity="success" sx={{ mb: 3 }}>
            <AlertTitle>Prerequisites</AlertTitle>
            Ghidra requires Java 17+ (JDK) to run. Download from adoptium.net or use your package manager.
          </Alert>

          <Typography variant="h6" gutterBottom>Installation</Typography>
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Windows Installation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                <ListItem><ListItemText primary="1. Install Java JDK 17+ from adoptium.net" secondary="Download the Windows x64 MSI installer for easiest setup" /></ListItem>
                <ListItem><ListItemText primary="2. Set JAVA_HOME environment variable" secondary="System Properties → Environment Variables → New System Variable" /></ListItem>
                <ListItem><ListItemText primary="3. Download Ghidra from ghidra-sre.org" secondary="Always download from the official NSA GitHub releases" /></ListItem>
                <ListItem><ListItemText primary="4. Extract ZIP to a permanent location" secondary="e.g., C:\\Tools\\ghidra_11.0_PUBLIC" /></ListItem>
                <ListItem><ListItemText primary="5. Run ghidraRun.bat to start" secondary="First run may prompt for JDK location" /></ListItem>
              </List>
              <CodeBlock title="PowerShell - Verify Java">{`# Check Java version
java -version

# Should show: openjdk version "17.x.x" or higher
# If not found, verify JAVA_HOME is set and in PATH`}</CodeBlock>
            </AccordionDetails>
          </Accordion>
          
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Linux Installation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Ubuntu/Debian">{`# Install Java 17
sudo apt update
sudo apt install openjdk-17-jdk

# Verify installation
java -version

# Download latest Ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip

# Extract
unzip ghidra_11.0_PUBLIC_20231222.zip

# Run Ghidra
cd ghidra_11.0_PUBLIC
./ghidraRun`}</CodeBlock>
              <CodeBlock title="Fedora/RHEL/CentOS">{`# Install Java 17
sudo dnf install java-17-openjdk-devel

# Set JAVA_HOME (add to ~/.bashrc)
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk

# Download and extract Ghidra same as above
./ghidraRun`}</CodeBlock>
              <CodeBlock title="Arch Linux">{`# Install from AUR (includes Java)
yay -S ghidra

# Or install Java manually
sudo pacman -S jdk17-openjdk

# Then download Ghidra manually`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">macOS Installation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Using Homebrew">{`# Install Java 17
brew install openjdk@17

# Link Java
sudo ln -sfn /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk /Library/Java/JavaVirtualMachines/openjdk-17.jdk

# Add to shell profile
export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
export JAVA_HOME=$(/usr/libexec/java_home -v 17)

# Download Ghidra from github.com/NationalSecurityAgency/ghidra/releases
# Extract and run
./ghidraRun`}</CodeBlock>
              <Alert severity="warning" sx={{ mt: 2 }}>
                <AlertTitle>Apple Silicon (M1/M2/M3) Note</AlertTitle>
                Ghidra runs natively on Apple Silicon. For best performance, ensure you're using an ARM64 
                version of Java. Rosetta 2 emulation also works but may be slower.
              </Alert>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Creating Your First Project</Typography>
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Project Setup Steps</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List>
                <ListItem>
                  <ListItemIcon><SpeedIcon /></ListItemIcon>
                  <ListItemText 
                    primary="1. File → New Project" 
                    secondary="Choose 'Non-Shared Project' for local work or 'Shared Project' for team collaboration" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SpeedIcon /></ListItemIcon>
                  <ListItemText 
                    primary="2. Select project directory and name" 
                    secondary="Projects store analysis data, so keep them organized by target or engagement" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SpeedIcon /></ListItemIcon>
                  <ListItemText 
                    primary="3. File → Import File (or drag and drop)" 
                    secondary="Select your binary (EXE, ELF, DLL, firmware, etc.)" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SpeedIcon /></ListItemIcon>
                  <ListItemText 
                    primary="4. Review the import dialog" 
                    secondary="Ghidra auto-detects format - verify language/compiler if known" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SpeedIcon /></ListItemIcon>
                  <ListItemText 
                    primary="5. Double-click the file to open in CodeBrowser" 
                    secondary="This is where the actual analysis happens" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SpeedIcon /></ListItemIcon>
                  <ListItemText 
                    primary='6. Click "Yes" to Auto-Analyze' 
                    secondary="Let Ghidra perform initial analysis (can take seconds to minutes depending on size)" 
                  />
                </ListItem>
              </List>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Analysis Options Configuration</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                When Ghidra prompts for auto-analysis, you can customize which analyzers run. 
                Click "Analyze Options" to see the full list. Here are the key ones:
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: "action.hover" }}>
                      <TableCell><strong>Analyzer</strong></TableCell>
                      <TableCell><strong>Description</strong></TableCell>
                      <TableCell><strong>Recommended When</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {analysisOptions.slice(0, 8).map((row) => (
                      <TableRow key={row.analyzer}>
                        <TableCell><Typography variant="body2" fontWeight="bold">{row.analyzer}</Typography></TableCell>
                        <TableCell><Typography variant="body2">{row.desc}</Typography></TableCell>
                        <TableCell><Chip label={row.when} size="small" variant="outlined" /></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Loading Debug Symbols (PDB)</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                If you have PDB files (Windows debug symbols), Ghidra can load them to provide function names, 
                types, and variable information. This dramatically improves analysis quality.
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="1. File → Load PDB File" secondary="Select the matching .pdb file" /></ListItem>
                <ListItem><ListItemText primary="2. Configure Symbol Server" secondary="Edit → Tool Options → Symbol Servers" /></ListItem>
                <ListItem><ListItemText primary="3. Microsoft Symbol Server" secondary="https://msdl.microsoft.com/download/symbols" /></ListItem>
              </List>
              <CodeBlock title="Symbol Server Path (Tool Options)">{`# Microsoft Symbol Server
srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols

# Local symbol cache
C:\\Symbols

# For Linux/Mac, use your home directory
srv*/home/user/.symbols*https://msdl.microsoft.com/download/symbols`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Supported File Formats</Typography>
          <Grid container spacing={2}>
            {[
              { format: "PE/COFF", desc: "Windows executables (.exe, .dll, .sys, .ocx)", icon: "🪟" },
              { format: "ELF", desc: "Linux/Unix executables and libraries (.so)", icon: "🐧" },
              { format: "Mach-O", desc: "macOS/iOS executables and frameworks", icon: "🍎" },
              { format: "DEX/APK", desc: "Android Dalvik bytecode and APK packages", icon: "🤖" },
              { format: "Raw Binary", desc: "Firmware, ROM dumps, bare metal code", icon: "💾" },
              { format: "Java Class", desc: "Java bytecode (.class, .jar files)", icon: "☕" },
              { format: "COFF", desc: "Object files from various compilers", icon: "📦" },
              { format: "Intel HEX", desc: "Firmware and microcontroller programs", icon: "🔧" },
              { format: "Motorola S-Record", desc: "Embedded system firmware files", icon: "📟" },
              { format: "PE .NET", desc: "C#/VB.NET managed executables", icon: "🔷" },
              { format: "WebAssembly", desc: "WASM binary modules", icon: "🌐" },
              { format: "MSI/CAB", desc: "Windows installer packages (via plugin)", icon: "📥" },
            ].map((item) => (
              <Grid item xs={6} sm={4} md={2} key={item.format}>
                <Card variant="outlined" sx={{ textAlign: "center", py: 2, height: "100%" }}>
                  <Typography variant="h4">{item.icon}</Typography>
                  <Typography variant="subtitle2" fontWeight="bold">{item.format}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>{item.desc}</Typography>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Understanding the Project Window</Typography>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Project Window Components</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                {[
                  { name: "Active Project", desc: "Currently open project with all imported files" },
                  { name: "Tool Chest", desc: "Launch CodeBrowser or other analysis tools" },
                  { name: "File Icons", desc: "Green checkmark = analyzed, Red X = import failed" },
                  { name: "Right-Click Menu", desc: "Delete, rename, export, version history" },
                  { name: "Folders", desc: "Organize binaries within the project" },
                  { name: "Recent Projects", desc: "Quick access to previously opened projects" },
                ].map((item) => (
                  <Grid item xs={12} sm={6} md={4} key={item.name}>
                    <Card variant="outlined">
                      <CardContent sx={{ py: 1.5, "&:last-child": { pb: 1.5 } }}>
                        <Typography variant="subtitle2" fontWeight="bold" color="primary">{item.name}</Typography>
                        <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>
        </TabPanel>

        {/* Tab 1: Interface */}
        <TabPanel value={tabValue} index={1}>
          <Typography variant="h5" gutterBottom>Ghidra Interface Overview</Typography>

          <Alert severity="info" sx={{ mb: 3 }}>
            The CodeBrowser is Ghidra's main analysis window. It contains multiple synchronized views 
            that update together as you navigate through the binary. Master the interface to analyze efficiently.
          </Alert>

          <Typography variant="h6" gutterBottom>Main Windows</Typography>
          <TableContainer component={Paper} sx={{ mb: 3 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Window</strong></TableCell>
                  <TableCell><strong>Shortcut</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {ghidraWindows.map((row) => (
                  <TableRow key={row.name}>
                    <TableCell>
                      <Typography fontWeight="bold" color="primary">{row.name}</Typography>
                    </TableCell>
                    <TableCell>
                      {row.shortcut && <Chip label={row.shortcut} size="small" variant="outlined" />}
                    </TableCell>
                    <TableCell>{row.description}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Understanding the Listing View</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                The Listing View is where you'll spend most of your time. It shows disassembled instructions 
                with addresses, bytes, mnemonics, and operands. Here's how to read it:
              </Typography>
              <CodeBlock title="Listing View Columns">{`Address    | Bytes      | Label      | Mnemonic | Operands            | Comment
-----------+------------+------------+----------+---------------------+------------------
00401000   | 55         |            | PUSH     | EBP                 |
00401001   | 8b ec      |            | MOV      | EBP,ESP             |
00401003   | 83 ec 08   |            | SUB      | ESP,0x8             |
00401006   | c7 45 fc   | main:      | MOV      | dword ptr [EBP-4],0 | local variable
           | 00 00 00 00|            |          |                     |

Color coding (default theme):
- Blue: References to other code locations
- Green: References to data
- Purple: Strings
- Orange: Immediates/constants
- Gray: Comments`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Understanding the Decompiler View</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                The Decompiler shows C-like pseudocode. Click in the Listing to sync, or vice versa. 
                Variables are automatically named (local_4, param_1) but can be renamed.
              </Typography>
              <CodeBlock title="Decompiler Features">{`// Hover over variables to see type info
// Right-click for context menu options:
// - Rename Variable (L)
// - Retype Variable (Ctrl+L)
// - Set Equate - name a constant
// - Find References
// - Edit Function Signature

// Example decompiled function:
int __cdecl check_password(char *input) {
    int result;
    char *expected = "secret123";
    
    result = strcmp(input, expected);  // Double-click to navigate
    if (result == 0) {
        return 1;  // Success
    }
    return 0;
}`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Symbol Tree Navigation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                The Symbol Tree organizes all symbols in the program hierarchically:
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Imports" secondary="Functions called from external libraries (DLLs, .so files)" /></ListItem>
                <ListItem><ListItemText primary="Exports" secondary="Functions/data exposed to other modules" /></ListItem>
                <ListItem><ListItemText primary="Functions" secondary="All identified functions in the binary" /></ListItem>
                <ListItem><ListItemText primary="Labels" secondary="Named locations that aren't functions" /></ListItem>
                <ListItem><ListItemText primary="Classes" secondary="C++ classes (if RTTI or debug info available)" /></ListItem>
                <ListItem><ListItemText primary="Namespaces" secondary="C++ namespaces and scopes" /></ListItem>
              </List>
              <Alert severity="success" sx={{ mt: 2 }}>
                <strong>Pro Tip:</strong> Use the filter box at the top to quickly find functions. 
                Type partial names like "crypt" to find all crypto-related functions.
              </Alert>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Keyboard Shortcuts</Typography>
          <Typography paragraph color="text.secondary">
            Mastering keyboard shortcuts dramatically speeds up analysis. These are the essential ones:
          </Typography>
          <Grid container spacing={2}>
            {keyboardShortcuts.map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.shortcut}>
                <Card variant="outlined">
                  <CardContent sx={{ py: 1, "&:last-child": { pb: 1 } }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Chip label={item.shortcut} color="primary" size="small" sx={{ fontFamily: "monospace", minWidth: 80 }} />
                      <Typography variant="body2">{item.action}</Typography>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Additional Useful Shortcuts</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                {[
                  { key: "Ctrl+Shift+E", action: "Open/focus Symbol Tree" },
                  { key: "Ctrl+E", action: "Open/focus Decompiler" },
                  { key: "Ctrl+D", action: "Add bookmark" },
                  { key: "Ctrl+G", action: "Go to program memory" },
                  { key: "P", action: "Make pointer at cursor" },
                  { key: "Y", action: "Define function signature" },
                  { key: "[", action: "Create array" },
                  { key: "Ctrl+L", action: "Retype variable (Decompiler)" },
                  { key: "M", action: "Add marker" },
                  { key: "Ctrl+Shift+G", action: "Script Manager" },
                  { key: "F2", action: "Create function at cursor" },
                  { key: "Delete", action: "Clear code/data" },
                ].map((item) => (
                  <Grid item xs={12} sm={6} md={4} key={item.key}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Chip label={item.key} size="small" variant="outlined" sx={{ fontFamily: "monospace", minWidth: 100 }} />
                      <Typography variant="body2">{item.action}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Common Tasks</Typography>
          <Grid container spacing={2}>
            {commonTasks.map((item) => (
              <Grid item xs={12} md={6} key={item.task}>
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography fontWeight="bold">{item.task}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {item.steps.map((step, idx) => (
                        <ListItem key={idx}>
                          <ListItemText primary={`${idx + 1}. ${step}`} />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Data Types & Structures</Typography>
          <Typography paragraph color="text.secondary">
            Understanding and defining data types is crucial for clean decompiler output.
          </Typography>
          <TableContainer component={Paper} sx={{ mb: 3 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Category</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                  <TableCell><strong>Example</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {dataTypeCategories.map((row) => (
                  <TableRow key={row.category}>
                    <TableCell><Typography fontWeight="bold" color="primary">{row.category}</Typography></TableCell>
                    <TableCell>{row.desc}</TableCell>
                    <TableCell><code style={{ fontSize: "0.85rem" }}>{row.example}</code></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Creating Custom Structures</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                Custom structures dramatically improve code readability. Here's how to create them:
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="1. Open Data Type Manager (Window → Data Type Manager)" /></ListItem>
                <ListItem><ListItemText primary="2. Right-click your program's archive → New → Structure" /></ListItem>
                <ListItem><ListItemText primary="3. Name the structure (e.g., 'NetworkPacket')" /></ListItem>
                <ListItem><ListItemText primary="4. Add fields with types and names" /></ListItem>
                <ListItem><ListItemText primary="5. Apply to data by selecting bytes and pressing T" /></ListItem>
              </List>
              <CodeBlock title="Example: Creating a File Header Structure">{`// Before: Raw bytes in decompiler
void process_file(byte *data) {
    if (*(uint *)data == 0x4d5a) {  // What is 0x4d5a?
        uint size = *(uint *)(data + 4);
        // ...
    }
}

// After: With custom structure applied
struct FileHeader {
    char magic[2];      // offset 0
    ushort reserved;    // offset 2  
    uint fileSize;      // offset 4
    uint flags;         // offset 8
    uint dataOffset;    // offset 12
};

void process_file(FileHeader *header) {
    if (header->magic[0] == 'M' && header->magic[1] == 'Z') {
        uint size = header->fileSize;  // Much clearer!
        // ...
    }
}`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Calling Conventions</Typography>
          <Typography paragraph color="text.secondary">
            Understanding calling conventions helps you interpret function parameters and return values correctly.
          </Typography>
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Convention</strong></TableCell>
                  <TableCell><strong>Platform</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                  <TableCell><strong>Key Registers</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {functionCallConventions.map((row) => (
                  <TableRow key={row.convention}>
                    <TableCell><Typography fontWeight="bold" fontFamily="monospace">{row.convention}</Typography></TableCell>
                    <TableCell><Chip label={row.platform} size="small" variant="outlined" /></TableCell>
                    <TableCell><Typography variant="body2">{row.desc}</Typography></TableCell>
                    <TableCell><Typography variant="caption" fontFamily="monospace">{row.registers}</Typography></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>

        {/* Tab 2: Analysis */}
        <TabPanel value={tabValue} index={2}>
          <Typography variant="h5" gutterBottom>Analysis Features</Typography>

          <Alert severity="info" sx={{ mb: 3 }}>
            <AlertTitle>Auto-Analysis</AlertTitle>
            When you first open a binary, Ghidra offers to run Auto-Analysis. This performs disassembly, 
            function detection, and type propagation automatically. You can always re-run specific analyzers 
            later from Analysis → Auto Analyze or Analysis → One Shot.
          </Alert>

          <Typography variant="h6" gutterBottom>Key Features</Typography>
          <TableContainer component={Paper} sx={{ mb: 3 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Feature</strong></TableCell>
                  <TableCell><strong>Category</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {analysisFeatures.map((row) => (
                  <TableRow key={row.feature}>
                    <TableCell>
                      <Typography fontWeight="bold">{row.feature}</Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={row.category} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>{row.description}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Complete Analyzer Reference</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                Ghidra includes many analyzers for different purposes. Here's when to enable them:
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: "action.hover" }}>
                      <TableCell><strong>Analyzer</strong></TableCell>
                      <TableCell><strong>Description</strong></TableCell>
                      <TableCell><strong>Use When</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {analysisOptions.map((row) => (
                      <TableRow key={row.analyzer}>
                        <TableCell><Typography variant="body2" fontWeight="bold">{row.analyzer}</Typography></TableCell>
                        <TableCell><Typography variant="body2">{row.desc}</Typography></TableCell>
                        <TableCell><Chip label={row.when} size="small" variant="outlined" /></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Supported Processors</Typography>
          <Grid container spacing={2}>
            {supportedProcessors.map((proc) => (
              <Grid item xs={12} sm={6} md={3} key={proc.arch}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Typography variant="subtitle1" fontWeight="bold">{proc.arch}</Typography>
                      {proc.common && <Chip label="Common" size="small" color="success" />}
                    </Box>
                    <Typography variant="body2" color="text.secondary">{proc.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>The Decompiler</Typography>
          <Typography paragraph>
            Ghidra's decompiler converts assembly code into readable C-like pseudocode. This is one of its 
            most powerful features, making it much easier to understand program logic without reading assembly.
          </Typography>
          <CodeBlock title="Example: Assembly vs Decompiled">{`; Original Assembly (x86)
push    ebp
mov     ebp, esp
sub     esp, 8
mov     dword ptr [ebp-4], 0
mov     dword ptr [ebp-8], 0Ah
mov     eax, [ebp-8]
add     eax, [ebp-4]
mov     esp, ebp
pop     ebp
ret

// Ghidra Decompiled Output
int example_function(void) {
    int local_4 = 0;
    int local_8 = 10;
    return local_8 + local_4;
}`}</CodeBlock>

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Decompiler Options & Tuning</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                Configure decompiler behavior in Edit → Tool Options → Decompiler:
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: "action.hover" }}>
                      <TableCell><strong>Option</strong></TableCell>
                      <TableCell><strong>Description</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {decompilerOptions.map((row) => (
                      <TableRow key={row.option}>
                        <TableCell><Typography fontWeight="bold" fontFamily="monospace">{row.option}</Typography></TableCell>
                        <TableCell>{row.desc}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Pattern Recognition</Typography>
          <Typography paragraph color="text.secondary">
            Learning to recognize common patterns helps you understand code faster:
          </Typography>
          <TableContainer component={Paper} sx={{ mb: 3 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Pattern</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                  <TableCell><strong>Indicators</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {patternRecognition.map((row) => (
                  <TableRow key={row.pattern}>
                    <TableCell><Typography fontWeight="bold" color="primary">{row.pattern}</Typography></TableCell>
                    <TableCell>{row.desc}</TableCell>
                    <TableCell><Typography variant="body2" fontFamily="monospace">{row.indicators}</Typography></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Identifying Virtual Function Tables (vtables)</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="C++ vtable Structure">{`// A vtable is an array of function pointers
// Used by C++ for virtual method dispatch

// In memory, it looks like:
vtable_Base:
  .quad Base::method1     ; offset 0
  .quad Base::method2     ; offset 8
  .quad Base::method3     ; offset 16

// Object layout:
struct Base {
    void** __vfptr;       ; Pointer to vtable (offset 0)
    int member_a;         ; offset 8
    int member_b;         ; offset 12
};

// Virtual call pattern (x64):
mov     rax, [rcx]        ; Load vtable ptr from object
call    [rax+0x10]        ; Call vtable[2] (method3)

// To analyze:
// 1. Find arrays of function pointers (Search → Memory → Address Tables)
// 2. Enable RTTI analyzer for Windows C++
// 3. Use RecoverClassesFromRTTI script
// 4. Create struct for object layout`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">String Decryption Patterns</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Common XOR String Decryption">{`// Malware often encrypts strings to avoid detection
// Common patterns:

// Single-byte XOR (most common)
void decrypt_xor(char *str, int len, char key) {
    for (int i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

// Rolling XOR (each byte uses different key)
void decrypt_rolling(char *str, int len) {
    char key = 0x41;
    for (int i = 0; i < len; i++) {
        str[i] ^= key;
        key = (key + 1) & 0xFF;  // Or key ^= str[i]
    }
}

// What to look for:
// 1. Loop iterating over data
// 2. XOR instruction inside loop
// 3. Constant byte value used in XOR
// 4. Result used with string functions

// To decrypt manually:
// 1. Select encrypted bytes
// 2. Right-click → Copy Special → Byte String
// 3. XOR with key in Python/CyberChef
// 4. Add decrypted string as comment`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Cross-References (XRefs)</Typography>
          <Typography paragraph>
            Cross-references are essential for understanding code flow. Press X on any symbol to see all references:
          </Typography>
          <Grid container spacing={2}>
            {[
              { type: "Call", desc: "Function is called from this location", icon: "→" },
              { type: "Read", desc: "Data is read at this location", icon: "R" },
              { type: "Write", desc: "Data is written at this location", icon: "W" },
              { type: "Address", desc: "Address is taken (pointer)", icon: "&" },
              { type: "Jump", desc: "Code jumps to this location", icon: "J" },
              { type: "Offset", desc: "Used as offset calculation", icon: "+" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.type}>
                <Card variant="outlined">
                  <CardContent sx={{ py: 1.5, "&:last-child": { pb: 1.5 } }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Chip label={item.icon} size="small" color="primary" sx={{ fontFamily: "monospace" }} />
                      <Typography fontWeight="bold">{item.type}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Working with Function Graphs</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                The Function Graph (View → Function Graph or press Space in Listing) shows control flow visually:
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Green edges" secondary="Conditional jump taken (true branch)" /></ListItem>
                <ListItem><ListItemText primary="Red edges" secondary="Conditional jump not taken (false branch)" /></ListItem>
                <ListItem><ListItemText primary="Blue edges" secondary="Unconditional jumps" /></ListItem>
                <ListItem><ListItemText primary="Purple blocks" secondary="Entry point" /></ListItem>
                <ListItem><ListItemText primary="Pink blocks" secondary="Exit points (RET instructions)" /></ListItem>
              </List>
              <Alert severity="success" sx={{ mt: 2 }}>
                <strong>Tip:</strong> Use View → Function Call Graph to see how functions call each other 
                across the entire program. Great for understanding program architecture.
              </Alert>
            </AccordionDetails>
          </Accordion>
        </TabPanel>

        {/* Tab 3: Scripting */}
        <TabPanel value={tabValue} index={3}>
          <Typography variant="h5" gutterBottom>Ghidra Scripting</Typography>

          <Alert severity="info" sx={{ mb: 3 }}>
            Ghidra supports Java and Python (Jython) scripting for automation and custom analysis. 
            Scripts can access all of Ghidra's APIs to automate repetitive tasks, batch process files, 
            or add custom functionality.
          </Alert>

          <Typography variant="h6" gutterBottom>Running Scripts</Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <List dense>
                <ListItem>
                  <ListItemIcon><FunctionsIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Window → Script Manager (Ctrl+Shift+G)" 
                    secondary="Browse, run, and manage scripts" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><FunctionsIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Script Directories" 
                    secondary="~/ghidra_scripts (user) and ghidra/Ghidra/Features/*/ghidra_scripts (built-in)" 
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><SettingsIcon /></ListItemIcon>
                  <ListItemText 
                    primary="Script Parameters" 
                    secondary="Use @param annotations for user input" 
                  />
                </ListItem>
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Alert severity="success">
                <AlertTitle>Python vs Java</AlertTitle>
                <List dense sx={{ py: 0 }}>
                  <ListItem sx={{ py: 0 }}><ListItemText primary="Python: Easier syntax, faster prototyping" /></ListItem>
                  <ListItem sx={{ py: 0 }}><ListItemText primary="Java: Better IDE support, type safety, performance" /></ListItem>
                  <ListItem sx={{ py: 0 }}><ListItemText primary="Both have full API access" /></ListItem>
                </List>
              </Alert>
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Script Categories</Typography>
          <Grid container spacing={2}>
            {scriptCategories.map((cat) => (
              <Grid item xs={12} sm={6} md={4} key={cat.category}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Typography variant="subtitle1" fontWeight="bold" color="primary" gutterBottom>
                      {cat.category}
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {cat.scripts.map((script) => (
                        <Chip key={script} label={script} size="small" variant="outlined" />
                      ))}
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Python Script Examples</Typography>
          
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Find All Strings</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="find_strings.py">{`# @category Analysis
# @description Find all defined strings in the binary
# @author VRAgent

from ghidra.program.model.data import StringDataType

program = currentProgram
listing = program.getListing()

print("=== Strings Found ===")
count = 0

for data in listing.getDefinedData(True):
    if data.hasStringValue():
        addr = data.getAddress()
        value = data.getValue()
        print("{}: {}".format(addr, value))
        count += 1

print("\\nTotal strings found: {}".format(count))`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Find Suspicious API Calls</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="find_suspicious_apis.py">{`# @category Security
# @description Find potentially dangerous API imports
# @author VRAgent

suspicious_apis = [
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
    "CreateRemoteThread", "NtUnmapViewOfSection", "LoadLibrary",
    "GetProcAddress", "ShellExecute", "WinExec", "CreateProcess",
    "RegSetValueEx", "InternetOpen", "URLDownloadToFile",
    "CryptDecrypt", "CryptEncrypt", "socket", "connect", "send", "recv"
]

program = currentProgram
symbol_table = program.getSymbolTable()

print("=== Suspicious API Calls ===\\n")

for api in suspicious_apis:
    symbols = symbol_table.getSymbols(api)
    for sym in symbols:
        refs = getReferencesTo(sym.getAddress())
        if refs:
            print("[!] {} found:".format(api))
            for ref in refs:
                func = getFunctionContaining(ref.getFromAddress())
                func_name = func.getName() if func else "unknown"
                print("    Called from {} at {}".format(func_name, ref.getFromAddress()))
            print()`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">XOR Decryption Helper</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="xor_decrypt_selection.py">{`# @category Crypto
# @description XOR decrypt selected bytes and show result
# @keybinding Ctrl+Shift+X
# @author VRAgent

from ghidra.program.model.mem import MemoryAccessException

# Get user input for XOR key
key_str = askString("XOR Key", "Enter XOR key (hex, e.g., 0x41 or 41):")
key = int(key_str, 16) if key_str.startswith("0x") else int(key_str, 16)

# Get current selection
selection = currentSelection
if not selection:
    popup("Please select bytes to decrypt")
else:
    start = selection.getMinAddress()
    end = selection.getMaxAddress()
    length = end.subtract(start) + 1
    
    # Read bytes
    memory = currentProgram.getMemory()
    encrypted = []
    addr = start
    for i in range(length):
        encrypted.append(memory.getByte(addr) & 0xFF)
        addr = addr.add(1)
    
    # Decrypt
    decrypted = ''.join([chr(b ^ key) for b in encrypted])
    
    # Show result
    print("=== XOR Decryption ===")
    print("Address: {} - {}".format(start, end))
    print("Key: 0x{:02X}".format(key))
    print("Decrypted: {}".format(decrypted))
    
    # Optionally add as comment
    if askYesNo("Add Comment", "Add decrypted string as comment?"):
        setEOLComment(start, "Decrypted: " + decrypted)`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Export Functions to CSV</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="export_functions.py">{`# @category Export
# @description Export all functions to CSV with details
# @author VRAgent

import csv
import os

# Ask for output file
output_file = askFile("Save CSV", "Save")
if output_file:
    fm = currentProgram.getFunctionManager()
    
    with open(str(output_file), 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Name', 'Address', 'Size', 'CallingConvention', 'Parameters', 'IsThunk'])
        
        for func in fm.getFunctions(True):
            name = func.getName()
            addr = str(func.getEntryPoint())
            size = func.getBody().getNumAddresses()
            cc = func.getCallingConventionName()
            params = func.getParameterCount()
            is_thunk = func.isThunk()
            
            writer.writerow([name, addr, size, cc, params, is_thunk])
    
    print("Exported {} functions to {}".format(fm.getFunctionCount(), output_file))`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Batch Rename Functions by Pattern</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="rename_by_string.py">{`# @category Refactoring  
# @description Rename functions based on strings they reference
# @author VRAgent

from ghidra.program.model.symbol import SourceType

fm = currentProgram.getFunctionManager()
renamed_count = 0

for func in fm.getFunctions(True):
    # Skip already named functions
    if not func.getName().startswith("FUN_"):
        continue
    
    # Look for string references in function
    body = func.getBody()
    refs = getReferencesFrom(func.getEntryPoint())
    
    for ref in refs:
        data = getDataAt(ref.getToAddress())
        if data and data.hasStringValue():
            string_val = str(data.getValue())
            # Clean string for function name
            if len(string_val) > 3 and len(string_val) < 30:
                clean_name = "fn_" + string_val.replace(" ", "_").replace(".", "_")[:20]
                try:
                    func.setName(clean_name, SourceType.USER_DEFINED)
                    print("Renamed {} to {}".format(func.getEntryPoint(), clean_name))
                    renamed_count += 1
                except:
                    pass
                break

print("\\nRenamed {} functions".format(renamed_count))`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Headless Analysis</Typography>
          <Typography paragraph>
            Run Ghidra scripts without the GUI for batch processing:
          </Typography>
          <CodeBlock title="Headless Mode Commands">{`# Basic headless analysis
./analyzeHeadless /path/to/project ProjectName \\
    -import /path/to/binary \\
    -postScript MyScript.py

# With script arguments
./analyzeHeadless /path/to/project ProjectName \\
    -import /path/to/binary \\
    -scriptPath /my/scripts \\
    -postScript analyze.py "arg1" "arg2"

# Process existing project
./analyzeHeadless /path/to/project ProjectName \\
    -process binary_name \\
    -noanalysis \\
    -postScript export_data.py

# Batch import multiple files
./analyzeHeadless /path/to/project BatchProject \\
    -import /malware/samples/ \\
    -recursive \\
    -postScript triage.py`}</CodeBlock>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Useful Built-in Scripts</Typography>
          <Grid container spacing={2}>
            {[
              { name: "FindCrypt", desc: "Detect cryptographic constants (AES S-box, DES, etc.)" },
              { name: "FunctionID", desc: "Identify known library functions by signature" },
              { name: "RecoverClassesFromRTTI", desc: "Recover C++ class hierarchies from RTTI" },
              { name: "SearchStringReferences", desc: "Find all cross-references to strings" },
              { name: "PropagateExternalParameters", desc: "Apply known function signatures" },
              { name: "FindPotentialDecompilerProblems", desc: "Identify decompilation issues" },
              { name: "ResolveX86orX64LinuxSyscalls", desc: "Name Linux system calls" },
              { name: "ComputeChecksum", desc: "Calculate checksums of binary sections" },
            ].map((script) => (
              <Grid item xs={12} sm={6} md={4} key={script.name}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle2" fontWeight="bold" color="primary">{script.name}</Typography>
                    <Typography variant="body2" color="text.secondary">{script.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </TabPanel>

        {/* Tab 4: Tips & Tricks */}
        <TabPanel value={tabValue} index={4}>
          <Typography variant="h5" gutterBottom>Tips & Best Practices</Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>Workflow Tips</Typography>
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Rename Everything</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    As you understand functions and variables, rename them with descriptive names. 
                    This makes the decompiled code much more readable.
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="L" secondary="Rename any symbol/label" /></ListItem>
                    <ListItem><ListItemText primary="Use prefixes" secondary="fn_, sub_, dat_, str_ for organization" /></ListItem>
                    <ListItem><ListItemText primary="Be descriptive" secondary="'parse_network_packet' > 'FUN_00401234'" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Use Comments Liberally</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    Add comments to document your findings. Future you (or teammates) will thank you.
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary=";" secondary="End-of-line comment" /></ListItem>
                    <ListItem><ListItemText primary="Ctrl+;" secondary="Plate comment (multi-line above)" /></ListItem>
                    <ListItem><ListItemText primary="Ctrl+Enter" secondary="Pre-comment in decompiler" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Start from Strings</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    Strings are your entry point into understanding code:
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Search → For Strings" secondary="Find all strings" /></ListItem>
                    <ListItem><ListItemText primary="Look for error messages" secondary="Often reveal function purpose" /></ListItem>
                    <ListItem><ListItemText primary="URLs, IPs, filenames" secondary="Network/file operations" /></ListItem>
                    <ListItem><ListItemText primary="Press X on string" secondary="Find all code using it" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Define Data Types</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    Create structs for data structures. Proper typing dramatically improves decompiler output.
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Window → Data Type Manager" secondary="Create/edit types" /></ListItem>
                    <ListItem><ListItemText primary="T" secondary="Apply type at cursor" /></ListItem>
                    <ListItem><ListItemText primary="Ctrl+L (decompiler)" secondary="Retype variable" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>Performance Tips</Typography>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Increase Memory</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    Edit support/launch.properties to increase heap size for large binaries:
                  </Typography>
                  <CodeBlock title="launch.properties">{`# Default is usually 1G - increase for large binaries
MAXMEM=4G

# For very large firmware images
MAXMEM=8G

# Also consider:
VMARG=-XX:+UseG1GC`}</CodeBlock>
                </AccordionDetails>
              </Accordion>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Selective Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    For very large binaries, skip auto-analysis initially:
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Import without analysis" secondary="Click 'No' on auto-analyze prompt" /></ListItem>
                    <ListItem><ListItemText primary="Manual disassembly" secondary="D to disassemble at cursor" /></ListItem>
                    <ListItem><ListItemText primary="One-shot analysis" secondary="Analyze → One Shot for specific regions" /></ListItem>
                    <ListItem><ListItemText primary="Select and analyze" secondary="Highlight region, then analyze selection" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Use Bookmarks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    Bookmark (Ctrl+D) interesting locations as you explore:
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Categories" secondary="TODO, Interesting, Vuln, Crypto, C2" /></ListItem>
                    <ListItem><ListItemText primary="Window → Bookmarks" secondary="View all bookmarks" /></ListItem>
                    <ListItem><ListItemText primary="Double-click" secondary="Navigate to bookmark" /></ListItem>
                    <ListItem><ListItemText primary="Export" secondary="Save bookmarks to share analysis" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight="bold">Navigation History</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography paragraph>
                    Use navigation history to move through your analysis:
                  </Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Alt+Left" secondary="Go back in history" /></ListItem>
                    <ListItem><ListItemText primary="Alt+Right" secondary="Go forward in history" /></ListItem>
                    <ListItem><ListItemText primary="Ctrl+M" secondary="Add marker at current location" /></ListItem>
                    <ListItem><ListItemText primary="Ctrl+J" secondary="Show marker navigation" /></ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Malware Analysis Tips</Typography>
          <Alert severity="warning" sx={{ mb: 3 }}>
            <AlertTitle>Safety First!</AlertTitle>
            Always analyze malware in an isolated virtual machine with snapshots. Never run malware on your host system.
          </Alert>
          
          <Grid container spacing={2}>
            {malwareAnalysisTips.map((tip, idx) => (
              <Grid item xs={12} sm={6} md={4} key={idx}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Typography variant="subtitle2" fontWeight="bold" color="primary">{tip.tip}</Typography>
                    <Typography variant="body2" color="text.secondary">{tip.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Common Malware Anti-Analysis Techniques</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Anti-Analysis Detection Patterns">{`// IsDebuggerPresent - Direct check
if (IsDebuggerPresent()) ExitProcess(0);

// NtGlobalFlag - PEB flag check
PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
if (peb->NtGlobalFlag & 0x70) ExitProcess(0);  // Heap flags set by debugger

// Timing check - Sleep difference
DWORD start = GetTickCount();
Sleep(1000);
if (GetTickCount() - start < 900) ExitProcess(0);  // Sleep skipped by debugger

// VM Detection - Registry keys
RegOpenKey(HKLM, "SOFTWARE\\VMware, Inc.\\VMware Tools", &key);
RegOpenKey(HKLM, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", &key);

// VM Detection - Known processes
if (FindProcess("vmtoolsd.exe") || FindProcess("VBoxService.exe")) ExitProcess(0);

// What to look for:
// - Calls to IsDebuggerPresent, CheckRemoteDebuggerPresent
// - Access to PEB structure
// - GetTickCount, QueryPerformanceCounter timing checks
// - Registry queries for VM software
// - CPUID checks for hypervisor`}</CodeBlock>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Ghidra Extensions</Typography>
          <Typography paragraph color="text.secondary">
            Extend Ghidra's functionality with community plugins and extensions:
          </Typography>
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: "action.hover" }}>
                  <TableCell><strong>Extension</strong></TableCell>
                  <TableCell><strong>Category</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {ghidraExtensions.map((ext) => (
                  <TableRow key={ext.name}>
                    <TableCell><Typography fontWeight="bold" color="primary">{ext.name}</Typography></TableCell>
                    <TableCell><Chip label={ext.category} size="small" variant="outlined" /></TableCell>
                    <TableCell>{ext.desc}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Installing Extensions</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                <ListItem><ListItemText primary="1. Download extension ZIP" secondary="From GitHub releases or build from source" /></ListItem>
                <ListItem><ListItemText primary="2. File → Install Extensions" secondary="In Ghidra Project window (not CodeBrowser)" /></ListItem>
                <ListItem><ListItemText primary="3. Click + and select ZIP" secondary="Or extract to Ghidra/Extensions folder" /></ListItem>
                <ListItem><ListItemText primary="4. Restart Ghidra" secondary="Extensions load on startup" /></ListItem>
              </List>
              <Alert severity="info" sx={{ mt: 2 }}>
                <strong>Building Extensions:</strong> Use gradle with Ghidra's build system. 
                Set GHIDRA_INSTALL_DIR environment variable and run <code>gradle buildExtension</code>
              </Alert>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Ghidra Server (Team Collaboration)</Typography>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography fontWeight="bold">Setting Up Ghidra Server</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography paragraph>
                Ghidra Server enables team collaboration with shared projects and version control:
              </Typography>
              <CodeBlock title="Server Setup (Linux)">{`# Navigate to server directory
cd $GHIDRA_HOME/server

# Initialize repository (first time only)
./svrAdmin -add myrepository

# Add users
./svrAdmin -add username --p

# Start server
./ghidraSvr start

# Default port: 13100
# Configure firewall accordingly`}</CodeBlock>
              <Alert severity="info" sx={{ mt: 2 }}>
                <strong>Connecting:</strong> In Ghidra, File → New Project → Shared Project → 
                Enter server address and credentials. Projects sync automatically.
              </Alert>
            </AccordionDetails>
          </Accordion>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Learning Resources</Typography>
          <Grid container spacing={2}>
            {[
              { resource: "Official Ghidra Docs", desc: "Help → Contents in Ghidra", type: "Built-in", color: "success" },
              { resource: "Ghidra Courses (NSA)", desc: "docs/GhidraClass in installation folder", type: "Free", color: "success" },
              { resource: "r/ReverseEngineering", desc: "Active community for RE discussion", type: "Community", color: "info" },
              { resource: "Ghidra Ninja (YouTube)", desc: "Video tutorials and walkthroughs", type: "Video", color: "primary" },
              { resource: "crackmes.one", desc: "Practice reversing challenges", type: "Practice", color: "warning" },
              { resource: "Practical Malware Analysis", desc: "Classic RE book, applicable to Ghidra", type: "Book", color: "secondary" },
              { resource: "RPISEC Modern Binary Exploitation", desc: "Free course with RE components", type: "Course", color: "success" },
              { resource: "MalwareTech Challenges", desc: "Beginner-friendly malware RE exercises", type: "Practice", color: "warning" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.resource}>
                <Card variant="outlined" sx={{ height: "100%" }}>
                  <CardContent>
                    <Chip label={item.type} size="small" color={item.color as any} sx={{ mb: 1 }} />
                    <Typography variant="subtitle2" fontWeight="bold">{item.resource}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>Quick Reference Card</Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight="bold" color="primary" gutterBottom>Navigation</Typography>
                  <List dense disablePadding>
                    {[
                      { k: "G", d: "Go to address" },
                      { k: "X", d: "Show XRefs" },
                      { k: "Alt+←/→", d: "History nav" },
                      { k: "Ctrl+D", d: "Bookmark" },
                      { k: "Space", d: "Function graph" },
                    ].map((item) => (
                      <ListItem key={item.k} sx={{ py: 0.25 }}>
                        <Chip label={item.k} size="small" sx={{ mr: 1, minWidth: 70 }} />
                        <ListItemText primary={item.d} />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight="bold" color="primary" gutterBottom>Editing</Typography>
                  <List dense disablePadding>
                    {[
                      { k: "L", d: "Rename label" },
                      { k: ";", d: "Add comment" },
                      { k: "T", d: "Set type" },
                      { k: "F", d: "Create function" },
                      { k: "D", d: "Define data" },
                    ].map((item) => (
                      <ListItem key={item.k} sx={{ py: 0.25 }}>
                        <Chip label={item.k} size="small" sx={{ mr: 1, minWidth: 70 }} />
                        <ListItemText primary={item.d} />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="subtitle1" fontWeight="bold" color="primary" gutterBottom>Search</Typography>
                  <List dense disablePadding>
                    {[
                      { k: "Ctrl+Shift+F", d: "Find strings" },
                      { k: "Ctrl+B", d: "Search bytes" },
                      { k: "N", d: "Next occurrence" },
                      { k: "Ctrl+F", d: "Text search" },
                      { k: "Ctrl+Shift+E", d: "Symbol tree" },
                    ].map((item) => (
                      <ListItem key={item.k} sx={{ py: 0.25 }}>
                        <Chip label={item.k} size="small" sx={{ mr: 1, minWidth: 70 }} />
                        <ListItemText primary={item.d} />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>
      </Paper>

      {/* Quiz Section */}
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
    </Container>
    </LearnPageLayout>
  );
};

export default GhidraGuidePage;
