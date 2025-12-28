import React, { useState } from "react";
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
  Radio,
  RadioGroup,
  FormControlLabel,
  LinearProgress,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import MemoryIcon from "@mui/icons-material/Memory";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import SchoolIcon from "@mui/icons-material/School";
import TerminalIcon from "@mui/icons-material/Terminal";
import SearchIcon from "@mui/icons-material/Search";
import WarningIcon from "@mui/icons-material/Warning";
import GavelIcon from "@mui/icons-material/Gavel";
import PsychologyIcon from "@mui/icons-material/Psychology";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";
import LockIcon from "@mui/icons-material/Lock";
import VisibilityIcon from "@mui/icons-material/Visibility";
import HistoryIcon from "@mui/icons-material/History";
import ExtensionIcon from "@mui/icons-material/Extension";
import StorageIcon from "@mui/icons-material/Storage";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import { useNavigate } from "react-router-dom";

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
  // Topic 1: What is Reverse Engineering (Questions 1-6)
  {
    id: 1,
    question: "What is reverse engineering in the context of software?",
    options: [
      "Writing code from scratch",
      "Analyzing compiled software to understand its functionality without source code",
      "Copying someone else's source code",
      "Creating documentation for existing code"
    ],
    correctAnswer: 1,
    explanation: "Reverse engineering is the process of analyzing compiled software to understand its functionality, structure, and behavior without access to the original source code.",
    topic: "What is RE"
  },
  {
    id: 2,
    question: "What happens during the compilation process that makes RE necessary?",
    options: [
      "Code becomes faster",
      "Variable names, comments, and high-level structure are lost",
      "Security is added to the code",
      "The code becomes open source"
    ],
    correctAnswer: 1,
    explanation: "During compilation, much information is lost including variable names, comments, and high-level structure. This is why RE is needed to reconstruct understanding of the code.",
    topic: "What is RE"
  },
  {
    id: 3,
    question: "Why is reverse engineering compared to archaeology?",
    options: [
      "Because it involves digging through old files",
      "Because you excavate layers of abstraction to understand original design and intent",
      "Because it requires ancient tools",
      "Because it only works on old software"
    ],
    correctAnswer: 1,
    explanation: "RE is like archaeology because you're excavating layers of abstraction to understand the original design and intent of the software creators.",
    topic: "What is RE"
  },
  {
    id: 4,
    question: "What is the primary output of reverse engineering?",
    options: [
      "The exact original source code",
      "Understanding of what the program does and how it works",
      "A faster version of the program",
      "A new programming language"
    ],
    correctAnswer: 1,
    explanation: "You won't get the exact original source code back, but you can understand what the program does, how it does it, and often find bugs, vulnerabilities, or hidden functionality.",
    topic: "What is RE"
  },
  {
    id: 5,
    question: "Which of the following is NOT a common use case for reverse engineering?",
    options: [
      "Malware analysis",
      "Creating original software from scratch",
      "Vulnerability research",
      "Legacy system maintenance"
    ],
    correctAnswer: 1,
    explanation: "Creating original software from scratch is not reverse engineering - it's forward engineering. RE is about understanding existing compiled software.",
    topic: "What is RE"
  },
  {
    id: 6,
    question: "What skills does reverse engineering require?",
    options: [
      "Only programming knowledge",
      "Patience, curiosity, pattern recognition, and systematic thinking",
      "Only mathematical skills",
      "Only networking knowledge"
    ],
    correctAnswer: 1,
    explanation: "RE requires a unique combination of patience, curiosity, pattern recognition, and systematic thinking to work backwards from compiled binaries.",
    topic: "What is RE"
  },
  // Topic 2: Why Learn RE (Questions 7-12)
  {
    id: 7,
    question: "Why is malware analysis an important application of reverse engineering?",
    options: [
      "To create new malware",
      "To understand threats and develop defenses against them",
      "To sell malware on the black market",
      "To make malware run faster"
    ],
    correctAnswer: 1,
    explanation: "Malware analysts use RE to understand how malicious software works, what it targets, and how to defend against it. This is critical for threat intelligence and incident response.",
    topic: "Why Learn RE"
  },
  {
    id: 8,
    question: "How does reverse engineering help with interoperability?",
    options: [
      "It makes software run slower",
      "It allows understanding proprietary protocols to build compatible software",
      "It removes all security features",
      "It converts all code to Python"
    ],
    correctAnswer: 1,
    explanation: "When systems need to communicate without documentation, RE provides answers. It helps understand proprietary protocols, file formats, and APIs to build compatible software.",
    topic: "Why Learn RE"
  },
  {
    id: 9,
    question: "Why is RE valuable for legacy system maintenance?",
    options: [
      "Legacy systems are always well-documented",
      "Because source code gets lost and RE is the only option for maintenance",
      "Legacy systems never need maintenance",
      "Because old code is easier to read"
    ],
    correctAnswer: 1,
    explanation: "Source code gets lost, companies go out of business, and developers move on. When critical software needs maintenance but no source exists, RE is the only option.",
    topic: "Why Learn RE"
  },
  {
    id: 10,
    question: "What career field uses RE to find security bugs before attackers?",
    options: [
      "Web design",
      "Vulnerability research",
      "Project management",
      "Database administration"
    ],
    correctAnswer: 1,
    explanation: "Vulnerability researchers use RE to find security bugs in software before attackers do. They discover zero-days, write exploits for pen testing, and help vendors fix issues through responsible disclosure.",
    topic: "Why Learn RE"
  },
  {
    id: 11,
    question: "Why is embedded/IoT security a growing field for RE?",
    options: [
      "IoT devices are never connected to the internet",
      "Billions of embedded devices run firmware that rarely gets security audits",
      "IoT devices have no software",
      "Embedded systems are always secure by default"
    ],
    correctAnswer: 1,
    explanation: "Billions of embedded devices run firmware that rarely gets security audits. RE skills let you analyze routers, smart devices, automotive systems, and more for vulnerabilities.",
    topic: "Why Learn RE"
  },
  {
    id: 12,
    question: "Why is game hacking considered a 'fun entry point' to RE?",
    options: [
      "Games have no protection",
      "Many security researchers started with game hacking and it teaches core RE concepts",
      "Games are always open source",
      "Game companies encourage hacking"
    ],
    correctAnswer: 1,
    explanation: "Many security researchers started with game hacking. It teaches core RE concepts while being engaging, and the skills transfer to security work.",
    topic: "Why Learn RE"
  },
  // Topic 3: Legal & Ethical (Questions 13-18)
  {
    id: 13,
    question: "What does DMCA stand for and what does it regulate?",
    options: [
      "Digital Music Copyright Act - music piracy",
      "Digital Millennium Copyright Act - circumventing copy protection",
      "Data Management Control Act - database access",
      "Digital Media Creation Act - content creation"
    ],
    correctAnswer: 1,
    explanation: "DMCA (Digital Millennium Copyright Act) prohibits circumventing copy protection, though it has security research exemptions.",
    topic: "Legal & Ethical"
  },
  {
    id: 14,
    question: "What makes the CFAA potentially problematic for researchers?",
    options: [
      "It only applies to government computers",
      "It has a vague 'exceeds authorization' clause",
      "It encourages all forms of hacking",
      "It doesn't apply to software"
    ],
    correctAnswer: 1,
    explanation: "The CFAA (Computer Fraud and Abuse Act) criminalizes unauthorized computer access and has a vague 'exceeds authorization' clause that has been controversial for researchers.",
    topic: "Legal & Ethical"
  },
  {
    id: 15,
    question: "Which RE activity is generally considered legal?",
    options: [
      "Bypassing copy protection for piracy",
      "Analyzing software you own for interoperability",
      "Distributing cracked software",
      "Breaking into others' computers to analyze their software"
    ],
    correctAnswer: 1,
    explanation: "Analyzing software you own or have licensed for interoperability purposes is generally legal. Always ensure you have proper authorization.",
    topic: "Legal & Ethical"
  },
  {
    id: 16,
    question: "What is 'responsible disclosure' in vulnerability research?",
    options: [
      "Never reporting bugs to anyone",
      "Selling bugs to the highest bidder",
      "Coordinating with vendors to fix issues before public disclosure",
      "Immediately publishing all vulnerabilities publicly"
    ],
    correctAnswer: 2,
    explanation: "Responsible disclosure involves reporting vulnerabilities to vendors, giving them reasonable time to fix (typically 90 days), and coordinating the public disclosure timing.",
    topic: "Legal & Ethical"
  },
  {
    id: 17,
    question: "What should you do before engaging in any RE activity with legal implications?",
    options: [
      "Just proceed if it seems harmless",
      "Consult with a qualified legal professional",
      "Ask your friends for advice",
      "Assume all RE is illegal"
    ],
    correctAnswer: 1,
    explanation: "Laws vary significantly by country and jurisdiction. Always consult with a qualified legal professional before engaging in RE activities that could have legal implications.",
    topic: "Legal & Ethical"
  },
  {
    id: 18,
    question: "Why is documentation important during RE work?",
    options: [
      "It's not important at all",
      "It helps show your methodology for legal protection and reproducibility",
      "It makes the analysis slower",
      "It's required by all software licenses"
    ],
    correctAnswer: 1,
    explanation: "Documentation helps show your methodology for legal protection, ensures reproducibility, and helps when explaining findings to others.",
    topic: "Legal & Ethical"
  },
  // Topic 4: RE Mindset (Questions 19-25)
  {
    id: 19,
    question: "What characteristic drives the best reverse engineers?",
    options: [
      "Desire for fame",
      "Insatiable curiosity about how things work",
      "Fear of failure",
      "Dislike of programming"
    ],
    correctAnswer: 1,
    explanation: "The best reverse engineers are driven by an almost obsessive need to understand how things work. This curiosity sustains you through the difficult parts of analysis.",
    topic: "RE Mindset"
  },
  {
    id: 20,
    question: "Why is 'extreme patience' listed as a key RE trait?",
    options: [
      "Because RE only takes a few minutes",
      "Because you might spend hours or days on a single function with dead ends and backtracking",
      "Because all binaries are simple",
      "Because decompilers always produce perfect output"
    ],
    correctAnswer: 1,
    explanation: "RE is slow, methodical work. You might spend hours (or days) on a single function, hit dead ends, misunderstand code, and need to backtrack repeatedly.",
    topic: "RE Mindset"
  },
  {
    id: 21,
    question: "What is pattern recognition in the context of RE?",
    options: [
      "Recognizing image patterns",
      "Recognizing common code structures like loops, conditionals, and compiler patterns",
      "Recognizing faces in code",
      "Recognizing programming languages by file extension"
    ],
    correctAnswer: 1,
    explanation: "With experience, you'll recognize common patterns: how compilers generate code for loops, conditionals, virtual function calls, etc. This dramatically speeds up analysis.",
    topic: "RE Mindset"
  },
  {
    id: 22,
    question: "What is hypothesis-driven analysis?",
    options: [
      "Randomly clicking through a disassembler",
      "Forming theories about what code does and testing them with breakpoints",
      "Assuming all code is malicious",
      "Writing reports without testing"
    ],
    correctAnswer: 1,
    explanation: "Hypothesis-driven analysis means forming hypotheses about what code does, then testing them. For example: 'I think this function validates passwords. Let me set a breakpoint and check.'",
    topic: "RE Mindset"
  },
  {
    id: 23,
    question: "Why is documentation called a 'habit' in RE?",
    options: [
      "Because you only document once at the end",
      "Because you should document as you go - future you will forget discoveries",
      "Because documentation is optional",
      "Because notes slow you down"
    ],
    correctAnswer: 1,
    explanation: "Always document as you go. Rename functions, add comments, create diagrams. Future you (even tomorrow-you) will forget what you discovered.",
    topic: "RE Mindset"
  },
  {
    id: 24,
    question: "What does 'systematic approach' mean in RE methodology?",
    options: [
      "Randomly exploring code",
      "Developing a structured methodology: reconnaissance, key functions, data structures, call graph",
      "Only using automated tools",
      "Skipping documentation"
    ],
    correctAnswer: 1,
    explanation: "A systematic approach involves developing a methodology: start with reconnaissance, identify key functions, understand data structures, map the call graph, and take notes obsessively.",
    topic: "RE Mindset"
  },
  {
    id: 25,
    question: "What should you do when stuck on an RE problem?",
    options: [
      "Give up immediately",
      "Take breaks, reduce the input, or shorten the path",
      "Never take breaks",
      "Delete all your notes and start over"
    ],
    correctAnswer: 1,
    explanation: "When stuck, take breaks but don't give up. Try reducing the input or shortening the path to isolate the problem.",
    topic: "RE Mindset"
  },
  // Topic 5: Types of RE (Questions 26-31)
  {
    id: 26,
    question: "What is Software RE (Binary Analysis)?",
    options: [
      "Analyzing hardware circuits",
      "Analyzing compiled executables, libraries, and applications",
      "Analyzing network packets only",
      "Analyzing physical devices"
    ],
    correctAnswer: 1,
    explanation: "Software RE is the most common form - analyzing compiled executables, libraries, and applications. This covers Windows PE files, Linux ELF binaries, mobile apps, and more.",
    topic: "Types of RE"
  },
  {
    id: 27,
    question: "What makes Malware RE different from general Software RE?",
    options: [
      "It's exactly the same",
      "It requires understanding anti-analysis techniques and safe analysis environments",
      "It's easier than regular RE",
      "It doesn't require any special tools"
    ],
    correctAnswer: 1,
    explanation: "Malware RE is specialized - it requires understanding anti-analysis techniques, safe analysis environments (sandboxes), and threat intelligence. It's often time-sensitive.",
    topic: "Types of RE"
  },
  {
    id: 28,
    question: "What does Hardware RE involve?",
    options: [
      "Only analyzing software",
      "Analyzing physical circuits, chips, extracting firmware, and understanding hardware security",
      "Only reading documentation",
      "Only using software tools"
    ],
    correctAnswer: 1,
    explanation: "Hardware RE involves analyzing physical circuits, chips, and electronic systems. It includes probing PCBs, extracting firmware from chips, and understanding hardware security modules.",
    topic: "Types of RE"
  },
  {
    id: 29,
    question: "What is Firmware RE?",
    options: [
      "Analyzing only web applications",
      "Analyzing software embedded in devices like routers, IoT devices, and automotive systems",
      "Analyzing only desktop software",
      "Analyzing only mobile apps"
    ],
    correctAnswer: 1,
    explanation: "Firmware RE analyzes software embedded in devices: routers, IoT devices, automotive ECUs, medical devices, industrial controllers. It bridges hardware and software RE.",
    topic: "Types of RE"
  },
  {
    id: 30,
    question: "What is Protocol RE focused on?",
    options: [
      "Understanding compiled executables",
      "Understanding proprietary network protocols, file formats, and communication standards",
      "Understanding hardware circuits",
      "Understanding user interfaces"
    ],
    correctAnswer: 1,
    explanation: "Protocol RE focuses on understanding proprietary network protocols, file formats, and communication standards. It often involves packet capture analysis and fuzzing.",
    topic: "Types of RE"
  },
  {
    id: 31,
    question: "Why is Game RE considered a specialized field?",
    options: [
      "Games don't have any protection",
      "Games often use custom formats, engines, and protection schemes requiring specialized knowledge",
      "Games are always open source",
      "Game RE doesn't require any special skills"
    ],
    correctAnswer: 1,
    explanation: "Games often use custom formats, engines, and protection schemes that require specialized knowledge. Game RE enables mods, cheats (single-player), and anti-cheat systems.",
    topic: "Types of RE"
  },
  // Topic 6: Static vs Dynamic Analysis (Questions 32-38)
  {
    id: 32,
    question: "What is static analysis in reverse engineering?",
    options: [
      "Running the program and watching it",
      "Examining the binary without executing it",
      "Only looking at network traffic",
      "Testing the program with user input"
    ],
    correctAnswer: 1,
    explanation: "Static analysis means examining the binary without executing it. You analyze disassembly, decompiled code, strings, imports/exports, and structure.",
    topic: "Static vs Dynamic"
  },
  {
    id: 33,
    question: "What is a key advantage of static analysis?",
    options: [
      "It requires running potentially malicious code",
      "It's safe - no risk of malware execution",
      "It only shows executed code paths",
      "It requires a specific environment"
    ],
    correctAnswer: 1,
    explanation: "Static analysis is safe - there's no risk of malware execution. You can see the complete codebase at once and analyze code paths that are hard to trigger.",
    topic: "Static vs Dynamic"
  },
  {
    id: 34,
    question: "What is a limitation of static analysis?",
    options: [
      "It's too dangerous",
      "Obfuscation and packing make analysis harder; you can't see runtime values",
      "It's too fast",
      "It shows too much information"
    ],
    correctAnswer: 1,
    explanation: "Static analysis limitations include: obfuscation/packing makes analysis harder, you can't see runtime values, self-modifying code is invisible, and you may miss dynamically loaded code.",
    topic: "Static vs Dynamic"
  },
  {
    id: 35,
    question: "What is dynamic analysis in reverse engineering?",
    options: [
      "Looking at code without running it",
      "Running the program and observing its behavior",
      "Only reading documentation",
      "Only examining file headers"
    ],
    correctAnswer: 1,
    explanation: "Dynamic analysis involves running the program and observing its behavior. You use debuggers to step through code, monitor system calls, network traffic, file operations, and memory state.",
    topic: "Static vs Dynamic"
  },
  {
    id: 36,
    question: "What is a key advantage of dynamic analysis?",
    options: [
      "It's always completely safe",
      "It automatically bypasses obfuscation/packing and shows actual runtime behavior",
      "It never requires any setup",
      "It shows all code paths at once"
    ],
    correctAnswer: 1,
    explanation: "Dynamic analysis automatically bypasses obfuscation/packing, shows actual runtime behavior and values, and makes it easier to understand complex logic.",
    topic: "Static vs Dynamic"
  },
  {
    id: 37,
    question: "What is a limitation of dynamic analysis?",
    options: [
      "It's completely safe for malware",
      "Risk of malware infection, anti-debugging interference, and only seeing executed paths",
      "It's too fast",
      "It never requires any tools"
    ],
    correctAnswer: 1,
    explanation: "Dynamic analysis limitations: risk of malware infection (requires isolation), anti-debugging techniques can interfere, you only see executed code paths, and may require specific environment/inputs.",
    topic: "Static vs Dynamic"
  },
  {
    id: 38,
    question: "What is the recommended approach for RE analysis?",
    options: [
      "Only use static analysis",
      "Only use dynamic analysis",
      "Combine both techniques iteratively (hybrid approach)",
      "Avoid both and only read documentation"
    ],
    correctAnswer: 2,
    explanation: "The most effective approach combines both techniques iteratively: start with static analysis for overview, use dynamic to understand specific functions or bypass protections, return to static with new insights, repeat.",
    topic: "Static vs Dynamic"
  },
  // Topic 7: Essential Tools (Questions 39-45)
  {
    id: 39,
    question: "What is Ghidra?",
    options: [
      "A commercial debugging tool",
      "A free, NSA-developed disassembler with an excellent decompiler",
      "A text editor",
      "A network scanner"
    ],
    correctAnswer: 1,
    explanation: "Ghidra is a free, NSA-developed disassembler and decompiler. It's extensible with excellent decompilation capabilities and widely used in the security community.",
    topic: "Essential Tools"
  },
  {
    id: 40,
    question: "What is IDA Pro known for?",
    options: [
      "Being free and open source",
      "Being the industry standard disassembler, though expensive",
      "Only working on mobile apps",
      "Being a network analysis tool"
    ],
    correctAnswer: 1,
    explanation: "IDA Pro is the industry standard disassembler. It's expensive but considered best-in-class for professional reverse engineering work.",
    topic: "Essential Tools"
  },
  {
    id: 41,
    question: "What is x64dbg?",
    options: [
      "A compiler",
      "A free, Windows-focused debugger with modern UI and plugin support",
      "A decompiler only",
      "A mobile app analyzer"
    ],
    correctAnswer: 1,
    explanation: "x64dbg is a free, Windows-focused debugger with a modern UI and plugin support. It's widely used for dynamic analysis on Windows.",
    topic: "Essential Tools"
  },
  {
    id: 42,
    question: "What is GDB primarily used for?",
    options: [
      "Windows kernel debugging",
      "Linux/Unix debugging (powerful but steep learning curve)",
      "Web application testing",
      "Mobile app development"
    ],
    correctAnswer: 1,
    explanation: "GDB (GNU Debugger) is the Linux/Unix standard debugger. It's powerful but has a steep learning curve with its command-line interface.",
    topic: "Essential Tools"
  },
  {
    id: 43,
    question: "What is the purpose of hex editors like HxD or 010 Editor?",
    options: [
      "Writing source code",
      "Viewing and editing raw binary data, understanding file structures",
      "Creating graphics",
      "Managing databases"
    ],
    correctAnswer: 1,
    explanation: "Hex editors let you view and edit raw binary data. They're essential for understanding file structures, patching binaries, and analyzing non-executable data.",
    topic: "Essential Tools"
  },
  {
    id: 44,
    question: "What does 'Detect It Easy' (DIE) tool help with?",
    options: [
      "Writing code",
      "Identifying packers, compilers, and protections used on a binary",
      "Creating network traffic",
      "Editing images"
    ],
    correctAnswer: 1,
    explanation: "Detect It Easy helps identify packers, compilers, and protections used on a binary. This is crucial for the initial triage phase of RE.",
    topic: "Essential Tools"
  },
  {
    id: 45,
    question: "What is Process Monitor used for?",
    options: [
      "Editing source code",
      "Windows syscall/file/registry monitoring during dynamic analysis",
      "Compiling programs",
      "Creating documentation"
    ],
    correctAnswer: 1,
    explanation: "Process Monitor is a Windows tool for monitoring syscalls, file operations, and registry access during dynamic analysis. It shows what a program does on the system.",
    topic: "Essential Tools"
  },
  // Topic 8: File Formats (Questions 46-52)
  {
    id: 46,
    question: "What file format does Windows use for executables?",
    options: [
      "ELF",
      "PE (Portable Executable)",
      "Mach-O",
      "APK"
    ],
    correctAnswer: 1,
    explanation: "Windows uses the PE (Portable Executable) format for .exe, .dll, and .sys files. Understanding PE is essential for Windows RE.",
    topic: "File Formats"
  },
  {
    id: 47,
    question: "What does the PE Import Table contain?",
    options: [
      "The program's source code",
      "API dependencies - functions the program uses from DLLs",
      "User documentation",
      "Encryption keys"
    ],
    correctAnswer: 1,
    explanation: "The Import Table lists API dependencies - functions the program imports from external DLLs. This reveals what system functionality the program uses.",
    topic: "File Formats"
  },
  {
    id: 48,
    question: "What file format does Linux use for executables?",
    options: [
      "PE",
      "ELF (Executable and Linkable Format)",
      "Mach-O",
      "DEX"
    ],
    correctAnswer: 1,
    explanation: "Linux uses ELF (Executable and Linkable Format). It's the standard for Linux, BSD, and many embedded systems.",
    topic: "File Formats"
  },
  {
    id: 49,
    question: "What are GOT and PLT in ELF files?",
    options: [
      "Compression algorithms",
      "Global Offset Table and Procedure Linkage Table - used for dynamic linking",
      "Graphics formats",
      "Text sections"
    ],
    correctAnswer: 1,
    explanation: "GOT (Global Offset Table) and PLT (Procedure Linkage Table) are used for dynamic linking in ELF files, resolving function addresses at runtime.",
    topic: "File Formats"
  },
  {
    id: 50,
    question: "What file format does macOS/iOS use?",
    options: [
      "PE",
      "ELF",
      "Mach-O",
      "APK"
    ],
    correctAnswer: 2,
    explanation: "macOS and iOS use Mach-O (Mach Object) format. It has unique features for the Apple ecosystem including Universal/Fat binaries for multi-architecture support.",
    topic: "File Formats"
  },
  {
    id: 51,
    question: "What is an APK file?",
    options: [
      "A Windows executable",
      "An Android Package containing DEX bytecode",
      "A Linux kernel module",
      "A macOS application"
    ],
    correctAnswer: 1,
    explanation: "APK (Android Package) is a ZIP archive containing DEX (Dalvik Executable) bytecode, AndroidManifest.xml, resources, and native libraries for Android apps.",
    topic: "File Formats"
  },
  {
    id: 52,
    question: "Why is knowing file formats important for RE?",
    options: [
      "It's not important at all",
      "It helps you find code, data, imports, and critical information quickly",
      "It's only needed for legal reasons",
      "It only matters for web development"
    ],
    correctAnswer: 1,
    explanation: "Knowing file formats helps you quickly find code, data, imports, and other critical information. Each OS uses different formats with specific headers, sections, and metadata.",
    topic: "File Formats"
  },
  // Topic 9: Assembly Language (Questions 53-59)
  {
    id: 53,
    question: "Why is assembly language important for RE?",
    options: [
      "It's the only programming language",
      "It's the human-readable representation of machine code that CPUs execute",
      "It's only used for web development",
      "It's optional and rarely needed"
    ],
    correctAnswer: 1,
    explanation: "Assembly is a human-readable representation of machine code - the actual instructions CPUs execute. You don't need to write it, but you must be able to read it for effective RE.",
    topic: "Assembly Language"
  },
  {
    id: 54,
    question: "In x86/x64 assembly, what does 'mov eax, 5' do?",
    options: [
      "Moves the value 5 to memory",
      "Sets the EAX register to the value 5",
      "Compares EAX with 5",
      "Jumps to address 5"
    ],
    correctAnswer: 1,
    explanation: "MOV is the move instruction. 'mov eax, 5' sets the EAX register to the value 5.",
    topic: "Assembly Language"
  },
  {
    id: 55,
    question: "What does the PUSH instruction do?",
    options: [
      "Removes a value from the stack",
      "Pushes a value onto the stack",
      "Compares two values",
      "Jumps to a new address"
    ],
    correctAnswer: 1,
    explanation: "PUSH pushes a value onto the stack. The stack is used for function calls, return addresses, and local variables.",
    topic: "Assembly Language"
  },
  {
    id: 56,
    question: "What does 'cmp eax, 0' followed by 'je label' do?",
    options: [
      "Always jumps to label",
      "Compares EAX with 0 and jumps to label if they are equal",
      "Sets EAX to 0",
      "Never jumps anywhere"
    ],
    correctAnswer: 1,
    explanation: "CMP compares two values and sets CPU flags. JE (Jump if Equal) then jumps to the label if the comparison showed equality (EAX == 0).",
    topic: "Assembly Language"
  },
  {
    id: 57,
    question: "In x86/x64, what register typically holds function return values?",
    options: [
      "ESP/RSP",
      "EAX/RAX",
      "EBP/RBP",
      "EIP/RIP"
    ],
    correctAnswer: 1,
    explanation: "EAX (32-bit) or RAX (64-bit) typically holds function return values in x86/x64 calling conventions.",
    topic: "Assembly Language"
  },
  {
    id: 58,
    question: "What is the stack pointer register in x86?",
    options: [
      "EAX",
      "ESP (or RSP in 64-bit)",
      "EBX",
      "ECX"
    ],
    correctAnswer: 1,
    explanation: "ESP (Stack Pointer) in 32-bit or RSP in 64-bit points to the current top of the stack. It's crucial for understanding function calls and local variables.",
    topic: "Assembly Language"
  },
  {
    id: 59,
    question: "What does 'ret' instruction do?",
    options: [
      "Returns a value to the caller",
      "Pops the return address from the stack and jumps to it",
      "Resets all registers",
      "Terminates the program"
    ],
    correctAnswer: 1,
    explanation: "RET pops the return address from the stack and jumps to it, returning control to the calling function.",
    topic: "Assembly Language"
  },
  // Topic 10: Common Patterns (Questions 60-65)
  {
    id: 60,
    question: "How does a FOR loop typically appear in assembly?",
    options: [
      "A single instruction",
      "Initialization, comparison, body, increment, and backward jump",
      "Only forward jumps",
      "No jumps at all"
    ],
    correctAnswer: 1,
    explanation: "Loops have initialization (counter = 0), comparison (counter < limit), body (the loop code), increment (counter++), and a backward jump to repeat.",
    topic: "Common Patterns"
  },
  {
    id: 61,
    question: "What assembly pattern indicates array access?",
    options: [
      "Only using immediate values",
      "Base address + (index × element size) pattern",
      "Only using jumps",
      "Only using stack operations"
    ],
    correctAnswer: 1,
    explanation: "Array access uses the pattern: base address + (index × element size). For example, [ebx + ecx*4] accesses array[ecx] where elements are 4 bytes.",
    topic: "Common Patterns"
  },
  {
    id: 62,
    question: "How can you recognize struct field access in assembly?",
    options: [
      "Random memory accesses",
      "Fixed offsets from a base pointer",
      "No memory accesses",
      "Only stack operations"
    ],
    correctAnswer: 1,
    explanation: "Struct field access shows as fixed offsets from a base pointer. For example, [ebx], [ebx+4], [ebx+8] indicates accessing fields at offsets 0, 4, and 8.",
    topic: "Common Patterns"
  },
  {
    id: 63,
    question: "What indicates an if-else statement in assembly?",
    options: [
      "Only MOV instructions",
      "Compare (CMP) followed by conditional jump (JE, JNE, etc.)",
      "Only arithmetic operations",
      "No jumps"
    ],
    correctAnswer: 1,
    explanation: "If-else statements use compare (CMP) followed by conditional jumps. The true branch executes, then jumps past the false branch (or vice versa).",
    topic: "Common Patterns"
  },
  {
    id: 64,
    question: "How are function calls typically structured in x64?",
    options: [
      "Arguments only on stack",
      "First arguments in registers (RCX, RDX, R8, R9), then CALL, return in RAX",
      "Arguments in random order",
      "No registers used"
    ],
    correctAnswer: 1,
    explanation: "x64 calling convention: first four arguments in RCX, RDX, R8, R9, additional on stack, CALL instruction, return value in RAX.",
    topic: "Common Patterns"
  },
  {
    id: 65,
    question: "What pattern suggests string operations?",
    options: [
      "Only arithmetic",
      "Loops with byte comparisons or calls to strlen, strcmp, strcpy",
      "Only jump instructions",
      "Only stack operations"
    ],
    correctAnswer: 1,
    explanation: "String operations show as loops checking bytes for null terminator (0), or calls to string functions like strlen, strcmp, strcpy.",
    topic: "Common Patterns"
  },
  // Topic 11: Anti-RE Techniques (Questions 66-70)
  {
    id: 66,
    question: "What is a 'packer' in the context of software protection?",
    options: [
      "A compression tool for images",
      "Software that compresses/encrypts code and adds an unpacking stub",
      "A debugging tool",
      "A type of compiler"
    ],
    correctAnswer: 1,
    explanation: "A packer compresses or encrypts the original code and adds a 'stub' that unpacks it at runtime. The real code only exists in memory during execution.",
    topic: "Anti-RE Techniques"
  },
  {
    id: 67,
    question: "What is code obfuscation?",
    options: [
      "Making code run faster",
      "Transforming code to make it harder to understand while preserving functionality",
      "Removing all code",
      "Adding helpful comments"
    ],
    correctAnswer: 1,
    explanation: "Code obfuscation transforms code to make it harder to understand while preserving functionality. Techniques include control flow flattening, dead code insertion, and string encryption.",
    topic: "Anti-RE Techniques"
  },
  {
    id: 68,
    question: "What is IsDebuggerPresent()?",
    options: [
      "A decompiler function",
      "A Windows API that checks if a debugger is attached to the process",
      "A compiler optimization",
      "A network function"
    ],
    correctAnswer: 1,
    explanation: "IsDebuggerPresent() is a Windows API that returns TRUE if a debugger is attached. It's a simple anti-debugging check that can be easily bypassed.",
    topic: "Anti-RE Techniques"
  },
  {
    id: 69,
    question: "How do VM/sandbox detection techniques work?",
    options: [
      "They speed up the program",
      "They check for artifacts like VM tools, registry keys, or resource limitations",
      "They improve security",
      "They help debugging"
    ],
    correctAnswer: 1,
    explanation: "VM/sandbox detection checks for artifacts like VMware tools, registry keys, MAC address prefixes, low resources, or lack of mouse movement to detect analysis environments.",
    topic: "Anti-RE Techniques"
  },
  {
    id: 70,
    question: "What is VMProtect?",
    options: [
      "A free debugger",
      "A commercial protector that converts code to virtual machine bytecode",
      "An open source tool",
      "A documentation tool"
    ],
    correctAnswer: 1,
    explanation: "VMProtect is a commercial protection tool that converts code to custom virtual machine bytecode, making RE much more difficult as analysts must first understand the VM.",
    topic: "Anti-RE Techniques"
  },
  // Topic 12: Methodology (Questions 71-75)
  {
    id: 71,
    question: "What is the first phase in RE methodology?",
    options: [
      "Deep dive into assembly",
      "Initial triage - identify file type, check for packers, extract strings",
      "Writing the final report",
      "Running the program immediately"
    ],
    correctAnswer: 1,
    explanation: "Initial triage comes first: identify file type, check for packers/protections, extract strings, review imports/exports, and document file hashes.",
    topic: "Methodology"
  },
  {
    id: 72,
    question: "What should you do during static analysis phase?",
    options: [
      "Only run the program",
      "Load in disassembler, find entry point, identify interesting functions, cross-reference strings",
      "Delete the binary",
      "Skip to documentation"
    ],
    correctAnswer: 1,
    explanation: "During static analysis: load in disassembler (Ghidra, IDA), find entry point and main(), identify interesting functions from names/imports, cross-reference strings, map program structure.",
    topic: "Methodology"
  },
  {
    id: 73,
    question: "What is important for dynamic analysis setup?",
    options: [
      "Use your main computer without protection",
      "Set up a safe environment (VM, sandbox) first",
      "Skip all safety measures",
      "Only use production systems"
    ],
    correctAnswer: 1,
    explanation: "For dynamic analysis, always set up a safe environment first (VM, sandbox). Then run with monitoring tools, set breakpoints, trace execution, and capture network traffic.",
    topic: "Methodology"
  },
  {
    id: 74,
    question: "What does the 'deep dive' phase involve?",
    options: [
      "Quick surface-level analysis",
      "Focus on specific functions, rename variables, document algorithms, handle anti-analysis",
      "Ignoring all details",
      "Only reading documentation"
    ],
    correctAnswer: 1,
    explanation: "Deep dive phase: focus on specific functions of interest, rename variables and functions, document algorithms and data structures, handle anti-analysis techniques, iterate between static and dynamic.",
    topic: "Methodology"
  },
  {
    id: 75,
    question: "Why is documentation the final phase but should be ongoing?",
    options: [
      "Documentation is optional",
      "You should document as you go for reproducibility, legal protection, and knowledge retention",
      "Documentation should only be done once",
      "Notes slow down analysis"
    ],
    correctAnswer: 1,
    explanation: "While documentation is listed as a final phase, you should document as you go. Write detailed notes, create diagrams, document methodology for reproducibility, save annotated projects, and prepare findings summary.",
    topic: "Methodology"
  },
];

// Quiz Section Component
function QuizSection() {
  const theme = useTheme();
  const [quizState, setQuizState] = useState<'start' | 'active' | 'results'>('start');
  const [currentQuestions, setCurrentQuestions] = useState<QuizQuestion[]>([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);
  const [answers, setAnswers] = useState<(number | null)[]>([]);
  const [showExplanation, setShowExplanation] = useState(false);

  const startQuiz = () => {
    // Randomly select 10 questions from the bank
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    const selected = shuffled.slice(0, 10);
    setCurrentQuestions(selected);
    setCurrentQuestionIndex(0);
    setSelectedAnswer(null);
    setAnswers([]);
    setShowExplanation(false);
    setQuizState('active');
  };

  const handleAnswerSelect = (answerIndex: number) => {
    if (showExplanation) return;
    setSelectedAnswer(answerIndex);
  };

  const handleSubmitAnswer = () => {
    if (selectedAnswer === null) return;
    setShowExplanation(true);
    setAnswers([...answers, selectedAnswer]);
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex < currentQuestions.length - 1) {
      setCurrentQuestionIndex(currentQuestionIndex + 1);
      setSelectedAnswer(null);
      setShowExplanation(false);
    } else {
      setQuizState('results');
    }
  };

  const calculateScore = () => {
    let correct = 0;
    answers.forEach((answer, index) => {
      if (answer === currentQuestions[index].correctAnswer) {
        correct++;
      }
    });
    return correct;
  };

  const getScoreMessage = (score: number) => {
    const percentage = (score / 10) * 100;
    if (percentage >= 90) return { message: "Outstanding! You're an RE expert!", color: "#10b981" };
    if (percentage >= 70) return { message: "Great job! Solid understanding of RE fundamentals.", color: "#3b82f6" };
    if (percentage >= 50) return { message: "Good effort! Review the topics you missed.", color: "#f59e0b" };
    return { message: "Keep learning! RE takes time and practice.", color: "#ef4444" };
  };

  if (quizState === 'start') {
    return (
      <Paper sx={{ p: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
        <Box sx={{ textAlign: "center" }}>
          <QuizIcon sx={{ fontSize: 64, color: "#8b5cf6", mb: 2 }} />
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
            Test Your Knowledge
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
            Take this quiz to test your understanding of reverse engineering fundamentals. 
            10 questions will be randomly selected from our question bank of 75 covering all topics.
          </Typography>
          <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap", mb: 3 }}>
            <Chip label="10 Questions" color="primary" />
            <Chip label="Random Selection" variant="outlined" />
            <Chip label="Instant Feedback" variant="outlined" />
          </Box>
          <Button
            variant="contained"
            size="large"
            startIcon={<QuizIcon />}
            onClick={startQuiz}
            sx={{
              px: 4,
              py: 1.5,
              borderRadius: 2,
              bgcolor: "#8b5cf6",
              "&:hover": { bgcolor: "#7c3aed" },
            }}
          >
            Start Quiz
          </Button>
        </Box>
      </Paper>
    );
  }

  if (quizState === 'results') {
    const score = calculateScore();
    const { message, color } = getScoreMessage(score);
    
    return (
      <Paper sx={{ p: 4, borderRadius: 3, bgcolor: alpha(color, 0.03), border: `1px solid ${alpha(color, 0.2)}` }}>
        <Box sx={{ textAlign: "center", mb: 4 }}>
          <EmojiEventsIcon sx={{ fontSize: 64, color, mb: 2 }} />
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            Quiz Complete!
          </Typography>
          <Typography variant="h2" sx={{ fontWeight: 800, color, mb: 1 }}>
            {score}/10
          </Typography>
          <Typography variant="h6" sx={{ color, mb: 3 }}>
            {message}
          </Typography>
          <LinearProgress 
            variant="determinate" 
            value={(score / 10) * 100} 
            sx={{ 
              height: 12, 
              borderRadius: 6, 
              mb: 3,
              maxWidth: 300,
              mx: "auto",
              bgcolor: alpha(color, 0.1),
              "& .MuiLinearProgress-bar": { bgcolor: color, borderRadius: 6 }
            }} 
          />
        </Box>
        
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Review Your Answers:
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {currentQuestions.map((q, index) => {
            const isCorrect = answers[index] === q.correctAnswer;
            return (
              <Grid item xs={12} key={q.id}>
                <Paper sx={{ 
                  p: 2, 
                  borderRadius: 2, 
                  bgcolor: alpha(isCorrect ? "#10b981" : "#ef4444", 0.05),
                  border: `1px solid ${alpha(isCorrect ? "#10b981" : "#ef4444", 0.2)}`
                }}>
                  <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                    <Box sx={{ 
                      width: 28, 
                      height: 28, 
                      borderRadius: "50%", 
                      bgcolor: isCorrect ? "#10b981" : "#ef4444",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      flexShrink: 0
                    }}>
                      <Typography variant="caption" sx={{ color: "white", fontWeight: 700 }}>
                        {index + 1}
                      </Typography>
                    </Box>
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.5 }}>
                        {q.question}
                      </Typography>
                      <Typography variant="caption" sx={{ color: isCorrect ? "#10b981" : "#ef4444" }}>
                        {isCorrect ? "✓ Correct" : `✗ Your answer: ${q.options[answers[index] || 0]}`}
                      </Typography>
                      {!isCorrect && (
                        <Typography variant="caption" sx={{ display: "block", color: "#10b981" }}>
                          Correct answer: {q.options[q.correctAnswer]}
                        </Typography>
                      )}
                    </Box>
                  </Box>
                </Paper>
              </Grid>
            );
          })}
        </Grid>
        
        <Box sx={{ display: "flex", justifyContent: "center", gap: 2 }}>
          <Button
            variant="contained"
            startIcon={<RefreshIcon />}
            onClick={startQuiz}
            sx={{
              px: 4,
              py: 1.5,
              borderRadius: 2,
              bgcolor: "#8b5cf6",
              "&:hover": { bgcolor: "#7c3aed" },
            }}
          >
            Try Again
          </Button>
        </Box>
      </Paper>
    );
  }

  // Active quiz state
  const currentQuestion = currentQuestions[currentQuestionIndex];
  const isCorrect = selectedAnswer === currentQuestion.correctAnswer;

  return (
    <Paper sx={{ p: 4, borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
      {/* Progress */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2" color="text.secondary">
            Question {currentQuestionIndex + 1} of {currentQuestions.length}
          </Typography>
          <Chip label={currentQuestion.topic} size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
        </Box>
        <LinearProgress 
          variant="determinate" 
          value={((currentQuestionIndex + 1) / currentQuestions.length) * 100} 
          sx={{ 
            height: 8, 
            borderRadius: 4,
            bgcolor: alpha("#8b5cf6", 0.1),
            "& .MuiLinearProgress-bar": { bgcolor: "#8b5cf6", borderRadius: 4 }
          }} 
        />
      </Box>

      {/* Question */}
      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
        {currentQuestion.question}
      </Typography>

      {/* Options */}
      <RadioGroup value={selectedAnswer} onChange={(e) => handleAnswerSelect(parseInt(e.target.value))}>
        <Grid container spacing={2}>
          {currentQuestion.options.map((option, index) => {
            let bgColor = "transparent";
            let borderColor = alpha(theme.palette.divider, 0.2);
            
            if (showExplanation) {
              if (index === currentQuestion.correctAnswer) {
                bgColor = alpha("#10b981", 0.1);
                borderColor = "#10b981";
              } else if (index === selectedAnswer && !isCorrect) {
                bgColor = alpha("#ef4444", 0.1);
                borderColor = "#ef4444";
              }
            } else if (selectedAnswer === index) {
              bgColor = alpha("#8b5cf6", 0.1);
              borderColor = "#8b5cf6";
            }

            return (
              <Grid item xs={12} key={index}>
                <Paper
                  onClick={() => handleAnswerSelect(index)}
                  sx={{
                    p: 2,
                    cursor: showExplanation ? "default" : "pointer",
                    borderRadius: 2,
                    bgcolor: bgColor,
                    border: `2px solid ${borderColor}`,
                    transition: "all 0.2s ease",
                    "&:hover": !showExplanation ? {
                      borderColor: "#8b5cf6",
                      bgcolor: alpha("#8b5cf6", 0.05),
                    } : {},
                  }}
                >
                  <FormControlLabel
                    value={index}
                    control={<Radio disabled={showExplanation} />}
                    label={option}
                    sx={{ m: 0, width: "100%" }}
                  />
                </Paper>
              </Grid>
            );
          })}
        </Grid>
      </RadioGroup>

      {/* Explanation */}
      {showExplanation && (
        <Paper sx={{ 
          p: 2, 
          mt: 3, 
          borderRadius: 2, 
          bgcolor: alpha(isCorrect ? "#10b981" : "#f59e0b", 0.1),
          border: `1px solid ${alpha(isCorrect ? "#10b981" : "#f59e0b", 0.3)}`
        }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: isCorrect ? "#10b981" : "#f59e0b", mb: 1 }}>
            {isCorrect ? "✓ Correct!" : "✗ Incorrect"}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {currentQuestion.explanation}
          </Typography>
        </Paper>
      )}

      {/* Actions */}
      <Box sx={{ display: "flex", justifyContent: "flex-end", mt: 3, gap: 2 }}>
        {!showExplanation ? (
          <Button
            variant="contained"
            onClick={handleSubmitAnswer}
            disabled={selectedAnswer === null}
            sx={{
              px: 4,
              borderRadius: 2,
              bgcolor: "#8b5cf6",
              "&:hover": { bgcolor: "#7c3aed" },
            }}
          >
            Submit Answer
          </Button>
        ) : (
          <Button
            variant="contained"
            onClick={handleNextQuestion}
            sx={{
              px: 4,
              borderRadius: 2,
              bgcolor: "#8b5cf6",
              "&:hover": { bgcolor: "#7c3aed" },
            }}
          >
            {currentQuestionIndex < currentQuestions.length - 1 ? "Next Question" : "See Results"}
          </Button>
        )}
      </Box>
    </Paper>
  );
}

// Outline sections for future expansion
const outlineSections = [
  {
    id: "what-is-re",
    title: "What is Reverse Engineering?",
    icon: <SearchIcon />,
    color: "#3b82f6",
    status: "Complete",
    description: "Definition, core concepts, and the fundamental idea of understanding software without source code",
  },
  {
    id: "why-re",
    title: "Why Learn Reverse Engineering?",
    icon: <PsychologyIcon />,
    color: "#8b5cf6",
    status: "Complete",
    description: "Career applications: malware analysis, vulnerability research, game hacking, interoperability, legacy systems",
  },
  {
    id: "legal-ethical",
    title: "Legal & Ethical Considerations",
    icon: <GavelIcon />,
    color: "#ef4444",
    status: "Complete",
    description: "DMCA, CFAA, responsible disclosure, when RE is legal, ethical guidelines, and professional boundaries",
  },
  {
    id: "mindset",
    title: "The RE Mindset",
    icon: <PsychologyIcon />,
    color: "#10b981",
    status: "Complete",
    description: "Patience, curiosity, pattern recognition, systematic approach, dealing with frustration, building intuition",
  },
  {
    id: "types-of-re",
    title: "Types of Reverse Engineering",
    icon: <ExtensionIcon />,
    color: "#f59e0b",
    status: "Complete",
    description: "Software RE, hardware RE, protocol RE, malware RE, firmware RE, and their differences",
  },
  {
    id: "static-vs-dynamic",
    title: "Static vs Dynamic Analysis",
    icon: <VisibilityIcon />,
    color: "#6366f1",
    status: "Complete",
    description: "When to use each approach, benefits, limitations, and how they complement each other",
  },
  {
    id: "tools-overview",
    title: "Essential Tools Overview",
    icon: <BuildIcon />,
    color: "#ec4899",
    status: "Complete",
    description: "Disassemblers (Ghidra, IDA), debuggers (x64dbg, GDB), hex editors, and supporting utilities",
  },
  {
    id: "file-formats",
    title: "Understanding File Formats",
    icon: <StorageIcon />,
    color: "#0ea5e9",
    status: "Complete",
    description: "PE (Windows), ELF (Linux), Mach-O (macOS), APK (Android), and why format knowledge matters",
  },
  {
    id: "assembly-intro",
    title: "Assembly Language Primer",
    icon: <CodeIcon />,
    color: "#dc2626",
    status: "Complete",
    description: "Why assembly matters, x86/x64 basics, ARM overview, reading disassembly output",
  },
  {
    id: "common-patterns",
    title: "Recognizing Common Patterns",
    icon: <ExtensionIcon />,
    color: "#22c55e",
    status: "Complete",
    description: "Loops, conditionals, function calls, string operations, and compiler-generated patterns",
  },
  {
    id: "anti-re",
    title: "Anti-Reverse Engineering Techniques",
    icon: <LockIcon />,
    color: "#f97316",
    status: "Complete",
    description: "Packers, obfuscation, anti-debugging, VM detection, and how to identify/bypass them",
  },
  {
    id: "methodology",
    title: "RE Methodology & Workflow",
    icon: <TerminalIcon />,
    color: "#8b5cf6",
    status: "Complete",
    description: "Systematic approach: initial triage, identifying entry points, mapping functionality, documentation",
  },
  {
    id: "practice-resources",
    title: "Practice Resources & CTFs",
    icon: <SchoolIcon />,
    color: "#3b82f6",
    status: "Complete",
    description: "Crackmes, RE CTF challenges, vulnerable apps, and recommended learning paths",
  },
  {
    id: "career-paths",
    title: "Career Paths in RE",
    icon: <SecurityIcon />,
    color: "#10b981",
    status: "Complete",
    description: "Malware analyst, vulnerability researcher, game security, anti-cheat, embedded security",
  },
];

// Quick stats for visual impact
const quickStats = [
  { value: "14", label: "Topics Covered", color: "#3b82f6" },
  { value: "∞", label: "Patience Required", color: "#ef4444" },
  { value: "1", label: "Core Skill", color: "#10b981" },
  { value: "0", label: "Source Code Needed", color: "#8b5cf6" },
];

export default function IntroToReverseEngineeringPage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Introduction to Reverse Engineering - Comprehensive beginner's guide covering what reverse engineering is, why it's valuable (malware analysis, vulnerability research, interoperability, legacy systems), legal and ethical considerations (DMCA, CFAA, responsible disclosure), the RE mindset, types of RE (software, hardware, protocol, firmware), static vs dynamic analysis, essential tools (Ghidra, IDA, x64dbg, GDB), file formats (PE, ELF, Mach-O, APK), assembly language primer, common patterns, anti-RE techniques, methodology, practice resources, and career paths.`;

  return (
    <LearnPageLayout pageTitle="Introduction to Reverse Engineering" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Back Button */}
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate("/learn")}
          sx={{ mb: 3 }}
        >
          Back to Learning Hub
        </Button>

        {/* Hero Banner */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#dc2626", 0.15)} 0%, ${alpha("#f97316", 0.15)} 50%, ${alpha("#8b5cf6", 0.15)} 100%)`,
            border: `1px solid ${alpha("#dc2626", 0.2)}`,
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
              background: `radial-gradient(circle, ${alpha("#dc2626", 0.1)} 0%, transparent 70%)`,
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
                  background: `linear-gradient(135deg, #dc2626, #f97316)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#dc2626", 0.3)}`,
                }}
              >
                <MemoryIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                  Introduction to Reverse Engineering
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                  Understanding software from the outside in
                </Typography>
              </Box>
            </Box>
            
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
              <Chip label="Beginner Friendly" color="success" />
              <Chip label="Fundamentals" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 600 }} />
              <Chip label="Malware Analysis" sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444", fontWeight: 600 }} />
              <Chip label="Vulnerability Research" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
              <Chip label="Security Research" sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 600 }} />
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
                bgcolor: alpha("#dc2626", 0.1),
                color: "#dc2626",
                "&:hover": {
                  bgcolor: alpha("#dc2626", 0.2),
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
              { label: "What is RE?", id: "what-is-re" },
              { label: "Why Learn RE?", id: "why-re" },
              { label: "Legal & Ethics", id: "legal-ethical" },
              { label: "RE Mindset", id: "mindset" },
              { label: "Types of RE", id: "types-of-re" },
              { label: "Static vs Dynamic", id: "static-vs-dynamic" },
              { label: "Tools", id: "tools-overview" },
              { label: "File Formats", id: "file-formats" },
              { label: "Assembly", id: "assembly-intro" },
              { label: "Patterns", id: "common-patterns" },
              { label: "Anti-RE", id: "anti-re" },
              { label: "Methodology", id: "methodology" },
              { label: "Practice", id: "practice-resources" },
              { label: "Careers", id: "career-paths" },
              { label: "Prerequisites", id: "prerequisites" },
              { label: "Next Steps", id: "next-steps" },
            ].map((nav) => (
              <Chip
                key={nav.id}
                label={nav.label}
                size="small"
                clickable
                onClick={() => document.getElementById(nav.id)?.scrollIntoView({ behavior: "smooth", block: "start" })}
                sx={{
                  fontWeight: 600,
                  fontSize: "0.75rem",
                  "&:hover": {
                    bgcolor: alpha("#dc2626", 0.15),
                    color: "#dc2626",
                  },
                }}
              />
            ))}
          </Box>
        </Paper>

        {/* ==================== INTRODUCTION ==================== */}
        <Typography id="intro" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🔬 What You'll Learn
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          A comprehensive foundation in reverse engineering concepts and techniques
        </Typography>

        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Reverse engineering</strong> is the art and science of understanding how software works without access 
            to its source code. It's like being a detective for code — you examine the compiled binary, analyze its behavior, 
            and reconstruct an understanding of what it does and how it does it.
          </Typography>
          <Box sx={{ my: 3 }}>
            <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
              This skill is <strong>fundamental to cybersecurity</strong>. Whether you want to analyze malware to understand 
              threats, find vulnerabilities in software before attackers do, ensure two systems can communicate (interoperability), 
              or maintain legacy systems with lost source code — reverse engineering is the key that unlocks these doors.
            </Typography>
          </Box>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            Unlike typical programming where you write code and see results, RE works in reverse: you start with the 
            compiled result (the binary) and work backwards to understand the original intent. This requires a unique 
            combination of <strong>patience, curiosity, pattern recognition, and systematic thinking</strong>. It can be 
            frustrating at times, but the "aha!" moments when pieces click into place are incredibly rewarding.
          </Typography>
        </Paper>

        {/* ==================== WHAT IS REVERSE ENGINEERING ==================== */}
        <Typography id="what-is-re" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🧩 What is Reverse Engineering?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding the fundamental concepts and definitions
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#dc2626", 0.03), border: `1px solid ${alpha("#dc2626", 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
            The Core Concept
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            When developers write software, they create human-readable <strong>source code</strong> (in languages like C, C++, 
            Python, etc.). This source code is then <strong>compiled</strong> or <strong>assembled</strong> into machine code — 
            the binary instructions that CPUs actually execute. This compilation process is a <em>one-way transformation</em>; 
            much information (variable names, comments, high-level structure) is lost.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            <strong>Reverse engineering is the process of analyzing compiled software to understand its functionality, 
            structure, and behavior</strong> — essentially reconstructing knowledge that was lost during compilation. 
            You won't get the exact original source code back, but you can understand what the program does, how it does it, 
            and often find bugs, vulnerabilities, or hidden functionality.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>
            Think of it like archaeology for software: you're excavating layers of abstraction to understand the original 
            design and intent of the creators.
          </Typography>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981", display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon /> Common Use Cases
              </Typography>
              <List dense>
                {[
                  "Malware analysis — understanding threats to defend against them",
                  "Vulnerability research — finding security bugs in software",
                  "Interoperability — making systems work together without documentation",
                  "Legacy system maintenance — supporting software with lost source code",
                  "Competitive analysis — understanding competitor products (legally)",
                  "Copy protection research — understanding DRM (for security research)",
                  "Game modding — creating modifications and enhancements",
                  "Embedded/IoT security — analyzing firmware in devices",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon /> Important Considerations
              </Typography>
              <List dense>
                {[
                  "Legal restrictions vary by jurisdiction and purpose",
                  "Some software is protected by DMCA or similar laws",
                  "Always ensure you have authorization to analyze software",
                  "Responsible disclosure is crucial when finding vulnerabilities",
                  "RE for bypassing copy protection may be illegal",
                  "Corporate policies may restrict RE of competitor products",
                  "Malware analysis requires isolated environments",
                  "Document your methodology for legal protection",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== WHY LEARN REVERSE ENGINEERING ==================== */}
        <Typography id="why-re" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          💡 Why Learn Reverse Engineering?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Career applications and real-world value of RE skills
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            Reverse engineering is one of the <strong>most versatile and in-demand skills</strong> in cybersecurity. 
            It opens doors to specialized career paths that are both intellectually challenging and well-compensated. 
            Here's why learning RE is worth your investment:
          </Typography>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon /> Malware Analysis
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Analyze viruses, ransomware, trojans, and other malicious software to understand how they work, 
                what they target, and how to defend against them. Malware analysts are critical to threat intelligence 
                teams and incident response.
              </Typography>
              <Chip label="High Demand" size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6", display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon /> Vulnerability Research
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Find security bugs in software before attackers do. Vulnerability researchers discover zero-days, 
                write exploits for penetration testing, and help vendors fix security issues through responsible disclosure. 
                Bug bounty programs offer significant rewards for critical findings.
              </Typography>
              <Chip label="$50K-500K+ Bug Bounties" size="small" sx={{ bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6" }} />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
                <ExtensionIcon /> Interoperability & Integration
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                When systems need to communicate without documentation, RE provides the answers. Understand proprietary 
                protocols, file formats, and APIs to build compatible software, create integrations, or develop open-source 
                alternatives to closed systems.
              </Typography>
              <Chip label="Essential for Open Source" size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }} />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
                <HistoryIcon /> Legacy System Maintenance
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Source code gets lost. Companies go out of business. Developers move on. When critical software needs 
                maintenance but no source exists, RE is the only option. This is especially common in industrial control 
                systems, embedded devices, and enterprise software.
              </Typography>
              <Chip label="Critical Infrastructure" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
                <MemoryIcon /> Game Hacking & Modding
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Create game mods, cheats for single-player games, or work in anti-cheat development. Understanding how 
                games work at the binary level enables everything from simple mods to sophisticated anti-cheat systems. 
                Many security researchers started with game hacking.
              </Typography>
              <Chip label="Fun Entry Point" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9", display: "flex", alignItems: "center", gap: 1 }}>
                <StorageIcon /> Embedded & IoT Security
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Billions of embedded devices run firmware that rarely gets security audits. RE skills let you analyze 
                routers, smart devices, automotive systems, medical devices, and industrial controllers for vulnerabilities 
                that could have serious real-world consequences.
              </Typography>
              <Chip label="Growing Field" size="small" sx={{ bgcolor: alpha("#0ea5e9", 0.1), color: "#0ea5e9" }} />
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== LEGAL & ETHICAL CONSIDERATIONS ==================== */}
        <Typography id="legal-ethical" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          ⚖️ Legal & Ethical Considerations
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding the legal landscape and professional boundaries
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, mb: 3 }}>
            <WarningIcon sx={{ color: "#ef4444", fontSize: 32, mt: 0.5 }} />
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                Important Disclaimer
              </Typography>
              <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
                This section provides <strong>general educational information</strong>, not legal advice. Laws vary significantly 
                by country and jurisdiction. Always consult with a qualified legal professional before engaging in any RE 
                activity that could have legal implications. When in doubt, don't do it.
              </Typography>
            </Box>
          </Box>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                🇺🇸 United States: Key Laws
              </Typography>
              <List dense>
                {[
                  { primary: "DMCA (Digital Millennium Copyright Act)", secondary: "Prohibits circumventing copy protection; has security research exemptions" },
                  { primary: "CFAA (Computer Fraud and Abuse Act)", secondary: "Criminalizes unauthorized computer access; vague 'exceeds authorization' clause" },
                  { primary: "Trade Secret Laws", secondary: "RE to discover trade secrets may violate state/federal laws" },
                  { primary: "Contract Law", secondary: "EULAs/ToS may contractually prohibit RE (enforceability varies)" },
                ].map((item) => (
                  <ListItem key={item.primary} sx={{ py: 1, px: 0, flexDirection: "column", alignItems: "flex-start" }}>
                    <ListItemText 
                      primary={item.primary} 
                      secondary={item.secondary}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 700 }} 
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
                ✅ Generally Legal RE Activities
              </Typography>
              <List dense>
                {[
                  "Analyzing software you own/licensed for interoperability",
                  "Security research with proper authorization",
                  "Analyzing malware in isolated environments for defense",
                  "RE for educational purposes on your own software",
                  "Bug bounty programs with explicit scope",
                  "Open source intelligence gathering (public binaries)",
                  "Maintaining legacy systems you own/operate",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            🤝 Responsible Disclosure & Ethics
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
            When you discover vulnerabilities through RE, you have an ethical (and sometimes legal) obligation to handle 
            them responsibly:
          </Typography>
          <Grid container spacing={2}>
            {[
              { step: "1", title: "Document Everything", desc: "Keep detailed notes on your methodology and findings" },
              { step: "2", title: "Contact the Vendor", desc: "Report through official security channels if available" },
              { step: "3", title: "Set a Timeline", desc: "Give reasonable time to fix (typically 90 days)" },
              { step: "4", title: "Coordinate Disclosure", desc: "Work with vendor on public disclosure timing" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.step}>
                <Box sx={{ textAlign: "center" }}>
                  <Box sx={{ width: 32, height: 32, borderRadius: "50%", bgcolor: alpha("#f59e0b", 0.1), display: "inline-flex", alignItems: "center", justifyContent: "center", mb: 1 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>{item.step}</Typography>
                  </Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== THE RE MINDSET ==================== */}
        <Typography id="mindset" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🧠 The RE Mindset
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Developing the mental framework for successful reverse engineering
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            Technical skills are important, but the <strong>right mindset</strong> is what separates good reverse engineers 
            from great ones. RE is as much a mental discipline as it is a technical one. The most successful reverse engineers 
            share certain characteristics and approaches that you can cultivate:
          </Typography>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                🔍 Insatiable Curiosity
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                The best reverse engineers are driven by an almost obsessive need to understand how things work. 
                They can't look at a piece of software without wondering what's happening beneath the surface. 
                This curiosity sustains you through the difficult parts of analysis.
              </Typography>
              <Chip label="'How does this really work?'" size="small" variant="outlined" />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                ⏳ Extreme Patience
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                RE is slow, methodical work. You might spend hours (or days) on a single function. You'll hit dead 
                ends, misunderstand code, and need to backtrack repeatedly. The ability to stay focused despite 
                frustration is essential. Take breaks, but don't give up.
              </Typography>
              <Chip label="'This will take as long as it takes'" size="small" variant="outlined" />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                🧩 Pattern Recognition
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                With experience, you'll start recognizing common patterns: how compilers generate code for loops, 
                conditionals, virtual function calls, string operations. This pattern recognition dramatically speeds 
                up analysis. Train your brain by studying many different binaries.
              </Typography>
              <Chip label="'I've seen this pattern before'" size="small" variant="outlined" />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                📊 Systematic Approach
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Don't just randomly click around in a disassembler. Develop a methodology: start with reconnaissance, 
                identify key functions, understand data structures, map the call graph. Take notes obsessively. 
                A systematic approach prevents you from getting lost in large binaries.
              </Typography>
              <Chip label="'Follow the process'" size="small" variant="outlined" />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
                🎯 Hypothesis-Driven Analysis
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Form hypotheses about what code does, then test them. "I think this function validates passwords. 
                Let me set a breakpoint and see what parameters it receives." This scientific approach is more 
                efficient than trying to understand everything at once.
              </Typography>
              <Chip label="'Test assumptions with evidence'" size="small" variant="outlined" />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
                📝 Documentation Habit
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Always document as you go. Rename functions, add comments, create diagrams. Future you (even tomorrow-you) 
                will forget what you discovered. Good documentation also helps when explaining findings to others and 
                provides legal protection by showing your methodology.
              </Typography>
              <Chip label="'If it's not documented, it didn't happen'" size="small" variant="outlined" />
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== TYPES OF REVERSE ENGINEERING ==================== */}
        <Typography id="types-of-re" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🔧 Types of Reverse Engineering
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Different domains and specializations within RE
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>
            "Reverse engineering" is a broad term that covers many different specializations. While the fundamental 
            skills overlap, each domain has unique challenges, tools, and knowledge requirements. Understanding 
            these different types helps you focus your learning path.
          </Typography>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6", display: "flex", alignItems: "center", gap: 1 }}>
                <CodeIcon /> Software RE (Binary Analysis)
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                The most common form — analyzing compiled executables, libraries, and applications. Covers 
                Windows PE files, Linux ELF binaries, macOS Mach-O, mobile apps, and more. This is the 
                foundation most RE courses focus on.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                <Chip label="Disassemblers" size="small" variant="outlined" />
                <Chip label="Debuggers" size="small" variant="outlined" />
                <Chip label="Decompilers" size="small" variant="outlined" />
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon /> Malware RE
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                A specialized subset of software RE focused on analyzing malicious code. Requires understanding 
                of anti-analysis techniques, safe analysis environments, and threat intelligence. Often time-sensitive 
                as you're racing against active threats.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                <Chip label="Sandbox Analysis" size="small" variant="outlined" />
                <Chip label="Unpacking" size="small" variant="outlined" />
                <Chip label="C2 Analysis" size="small" variant="outlined" />
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
                <MemoryIcon /> Hardware RE
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Analyzing physical circuits, chips, and electronic systems. Involves probing PCBs, extracting 
                firmware from chips, analyzing custom ASICs, and understanding hardware security modules. 
                Requires electronics knowledge and specialized equipment.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                <Chip label="Logic Analyzers" size="small" variant="outlined" />
                <Chip label="JTAG" size="small" variant="outlined" />
                <Chip label="Chip Decapping" size="small" variant="outlined" />
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
                <StorageIcon /> Firmware RE
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Analyzing software embedded in devices: routers, IoT devices, automotive ECUs, medical devices, 
                industrial controllers. Bridges hardware and software RE. Often involves extracting and analyzing 
                complete filesystem images.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                <Chip label="Binwalk" size="small" variant="outlined" />
                <Chip label="Emulation" size="small" variant="outlined" />
                <Chip label="Flash Dump" size="small" variant="outlined" />
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon /> Protocol RE
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Understanding proprietary network protocols, file formats, and communication standards. Often 
                involves packet capture analysis, fuzzing, and understanding serialization formats. Critical for 
                interoperability and security testing.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                <Chip label="Wireshark" size="small" variant="outlined" />
                <Chip label="Protocol Buffers" size="small" variant="outlined" />
                <Chip label="Format Specs" size="small" variant="outlined" />
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9", display: "flex", alignItems: "center", gap: 1 }}>
                <ExtensionIcon /> Game RE
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Specialized in video games — understanding game engines, creating mods, developing cheats 
                (for single-player), or building anti-cheat systems. Games often use custom formats, engines, 
                and protection schemes that require specialized knowledge.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                <Chip label="Game Engines" size="small" variant="outlined" />
                <Chip label="Memory Editing" size="small" variant="outlined" />
                <Chip label="Anti-Cheat" size="small" variant="outlined" />
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== STATIC VS DYNAMIC ANALYSIS ==================== */}
        <Typography id="static-vs-dynamic" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🔬 Static vs Dynamic Analysis
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Two fundamental approaches to understanding software
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#6366f1", 0.03), border: `1px solid ${alpha("#6366f1", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>
            Reverse engineering uses two complementary approaches: <strong>static analysis</strong> (examining code without 
            running it) and <strong>dynamic analysis</strong> (observing behavior during execution). Most real-world RE 
            combines both techniques. Understanding when to use each is crucial for efficient analysis.
          </Typography>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                📖 Static Analysis
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Examining the binary without executing it. You analyze the disassembly, decompiled code, strings, 
                imports/exports, and structure to understand functionality.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#10b981" }}>Advantages:</Typography>
              <List dense sx={{ mb: 2 }}>
                {[
                  "Safe — no risk of malware execution",
                  "See the complete codebase at once",
                  "No need for working environment/dependencies",
                  "Can analyze code paths that are hard to trigger",
                  "Reproducible analysis",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>Limitations:</Typography>
              <List dense>
                {[
                  "Obfuscation/packing makes analysis harder",
                  "Can't see runtime values or behavior",
                  "Self-modifying code is invisible",
                  "May miss dynamically loaded code",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <WarningIcon sx={{ fontSize: 14, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                ▶️ Dynamic Analysis
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Running the program and observing its behavior. Use debuggers to step through code, monitor system 
                calls, network traffic, file operations, and memory state.
              </Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#10b981" }}>Advantages:</Typography>
              <List dense sx={{ mb: 2 }}>
                {[
                  "See actual runtime behavior and values",
                  "Bypass obfuscation/packing automatically",
                  "Observe real data flow and state",
                  "Easier to understand complex logic",
                  "Find code triggered by specific inputs",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>Limitations:</Typography>
              <List dense>
                {[
                  "Risk of malware infection — requires isolation",
                  "Anti-debugging techniques can interfere",
                  "Only see executed code paths",
                  "May require specific environment/inputs",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <WarningIcon sx={{ fontSize: 14, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            🔄 The Hybrid Approach (Recommended)
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
            The most effective approach combines both techniques iteratively: Start with static analysis to get an 
            overview (strings, imports, structure). Use dynamic analysis to understand specific functions or bypass 
            protections. Return to static analysis with new insights. Repeat until you understand the target fully.
          </Typography>
        </Paper>

        {/* ==================== ESSENTIAL TOOLS OVERVIEW ==================== */}
        <Typography id="tools-overview" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🛠️ Essential Tools Overview
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The fundamental tools every reverse engineer needs
        </Typography>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
                🔍 Disassemblers & Decompilers
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Convert machine code back to assembly (disassembly) or pseudo-code (decompilation). These are your 
                primary analysis tools for static analysis.
              </Typography>
              <List dense>
                {[
                  { name: "Ghidra", desc: "Free, NSA-developed, excellent decompiler, extensible" },
                  { name: "IDA Pro", desc: "Industry standard, expensive, best-in-class" },
                  { name: "Binary Ninja", desc: "Modern UI, great API, mid-range price" },
                  { name: "Radare2/Cutter", desc: "Free, open-source, command-line focused" },
                ].map((tool) => (
                  <ListItem key={tool.name} sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={tool.name} 
                      secondary={tool.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 700 }} 
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                🐛 Debuggers
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Allow you to run programs step-by-step, set breakpoints, examine memory and registers, and modify 
                execution flow. Essential for dynamic analysis.
              </Typography>
              <List dense>
                {[
                  { name: "x64dbg", desc: "Free, Windows-focused, modern UI, plugin support" },
                  { name: "WinDbg", desc: "Microsoft's debugger, kernel debugging, crash analysis" },
                  { name: "GDB", desc: "Linux/Unix standard, powerful but steep learning curve" },
                  { name: "LLDB", desc: "macOS default, Xcode integration" },
                ].map((tool) => (
                  <ListItem key={tool.name} sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={tool.name} 
                      secondary={tool.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 700 }} 
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                📊 Hex Editors & Viewers
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                View and edit raw binary data. Essential for understanding file structures, patching binaries, and 
                analyzing non-executable data.
              </Typography>
              <List dense>
                {[
                  { name: "HxD", desc: "Free, Windows, fast and lightweight" },
                  { name: "010 Editor", desc: "Binary templates, powerful scripting" },
                  { name: "ImHex", desc: "Free, cross-platform, pattern language" },
                  { name: "xxd/hexdump", desc: "Command-line utilities for quick viewing" },
                ].map((tool) => (
                  <ListItem key={tool.name} sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={tool.name} 
                      secondary={tool.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 700 }} 
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                🔧 Supporting Utilities
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Specialized tools for specific tasks that complement your main analysis tools.
              </Typography>
              <List dense>
                {[
                  { name: "Process Monitor", desc: "Windows syscall/file/registry monitoring" },
                  { name: "Wireshark", desc: "Network traffic capture and analysis" },
                  { name: "PE-bear/CFF Explorer", desc: "PE file structure viewers" },
                  { name: "Detect It Easy", desc: "Identify packers, compilers, protections" },
                  { name: "strings", desc: "Extract readable strings from binaries" },
                ].map((tool) => (
                  <ListItem key={tool.name} sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={tool.name} 
                      secondary={tool.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 700 }} 
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== UNDERSTANDING FILE FORMATS ==================== */}
        <Typography id="file-formats" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📁 Understanding File Formats
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The structure of executable files across different platforms
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>
            Before diving into code analysis, you need to understand how executable files are structured. Each operating 
            system uses different file formats with specific headers, sections, and metadata. Knowing these formats helps 
            you find code, data, imports, and other critical information quickly.
          </Typography>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                🪟 PE Format (Windows)
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Portable Executable — used for .exe, .dll, .sys files on Windows. Understanding PE is essential for 
                Windows RE.
              </Typography>
              <List dense>
                {[
                  "DOS Header & Stub (legacy compatibility)",
                  "PE Header (machine type, timestamps)",
                  "Optional Header (entry point, image base)",
                  "Section Headers (.text, .data, .rdata, .rsrc)",
                  "Import/Export Tables (API dependencies)",
                  "Relocation Table (ASLR support)",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                🐧 ELF Format (Linux/Unix)
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Executable and Linkable Format — standard for Linux, BSD, and many embedded systems.
              </Typography>
              <List dense>
                {[
                  "ELF Header (magic bytes, architecture)",
                  "Program Headers (memory layout for loading)",
                  "Section Headers (.text, .data, .bss, .rodata)",
                  "Symbol Tables (function/variable names)",
                  "Dynamic Section (shared library dependencies)",
                  "GOT/PLT (Global Offset Table, Procedure Linkage)",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                🍎 Mach-O Format (macOS/iOS)
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Mach Object — Apple's native executable format. Unique features for Apple ecosystem.
              </Typography>
              <List dense>
                {[
                  "Mach Header (CPU type, file type)",
                  "Load Commands (segments, libraries)",
                  "Segments (__TEXT, __DATA, __LINKEDIT)",
                  "Universal/Fat Binaries (multi-architecture)",
                  "Code Signing (required for iOS)",
                  "Objective-C/Swift metadata",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                🤖 APK/DEX Format (Android)
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Android Package — ZIP archive containing Dalvik Executable (DEX) bytecode.
              </Typography>
              <List dense>
                {[
                  "AndroidManifest.xml (permissions, components)",
                  "classes.dex (Dalvik/ART bytecode)",
                  "resources.arsc (compiled resources)",
                  "lib/ folder (native .so libraries)",
                  "META-INF/ (signatures, certificates)",
                  "Tools: jadx, apktool, dex2jar",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== ASSEMBLY LANGUAGE PRIMER ==================== */}
        <Typography id="assembly-intro" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          💻 Assembly Language Primer
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The language of CPUs — your window into how software really works
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#dc2626", 0.03), border: `1px solid ${alpha("#dc2626", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 2 }}>
            Assembly language is a human-readable representation of machine code — the actual instructions your CPU 
            executes. You don't need to write assembly (compilers do that), but you <strong>must be able to read it</strong> 
            for effective reverse engineering. It looks intimidating at first, but patterns emerge quickly with practice.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>
            Most RE focuses on <strong>x86/x64</strong> (Intel/AMD) for desktop and <strong>ARM</strong> for mobile/embedded. 
            The concepts transfer between architectures — once you learn one, others come faster.
          </Typography>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                📝 x86/x64 Basics (Intel Syntax)
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2, fontFamily: "monospace", bgcolor: alpha("#000", 0.03), p: 1.5, borderRadius: 1 }}>
                mov eax, 5        ; eax = 5<br/>
                add eax, 3        ; eax = eax + 3<br/>
                push eax          ; push to stack<br/>
                call function     ; call function<br/>
                cmp eax, 0        ; compare eax with 0<br/>
                je label          ; jump if equal<br/>
                ret               ; return from function
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Common registers: EAX/RAX (return values), EBX/RBX, ECX/RCX (counter), EDX/RDX, 
                ESP/RSP (stack pointer), EBP/RBP (base pointer), EIP/RIP (instruction pointer)
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                📱 ARM Basics
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2, fontFamily: "monospace", bgcolor: alpha("#000", 0.03), p: 1.5, borderRadius: 1 }}>
                mov r0, #5        ; r0 = 5<br/>
                add r0, r0, #3    ; r0 = r0 + 3<br/>
                push {'{'}r0{'}'}        ; push to stack<br/>
                bl function       ; branch with link (call)<br/>
                cmp r0, #0        ; compare r0 with 0<br/>
                beq label         ; branch if equal<br/>
                bx lr             ; return (branch to link reg)
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Common registers: R0-R3 (arguments/return), R4-R11 (general purpose), 
                R12 (IP), R13/SP (stack), R14/LR (link/return), R15/PC (program counter)
              </Typography>
            </Paper>
          </Grid>
        </Grid>

        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            🎯 Key Concepts to Understand
          </Typography>
          <Grid container spacing={2}>
            {[
              { title: "Registers", desc: "Fast CPU storage for data and addresses" },
              { title: "Stack", desc: "LIFO structure for local variables, return addresses" },
              { title: "Calling Conventions", desc: "How functions receive arguments and return values" },
              { title: "Memory Addressing", desc: "Direct, indirect, indexed, and relative modes" },
              { title: "Flags", desc: "Zero, Carry, Sign, Overflow — used for conditionals" },
              { title: "Endianness", desc: "Byte order (little-endian for x86, varies for ARM)" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.title}>
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== RECOGNIZING COMMON PATTERNS ==================== */}
        <Typography id="common-patterns" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🧩 Recognizing Common Patterns
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          How high-level constructs look in assembly
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>
            Compilers transform high-level code into predictable assembly patterns. Once you recognize these patterns, 
            you can quickly identify if-statements, loops, function calls, and data structures without reading every 
            instruction. This pattern recognition is what makes experienced reverse engineers fast.
          </Typography>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                🔀 If-Else Statements
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Conditionals use compare (CMP) followed by conditional jumps (JE, JNE, JG, JL, etc.).
              </Typography>
              <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.03), p: 1.5, borderRadius: 1 }}>
                cmp eax, 10       ; if (x == 10)<br/>
                jne else_branch   ; jump if not equal<br/>
                ; ... if-body ...<br/>
                jmp end_if<br/>
                else_branch:<br/>
                ; ... else-body ...<br/>
                end_if:
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                🔄 For/While Loops
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Loops have initialization, comparison, body, increment, and backward jump.
              </Typography>
              <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.03), p: 1.5, borderRadius: 1 }}>
                xor ecx, ecx      ; i = 0<br/>
                loop_start:<br/>
                cmp ecx, 10       ; while (i &lt; 10)<br/>
                jge loop_end      ; exit if i &gt;= 10<br/>
                ; ... loop body ...<br/>
                inc ecx           ; i++<br/>
                jmp loop_start    ; repeat<br/>
                loop_end:
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                📞 Function Calls
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Arguments pushed/moved to registers, CALL instruction, return value in EAX/RAX.
              </Typography>
              <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.03), p: 1.5, borderRadius: 1 }}>
                ; x64 calling convention<br/>
                mov rcx, arg1     ; 1st argument<br/>
                mov rdx, arg2     ; 2nd argument<br/>
                mov r8, arg3      ; 3rd argument<br/>
                call function<br/>
                ; return value in rax
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                📊 Array Access
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Base address + (index × element size) pattern is key to recognizing arrays.
              </Typography>
              <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.03), p: 1.5, borderRadius: 1 }}>
                ; array[i] where sizeof(int) = 4<br/>
                mov eax, [ebx + ecx*4]<br/>
                ; ebx = base address<br/>
                ; ecx = index<br/>
                ; *4 = element size
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
                🔤 String Operations
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Look for loops with byte comparisons, or calls to string functions (strlen, strcmp, strcpy).
              </Typography>
              <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.03), p: 1.5, borderRadius: 1 }}>
                ; string length pattern<br/>
                xor ecx, ecx      ; counter = 0<br/>
                loop:<br/>
                cmp byte [esi+ecx], 0  ; null terminator?<br/>
                je done<br/>
                inc ecx           ; counter++<br/>
                jmp loop
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
                🏗️ Struct Access
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Fixed offsets from a base pointer indicate struct field access.
              </Typography>
              <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.03), p: 1.5, borderRadius: 1 }}>
                ; struct ptr in ebx<br/>
                mov eax, [ebx]      ; field at offset 0<br/>
                mov ecx, [ebx+4]    ; field at offset 4<br/>
                mov edx, [ebx+8]    ; field at offset 8<br/>
                ; consistent offsets = struct
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== ANTI-REVERSE ENGINEERING TECHNIQUES ==================== */}
        <Typography id="anti-re" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🔒 Anti-Reverse Engineering Techniques
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          How software tries to resist analysis — and how to overcome it
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>
            Software developers use various techniques to make reverse engineering harder. These range from simple 
            obfuscation to sophisticated VM-based protection. Understanding these techniques is essential — both to 
            bypass them during analysis and to understand their limitations if you're implementing protections.
          </Typography>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                📦 Packers & Crypters
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Compress or encrypt the original code and add a "stub" that unpacks it at runtime. The real code 
                only exists in memory during execution.
              </Typography>
              <List dense>
                {[
                  { name: "UPX", desc: "Common open-source packer, easily unpacked" },
                  { name: "Themida/WinLicense", desc: "Commercial protector with VM" },
                  { name: "VMProtect", desc: "Converts code to virtual machine bytecode" },
                  { name: "ASPack, PECompact", desc: "Legacy packers still seen in wild" },
                ].map((item) => (
                  <ListItem key={item.name} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.name} 
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 700 }} 
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
              <Chip label="Bypass: Dump from memory after unpacking" size="small" sx={{ mt: 1, bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                🌀 Code Obfuscation
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Transform code to make it harder to understand while preserving functionality. Increases analysis time 
                but doesn't make RE impossible.
              </Typography>
              <List dense>
                {[
                  "Control flow flattening — destroys normal if/loop structure",
                  "Dead code insertion — adds useless instructions",
                  "Instruction substitution — replaces simple ops with complex equivalents",
                  "String encryption — hides readable strings",
                  "Opaque predicates — conditionals with known outcomes",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <LockIcon sx={{ fontSize: 14, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                🐛 Anti-Debugging Techniques
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Detect or prevent debugger attachment. Often combined to create layered protection.
              </Typography>
              <List dense>
                {[
                  "IsDebuggerPresent() — Windows API check",
                  "PEB.BeingDebugged flag — direct memory check",
                  "NtQueryInformationProcess — more reliable detection",
                  "Timing checks — debuggers slow execution",
                  "Hardware breakpoint detection — check DR registers",
                  "INT 3 scanning — look for software breakpoints",
                  "Self-debugging — attach debugger to prevent others",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <BugReportIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                🖥️ VM/Sandbox Detection
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Detect analysis environments and behave differently (or not at all) when detected. Common in malware.
              </Typography>
              <List dense>
                {[
                  "Check for VM artifacts (VMware tools, registry keys)",
                  "CPUID instruction — reveals hypervisor presence",
                  "MAC address prefixes (VMware, VirtualBox)",
                  "Low resources (RAM, disk, CPU cores)",
                  "Mouse movement patterns — humans move mice",
                  "Recent files/documents — empty = sandbox",
                  "Sleep acceleration detection",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <VisibilityIcon sx={{ fontSize: 14, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== RE METHODOLOGY & WORKFLOW ==================== */}
        <Typography id="methodology" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📝 RE Methodology & Workflow
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          A systematic approach to reverse engineering any target
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>
            Having a consistent methodology prevents you from getting lost in large binaries. This workflow adapts to 
            your specific goals — malware analysis, vulnerability research, or understanding functionality — but the 
            core phases remain the same.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            {
              step: "1",
              title: "Initial Triage",
              color: "#3b82f6",
              tasks: [
                "Identify file type (PE, ELF, Mach-O, etc.)",
                "Check for packers/protections (DIE, Exeinfo)",
                "Extract strings for quick insights",
                "Review imports/exports for API usage",
                "Document file hashes (MD5, SHA256)",
              ],
            },
            {
              step: "2",
              title: "Static Analysis",
              color: "#8b5cf6",
              tasks: [
                "Load in disassembler (Ghidra, IDA)",
                "Find entry point and main()",
                "Identify interesting functions from names/imports",
                "Cross-reference strings to code",
                "Map high-level program structure",
              ],
            },
            {
              step: "3",
              title: "Dynamic Analysis",
              color: "#f59e0b",
              tasks: [
                "Set up safe environment (VM, sandbox)",
                "Run with monitoring (ProcMon, API Monitor)",
                "Set breakpoints on interesting functions",
                "Trace execution and observe behavior",
                "Capture network traffic if applicable",
              ],
            },
            {
              step: "4",
              title: "Deep Dive",
              color: "#22c55e",
              tasks: [
                "Focus on specific functions of interest",
                "Rename variables and functions as you understand them",
                "Document algorithms and data structures",
                "Handle anti-analysis techniques",
                "Iterate between static and dynamic",
              ],
            },
            {
              step: "5",
              title: "Documentation",
              color: "#ec4899",
              tasks: [
                "Write detailed notes as you go",
                "Create diagrams (call graphs, data flow)",
                "Document your methodology for reproducibility",
                "Save annotated IDB/Ghidra project",
                "Prepare report or findings summary",
              ],
            },
          ].map((phase) => (
            <Grid item xs={12} sm={6} md={4} key={phase.step}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 3, border: `1px solid ${alpha(phase.color, 0.2)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                  <Box
                    sx={{
                      width: 36,
                      height: 36,
                      borderRadius: "50%",
                      bgcolor: alpha(phase.color, 0.1),
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    <Typography variant="h6" sx={{ fontWeight: 800, color: phase.color }}>
                      {phase.step}
                    </Typography>
                  </Box>
                  <Typography variant="h6" sx={{ fontWeight: 700 }}>
                    {phase.title}
                  </Typography>
                </Box>
                <List dense>
                  {phase.tasks.map((task) => (
                    <ListItem key={task} sx={{ py: 0.2, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 20 }}>
                        <CheckCircleIcon sx={{ fontSize: 12, color: phase.color }} />
                      </ListItemIcon>
                      <ListItemText primary={task} primaryTypographyProps={{ variant: "caption" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== PRACTICE RESOURCES & CTFs ==================== */}
        <Typography id="practice-resources" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🎮 Practice Resources & CTFs
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Where to practice and build your skills
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>
            Reverse engineering is a skill learned by doing. Theory only gets you so far — you need to analyze real 
            binaries to develop intuition and speed. Start with crackmes (small challenges designed for learning), 
            then progress to CTF challenges and real-world samples.
          </Typography>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                🔓 Crackmes & Keygenmes
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Small programs specifically designed for RE practice. Usually involve finding a serial key or patching.
              </Typography>
              <List dense>
                {[
                  { name: "crackmes.one", desc: "Largest collection, difficulty ratings" },
                  { name: "reversing.kr", desc: "Quality challenges with walkthroughs" },
                  { name: "crackmes.de (archive)", desc: "Classic challenges, use web archive" },
                  { name: "Root-Me", desc: "Mixed challenges including cracking" },
                ].map((item) => (
                  <ListItem key={item.name} sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={item.name} 
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 700 }} 
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                🏳️ CTF Platforms
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Capture The Flag competitions with RE categories. Great for varied challenges and competition.
              </Typography>
              <List dense>
                {[
                  { name: "picoCTF", desc: "Beginner-friendly, always available" },
                  { name: "CTFtime.org", desc: "Calendar of all CTF events worldwide" },
                  { name: "Pwnable.kr/tw", desc: "Binary exploitation focused" },
                  { name: "Hack The Box", desc: "Challenges and machines with RE elements" },
                  { name: "OverTheWire", desc: "Wargames for various skill levels" },
                ].map((item) => (
                  <ListItem key={item.name} sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={item.name} 
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 700 }} 
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                🧪 Malware Samples (Advanced)
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Real malware for analysis practice. REQUIRES isolated environment — never analyze on your main machine.
              </Typography>
              <List dense>
                {[
                  { name: "MalwareBazaar", desc: "abuse.ch repository, tagged samples" },
                  { name: "VirusTotal", desc: "Download samples (requires account)" },
                  { name: "theZoo", desc: "GitHub repo of malware for research" },
                  { name: "VX Underground", desc: "Large collection, papers, and tools" },
                ].map((item) => (
                  <ListItem key={item.name} sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={item.name} 
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 700 }} 
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
              <Chip label="⚠️ Use isolated VM only!" size="small" sx={{ mt: 1, bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                📚 Learning Resources
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Books, courses, and tutorials to build foundational knowledge.
              </Typography>
              <List dense>
                {[
                  { name: "Practical Malware Analysis", desc: "THE book for malware RE" },
                  { name: "Reverse Engineering for Beginners", desc: "Free online, comprehensive" },
                  { name: "x86 Assembly Guide", desc: "cs.virginia.edu reference" },
                  { name: "OpenSecurityTraining2", desc: "Free video courses, excellent" },
                  { name: "Ghidra Ninja YouTube", desc: "Ghidra tips and tutorials" },
                ].map((item) => (
                  <ListItem key={item.name} sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={item.name} 
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 700 }} 
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== CAREER PATHS IN RE ==================== */}
        <Typography id="career-paths" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          💼 Career Paths in RE
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Professional roles that leverage reverse engineering skills
        </Typography>

        <Paper sx={{ p: 4, mb: 3, borderRadius: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>
            Reverse engineering opens doors to some of the most specialized and well-compensated roles in cybersecurity. 
            These positions are in high demand because the skills are rare and take years to develop. Here are the main 
            career paths where RE is central:
          </Typography>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
                🧬 Malware Analyst
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Analyze malicious software to understand capabilities, extract IOCs (Indicators of Compromise), and 
                develop detections. Work at security vendors, threat intelligence firms, or enterprise security teams.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1 }}>
                <Chip label="$90K-180K+" size="small" sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
                <Chip label="High Demand" size="small" variant="outlined" />
              </Box>
              <Typography variant="caption" color="text.secondary">
                Key skills: Static/dynamic analysis, Windows internals, scripting, threat intelligence
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#3b82f6" }}>
                🔍 Vulnerability Researcher
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Find security bugs in software through RE and fuzzing. Work for security firms, tech companies, or 
                independently through bug bounty programs. Some researchers earn $500K+ from critical bugs.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1 }}>
                <Chip label="$100K-300K+ (+ bounties)" size="small" sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
                <Chip label="Elite" size="small" variant="outlined" />
              </Box>
              <Typography variant="caption" color="text.secondary">
                Key skills: Exploit development, fuzzing, deep OS knowledge, specific target expertise
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>
                🎮 Game Security / Anti-Cheat
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Protect games from cheaters by understanding and defeating cheat techniques. Or work on the offensive 
                side developing game trainers and mods. Unique niche with passionate community.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1 }}>
                <Chip label="$80K-200K" size="small" sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
                <Chip label="Fun Niche" size="small" variant="outlined" />
              </Box>
              <Typography variant="caption" color="text.secondary">
                Key skills: Game engines, memory manipulation, kernel development, anti-tamper
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>
                🛡️ Embedded/IoT Security
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Secure firmware in devices: routers, automotive systems, medical devices, industrial controllers. 
                Critical infrastructure focus means high stakes and high pay.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1 }}>
                <Chip label="$100K-200K+" size="small" sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
                <Chip label="Growing Fast" size="small" variant="outlined" />
              </Box>
              <Typography variant="caption" color="text.secondary">
                Key skills: Firmware extraction, hardware hacking, ARM/MIPS, protocol analysis
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>
                🏢 Security Consultant
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                Apply RE skills in penetration testing, security assessments, and incident response. Varied work 
                across different clients and industries. Good entry point with growth potential.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1 }}>
                <Chip label="$80K-180K" size="small" sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
                <Chip label="Versatile" size="small" variant="outlined" />
              </Box>
              <Typography variant="caption" color="text.secondary">
                Key skills: Broad security knowledge, communication, client management, RE basics
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#0ea5e9" }}>
                🌐 Government/Intelligence
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                NSA, GCHQ, and similar agencies hire RE specialists for offensive and defensive cyber operations. 
                Requires clearance but offers unique challenges and job security.
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1 }}>
                <Chip label="$80K-160K + benefits" size="small" sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
                <Chip label="Clearance Required" size="small" variant="outlined" />
              </Box>
              <Typography variant="caption" color="text.secondary">
                Key skills: Deep expertise, discretion, often nation-state level targets
              </Typography>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== COURSE OUTLINE ==================== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            SUMMARY
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="outline" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📚 Course Outline
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Topics we'll cover in this comprehensive introduction (content coming soon)
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {outlineSections.map((section, index) => (
            <Grid item xs={12} sm={6} md={4} key={section.id}>
              <Paper
                sx={{
                  p: 2.5,
                  height: "100%",
                  borderRadius: 3,
                  border: `1px solid ${alpha(section.color, section.status === "Complete" ? 0.3 : 0.15)}`,
                  bgcolor: section.status === "Complete" ? alpha(section.color, 0.03) : "transparent",
                  opacity: section.status === "Complete" ? 1 : 0.75,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    transform: "translateY(-2px)",
                    borderColor: section.color,
                    opacity: 1,
                    boxShadow: `0 8px 24px ${alpha(section.color, 0.15)}`,
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 1 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: 1.5,
                        bgcolor: alpha(section.color, 0.1),
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: section.color,
                      }}
                    >
                      {section.icon}
                    </Box>
                    <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary" }}>
                      {String(index + 1).padStart(2, "0")}
                    </Typography>
                  </Box>
                  <Chip
                    label={section.status}
                    size="small"
                    icon={section.status === "Complete" ? <CheckCircleIcon sx={{ fontSize: 14 }} /> : <RadioButtonUncheckedIcon sx={{ fontSize: 14 }} />}
                    sx={{
                      fontSize: "0.65rem",
                      height: 22,
                      bgcolor: section.status === "Complete" ? alpha("#10b981", 0.1) : alpha("#6b7280", 0.1),
                      color: section.status === "Complete" ? "#10b981" : "#6b7280",
                      "& .MuiChip-icon": {
                        color: section.status === "Complete" ? "#10b981" : "#6b7280",
                      },
                    }}
                  />
                </Box>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                  {section.title}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ lineHeight: 1.5 }}>
                  {section.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== PREREQUISITES ==================== */}
        <Typography id="prerequisites" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📋 Prerequisites
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          What you should know before diving into reverse engineering
        </Typography>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
                ✅ Helpful to Have
              </Typography>
              <List dense>
                {[
                  "Basic programming knowledge (any language)",
                  "Understanding of how computers work",
                  "Familiarity with command line",
                  "Curiosity and patience",
                  "Basic understanding of memory concepts",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                ⚡ Nice to Have
              </Typography>
              <List dense>
                {[
                  "C/C++ programming experience",
                  "Understanding of operating systems",
                  "Basic networking knowledge",
                  "Experience with hex editors",
                  "Linux command line familiarity",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <TipsAndUpdatesIcon sx={{ fontSize: 14, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                📚 We'll Teach You
              </Typography>
              <List dense>
                {[
                  "Assembly language basics",
                  "How to use disassemblers",
                  "Debugging techniques",
                  "Binary file formats",
                  "Common patterns to recognize",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <SchoolIcon sx={{ fontSize: 14, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== NEXT STEPS ==================== */}
        <Typography id="next-steps" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🚀 Next Steps
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Continue your reverse engineering journey with these related topics
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            { title: "Debugging 101", path: "/learn/debugging-101", color: "#3b82f6", description: "Learn the fundamentals of debugging" },
            { title: "Ghidra Guide", path: "/learn/ghidra", color: "#dc2626", description: "Master the NSA's free RE tool" },
            { title: "Windows Internals", path: "/learn/windows-internals", color: "#8b5cf6", description: "PE format, APIs, and internals" },
            { title: "Android RE", path: "/learn/android-reverse-engineering", color: "#22c55e", description: "Mobile reverse engineering" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={3} key={item.title}>
              <Paper
                onClick={() => navigate(item.path)}
                sx={{
                  p: 2.5,
                  textAlign: "center",
                  cursor: "pointer",
                  borderRadius: 3,
                  border: `1px solid ${alpha(item.color, 0.2)}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    borderColor: item.color,
                    boxShadow: `0 8px 24px ${alpha(item.color, 0.2)}`,
                  },
                }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>
                  {item.title}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {item.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Key Takeaways */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon sx={{ color: "#10b981" }} />
            Key Takeaways
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>RE is Detective Work</Typography>
              <Typography variant="body2" color="text.secondary">
                You're analyzing compiled software to understand its behavior without source code — like digital archaeology.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>Critical for Security</Typography>
              <Typography variant="body2" color="text.secondary">
                Essential for malware analysis, vulnerability research, and understanding how software really works.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>Patience is Key</Typography>
              <Typography variant="body2" color="text.secondary">
                RE requires systematic thinking, pattern recognition, and persistence. The learning curve is steep but rewarding.
              </Typography>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== QUIZ SECTION ==================== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            TEST YOUR KNOWLEDGE
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="quiz" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📝 Knowledge Quiz
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Test your understanding of reverse engineering fundamentals with this interactive quiz
        </Typography>

        <Box sx={{ mb: 5 }}>
          <QuizSection />
        </Box>

        {/* Footer Navigation */}
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
              borderColor: alpha("#dc2626", 0.3),
              color: "#dc2626",
              "&:hover": {
                borderColor: "#dc2626",
                bgcolor: alpha("#dc2626", 0.05),
              },
            }}
          >
            Return to Learning Hub
          </Button>
        </Box>
      </Container>
    </LearnPageLayout>
  );
}
