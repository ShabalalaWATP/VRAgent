import React, { useEffect, useState } from "react";
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
  Radio,
  RadioGroup,
  FormControlLabel,
  LinearProgress,
  Drawer,
  Fab,
  Divider,
  alpha,
  useTheme,
  useMediaQuery,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import ShieldIcon from "@mui/icons-material/Shield";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SearchIcon from "@mui/icons-material/Search";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import MemoryIcon from "@mui/icons-material/Memory";
import TuneIcon from "@mui/icons-material/Tune";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import SchoolIcon from "@mui/icons-material/School";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";

// ==================== QUIZ SECTION ====================
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

const questionBank: QuizQuestion[] = [
  // Topic 1: Debugging Basics (Questions 1-12)
  { id: 1, question: "What is the primary purpose of a debugger?", options: ["To compile code faster", "To pause and inspect program execution", "To write code automatically", "To deploy applications"], correctAnswer: 1, explanation: "A debugger allows you to pause a program, inspect its state, and step through execution to understand behavior.", topic: "Debugging Basics" },
  { id: 2, question: "What is a breakpoint?", options: ["A syntax error in code", "A stop point where execution pauses", "A memory allocation point", "A function return value"], correctAnswer: 1, explanation: "A breakpoint is a marker you set in code where the debugger will pause execution, letting you inspect the state.", topic: "Debugging Basics" },
  { id: 3, question: "What does 'step over' mean in debugging?", options: ["Skip the entire program", "Run the current line without entering functions", "Enter every function call", "Exit the debugger"], correctAnswer: 1, explanation: "Step over executes the current line but doesn't enter any function calls, moving to the next line.", topic: "Debugging Basics" },
  { id: 4, question: "What does 'step into' do?", options: ["Skips the current function", "Enters the function called on the current line", "Exits the current function", "Restarts the program"], correctAnswer: 1, explanation: "Step into enters a function call to debug inside it, letting you see the function's internal execution.", topic: "Debugging Basics" },
  { id: 5, question: "What is a watchpoint?", options: ["A timer for execution", "A pause when a variable or memory changes", "A log message", "A code comment"], correctAnswer: 1, explanation: "A watchpoint (or data breakpoint) pauses execution when a specific variable or memory address changes.", topic: "Debugging Basics" },
  { id: 6, question: "What does 'step out' do?", options: ["Closes the debugger", "Runs until the current function returns", "Deletes a breakpoint", "Saves the debug session"], correctAnswer: 1, explanation: "Step out continues execution until the current function returns, useful for exiting after confirming a function is fine.", topic: "Debugging Basics" },
  { id: 7, question: "Why are debug symbols important?", options: ["They speed up execution", "They map code to source lines for debugging", "They reduce file size", "They encrypt the binary"], correctAnswer: 1, explanation: "Debug symbols contain information that maps compiled code back to source lines, enabling meaningful debugging.", topic: "Debugging Basics" },
  { id: 8, question: "What is the stack in debugging context?", options: ["A list of variables", "Memory for function calls and local variables", "A network buffer", "A code editor feature"], correctAnswer: 1, explanation: "The stack stores return addresses and local variables for function calls, showing the execution path.", topic: "Debugging Basics" },
  { id: 9, question: "What are registers in a CPU?", options: ["Large storage drives", "Small, fast CPU storage for current operations", "Memory management units", "Input/output controllers"], correctAnswer: 1, explanation: "Registers are small, fast storage locations in the CPU that hold values currently being processed.", topic: "Debugging Basics" },
  { id: 10, question: "What is the benefit of a debugger over print statements?", options: ["Debuggers are faster to type", "Debuggers show real state without code changes", "Print statements are more accurate", "Debuggers work offline only"], correctAnswer: 1, explanation: "Debuggers let you inspect the actual program state at runtime without modifying the code with print statements.", topic: "Debugging Basics" },
  { id: 11, question: "What does attaching a debugger mean?", options: ["Installing debug software", "Connecting the debugger to a running process", "Compiling with debug flags", "Saving debug logs"], correctAnswer: 1, explanation: "Attaching means connecting the debugger to an already running process to inspect and control it.", topic: "Debugging Basics" },
  { id: 12, question: "Why disable optimizations when debugging?", options: ["To make code run faster", "Optimizations can reorder code, making debugging confusing", "It reduces file size", "Optimizations add bugs"], correctAnswer: 1, explanation: "Compiler optimizations can reorder, inline, or eliminate code, making it hard to match source to execution.", topic: "Debugging Basics" },

  // Topic 2: Debugging Workflow (Questions 13-24)
  { id: 13, question: "What is the first step in a debugging workflow?", options: ["Fix the bug immediately", "Reproduce the bug reliably", "Delete suspicious code", "Add more features"], correctAnswer: 1, explanation: "Reproducing the bug reliably is essential before you can systematically find and fix the root cause.", topic: "Debugging Workflow" },
  { id: 14, question: "What is a hypothesis loop in debugging?", options: ["A circular dependency", "Observe, hypothesize, test, learn cycle", "An infinite loop bug", "A memory leak pattern"], correctAnswer: 1, explanation: "The hypothesis loop is a systematic approach: observe the bug, hypothesize a cause, test it, and learn from results.", topic: "Debugging Workflow" },
  { id: 15, question: "Why is reproducibility important in debugging?", options: ["It makes reports longer", "You can verify fixes and test hypotheses consistently", "It slows down debugging", "It's not important"], correctAnswer: 1, explanation: "Reproducibility ensures you can verify fixes work and test hypotheses under the same conditions.", topic: "Debugging Workflow" },
  { id: 16, question: "What should you do if stuck debugging?", options: ["Give up immediately", "Reduce input or shorten the path", "Add more code", "Ignore the bug"], correctAnswer: 1, explanation: "When stuck, reducing the input size or shortening the code path helps isolate the problem.", topic: "Debugging Workflow" },
  { id: 17, question: "Why change only one thing at a time during debugging?", options: ["To slow down", "So you can trust which change fixed the issue", "To add complexity", "It doesn't matter"], correctAnswer: 1, explanation: "Changing one thing at a time ensures you know exactly which change resolved or affected the bug.", topic: "Debugging Workflow" },
  { id: 18, question: "What is a minimal reproduction?", options: ["The smallest code that demonstrates the bug", "A full application copy", "A backup of all files", "A log file"], correctAnswer: 0, explanation: "A minimal reproduction is the smallest possible code or input that still triggers the bug, making it easier to debug.", topic: "Debugging Workflow" },
  { id: 19, question: "Why record exact inputs when debugging?", options: ["For documentation only", "To reliably reproduce the exact conditions", "To make files larger", "For legal reasons"], correctAnswer: 1, explanation: "Recording exact inputs, flags, and environment variables ensures you can reproduce the bug consistently.", topic: "Debugging Workflow" },
  { id: 20, question: "What is root cause analysis?", options: ["Finding the first incorrect value or decision", "Analyzing plant roots", "Checking file permissions", "Reviewing code style"], correctAnswer: 0, explanation: "Root cause analysis identifies the fundamental reason (first incorrect value or decision) for the bug.", topic: "Debugging Workflow" },
  { id: 21, question: "When should you use logging vs a debugger?", options: ["Always use logging", "Logging for production issues; debugger for local deep inspection", "Never use logging", "They're identical"], correctAnswer: 1, explanation: "Logging works well for production and long flows; debuggers are better for local reproduction and deep inspection.", topic: "Debugging Workflow" },
  { id: 22, question: "What are common debugging entry points?", options: ["Random code lines", "Crash reports, failed tests, unexpected output", "Comments in code", "Import statements"], correctAnswer: 1, explanation: "Common entry points include crash reports, stack traces, failing tests, and unexpected outputs.", topic: "Debugging Workflow" },
  { id: 23, question: "Why work backward from the symptom?", options: ["It's more fun", "To find the first wrong value that caused the symptom", "To add more bugs", "It's not recommended"], correctAnswer: 1, explanation: "Working backward from the symptom helps trace back to the first point where state went wrong.", topic: "Debugging Workflow" },
  { id: 24, question: "What should debug notes include?", options: ["Only the fix", "Bug description, repro steps, expected vs actual, evidence", "Just the date", "Nothing"], correctAnswer: 1, explanation: "Good debug notes include the bug description, reproduction steps, expected vs actual behavior, and evidence.", topic: "Debugging Workflow" },

  // Topic 3: Breakpoint Types (Questions 25-36)
  { id: 25, question: "What is a line breakpoint?", options: ["A line of text", "A breakpoint that stops at a specific source line", "A comment in code", "A variable declaration"], correctAnswer: 1, explanation: "A line breakpoint pauses execution when the specified line of source code is reached.", topic: "Breakpoint Types" },
  { id: 26, question: "When should you use a function breakpoint?", options: ["When you know the exact line", "When you want to stop when any call to a function occurs", "Only for main functions", "Never"], correctAnswer: 1, explanation: "Function breakpoints are useful when you don't know the exact line but want to stop on any call to a function.", topic: "Breakpoint Types" },
  { id: 27, question: "What is a conditional breakpoint?", options: ["A breakpoint that always stops", "A breakpoint that stops only when a condition is true", "A temporary breakpoint", "A disabled breakpoint"], correctAnswer: 1, explanation: "Conditional breakpoints only pause when a specified condition evaluates to true, useful for loops or specific cases.", topic: "Breakpoint Types" },
  { id: 28, question: "When are conditional breakpoints most useful?", options: ["For simple single-line bugs", "For loops or large input sets where you need a specific case", "For compilation errors", "For styling issues"], correctAnswer: 1, explanation: "Conditional breakpoints shine in loops or when processing many items, letting you stop only on interesting cases.", topic: "Breakpoint Types" },
  { id: 29, question: "What is a data breakpoint?", options: ["A breakpoint on data files", "A breakpoint that triggers when a memory address changes", "A breakpoint on database queries", "A breakpoint on network data"], correctAnswer: 1, explanation: "A data breakpoint (hardware watchpoint) triggers when a specific memory address is written to or read.", topic: "Breakpoint Types" },
  { id: 30, question: "What is a temporary breakpoint?", options: ["A breakpoint that lasts forever", "A breakpoint that is automatically removed after being hit once", "A broken breakpoint", "A backup breakpoint"], correctAnswer: 1, explanation: "A temporary breakpoint is automatically deleted after it's hit once, useful for one-time stops.", topic: "Breakpoint Types" },
  { id: 31, question: "Where should you place your first breakpoint?", options: ["At the start of main()", "Near where the bug/symptom appears", "At the end of the file", "Random location"], correctAnswer: 1, explanation: "Start with a breakpoint near where the symptom appears, then move backward to find the root cause.", topic: "Breakpoint Types" },
  { id: 32, question: "How do you debug unexpected mutations?", options: ["Add print statements everywhere", "Use watchpoints to pause when the value changes", "Restart the program repeatedly", "Ignore them"], correctAnswer: 1, explanation: "Watchpoints are ideal for finding where unexpected changes occur, pausing when the value is modified.", topic: "Breakpoint Types" },
  { id: 33, question: "What can you capture with a watchpoint besides the new value?", options: ["Only the new value", "The call stack showing who made the change", "The file creation date", "Nothing else"], correctAnswer: 1, explanation: "When a watchpoint triggers, you can examine the call stack to see exactly what code path modified the value.", topic: "Breakpoint Types" },
  { id: 34, question: "What is a logpoint (tracepoint)?", options: ["A breakpoint that crashes", "A breakpoint that logs a message without stopping", "A point for network logging", "A comment marker"], correctAnswer: 1, explanation: "A logpoint outputs a message to the console when hit without pausing execution, like a non-intrusive print.", topic: "Breakpoint Types" },
  { id: 35, question: "When should you use temporary vs permanent breakpoints?", options: ["Always use permanent", "Temporary for one-time checks; permanent for repeated investigation", "Always use temporary", "They're the same"], correctAnswer: 1, explanation: "Temporary breakpoints work for quick checks; permanent ones stay for repeated investigation of an area.", topic: "Breakpoint Types" },
  { id: 36, question: "What does 'break on function entry' mean?", options: ["The function stops working", "The debugger pauses when the function is called", "The function is deleted", "An error occurs"], correctAnswer: 1, explanation: "Breaking on function entry pauses execution right when the function starts, before any of its code runs.", topic: "Breakpoint Types" },

  // Topic 4: Stepping Modes (Questions 37-48)
  { id: 37, question: "What is the difference between step over and step into?", options: ["No difference", "Step over skips functions; step into enters them", "Step into is faster", "Step over stops debugging"], correctAnswer: 1, explanation: "Step over executes functions as a single unit; step into goes inside function calls to debug them.", topic: "Stepping Modes" },
  { id: 38, question: "When should you use step over?", options: ["When you want to see inside every function", "When moving quickly through known-good code", "When debugging library functions", "Never"], correctAnswer: 1, explanation: "Use step over to move quickly past functions you've already verified or aren't interested in.", topic: "Stepping Modes" },
  { id: 39, question: "When should you use step into?", options: ["Never", "When you want to inspect a function's internal behavior", "Only for main()", "When you want to skip code"], correctAnswer: 1, explanation: "Step into is used when you want to debug inside a function to see how it processes data.", topic: "Stepping Modes" },
  { id: 40, question: "What does step out do after stepping into a function?", options: ["Crashes the program", "Runs until the function returns", "Deletes the function", "Starts over"], correctAnswer: 1, explanation: "Step out continues execution until the current function returns, useful for exiting after confirming it's fine.", topic: "Stepping Modes" },
  { id: 41, question: "What is 'run to cursor'?", options: ["Moving the mouse", "Running until execution reaches a specific line", "Printing cursor position", "A graphics feature"], correctAnswer: 1, explanation: "Run to cursor executes until the line where your cursor is placed, like a temporary breakpoint.", topic: "Stepping Modes" },
  { id: 42, question: "How does stepping work with recursive functions?", options: ["It doesn't work", "Each recursive call adds a new stack frame to step through", "Recursion is ignored", "It crashes"], correctAnswer: 1, explanation: "In recursive functions, stepping into each call adds a new stack frame, and you can step out of each level.", topic: "Stepping Modes" },
  { id: 43, question: "What is reverse debugging?", options: ["Debugging in reverse alphabetical order", "Stepping backward through execution history", "Debugging in a mirror", "Writing code backwards"], correctAnswer: 1, explanation: "Reverse debugging lets you step backward through execution to see what led to the current state.", topic: "Stepping Modes" },
  { id: 44, question: "When might step into go somewhere unexpected?", options: ["Never", "When inlined code or compiler-generated code is involved", "When you press the wrong button", "Always"], correctAnswer: 1, explanation: "Step into might enter compiler-generated code, library functions, or inlined code unexpectedly.", topic: "Stepping Modes" },
  { id: 45, question: "How do you skip stepping into library functions?", options: ["Can't be done", "Use step over or configure the debugger to skip certain modules", "Delete the libraries", "Restart the debugger"], correctAnswer: 1, explanation: "Most debuggers let you configure which code to skip or use step over to avoid entering libraries.", topic: "Stepping Modes" },
  { id: 46, question: "What does 'continue' do in a debugger?", options: ["Saves your work", "Resumes execution until the next breakpoint or end", "Closes the debugger", "Compiles the code"], correctAnswer: 1, explanation: "Continue resumes normal execution until another breakpoint is hit or the program ends.", topic: "Stepping Modes" },
  { id: 47, question: "What happens if you step at the last line of a function?", options: ["The program crashes", "Execution returns to the caller", "Nothing", "A new function is created"], correctAnswer: 1, explanation: "Stepping from the last line returns to the calling function at the point after the call.", topic: "Stepping Modes" },
  { id: 48, question: "Why might stepping appear to skip lines?", options: ["The debugger is broken", "Optimizations or the line has no executable code", "Lines are too long", "The monitor is too small"], correctAnswer: 1, explanation: "Compiler optimizations may combine or eliminate lines, and some lines (like declarations) have no executable code.", topic: "Stepping Modes" },

  // Topic 5: Memory and Registers (Questions 49-60)
  { id: 49, question: "What is the difference between stack and heap?", options: ["They're the same", "Stack is for function calls; heap is for dynamic allocation", "Heap is faster", "Stack is larger"], correctAnswer: 1, explanation: "The stack stores function calls and local variables; the heap stores dynamically allocated objects.", topic: "Memory and Registers" },
  { id: 50, question: "What is the instruction pointer?", options: ["A pointer to data", "A register showing where the CPU is executing", "A function parameter", "A memory address for strings"], correctAnswer: 1, explanation: "The instruction pointer (EIP/RIP) holds the address of the currently executing instruction.", topic: "Memory and Registers" },
  { id: 51, question: "What is the stack pointer?", options: ["A pointer to the heap", "A register pointing to the current top of the stack", "A null pointer", "An array index"], correctAnswer: 1, explanation: "The stack pointer (ESP/RSP) points to the current top of the stack, tracking function call frames.", topic: "Memory and Registers" },
  { id: 52, question: "What is a stack frame?", options: ["A picture frame", "The memory area for one function's local variables and metadata", "A network packet", "A GUI element"], correctAnswer: 1, explanation: "A stack frame contains a function's return address, parameters, and local variables.", topic: "Memory and Registers" },
  { id: 53, question: "What does a call stack show?", options: ["Future function calls", "The chain of function calls that led to the current point", "Memory usage graphs", "CPU temperature"], correctAnswer: 1, explanation: "The call stack shows the nested function calls from the program entry point to the current execution point.", topic: "Memory and Registers" },
  { id: 54, question: "What might a corrupted stack look like?", options: ["Extra bright colors", "Missing or odd stack frames, wrong return addresses", "Slower execution", "More memory"], correctAnswer: 1, explanation: "A corrupted stack may show missing frames, garbage return addresses, or impossible call sequences.", topic: "Memory and Registers" },
  { id: 55, question: "What is a null pointer dereference?", options: ["A valid operation", "Accessing memory through a pointer that is zero/null", "Setting a pointer to null", "Declaring a pointer"], correctAnswer: 1, explanation: "A null pointer dereference attempts to read or write memory at address zero, causing a crash.", topic: "Memory and Registers" },
  { id: 56, question: "What is use-after-free?", options: ["Using memory after it was freed/deallocated", "A memory optimization", "Freeing memory twice", "A valid pattern"], correctAnswer: 0, explanation: "Use-after-free occurs when code accesses memory that has already been freed, leading to undefined behavior.", topic: "Memory and Registers" },
  { id: 57, question: "What is a buffer overflow?", options: ["A buffer that is too small", "Writing past the boundaries of allocated memory", "A network congestion", "A display issue"], correctAnswer: 1, explanation: "A buffer overflow writes data beyond the allocated buffer size, potentially corrupting adjacent memory.", topic: "Memory and Registers" },
  { id: 58, question: "What do memory red flags look like?", options: ["Green indicators", "Negative sizes, huge values, impossible addresses", "Normal values", "Fast execution"], correctAnswer: 1, explanation: "Red flags include negative or huge size values, pointers outside valid ranges, and garbage in local variables.", topic: "Memory and Registers" },
  { id: 59, question: "What is the base pointer used for?", options: ["Pointing to the heap", "Locating local variables within a stack frame", "Network addressing", "File operations"], correctAnswer: 1, explanation: "The base pointer (EBP/RBP) provides a reference point for accessing local variables and parameters in a stack frame.", topic: "Memory and Registers" },
  { id: 60, question: "What is an off-by-one error?", options: ["An error on line 1", "An error where an index is one more or less than intended", "A network latency issue", "A compilation warning"], correctAnswer: 1, explanation: "Off-by-one errors occur when an array index or count is one more or less than correct, often at boundaries.", topic: "Memory and Registers" },

  // Topic 6: Bug Detection (Questions 61-68)
  { id: 61, question: "What signals might indicate a bug?", options: ["Smooth execution", "Crashes at same location, unexpected values", "Fast performance", "Clean logs"], correctAnswer: 1, explanation: "Consistent crashes, stack traces pointing to input handling, and sudden value changes signal bugs.", topic: "Bug Detection" },
  { id: 62, question: "What telemetry helps find bugs?", options: ["Marketing data", "Crash dumps, logs, test outputs, profiles", "Social media", "Weather data"], correctAnswer: 1, explanation: "Crash dumps, application logs, test outputs, and performance profiles help locate and understand bugs.", topic: "Bug Detection" },
  { id: 63, question: "What artifacts should you capture from a crash?", options: ["Only the error message", "Core dump, stack trace, input, version, config", "Just the time", "Nothing"], correctAnswer: 1, explanation: "Capture the core dump, full stack trace, triggering input, version/build hash, and configuration.", topic: "Bug Detection" },
  { id: 64, question: "What is a flaky bug?", options: ["A consistently reproducible bug", "A bug that appears intermittently or inconsistently", "A fixed bug", "A documentation error"], correctAnswer: 1, explanation: "A flaky bug is non-deterministic, appearing sometimes but not always under similar conditions.", topic: "Bug Detection" },
  { id: 65, question: "How do you verify a fix is correct?", options: ["Assume it works", "Re-run the exact repro steps and run tests", "Delete the code", "Ask someone else"], correctAnswer: 1, explanation: "Verify by re-running the exact reproduction steps and running relevant tests to confirm the fix.", topic: "Bug Detection" },
  { id: 66, question: "What is triage in debugging?", options: ["Fixing bugs randomly", "Prioritizing and categorizing bugs for investigation", "Deleting old code", "Writing documentation"], correctAnswer: 1, explanation: "Triage involves assessing, prioritizing, and categorizing bugs to determine investigation order.", topic: "Bug Detection" },
  { id: 67, question: "What questions help during triage?", options: ["What color is the code?", "Is it reproducible? Did it start after a change? Is it deterministic?", "What font is used?", "How many lines?"], correctAnswer: 1, explanation: "Key triage questions: Is it reproducible elsewhere? When did it start? Is it data or time dependent? Deterministic or flaky?", topic: "Bug Detection" },
  { id: 68, question: "What is the root cause checklist?", options: ["A list of root vegetables", "First wrong value identified, reason understood, fix verified, tests added", "A shopping list", "A deployment guide"], correctAnswer: 1, explanation: "Root cause checklist: Identify first incorrect value, understand reason, verify fix works, add test coverage.", topic: "Bug Detection" },

  // Topic 7: Debug Tools (Questions 69-75)
  { id: 69, question: "What is GDB?", options: ["A database", "GNU Debugger for Linux/Unix", "A graphics card", "A programming language"], correctAnswer: 1, explanation: "GDB (GNU Debugger) is a powerful debugger for Linux/Unix systems supporting many languages.", topic: "Debug Tools" },
  { id: 70, question: "What is LLDB?", options: ["A database", "The LLVM debugger used on macOS and Linux", "A display driver", "A log file"], correctAnswer: 1, explanation: "LLDB is the debugger from the LLVM project, commonly used on macOS and also available on Linux.", topic: "Debug Tools" },
  { id: 71, question: "What is WinDbg?", options: ["A Windows game", "Microsoft's debugger for Windows", "A wireless adapter", "A web browser"], correctAnswer: 1, explanation: "WinDbg is Microsoft's powerful debugger for Windows applications and kernel debugging.", topic: "Debug Tools" },
  { id: 72, question: "What does the 'bt' command do in GDB?", options: ["Closes GDB", "Shows the backtrace (call stack)", "Sets a breakpoint", "Runs the program"], correctAnswer: 1, explanation: "The 'bt' (backtrace) command displays the current call stack showing how you reached the current point.", topic: "Debug Tools" },
  { id: 73, question: "How do you set a breakpoint at main in GDB?", options: ["break main", "stop main", "pause main", "halt main"], correctAnswer: 0, explanation: "In GDB, 'break main' sets a breakpoint at the beginning of the main function.", topic: "Debug Tools" },
  { id: 74, question: "What does 'info locals' show in GDB?", options: ["System information", "Local variables in the current frame", "Global settings", "Network info"], correctAnswer: 1, explanation: "The 'info locals' command displays all local variables and their values in the current stack frame.", topic: "Debug Tools" },
  { id: 75, question: "What is a core dump?", options: ["A trash file", "A snapshot of memory when a program crashes", "A database backup", "A log rotation"], correctAnswer: 1, explanation: "A core dump is a file containing the memory image of a process at the time it crashed, useful for post-mortem debugging.", topic: "Debug Tools" },
];

const QuizSection: React.FC = () => {
  const [quizState, setQuizState] = useState<'start' | 'active' | 'results'>('start');
  const [currentQuestions, setCurrentQuestions] = useState<QuizQuestion[]>([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<{ [key: number]: number }>({});
  const [showExplanation, setShowExplanation] = useState(false);
  const [score, setScore] = useState(0);

  const startQuiz = () => {
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    setCurrentQuestions(shuffled.slice(0, 10));
    setCurrentQuestionIndex(0);
    setSelectedAnswers({});
    setShowExplanation(false);
    setScore(0);
    setQuizState('active');
  };

  const handleAnswerSelect = (answerIndex: number) => {
    if (showExplanation) return;
    setSelectedAnswers({ ...selectedAnswers, [currentQuestionIndex]: answerIndex });
  };

  const handleSubmitAnswer = () => {
    if (selectedAnswers[currentQuestionIndex] === undefined) return;
    if (selectedAnswers[currentQuestionIndex] === currentQuestions[currentQuestionIndex].correctAnswer) {
      setScore(score + 1);
    }
    setShowExplanation(true);
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex < currentQuestions.length - 1) {
      setCurrentQuestionIndex(currentQuestionIndex + 1);
      setShowExplanation(false);
    } else {
      setQuizState('results');
    }
  };

  const getScoreMessage = () => {
    const percentage = (score / 10) * 100;
    if (percentage >= 90) return { text: "Outstanding! You're a debugging expert!", color: "#22c55e" };
    if (percentage >= 70) return { text: "Great job! Strong debugging knowledge!", color: "#3b82f6" };
    if (percentage >= 50) return { text: "Good effort! Keep practicing debugging concepts.", color: "#f59e0b" };
    return { text: "Keep learning! Review the debugging fundamentals.", color: "#ef4444" };
  };

  if (quizState === 'start') {
    return (
      <Paper sx={{ p: 4, bgcolor: "#0f1422", borderRadius: 3, textAlign: "center", border: "1px solid rgba(59, 130, 246, 0.3)" }}>
        <QuizIcon sx={{ fontSize: 64, color: "#3b82f6", mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, color: "#e2e8f0", mb: 2 }}>Debugging Knowledge Quiz</Typography>
        <Typography variant="body1" sx={{ color: "grey.400", mb: 3 }}>
          Test your debugging knowledge with 10 randomly selected questions from our bank of 75 questions covering
          debugger basics, breakpoints, stepping, memory inspection, and bug detection.
        </Typography>
        <Box sx={{ display: "flex", justifyContent: "center", gap: 2, flexWrap: "wrap", mb: 3 }}>
          {["Debugging Basics", "Workflow", "Breakpoints", "Memory", "Bug Detection"].map((topic) => (
            <Chip key={topic} label={topic} size="small" sx={{ bgcolor: "rgba(59, 130, 246, 0.2)", color: "#3b82f6" }} />
          ))}
        </Box>
        <Button variant="contained" size="large" onClick={startQuiz} sx={{ bgcolor: "#3b82f6", "&:hover": { bgcolor: "#2563eb" } }}>
          Start Quiz
        </Button>
      </Paper>
    );
  }

  if (quizState === 'results') {
    const scoreMsg = getScoreMessage();
    return (
      <Paper sx={{ p: 4, bgcolor: "#0f1422", borderRadius: 3, border: "1px solid rgba(59, 130, 246, 0.3)" }}>
        <Box sx={{ textAlign: "center", mb: 4 }}>
          <EmojiEventsIcon sx={{ fontSize: 64, color: scoreMsg.color, mb: 2 }} />
          <Typography variant="h4" sx={{ fontWeight: 700, color: "#e2e8f0", mb: 1 }}>Quiz Complete!</Typography>
          <Typography variant="h2" sx={{ fontWeight: 800, color: scoreMsg.color, mb: 2 }}>{score}/10</Typography>
          <Typography variant="h6" sx={{ color: scoreMsg.color }}>{scoreMsg.text}</Typography>
        </Box>
        <Typography variant="h6" sx={{ fontWeight: 700, color: "#e2e8f0", mb: 2 }}>Review Your Answers:</Typography>
        <Box sx={{ maxHeight: 400, overflow: "auto", mb: 3 }}>
          {currentQuestions.map((q, idx) => {
            const isCorrect = selectedAnswers[idx] === q.correctAnswer;
            return (
              <Paper key={q.id} sx={{ p: 2, mb: 2, bgcolor: isCorrect ? "rgba(34, 197, 94, 0.1)" : "rgba(239, 68, 68, 0.1)", border: `1px solid ${isCorrect ? "#22c55e" : "#ef4444"}`, borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ color: "#e2e8f0", mb: 1 }}>{idx + 1}. {q.question}</Typography>
                <Typography variant="body2" sx={{ color: isCorrect ? "#22c55e" : "#ef4444" }}>
                  Your answer: {q.options[selectedAnswers[idx]]} {isCorrect ? "✓" : "✗"}
                </Typography>
                {!isCorrect && <Typography variant="body2" sx={{ color: "#22c55e" }}>Correct: {q.options[q.correctAnswer]}</Typography>}
              </Paper>
            );
          })}
        </Box>
        <Box sx={{ display: "flex", justifyContent: "center" }}>
          <Button variant="contained" startIcon={<RefreshIcon />} onClick={startQuiz} sx={{ bgcolor: "#3b82f6", "&:hover": { bgcolor: "#2563eb" } }}>
            Try Again
          </Button>
        </Box>
      </Paper>
    );
  }

  const currentQ = currentQuestions[currentQuestionIndex];
  const progress = ((currentQuestionIndex + 1) / currentQuestions.length) * 100;

  return (
    <Paper sx={{ p: 4, bgcolor: "#0f1422", borderRadius: 3, border: "1px solid rgba(59, 130, 246, 0.3)" }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Chip label={currentQ.topic} size="small" sx={{ bgcolor: "rgba(59, 130, 246, 0.2)", color: "#3b82f6" }} />
        <Typography variant="body2" sx={{ color: "grey.400" }}>Question {currentQuestionIndex + 1} of {currentQuestions.length}</Typography>
      </Box>
      <LinearProgress variant="determinate" value={progress} sx={{ mb: 3, bgcolor: "rgba(59, 130, 246, 0.2)", "& .MuiLinearProgress-bar": { bgcolor: "#3b82f6" } }} />
      <Typography variant="h6" sx={{ fontWeight: 600, color: "#e2e8f0", mb: 3 }}>{currentQ.question}</Typography>
      <RadioGroup value={selectedAnswers[currentQuestionIndex] ?? ""} onChange={(e) => handleAnswerSelect(parseInt(e.target.value))}>
        {currentQ.options.map((option, idx) => {
          let bgColor = "transparent";
          let borderColor = "rgba(255,255,255,0.1)";
          if (showExplanation) {
            if (idx === currentQ.correctAnswer) { bgColor = "rgba(34, 197, 94, 0.15)"; borderColor = "#22c55e"; }
            else if (idx === selectedAnswers[currentQuestionIndex]) { bgColor = "rgba(239, 68, 68, 0.15)"; borderColor = "#ef4444"; }
          } else if (selectedAnswers[currentQuestionIndex] === idx) { bgColor = "rgba(59, 130, 246, 0.15)"; borderColor = "#3b82f6"; }
          return (
            <Paper key={idx} sx={{ mb: 1.5, p: 1.5, bgcolor: bgColor, border: `1px solid ${borderColor}`, borderRadius: 2, cursor: showExplanation ? "default" : "pointer", transition: "all 0.2s" }} onClick={() => !showExplanation && handleAnswerSelect(idx)}>
              <FormControlLabel value={idx} control={<Radio sx={{ color: "grey.500", "&.Mui-checked": { color: "#3b82f6" } }} />} label={<Typography sx={{ color: "#e2e8f0" }}>{option}</Typography>} sx={{ m: 0, width: "100%" }} disabled={showExplanation} />
            </Paper>
          );
        })}
      </RadioGroup>
      {showExplanation && (
        <Alert severity="info" sx={{ mt: 3, bgcolor: "rgba(59, 130, 246, 0.1)", border: "1px solid rgba(59, 130, 246, 0.3)", "& .MuiAlert-message": { color: "#e2e8f0" } }}>
          <AlertTitle sx={{ color: "#3b82f6" }}>Explanation</AlertTitle>
          {currentQ.explanation}
        </Alert>
      )}
      <Box sx={{ display: "flex", justifyContent: "flex-end", mt: 3, gap: 2 }}>
        {!showExplanation ? (
          <Button variant="contained" onClick={handleSubmitAnswer} disabled={selectedAnswers[currentQuestionIndex] === undefined} sx={{ bgcolor: "#3b82f6", "&:hover": { bgcolor: "#2563eb" } }}>
            Submit Answer
          </Button>
        ) : (
          <Button variant="contained" onClick={handleNextQuestion} sx={{ bgcolor: "#3b82f6", "&:hover": { bgcolor: "#2563eb" } }}>
            {currentQuestionIndex < currentQuestions.length - 1 ? "Next Question" : "See Results"}
          </Button>
        )}
      </Box>
    </Paper>
  );
};

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
        border: "1px solid rgba(59, 130, 246, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#3b82f6", color: "#0b1020" }} />
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

export default function Debugging101Page() {
  const navigate = useNavigate();
  const theme = useTheme();
  const accent = "#3b82f6";

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "overview", label: "Overview", icon: <SecurityIcon /> },
    { id: "reverse-engineer", label: "Reverse Engineer Lens", icon: <BugReportIcon /> },
    { id: "platform-tools", label: "Platform Tools", icon: <BuildIcon /> },
    { id: "workflow", label: "Workflow", icon: <TuneIcon /> },
    { id: "breakpoints", label: "Breakpoints", icon: <CodeIcon /> },
    { id: "memory", label: "Memory & Registers", icon: <MemoryIcon /> },
    { id: "detection", label: "Detection", icon: <SearchIcon /> },
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

  // Data arrays
  const objectives = [
    "Explain what a debugger is and why it is useful.",
    "Teach core debugging concepts: breakpoints, stepping, and inspection.",
    "Show a repeatable workflow for finding bugs.",
    "Introduce memory, stack, and register basics.",
    "Adopt a reverse engineer mindset for runtime investigation.",
    "Map platform-specific debugging tools for Android, Windows, and web apps.",
    "Provide safe, beginner-friendly practice steps.",
  ];
  const beginnerPath = [
    "1) Read the beginner explanation and glossary.",
    "2) Learn how breakpoints and stepping work.",
    "3) Practice inspecting variables, stack, and registers.",
    "4) Use the workflow checklist for a sample bug.",
    "5) Record findings and verify the fix.",
  ];
  const keyIdeas = [
    "A debugger pauses a program so you can see what it is doing.",
    "Breakpoints let you stop at exact lines or functions.",
    "Stepping moves through code one instruction or line at a time.",
    "Inspecting variables and memory reveals the real state, not guesses.",
  ];
  const glossary = [
    { term: "Breakpoint", desc: "A stop point in code where execution pauses." },
    { term: "Step over", desc: "Run the current line without entering a function." },
    { term: "Step into", desc: "Enter a function call to debug inside it." },
    { term: "Stack", desc: "Memory used for function calls and local variables." },
    { term: "Register", desc: "Small, fast CPU storage for current operations." },
    { term: "Watchpoint", desc: "Pause when a variable or memory address changes." },
  ];
  const misconceptions = [
    {
      myth: "Debuggers are only for experts.",
      reality: "Basic debugging is a beginner skill that saves hours.",
    },
    {
      myth: "Print statements are always enough.",
      reality: "Debuggers show real state without code changes.",
    },
    {
      myth: "Debugging is just stepping line by line.",
      reality: "Good debugging is a workflow: reproduce, isolate, verify.",
    },
  ];
  const mindsetHabits = [
    "Observe before changing anything. The first state is often the most honest.",
    "Work backward from the symptom to the first wrong value.",
    "Change one thing at a time so you can trust the result.",
    "Write down what you expected and what you saw.",
    "If stuck, reduce the input or shorten the path.",
  ];
  const reproducibilityTips = [
    "Record exact inputs, flags, and environment variables.",
    "Control randomness with fixed seeds or deterministic data.",
    "Use smaller datasets to shorten the path.",
    "Keep the binary and source version in sync.",
    "Confirm the bug still exists after each change.",
  ];
  const bugTypeMap = [
    { type: "Logic error", signals: "Wrong output, failed assertions", approach: "Trace decisions and invariants" },
    { type: "State corruption", signals: "Values flip or drift", approach: "Watchpoints, compare before/after" },
    { type: "Boundary error", signals: "Crashes or off-by-one results", approach: "Check indexes and sizes" },
    { type: "Timing issue", signals: "Flaky or order-dependent behavior", approach: "Trace ordering and add delays" },
    { type: "Configuration", signals: "Works on one machine only", approach: "Diff env vars, versions, flags" },
  ];
  const signalNoiseTips = [
    "Look for the first error or warning, not the last.",
    "Align logs with debugger steps using timestamps.",
    "Prefer debugger state over printed output.",
    "Ignore unrelated warnings until the main failure is fixed.",
  ];
  const reverseEngineerMindset = [
    {
      title: "Treat the program as evidence",
      description: "Assume the running binary is the source of truth. Validate hypotheses against runtime state, not assumptions.",
      focus: "Live memory, registers, stack frames, system calls",
    },
    {
      title: "Reconstruct intent from behavior",
      description: "When source is missing or obfuscated, infer intent by watching inputs, outputs, and side effects.",
      focus: "Network traffic, filesystem writes, API usage",
    },
    {
      title: "Follow the data, not the code",
      description: "Track the data that triggers the bug. The first wrong transformation is the real root cause.",
      focus: "Watchpoints, tainted inputs, argument tracing",
    },
    {
      title: "Symbols are a map, not a guarantee",
      description: "Debug symbols, stack traces, and logs accelerate work, but always verify with runtime state.",
      focus: "Symbol servers, crash dumps, module boundaries",
    },
  ];
  const reverseEngineerArtifacts = [
    { artifact: "Crash dumps", use: "Recover call stacks, registers, and memory at failure time" },
    { artifact: "Strings and imports", use: "Quickly identify capabilities and code paths" },
    { artifact: "Dynamic traces", use: "Observe runtime behavior and hidden branches" },
    { artifact: "Binary diffs", use: "Locate changes across versions and regressions" },
    { artifact: "Network captures", use: "See protocol usage and malformed inputs" },
    { artifact: "Heap/stack snapshots", use: "Find corruption and unexpected mutations" },
  ];
  const reverseEngineerWorkflow = [
    "Establish a reliable repro in a controlled lab.",
    "Identify the failure boundary (input, function, or module).",
    "Capture artifacts: stack trace, memory snapshot, logs, and network traces.",
    "Instrument the binary to observe data flow and side effects.",
    "Confirm the first wrong value and trace back to its origin.",
    "Validate the fix with the same inputs and environment.",
  ];
  const androidTools = [
    { name: "Android Studio Debugger", category: "IDE", use: "Breakpoints, variables, and JDWP inspection" },
    { name: "adb + logcat", category: "CLI", use: "Device control, logs, app lifecycle, and intents" },
    { name: "Frida", category: "Dynamic instrumentation", use: "Hook Java and native methods at runtime" },
    { name: "Objection", category: "Runtime tooling", use: "Convenience layer over Frida for mobile apps" },
    { name: "Jadx", category: "Decompiler", use: "Inspect APK code and control flow" },
    { name: "apktool", category: "Patching", use: "Decode resources and modify smali" },
    { name: "LLDB", category: "Native debug", use: "Debug JNI/native libraries and crashes" },
  ];
  const windowsTools = [
    { name: "WinDbg", category: "System debugger", use: "Crash dumps, symbols, and kernel/user stacks" },
    { name: "x64dbg", category: "User-mode debugger", use: "Breakpoints, memory maps, and patching" },
    { name: "Visual Studio Debugger", category: "IDE", use: "Source-level and mixed-mode debugging" },
    { name: "Process Explorer", category: "Sysinternals", use: "Inspect handles, threads, and loaded modules" },
    { name: "Process Monitor", category: "Sysinternals", use: "Trace file, registry, and network activity" },
    { name: "API Monitor", category: "API tracing", use: "Observe Win32 API calls and parameters" },
    { name: "Ghidra", category: "Disassembler", use: "Static analysis and function recovery" },
  ];
  const webTools = [
    { name: "Chrome DevTools", category: "Browser", use: "Breakpoints, network, performance, and memory tools" },
    { name: "Firefox DevTools", category: "Browser", use: "JS debugging, network analysis, and CSS inspection" },
    { name: "React DevTools", category: "Framework", use: "Component tree, props, and state inspection" },
    { name: "Redux DevTools", category: "State", use: "Action timeline and time-travel debugging" },
    { name: "VS Code Debugger", category: "IDE", use: "Node.js server-side breakpoints and attach" },
    { name: "Burp Suite", category: "Proxy", use: "Intercept, replay, and modify HTTP requests" },
    { name: "Fiddler Classic", category: "Proxy", use: "Capture and analyze HTTP(S) traffic" },
  ];
  const debuggingMentalModel = [
    "Inputs flow into code paths, update internal state, and produce outputs you can observe.",
    "The first wrong value is usually upstream of the visible symptom; find that divergence point.",
    "Invariants describe what must always be true; breakpoints around invariant checks are powerful.",
    "The call stack is a timeline of decisions that explains how you arrived at the current state.",
  ];
  const narrowingStrategies = [
    "Use binary search on commits (git bisect) to isolate when a regression was introduced.",
    "Disable or stub subsystems to shrink the path while keeping the bug reproducible.",
    "Bracket the failure with early and late breakpoints to isolate the smallest failing region.",
    "Add assertions for expected state to pinpoint where the assumption breaks.",
    "Reduce concurrency by forcing single-threaded execution or deterministic scheduling.",
  ];
  const breakpointPlacementTips = [
    "Place breakpoints at boundaries: input parsing, validation, and data transformations.",
    "Stop at loop entry and add conditions to catch the first bad iteration.",
    "Target error handling branches to understand why a failure path was taken.",
    "Use temporary breakpoints to confirm a path, then remove to reduce noise.",
    "Prefer a few high-signal breakpoints over dozens of low-signal ones.",
  ];
  const triagePriorities = [
    "User impact: data loss, security risk, or widespread failures come first.",
    "Frequency: issues that happen often are easier to reproduce and should be fixed quickly.",
    "Scope: determine if the bug is isolated or systemic to avoid partial fixes.",
    "Regression risk: prioritize bugs introduced by recent changes or deployments.",
  ];
  const safeLabChecklistExpanded = [
    "Use sanitized or synthetic data that mirrors production structure without sensitive content.",
    "Record exact environment versions (runtime, dependencies, OS) to avoid mismatches.",
    "Keep destructive actions disabled by default until you confirm safety.",
    "Document how to reset the environment so you can reproduce from a clean state.",
  ];

  const howDebuggingWorks = [
    "The debugger attaches to a program and can pause execution.",
    "It reads memory and CPU registers to show current state.",
    "Breakpoints stop execution at specific places.",
    "Stepping runs code in small controlled steps.",
    "You can inspect or change values to test hypotheses.",
  ];
  const workflow = [
    "Reproduce the bug reliably with a known input.",
    "Set a breakpoint near the suspected area.",
    "Step through and watch how values change.",
    "Identify the first point where state goes wrong.",
    "Fix the bug and verify with the same steps.",
  ];
  const hypothesisLoop = [
    "Observe: describe the wrong behavior precisely.",
    "Hypothesize: name one change that would explain it.",
    "Test: set a breakpoint or watchpoint for that change.",
    "Learn: adjust the hypothesis and repeat.",
  ];
  const minimalReproChecklist = [
    "Single failing input captured.",
    "Steps reduced to the minimum path.",
    "Only one variable changes at a time.",
    "External dependencies fixed or mocked.",
    "Repro steps written so someone else can follow.",
  ];
  const buildSettings = [
    "Use debug symbols to map code to lines.",
    "Disable heavy optimizations while learning the bug.",
    "Generate source maps for web apps.",
    "Match the binary to the source version you are debugging.",
  ];
  const loggingVsDebugger = [
    { choice: "Logging", bestFor: "Production issues, long flows", tradeoff: "Requires code changes, can miss timing" },
    { choice: "Debugger", bestFor: "Local repro, deep inspection", tradeoff: "Halts execution, needs access" },
    { choice: "Tracing/Profiling", bestFor: "Performance or ordering", tradeoff: "Extra setup and overhead" },
  ];
  const commonEntryPoints = [
    "Crash reports or stack traces.",
    "Failing tests or assertions.",
    "Unexpected output or wrong calculations.",
    "Performance problems or infinite loops.",
  ];
  const toolsByPlatform = [
    { platform: "Windows", tools: "WinDbg, Visual Studio Debugger" },
    { platform: "Linux", tools: "GDB, LLDB" },
    { platform: "macOS", tools: "LLDB, Xcode Debugger" },
  ];

  const breakpointTypes = [
    { type: "Line breakpoint", use: "Stop at a specific line in source code.", tip: "Start near where the bug first appears." },
    { type: "Function breakpoint", use: "Stop when a function is called.", tip: "Useful when you do not know the exact line." },
    { type: "Conditional breakpoint", use: "Stop only when a condition is true.", tip: "Great for loops or large input sets." },
    { type: "Watchpoint", use: "Stop when a variable or memory changes.", tip: "Use for unexpected mutations." },
  ];
  const steppingModes = [
    { mode: "Step over", meaning: "Run the current line but do not enter functions.", when: "Use to move quickly through known-good code." },
    { mode: "Step into", meaning: "Enter the function called on this line.", when: "Use to inspect a function in detail." },
    { mode: "Step out", meaning: "Run until the current function returns.", when: "Use to exit a function after confirming it is fine." },
  ];
  const breakpointStrategies = [
    "Place the first breakpoint at the symptom, then move backward.",
    "Break on function entry when you are unsure where a value changes.",
    "Use conditional breakpoints to stop only on the bad case.",
    "Use temporary breakpoints once a path is confirmed.",
  ];
  const watchpointTips = [
    "Watch a variable when it changes in unexpected places.",
    "Use data breakpoints for a specific memory address.",
    "Capture the call stack to find the writer.",
  ];

  const memoryBasics = [
    "The stack stores return addresses and local variables.",
    "The heap stores dynamically allocated objects.",
    "Registers hold current CPU state and function parameters.",
    "Reading memory shows what values truly exist at runtime.",
  ];
  const registerHints = [
    "Instruction pointer shows where the CPU is executing.",
    "Stack pointer shows the current top of the stack.",
    "Base pointer helps locate local variables.",
  ];
  const stackFrameTips = [
    "The top frame is where execution is paused.",
    "Older frames show how you got there.",
    "Inspect arguments and locals before stepping.",
    "Corrupted stacks often show missing or odd frames.",
  ];
  const memoryAreas = [
    { area: "Stack", lifetime: "Per function call", risk: "Out-of-scope access" },
    { area: "Heap", lifetime: "Manual or GC-managed", risk: "Leaks, use-after-free" },
    { area: "Globals", lifetime: "Program lifetime", risk: "Hidden shared state" },
  ];
  const commonMemoryBugs = [
    "Off-by-one index errors.",
    "Use-after-free or stale references.",
    "Null or invalid pointer dereferences.",
    "Buffer overflows from unchecked lengths.",
  ];
  const memoryRedFlags = [
    "Values changing without a code path.",
    "Length or size fields that are negative or huge.",
    "Pointers that do not align with expected ranges.",
    "Local variables with garbage values.",
  ];
  const pitfalls = [
    "Chasing symptoms instead of the first incorrect value.",
    "Stepping too far without taking notes.",
    "Changing code or inputs while debugging (non-repeatable).",
    "Ignoring the possibility of uninitialized data.",
    "Not checking boundary conditions in loops.",
  ];

  const detectionSignals = [
    "Consistent crashes at the same location.",
    "Stack traces that point to input handling.",
    "Sudden value changes after a specific call.",
    "Variables that are null or unexpected types.",
  ];
  const telemetrySources = [
    "Crash dumps and stack traces.",
    "Application logs around failure points.",
    "Test logs and assertion outputs.",
    "Performance profiles for slow paths.",
  ];
  const crashArtifacts = [
    "Crash or core dump file.",
    "Exact error message and stack trace.",
    "Input that triggered the failure.",
    "Version/build hash and config flags.",
  ];
  const triageQuestions = [
    "Is the bug reproducible on another machine?",
    "Did it start after a specific change or release?",
    "Is the issue data-specific or time-specific?",
    "Is the failure deterministic or flaky?",
  ];
  const rootCauseChecklist = [
    "First incorrect value or decision identified.",
    "Reason for the incorrect state understood.",
    "Fix removes the repro and no new regressions.",
    "Tests cover the failing case.",
  ];
  const triageSteps = [
    "Confirm the exact input that triggers the bug.",
    "Capture the stack trace and error message.",
    "Reproduce under the debugger.",
    "Verify which line first shows a wrong value.",
    "Fix and re-run the same steps to confirm.",
  ];

  const preventionChecklist = [
    "Add tests for edge cases and boundary values.",
    "Use assertions to catch invalid state early.",
    "Log critical inputs and outputs for key steps.",
    "Validate input sizes and types.",
    "Keep functions small and focused.",
  ];
  const safePractices = [
    "Use a local or staging environment for debugging.",
    "Avoid debugging with real user data.",
    "Record steps as you go to make fixes repeatable.",
    "Turn off debug logs before releasing to production.",
  ];
  const practiceExercises = [
    "Off-by-one loop bug in a small array function.",
    "Null pointer crash in a simple parser.",
    "Incorrect branch in a calculator function.",
    "Performance stall in a naive search algorithm.",
  ];
  const reportChecklist = [
    "Bug summary and steps to reproduce.",
    "Root cause in one sentence.",
    "Fix summary and risk assessment.",
    "Verification steps and results.",
  ];
  const validationLadder = [
    "Re-run the exact repro steps.",
    "Run the targeted test suite.",
    "Run broader regression tests if available.",
    "Confirm logs show the expected state.",
  ];
  const labSteps = [
    "Pick a small sample app with a known bug.",
    "Set a breakpoint before the bug appears.",
    "Step through and watch variables change.",
    "Inspect stack and registers when behavior changes.",
    "Fix the bug and verify the same steps.",
  ];
  const verificationChecklist = [
    "Bug is reproducible before the fix.",
    "Debugger shows correct state after the fix.",
    "Tests pass for the affected path.",
    "No new errors introduced by the change.",
  ];
  const safeBoundaries = [
    "Only debug software you own or have permission to test.",
    "Do not attach debuggers to production services.",
    "Do not handle sensitive data in a debugger session.",
    "Focus on diagnosis and verification, not exploitation.",
  ];

  const gdbBasics = `# GDB basics
gdb ./app
break main
run
next
step
info locals
bt`;
  const lldbBasics = `# LLDB basics
lldb ./app
breakpoint set --name main
run
next
step
frame variable
bt`;
  const winDbgBasics = `# WinDbg basics
.symfix; .reload
bp main
g
t
p
r
kb`;
  const notesTemplate = `# Debugging notes
Bug: <short description>
Repro steps:
1.
2.

Expected vs actual:
- Expected:
- Actual:

First wrong value:
Location:
Evidence:

Fix idea:
Validation steps:
`;
  const conditionalBreakpointExample = `# Conditional breakpoints
# Stop when userId is invalid
break validateUser if userId <= 0

# Stop when loop index reaches the boundary
break processItems if i == items.size - 1`;

  const pageContext = `This page covers debugging fundamentals including debugger concepts, breakpoints, memory inspection, call stacks, and common debugging tools. Topics include reproducible workflows, hypothesis-driven debugging, narrowing strategies, build symbols, logging vs debugging tradeoffs, bug triage priorities, reverse engineering perspective, platform toolkits for Android/Windows/web apps, and safe practice routines.`;

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
    <LearnPageLayout pageTitle="Debugging 101" pageContext={pageContext}>
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

      {/* Scroll to Top Button - Mobile Only */}
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
              Course Navigation
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

          {/* Hero Banner */}
          <Paper
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.15)} 0%, ${alpha("#38bdf8", 0.15)} 50%, ${alpha("#8b5cf6", 0.15)} 100%)`,
              border: `1px solid ${alpha("#3b82f6", 0.2)}`,
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
                    background: `linear-gradient(135deg, #3b82f6, #38bdf8)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 8px 32px ${alpha("#3b82f6", 0.3)}`,
                  }}
                >
                  <BugReportIcon sx={{ fontSize: 42, color: "#fff" }} />
                </Box>
                <Box>
                  <Typography
                    variant="h3"
                    sx={{
                      fontWeight: 800,
                      background: "linear-gradient(135deg, #3b82f6 0%, #38bdf8 100%)",
                      backgroundClip: "text",
                      WebkitBackgroundClip: "text",
                      color: "transparent",
                    }}
                  >
                    Debugging 101
                  </Typography>
                  <Typography variant="h6" sx={{ color: "grey.400" }}>
                    A beginner-friendly guide to finding bugs with confidence.
                  </Typography>
                </Box>
              </Box>

              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip icon={<BugReportIcon />} label="Breakpoints" size="small" sx={{ bgcolor: alpha(accent, 0.2), color: accent }} />
                <Chip icon={<SearchIcon />} label="Stepping" size="small" sx={{ bgcolor: alpha(accent, 0.2), color: accent }} />
                <Chip icon={<MemoryIcon />} label="Memory" size="small" sx={{ bgcolor: alpha(accent, 0.2), color: accent }} />
                <Chip icon={<SecurityIcon />} label="RE Mindset" size="small" sx={{ bgcolor: alpha(accent, 0.2), color: accent }} />
                <Chip icon={<BuildIcon />} label="Platform Tools" size="small" sx={{ bgcolor: alpha(accent, 0.2), color: accent }} />
                <Chip icon={<ShieldIcon />} label="Safe Workflow" size="small" sx={{ bgcolor: alpha(accent, 0.2), color: accent }} />
              </Box>

              <Alert severity="info" sx={{ bgcolor: alpha(accent, 0.1), border: `1px solid ${alpha(accent, 0.3)}` }}>
                <AlertTitle>Beginner Friendly</AlertTitle>
                This page focuses on safe, practical debugging skills you can use in any codebase.
              </Alert>
            </Box>
          </Paper>

          {/* ==================== INTRODUCTION ==================== */}
          <Typography id="intro" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 100 }}>
            What is Debugging?
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Debugging is the practice of finding out why software behaves differently than expected. A debugger
              lets you pause a program, look inside it, and step through its logic. Instead of guessing, you can
              see the real values in memory, the exact line being executed, and the call stack that led there.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              A beginner-friendly way to think about debugging is: you are comparing <strong>what you expected</strong>
              with <strong>what actually happened</strong>. That gap is your clue. A debugger makes the gap visible by
              showing you the real values at the exact moment the program makes a decision. Every time you step,
              you answer a simple question: "Did the program still behave as I expected on this line?"
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Think of a debugger like a "pause and inspect" button for software. You can stop at a line, inspect
              variables, and move forward one step at a time. This is especially powerful when a bug only appears
              after many steps or under specific inputs.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Beginners often feel lost because a running program has lots of moving parts. The trick is to narrow
              your focus to a small, observable path. Pick one failing input. Identify the function or screen where
              the symptom appears. Then move backward, line by line, until you find the first place where the state
              stops matching your expectation.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Debugging is not about stepping randomly. The best debuggers use a simple workflow: reproduce the bug,
              isolate the first wrong value, test a hypothesis, and verify the fix. The goal is to learn what the
              program is truly doing, not what we hope it is doing.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              If you ever feel stuck, pause and write down three things: what you expected, what you saw, and what
              you plan to test next. This turns a messy problem into a small experiment. Debugging is a sequence of
              experiments, not a single moment of genius.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Think of debugging as data collection. You are gathering evidence about state transitions, inputs, and
              outputs until the behavior makes sense. The fastest path to a fix is rarely intuition alone; it is a
              careful trail of observations that narrows the search space.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Most bugs are chains, not single points. A small configuration mistake can flow through a system and
              surface as a crash far away. Your job is to separate symptoms from causes and identify the earliest
              incorrect assumption that started the chain.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Good debuggers define invariants: rules that must always be true. When an invariant fails, you have a
              precise anchor for investigation. This is more reliable than guessing and keeps debugging systematic.
            </Typography>
            <Typography variant="body2" sx={{ color: "grey.400" }}>
              This guide explains core debugging concepts, common tools, and a safe practice workflow for beginners.
            </Typography>
          </Paper>

          {/* ==================== OVERVIEW ==================== */}
          <Typography id="overview" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 100 }}>
            Overview
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Debugging Mental Model
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Debugging is a disciplined search for the first point where reality diverges from expectation. Every
              program can be viewed as a series of state changes: inputs arrive, code executes, state updates, and
              outputs are produced. When outputs are wrong, the fastest path is to locate the earliest incorrect state.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Start by drawing a simple pipeline in your head: <em>Input → Transform → Output</em>. When the output is
              wrong, ask which transform could have produced that wrong value. Then inspect the input and the state
              just before the transform. This keeps you from jumping around and helps you debug in a straight line.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              The call stack tells you how you arrived at the current line. Treat it as a breadcrumb trail of decisions.
              When the current state looks wrong, walk up the stack to see which function first introduced the bad value.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              A good mental model also includes <strong>invariants</strong> (facts that should always be true). For example,
              "userId should never be empty here" or "array index must be within bounds." Place breakpoints around
              these invariants and check them at runtime. When an invariant breaks, you are very close to the bug.
            </Typography>
            <List dense>
              {debuggingMentalModel.map((item) => (
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
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Debugging Mindset
            </Typography>
            <List dense>
              {mindsetHabits.map((item) => (
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
              Repro Tips
            </Typography>
            <List dense>
              {reproducibilityTips.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <SearchIcon color="info" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Bug Types Quick Map
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "#38bdf8" }}>Type</TableCell>
                    <TableCell sx={{ color: "#38bdf8" }}>Signals</TableCell>
                    <TableCell sx={{ color: "#38bdf8" }}>Approach</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {bugTypeMap.map((item) => (
                    <TableRow key={item.type}>
                      <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.type}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{item.signals}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{item.approach}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Signal vs Noise
            </Typography>
            <List dense>
              {signalNoiseTips.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <WarningIcon color="warning" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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
                      border: "1px solid rgba(59, 130, 246, 0.25)",
                      height: "100%",
                    }}
                  >
                    <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1 }}>
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

          {/* ==================== REVERSE ENGINEER ==================== */}
          <Typography id="reverse-engineer" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 100 }}>
            Reverse Engineer's Perspective
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Reverse engineers debug software without trusting source code. They treat the running program as evidence,
              validate hypotheses against live state, and reconstruct intent from behavior. This perspective is valuable
              even in normal development because it forces you to rely on facts: memory, registers, call stacks, and I/O.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300" }}>
              When a bug is elusive, think like a reverse engineer: capture artifacts, instrument runtime behavior,
              and track the data that triggered the failure until you find the first incorrect transformation.
            </Typography>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 2 }}>
              Reverse Engineering Mindset
            </Typography>
            <Grid container spacing={2}>
              {reverseEngineerMindset.map((item) => (
                <Grid item xs={12} md={6} key={item.title}>
                  <Paper sx={{ p: 2, bgcolor: "#0b1020", borderRadius: 2, border: "1px solid rgba(56, 189, 248, 0.25)" }}>
                    <Typography variant="subtitle2" sx={{ color: "#38bdf8", mb: 1 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>
                      {item.description}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "grey.400" }}>
                      Focus: {item.focus}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              High-Value Artifacts
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "#3b82f6" }}>Artifact</TableCell>
                    <TableCell sx={{ color: "#3b82f6" }}>Why it helps</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {reverseEngineerArtifacts.map((item) => (
                    <TableRow key={item.artifact}>
                      <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.artifact}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{item.use}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Reverse Engineering Workflow
            </Typography>
            <List dense>
              {reverseEngineerWorkflow.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <CheckCircleIcon color="success" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          {/* ==================== PLATFORM TOOLS ==================== */}
          <Typography id="platform-tools" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 100 }}>
            Platform Debugging Toolkits
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="body1" sx={{ color: "grey.300" }}>
              Each platform has its own debugging stack. The tools below are widely used by software reverse engineers
              and engineers in practice. Start with the platform debugger, then add instrumentation, tracing, and proxies
              when behavior is hidden or hard to reproduce.
            </Typography>
          </Paper>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: "#0f1422", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Android
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Tool</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Use</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {androidTools.map((tool) => (
                        <TableRow key={tool.name}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{tool.name}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{tool.use}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: "#0f1422", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Windows
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#3b82f6" }}>Tool</TableCell>
                        <TableCell sx={{ color: "#3b82f6" }}>Use</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {windowsTools.map((tool) => (
                        <TableRow key={tool.name}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{tool.name}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{tool.use}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: "#0f1422", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 1 }}>
                  Web Apps
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#22c55e" }}>Tool</TableCell>
                        <TableCell sx={{ color: "#22c55e" }}>Use</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {webTools.map((tool) => (
                        <TableRow key={tool.name}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{tool.name}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{tool.use}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>
          </Grid>

          {/* ==================== WORKFLOW ==================== */}
          <Typography id="workflow" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 100 }}>
            Workflow
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              How Debugging Works
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              A debugger sits between you and the running program. It can pause execution, inspect live data, and then
              resume. The trick is to pause at the right moment and ask focused questions about the current state.
              Stepping without a hypothesis often wastes time, so pair each breakpoint with a concrete question.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Beginners often try to step through everything. That is overwhelming and slow. Instead, place a breakpoint
              near the symptom, then use "step over" to skip known-good code and "step into" only when you need to see
              a function's internal behavior. This makes debugging targeted and efficient.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              If the bug only happens after many steps, use conditional breakpoints or logpoints. They let you pause
              only when a condition is true (for example, a value becomes negative), which keeps you focused on the
              exact moment the state changes.
            </Typography>
            <List dense>
              {howDebuggingWorks.map((item) => (
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
              Debugging Workflow
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              A workflow keeps you from chasing random clues. Start with a reliable reproduction, move to a narrow
              region of code, and then validate each assumption. If you cannot reproduce, you cannot fix. If you cannot
              explain why a fix worked, the bug may return later.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Think of each step as a gate. You cannot pass to the next gate until the current one is solid. For example:
              do you have the same input each time? Are you sure you are in the right function? Have you confirmed the
              variable is wrong at this line? This disciplined approach prevents "fixing" the wrong thing.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Once you find the first wrong value, stop and trace backward to the line where it was created. The creation
              point is almost always the root cause. Fixing anything after that is usually just hiding the symptom.
            </Typography>
            <List dense>
              {workflow.map((item) => (
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
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Hypothesis Loop
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              A hypothesis is a specific, testable guess. "The data is wrong" is too broad. "The discount is applied
              twice when the cart has more than five items" is a good hypothesis. Good hypotheses lead to clear tests
              and quick answers.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              If your hypothesis is wrong, that is progress. It means you just eliminated a path. Debugging is the
              process of eliminating paths until only the real cause remains.
            </Typography>
            <List dense>
              {hypothesisLoop.map((item) => (
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
              Narrowing Strategies
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              When a bug feels overwhelming, focus on shrinking the search space. Reduce the input, isolate the feature,
              and remove anything unrelated to the failure. The goal is to make the bug small enough that it cannot hide.
            </Typography>
            <List dense>
              {narrowingStrategies.map((item) => (
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
              Minimum Repro Checklist
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              A minimal reproduction is the smallest test that still fails. The smaller it is, the faster you can
              iterate. It also makes it easier to share the issue with teammates, file a bug report, or write a test
              that prevents regressions.
            </Typography>
            <List dense>
              {minimalReproChecklist.map((item) => (
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
              Build Settings That Matter
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Build flags shape how debuggable a binary is. Optimizations can reorder, inline, or remove code, which
              makes stepping confusing and can hide variables. Debug symbols map compiled instructions back to source
              lines so the debugger can show meaningful context.
            </Typography>
            <List dense>
              {buildSettings.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <BuildIcon color="info" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Logging vs Debugger
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Logging is great for long-running or production-only issues, while a debugger shines when you can
              reproduce locally and need precise state. Many teams use both: logs to detect the failure and a debugger
              to isolate the root cause. The key is choosing the least intrusive tool that still answers your question.
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "#38bdf8" }}>Approach</TableCell>
                    <TableCell sx={{ color: "#38bdf8" }}>Best For</TableCell>
                    <TableCell sx={{ color: "#38bdf8" }}>Tradeoffs</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {loggingVsDebugger.map((item) => (
                    <TableRow key={item.choice}>
                      <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.choice}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{item.bestFor}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{item.tradeoff}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Debug Notes Template
            </Typography>
            <CodeBlock code={notesTemplate} language="text" />
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Common Entry Points
            </Typography>
            <List dense>
              {commonEntryPoints.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <SearchIcon color="info" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Debugger Tools by Platform
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "#38bdf8" }}>Platform</TableCell>
                    <TableCell sx={{ color: "#38bdf8" }}>Tools</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {toolsByPlatform.map((item) => (
                    <TableRow key={item.platform}>
                      <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.platform}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{item.tools}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* ==================== BREAKPOINTS ==================== */}
          <Typography id="breakpoints" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 100 }}>
            Breakpoints & Stepping
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Breakpoint Types
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "#38bdf8" }}>Type</TableCell>
                    <TableCell sx={{ color: "#38bdf8" }}>Use</TableCell>
                    <TableCell sx={{ color: "#38bdf8" }}>Tip</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {breakpointTypes.map((item) => (
                    <TableRow key={item.type}>
                      <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.type}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{item.use}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{item.tip}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Breakpoint Placement Guide
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Breakpoints are most useful when they validate a specific hypothesis. Place them where data crosses
              a boundary, where it is transformed, or right before a decision is made. This minimizes stepping while
              maximizing the information you collect.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              For beginners, a simple rule helps: set the first breakpoint at the <strong>symptom</strong>, then set
              the next breakpoint just before the code that produced that symptom. Repeat until you find the first
              wrong value. This "walk backward" pattern keeps your investigation focused and avoids random stepping.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              If you are unsure where to start, place breakpoints on input parsing, validation, and output formatting.
              These are natural boundaries where the program takes in data, changes it, and exposes results.
            </Typography>
            <List dense>
              {breakpointPlacementTips.map((item) => (
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
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Stepping Modes
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Stepping is a control knob. Use step into when you need to inspect a function's internals, step over to
              avoid library noise, and step out to return to higher level context. If you find yourself stepping for a
              long time, you probably need a better breakpoint.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              A practical beginner tactic is to step until the values diverge from your expectation, then stop and
              inspect. You do not need to understand every line. Focus on where the state becomes surprising, because
              that is where the bug is born.
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "#38bdf8" }}>Mode</TableCell>
                    <TableCell sx={{ color: "#38bdf8" }}>Meaning</TableCell>
                    <TableCell sx={{ color: "#38bdf8" }}>When to Use</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {steppingModes.map((item) => (
                    <TableRow key={item.mode}>
                      <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.mode}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{item.meaning}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{item.when}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Breakpoint Strategy
            </Typography>
            <List dense>
              {breakpointStrategies.map((item) => (
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
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Conditional Examples
            </Typography>
            <CodeBlock code={conditionalBreakpointExample} language="text" />
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Watchpoints and Data Breakpoints
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Watchpoints pause when a value changes, which is perfect for tracking mysterious mutations. If a variable
              flips unexpectedly, set a watchpoint on its memory location and let the debugger catch the exact line that
              changed it. This is one of the fastest ways to find hidden side effects.
            </Typography>
            <List dense>
              {watchpointTips.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <SearchIcon color="info" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Common Debugger Commands
            </Typography>
            <Accordion sx={{ bgcolor: "#0f1422", borderRadius: 2, mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1">GDB</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock code={gdbBasics} language="bash" />
              </AccordionDetails>
            </Accordion>
            <Accordion sx={{ bgcolor: "#0f1422", borderRadius: 2, mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1">LLDB</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock code={lldbBasics} language="bash" />
              </AccordionDetails>
            </Accordion>
            <Accordion sx={{ bgcolor: "#0f1422", borderRadius: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1">WinDbg</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CodeBlock code={winDbgBasics} language="text" />
              </AccordionDetails>
            </Accordion>
          </Paper>

          {/* ==================== MEMORY & REGISTERS ==================== */}
          <Typography id="memory" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 100 }}>
            Memory & Registers
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Memory Basics
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Memory is just storage, but different regions have different lifetimes and rules. The stack is fast and
              automatic, the heap is flexible but requires careful ownership, and globals live for the entire program.
              Many bugs happen when code assumes one lifetime but uses another.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              A beginner-friendly mental model is to imagine a stack of sticky notes (the stack) and a big bulletin board
              (the heap). Stack notes are temporary and get thrown away automatically when a function ends. Heap notes
              stay until you remove them. If you keep using a sticky note after it was thrown away, you get crashes or
              strange behavior.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              If a crash appears far away from the cause, suspect memory corruption or unexpected mutation. Watchpoints
              and heap tooling help you catch the exact write that introduced the bad data.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              When debugging memory issues, slow down and inspect one pointer at a time. Check whether it is null, whether
              it points to valid memory, and whether the data at that address matches what you expect. A single invalid
              pointer can create a chain of confusing symptoms.
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
              Register Hints
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Registers show what the CPU is doing right now. Even if you never touch assembly, registers are useful
              for spotting patterns like bad pointer values, unexpected return codes, or inputs that were never validated.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              As a beginner, you do not need to memorize every register. Focus on a few: the instruction pointer
              (where you are), the stack pointer (where the stack is), and registers holding function arguments. These
              can quickly reveal whether a function was called with the wrong data.
            </Typography>
            <List dense>
              {registerHints.map((item) => (
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
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Stack Frames in Practice
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Each stack frame represents one function call. When you move up a frame, you move backward in time to see
              the arguments and local variables that led to the current state. This is one of the fastest ways to find
              where a bad value originated.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              If you are unsure where the bug started, pick the frame that first sees the wrong value. Inspect its
              arguments and then step into the function that produced them. This "find the first frame with bad data"
              technique is reliable across most bugs.
            </Typography>
            <List dense>
              {stackFrameTips.map((item) => (
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
              Memory Areas
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: "#38bdf8" }}>Area</TableCell>
                    <TableCell sx={{ color: "#38bdf8" }}>Lifetime</TableCell>
                    <TableCell sx={{ color: "#38bdf8" }}>Common Risk</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {memoryAreas.map((item) => (
                    <TableRow key={item.area}>
                      <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.area}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{item.lifetime}</TableCell>
                      <TableCell sx={{ color: "grey.400" }}>{item.risk}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Common Memory Bugs
            </Typography>
            <List dense>
              {commonMemoryBugs.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <WarningIcon color="warning" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Memory Red Flags
            </Typography>
            <List dense>
              {memoryRedFlags.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <WarningIcon color="warning" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Common Pitfalls
            </Typography>
            <List dense>
              {pitfalls.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <WarningIcon color="warning" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          {/* ==================== DETECTION ==================== */}
          <Typography id="detection" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 100 }}>
            Bug Detection & Triage
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Detection Signals
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Detection is about noticing patterns that indicate something is wrong. A crash is obvious, but many bugs
              are quieter: wrong totals, missing UI updates, or a request that succeeds with the wrong data. Train yourself
              to treat "almost right" results as clues, not noise.
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
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Triage Priorities
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Not every bug should be treated equally. Triage is the process of deciding what to investigate first, based
              on impact, urgency, and confidence in reproduction. This helps teams focus on the most important fixes and
              avoid thrashing.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Beginners often chase the most mysterious bug first. A better approach is to prioritize by impact and
              certainty. A small bug you can reproduce is often more valuable to fix than a huge bug you cannot reproduce.
            </Typography>
            <List dense>
              {triagePriorities.map((item) => (
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
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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
              Crash Artifacts to Capture
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              When a crash happens, your goal is to capture the moment. Even a short stack trace can save hours. If you
              can gather artifacts once, you can debug offline without reproducing the crash every time.
            </Typography>
            <List dense>
              {crashArtifacts.map((item) => (
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
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Triage Questions
            </Typography>
            <List dense>
              {triageQuestions.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <SearchIcon color="info" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
              Root Cause Checklist
            </Typography>
            <List dense>
              {rootCauseChecklist.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <CheckCircleIcon color="success" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Quick Triage Steps
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Triage is a fast, structured check. The goal is not to fix the bug yet, but to confirm it exists, gather
              evidence, and decide how to proceed. Think of this as your 10-minute investigation before you commit
              to a longer debugging session.
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

          {/* ==================== SAFE LAB ==================== */}
          <Typography id="safe-lab" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 100 }}>
            Safe Lab & Practice
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Safe Lab Setup Notes
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Debugging changes the running state of a program and can expose sensitive data. Use an isolated lab
              environment that mirrors production in structure but not in secrets. If you must debug a live system, do
              it with strict permissions and clear rollback plans.
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              A safe lab for beginners can be as simple as a local virtual machine or a separate test account. The key is
              to avoid real user data and to keep logs, keys, and credentials out of your debugging session. This makes
              it safe to pause, inspect, and modify state without risking production systems.
            </Typography>
            <List dense>
              {safeLabChecklistExpanded.map((item) => (
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
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Safe Lab Walkthrough
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Think of the lab walkthrough as a checklist you can repeat. Each step is designed to reduce uncertainty:
              capture the environment, reproduce the bug, instrument the code, and verify the fix. When you can repeat
              this process, debugging becomes predictable instead of stressful.
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
              Practice Exercises
            </Typography>
            <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
              Practice is what turns concepts into skills. Start with small, controlled bugs and gradually increase
              complexity. The goal is not speed, but confidence: can you reproduce the issue, isolate the cause, and
              explain the fix clearly?
            </Typography>
            <List dense>
              {practiceExercises.map((item) => (
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
              Safe Debugging Practices
            </Typography>
            <List dense>
              {safePractices.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <ShieldIcon color="success" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

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

          <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
              Validation Ladder
            </Typography>
            <List dense>
              {validationLadder.map((item) => (
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
              Debugging Report Checklist
            </Typography>
            <List dense>
              {reportChecklist.map((item) => (
                <ListItem key={item}>
                  <ListItemIcon>
                    <CheckCircleIcon color="info" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          <Paper sx={{ p: 2.5, mb: 4, bgcolor: "#0f1422", borderRadius: 2 }}>
            <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
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

          {/* ==================== QUIZ ==================== */}
          <Typography id="quiz" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 100 }}>
            Knowledge Quiz
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Typography variant="body1" sx={{ color: "grey.400", mb: 3 }}>
            Test your understanding of debugging fundamentals with this interactive quiz. Questions cover
            debugger basics, breakpoints, stepping modes, memory inspection, and bug detection.
          </Typography>
          <QuizSection />

          {/* Back to Learning Hub Button */}
          <Box sx={{ mt: 4, textAlign: "center" }}>
            <Button
              variant="outlined"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ borderColor: "#3b82f6", color: "#3b82f6" }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
