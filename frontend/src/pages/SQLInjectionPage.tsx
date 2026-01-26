import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  Box,
  Container,
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
  alpha,
  useTheme,
  Divider,
  Fab,
  Drawer,
  LinearProgress,
  useMediaQuery,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import QuizIcon from "@mui/icons-material/Quiz";
import StorageIcon from "@mui/icons-material/Storage";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import ShieldIcon from "@mui/icons-material/Shield";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SearchIcon from "@mui/icons-material/Search";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import LockIcon from "@mui/icons-material/Lock";
import TerminalIcon from "@mui/icons-material/Terminal";
import PublicIcon from "@mui/icons-material/Public";
import SpeedIcon from "@mui/icons-material/Speed";
import DataObjectIcon from "@mui/icons-material/DataObject";
import InfoIcon from "@mui/icons-material/Info";
import SchoolIcon from "@mui/icons-material/School";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import HistoryIcon from "@mui/icons-material/History";
import VisibilityIcon from "@mui/icons-material/Visibility";
import TuneIcon from "@mui/icons-material/Tune";
import MemoryIcon from "@mui/icons-material/Memory";
import ApiIcon from "@mui/icons-material/Api";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

// ========== CODE BLOCK COMPONENT ==========
const CodeBlock: React.FC<{ code: string; language?: string; title?: string }> = ({
  code,
  language = "sql",
  title,
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
        bgcolor: "#0d1117",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(249, 115, 22, 0.2)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#f97316", color: "#0b1020", fontWeight: 600 }} />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: "#e2e8f0" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      {title && (
        <Typography variant="caption" sx={{ color: "#94a3b8", display: "block", mb: 1 }}>
          {title}
        </Typography>
      )}
      <Box
        component="pre"
        sx={{
          m: 0,
          overflow: "auto",
          fontFamily: "'Fira Code', 'Monaco', monospace",
          fontSize: "0.85rem",
          color: "#e2e8f0",
          pt: title ? 0 : 2,
          lineHeight: 1.6,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

// ========== QUIZ DATA ==========
const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#f97316";

const quizQuestions: QuizQuestion[] = [
  // ===== FUNDAMENTALS (15 questions) =====
  {
    id: 1,
    topic: "Fundamentals",
    question: "What is SQL injection?",
    options: [
      "A database backup process",
      "Inserting malicious SQL through untrusted input",
      "Encrypting SQL queries",
      "Running SQL in the browser",
    ],
    correctAnswer: 1,
    explanation: "SQL injection happens when untrusted input becomes part of a SQL command.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "SQL injection occurs when an application:",
    options: [
      "Uses HTTPS",
      "Concatenates untrusted input into SQL",
      "Encrypts data at rest",
      "Uses an ORM",
    ],
    correctAnswer: 1,
    explanation: "String concatenation allows user input to change the query structure.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "The primary impact of SQL injection is:",
    options: [
      "Faster queries",
      "Unauthorized data access or modification",
      "Improved caching",
      "Better UI performance",
    ],
    correctAnswer: 1,
    explanation: "Attackers can read, modify, or delete data beyond their permissions.",
  },
  {
    id: 4,
    topic: "Fundamentals",
    question: "The best first-line defense against SQL injection is:",
    options: [
      "Input blacklists",
      "Parameterized queries or prepared statements",
      "Obfuscating SQL",
      "Hiding endpoints",
    ],
    correctAnswer: 1,
    explanation: "Parameters separate data from code, preventing SQL interpretation.",
  },
  {
    id: 5,
    topic: "Fundamentals",
    question: "Why is input validation alone insufficient for SQL injection?",
    options: [
      "It slows the app",
      "Attackers can bypass it and still inject SQL",
      "It breaks TLS",
      "It disables logging",
    ],
    correctAnswer: 1,
    explanation: "Validation helps but does not replace parameterized queries.",
  },
  {
    id: 6,
    topic: "Fundamentals",
    question: "What does SQL stand for?",
    options: [
      "Structured Query Language",
      "Simple Query Logic",
      "Standard Question Language",
      "System Query Lookup",
    ],
    correctAnswer: 0,
    explanation: "SQL stands for Structured Query Language, used to interact with databases.",
  },
  {
    id: 7,
    topic: "Fundamentals",
    question: "Which OWASP category does SQL injection belong to?",
    options: [
      "Broken Access Control",
      "Injection",
      "Security Misconfiguration",
      "Cryptographic Failures",
    ],
    correctAnswer: 1,
    explanation: "SQL injection is a type of injection vulnerability in the OWASP Top 10.",
  },
  {
    id: 8,
    topic: "Fundamentals",
    question: "What character is most commonly used to test for SQL injection?",
    options: [
      "Single quote (')",
      "Semicolon (;)",
      "Asterisk (*)",
      "Ampersand (&)",
    ],
    correctAnswer: 0,
    explanation: "A single quote can break SQL string syntax and reveal vulnerabilities.",
  },
  {
    id: 9,
    topic: "Fundamentals",
    question: "The core problem in SQL injection is:",
    options: [
      "Slow database queries",
      "Data treated as executable code",
      "Missing encryption",
      "Weak passwords",
    ],
    correctAnswer: 1,
    explanation: "SQLi occurs when user data is interpreted as SQL commands.",
  },
  {
    id: 10,
    topic: "Fundamentals",
    question: "Which layer of the application is SQL injection targeting?",
    options: [
      "Presentation layer",
      "Network layer",
      "Data layer",
      "Session layer",
    ],
    correctAnswer: 2,
    explanation: "SQL injection targets the data layer where database queries are executed.",
  },
  {
    id: 11,
    topic: "Fundamentals",
    question: "What is a prepared statement?",
    options: [
      "A pre-compiled SQL template with placeholders for data",
      "A backup of the database",
      "A type of stored procedure",
      "An encrypted query",
    ],
    correctAnswer: 0,
    explanation: "Prepared statements separate SQL structure from data values.",
  },
  {
    id: 12,
    topic: "Fundamentals",
    question: "SQL injection can affect which types of applications?",
    options: [
      "Only web applications",
      "Only mobile apps",
      "Any application that uses SQL databases",
      "Only REST APIs",
    ],
    correctAnswer: 2,
    explanation: "Any application building SQL queries from user input can be vulnerable.",
  },
  {
    id: 13,
    topic: "Fundamentals",
    question: "What is the difference between SQLi and stored XSS?",
    options: [
      "SQLi targets databases, XSS targets browsers",
      "They are the same thing",
      "SQLi is client-side, XSS is server-side",
      "There is no difference",
    ],
    correctAnswer: 0,
    explanation: "SQLi manipulates database queries while XSS injects scripts into web pages.",
  },
  {
    id: 14,
    topic: "Fundamentals",
    question: "Why do ORMs not fully protect against SQL injection?",
    options: [
      "They can be bypassed with raw SQL queries",
      "They don't support parameters",
      "They only work with NoSQL",
      "They always encrypt data",
    ],
    correctAnswer: 0,
    explanation: "ORMs can be misused when developers drop down to raw SQL.",
  },
  {
    id: 15,
    topic: "Fundamentals",
    question: "What is a query parameter placeholder?",
    options: [
      "A symbol like ? or $1 that marks where data should go",
      "A database column name",
      "A type of SQL comment",
      "An encryption key",
    ],
    correctAnswer: 0,
    explanation: "Placeholders mark data positions, keeping them separate from SQL code.",
  },
  // ===== INJECTION TYPES (12 questions) =====
  {
    id: 16,
    topic: "Injection Types",
    question: "Error-based SQL injection relies on:",
    options: [
      "Silent responses",
      "Database error messages",
      "Only timing",
      "Only DNS lookups",
    ],
    correctAnswer: 1,
    explanation: "Error messages can leak query structure and data.",
  },
  {
    id: 17,
    topic: "Injection Types",
    question: "Union-based SQL injection requires:",
    options: [
      "Matching column counts and compatible types",
      "A WAF bypass",
      "A file upload",
      "TLS downgrade",
    ],
    correctAnswer: 0,
    explanation: "Union queries must align column counts and types.",
  },
  {
    id: 18,
    topic: "Injection Types",
    question: "Boolean-based blind SQL injection uses:",
    options: [
      "Response differences for true/false conditions",
      "Syntax errors only",
      "Only DNS callbacks",
      "Stacked queries",
    ],
    correctAnswer: 0,
    explanation: "Attackers infer data from changes in responses.",
  },
  {
    id: 19,
    topic: "Injection Types",
    question: "Time-based SQL injection confirms execution by:",
    options: [
      "Returning rows",
      "Triggering delays like SLEEP",
      "Changing HTTP status only",
      "Dropping tables",
    ],
    correctAnswer: 1,
    explanation: "Delays indicate the injected condition evaluated true.",
  },
  {
    id: 20,
    topic: "Injection Types",
    question: "Out-of-band SQL injection exfiltrates data via:",
    options: [
      "DNS or HTTP requests from the database server",
      "Error messages in the response",
      "Timing differences",
      "Response headers only",
    ],
    correctAnswer: 0,
    explanation: "OOB attacks use external channels the attacker controls.",
  },
  {
    id: 21,
    topic: "Injection Types",
    question: "Second-order SQL injection occurs when:",
    options: [
      "Stored malicious input is used in a later query",
      "Two queries run simultaneously",
      "The database is queried twice",
      "Two users attack at once",
    ],
    correctAnswer: 0,
    explanation: "Second-order attacks exploit stored data used later without proper sanitization.",
  },
  {
    id: 22,
    topic: "Injection Types",
    question: "What makes stacked queries dangerous?",
    options: [
      "They can execute INSERT, UPDATE, DELETE commands",
      "They run faster",
      "They bypass authentication",
      "They encrypt data",
    ],
    correctAnswer: 0,
    explanation: "Stacked queries allow arbitrary SQL execution beyond SELECT.",
  },
  {
    id: 23,
    topic: "Injection Types",
    question: "In-band SQL injection means:",
    options: [
      "Results are returned in the same channel as the attack",
      "The attack uses bandwidth limits",
      "Only network attacks are possible",
      "The database is local",
    ],
    correctAnswer: 0,
    explanation: "In-band attacks receive results directly in the HTTP response.",
  },
  {
    id: 24,
    topic: "Injection Types",
    question: "Which injection type is slowest for data extraction?",
    options: [
      "Time-based blind",
      "Union-based",
      "Error-based",
      "In-band",
    ],
    correctAnswer: 0,
    explanation: "Time-based blind requires waiting for delays for each character.",
  },
  {
    id: 25,
    topic: "Injection Types",
    question: "What is inferential SQL injection?",
    options: [
      "Another name for blind SQL injection",
      "Injection using machine learning",
      "Automated injection",
      "A type of stored procedure attack",
    ],
    correctAnswer: 0,
    explanation: "Inferential/blind SQLi requires deducing data from indirect signals.",
  },
  {
    id: 26,
    topic: "Injection Types",
    question: "UNION SELECT NULL is used to:",
    options: [
      "Determine the number of columns in the query",
      "Delete all data",
      "Create a new table",
      "Encrypt the response",
    ],
    correctAnswer: 0,
    explanation: "Adding NULLs helps find the correct column count for UNION attacks.",
  },
  {
    id: 27,
    topic: "Injection Types",
    question: "Which is NOT a valid SQL injection type?",
    options: [
      "Buffer-based injection",
      "Error-based injection",
      "Time-based blind injection",
      "Union-based injection",
    ],
    correctAnswer: 0,
    explanation: "Buffer-based is a memory corruption attack, not SQL injection.",
  },
  // ===== DETECTION (10 questions) =====
  {
    id: 28,
    topic: "Detection",
    question: "MySQL error 'You have an error in your SQL syntax' suggests:",
    options: [
      "A caching issue",
      "Possible error-based SQL injection",
      "Valid input",
      "TLS failure",
    ],
    correctAnswer: 1,
    explanation: "Syntax errors are a common SQLi signal.",
  },
  {
    id: 29,
    topic: "Detection",
    question: "Repeated 500 errors after adding quotes to input indicates:",
    options: [
      "Potential SQL injection",
      "Successful MFA",
      "CSP violation",
      "Normal traffic",
    ],
    correctAnswer: 0,
    explanation: "Quotes can break query strings and trigger SQL errors.",
  },
  {
    id: 30,
    topic: "Detection",
    question: "Which log source is most useful for detecting SQLi attempts?",
    options: [
      "Application and database logs",
      "DNS logs only",
      "Email logs",
      "Print spooler logs",
    ],
    correctAnswer: 0,
    explanation: "Application and database logs show query errors and unusual patterns.",
  },
  {
    id: 31,
    topic: "Detection",
    question: "A WAF detecting 'UNION SELECT' in a request suggests:",
    options: [
      "A SQL injection attempt",
      "Normal database operation",
      "Successful authentication",
      "File upload in progress",
    ],
    correctAnswer: 0,
    explanation: "UNION SELECT is a common SQLi payload for data extraction.",
  },
  {
    id: 32,
    topic: "Detection",
    question: "Response time of exactly 5 seconds after input with SLEEP(5) indicates:",
    options: [
      "Time-based SQL injection vulnerability",
      "Network latency",
      "Database optimization",
      "Caching working correctly",
    ],
    correctAnswer: 0,
    explanation: "Consistent delays matching the SLEEP value confirm SQLi.",
  },
  {
    id: 33,
    topic: "Detection",
    question: "Which HTTP status code often indicates a SQL error?",
    options: [
      "500 Internal Server Error",
      "200 OK",
      "301 Redirect",
      "404 Not Found",
    ],
    correctAnswer: 0,
    explanation: "Unhandled SQL errors often result in 500 status codes.",
  },
  {
    id: 34,
    topic: "Detection",
    question: "Seeing 'ORA-01756' in a response indicates:",
    options: [
      "Oracle database SQL error",
      "MySQL connection issue",
      "PostgreSQL warning",
      "MongoDB exception",
    ],
    correctAnswer: 0,
    explanation: "ORA- prefixed errors are Oracle database error codes.",
  },
  {
    id: 35,
    topic: "Detection",
    question: "What indicates a successful blind SQLi condition?",
    options: [
      "Different response content for true vs false conditions",
      "Same response every time",
      "404 errors",
      "Faster response times",
    ],
    correctAnswer: 0,
    explanation: "Blind SQLi relies on detecting differences in responses.",
  },
  {
    id: 36,
    topic: "Detection",
    question: "Database audit logs showing access to information_schema suggests:",
    options: [
      "Possible reconnaissance for SQLi attack",
      "Normal application behavior",
      "Backup in progress",
      "Index optimization",
    ],
    correctAnswer: 0,
    explanation: "Attackers query information_schema to discover table structures.",
  },
  {
    id: 37,
    topic: "Detection",
    question: "Which pattern in logs indicates potential SQLi probing?",
    options: [
      "Multiple requests with ', \", --, and # characters",
      "Normal GET requests",
      "Image file downloads",
      "CSS file requests",
    ],
    correctAnswer: 0,
    explanation: "Special SQL characters in input often indicate injection testing.",
  },
  // ===== PREVENTION (12 questions) =====
  {
    id: 38,
    topic: "Prevention",
    question: "Parameterized queries prevent SQL injection because they:",
    options: [
      "Send SQL and data separately",
      "Encrypt SQL",
      "Hide endpoints",
      "Disable logging",
    ],
    correctAnswer: 0,
    explanation: "Parameters ensure user input cannot alter query structure.",
  },
  {
    id: 39,
    topic: "Prevention",
    question: "Escaping user input alone is:",
    options: [
      "Error-prone and incomplete",
      "Always sufficient",
      "Better than parameters",
      "Required for all queries",
    ],
    correctAnswer: 0,
    explanation: "Escaping rules vary and miss many injection contexts.",
  },
  {
    id: 40,
    topic: "Prevention",
    question: "Dynamic ORDER BY is safest when you:",
    options: [
      "Use an allowlist and map to known columns",
      "Concatenate user input directly",
      "Store input in cookies",
      "Use SELECT * only",
    ],
    correctAnswer: 0,
    explanation: "Identifiers cannot be parameterized, so allowlisting is required.",
  },
  {
    id: 41,
    topic: "Prevention",
    question: "Which query is safest?",
    options: [
      "SELECT * FROM users WHERE id = ?",
      "SELECT * FROM users WHERE id = ' + id + '",
      "SELECT * FROM users WHERE id = ${id}",
      "SELECT * FROM users ORDER BY ' + col",
    ],
    correctAnswer: 0,
    explanation: "The ? placeholder indicates a parameterized query.",
  },
  {
    id: 42,
    topic: "Prevention",
    question: "Least privilege for database accounts means:",
    options: [
      "Only granting permissions needed for the application",
      "Using the root account for simplicity",
      "Sharing credentials across applications",
      "Disabling all security features",
    ],
    correctAnswer: 0,
    explanation: "Limiting permissions reduces the impact of successful SQLi.",
  },
  {
    id: 43,
    topic: "Prevention",
    question: "Input validation should be used:",
    options: [
      "As defense in depth, not as the only protection",
      "Instead of parameterized queries",
      "Only for numeric inputs",
      "Only on the client side",
    ],
    correctAnswer: 0,
    explanation: "Validation adds a layer but cannot replace proper parameterization.",
  },
  {
    id: 44,
    topic: "Prevention",
    question: "Stored procedures can prevent SQLi if they:",
    options: [
      "Use parameterized inputs and don't build dynamic SQL",
      "Are written in any language",
      "Use string concatenation internally",
      "Are encrypted",
    ],
    correctAnswer: 0,
    explanation: "Stored procedures must still use parameters to be safe.",
  },
  {
    id: 45,
    topic: "Prevention",
    question: "What should you do with detailed SQL error messages?",
    options: [
      "Log them server-side but show generic errors to users",
      "Display them to help users debug",
      "Email them to all users",
      "Store them in cookies",
    ],
    correctAnswer: 0,
    explanation: "Detailed errors help attackers; log internally only.",
  },
  {
    id: 46,
    topic: "Prevention",
    question: "Web Application Firewalls (WAFs) are:",
    options: [
      "Defense in depth, not a primary SQLi fix",
      "A complete solution for SQLi",
      "Only useful for XSS",
      "A replacement for input validation",
    ],
    correctAnswer: 0,
    explanation: "WAFs can be bypassed; proper coding is the real solution.",
  },
  {
    id: 47,
    topic: "Prevention",
    question: "Code review for SQLi should focus on:",
    options: [
      "All places where user input reaches database queries",
      "Only login forms",
      "CSS styling",
      "Image optimization",
    ],
    correctAnswer: 0,
    explanation: "Any input path to a query is a potential vulnerability.",
  },
  {
    id: 48,
    topic: "Prevention",
    question: "SAST tools help prevent SQLi by:",
    options: [
      "Automatically finding vulnerable code patterns",
      "Encrypting the database",
      "Blocking network traffic",
      "Compressing queries",
    ],
    correctAnswer: 0,
    explanation: "Static analysis finds SQLi patterns before deployment.",
  },
  {
    id: 49,
    topic: "Prevention",
    question: "Network segmentation helps limit SQLi impact by:",
    options: [
      "Preventing direct database access from compromised web servers",
      "Making queries faster",
      "Encrypting all traffic",
      "Removing the need for authentication",
    ],
    correctAnswer: 0,
    explanation: "Segmentation limits lateral movement after a breach.",
  },
  // ===== DATABASE SPECIFIC (10 questions) =====
  {
    id: 50,
    topic: "Database",
    question: "In MySQL, which function causes a time delay?",
    options: [
      "SLEEP()",
      "WAITFOR DELAY",
      "pg_sleep()",
      "PAUSE()",
    ],
    correctAnswer: 0,
    explanation: "SLEEP() is MySQL's native delay function.",
  },
  {
    id: 51,
    topic: "Database",
    question: "MSSQL time-based injection typically uses:",
    options: [
      "WAITFOR DELAY '0:0:5'",
      "SLEEP(5)",
      "pg_sleep(5)",
      "benchmark()",
    ],
    correctAnswer: 0,
    explanation: "WAITFOR DELAY is MSSQL's mechanism for time delays.",
  },
  {
    id: 52,
    topic: "Database",
    question: "To list tables in MySQL, you would query:",
    options: [
      "information_schema.tables",
      "pg_tables",
      "sysobjects",
      "all_tables",
    ],
    correctAnswer: 0,
    explanation: "MySQL uses information_schema for metadata.",
  },
  {
    id: 53,
    topic: "Database",
    question: "PostgreSQL uses which function for time delays?",
    options: [
      "pg_sleep()",
      "SLEEP()",
      "WAITFOR DELAY",
      "DELAY()",
    ],
    correctAnswer: 0,
    explanation: "pg_sleep() is PostgreSQL's delay function.",
  },
  {
    id: 54,
    topic: "Database",
    question: "Oracle string concatenation uses:",
    options: [
      "The || operator",
      "The + operator",
      "CONCAT only",
      "The & operator",
    ],
    correctAnswer: 0,
    explanation: "Oracle uses || for string concatenation.",
  },
  {
    id: 55,
    topic: "Database",
    question: "SQLite metadata is stored in:",
    options: [
      "sqlite_master",
      "information_schema",
      "sysobjects",
      "pg_catalog",
    ],
    correctAnswer: 0,
    explanation: "sqlite_master contains table and schema information.",
  },
  {
    id: 56,
    topic: "Database",
    question: "MSSQL string concatenation uses:",
    options: [
      "The + operator",
      "The || operator",
      "CONCAT only",
      "The & operator",
    ],
    correctAnswer: 0,
    explanation: "MSSQL uses + for string concatenation.",
  },
  {
    id: 57,
    topic: "Database",
    question: "Which database uses -- for single-line comments?",
    options: [
      "All major SQL databases",
      "Only MySQL",
      "Only PostgreSQL",
      "None of them",
    ],
    correctAnswer: 0,
    explanation: "Double-dash comments work across SQL implementations.",
  },
  {
    id: 58,
    topic: "Database",
    question: "MySQL-specific comment syntax includes:",
    options: [
      "# for single-line comments",
      "// for comments",
      "REM for comments",
      "' for comments",
    ],
    correctAnswer: 0,
    explanation: "MySQL uniquely supports # as a comment character.",
  },
  {
    id: 59,
    topic: "Database",
    question: "To get the current user in PostgreSQL:",
    options: [
      "SELECT current_user",
      "SELECT @@user",
      "SELECT USER()",
      "SELECT SUSER_NAME()",
    ],
    correctAnswer: 0,
    explanation: "current_user is the PostgreSQL syntax.",
  },
  // ===== TOOLS (8 questions) =====
  {
    id: 60,
    topic: "Tools",
    question: "SQLMap's --dbs flag is used to:",
    options: [
      "Enumerate available databases",
      "Delete databases",
      "Create backups",
      "Configure SSL",
    ],
    correctAnswer: 0,
    explanation: "--dbs lists all databases accessible through the injection point.",
  },
  {
    id: 61,
    topic: "Tools",
    question: "SQLMap's -r flag is used to:",
    options: [
      "Load a saved HTTP request from a file",
      "Run recursively",
      "Generate reports",
      "Restart the scan",
    ],
    correctAnswer: 0,
    explanation: "The -r flag tests requests saved from Burp or other tools.",
  },
  {
    id: 62,
    topic: "Tools",
    question: "SQLMap tamper scripts are used to:",
    options: [
      "Modify payloads to bypass WAFs",
      "Encrypt database connections",
      "Create backups",
      "Generate documentation",
    ],
    correctAnswer: 0,
    explanation: "Tamper scripts transform payloads to evade filters.",
  },
  {
    id: 63,
    topic: "Tools",
    question: "The --level and --risk options in SQLMap control:",
    options: [
      "Testing depth and aggressiveness",
      "Output formatting",
      "Network bandwidth",
      "File permissions",
    ],
    correctAnswer: 0,
    explanation: "Higher levels test more injection points and payloads.",
  },
  {
    id: 64,
    topic: "Tools",
    question: "OWASP ZAP is:",
    options: [
      "A free web application security scanner",
      "A database backup tool",
      "A code editor",
      "A network monitor",
    ],
    correctAnswer: 0,
    explanation: "ZAP is an open-source alternative to Burp Suite.",
  },
  {
    id: 65,
    topic: "Tools",
    question: "Burp Suite is primarily used for:",
    options: [
      "Intercepting and modifying HTTP requests",
      "Writing SQL queries",
      "Database administration",
      "Network monitoring only",
    ],
    correctAnswer: 0,
    explanation: "Burp Suite is a web security testing proxy.",
  },
  {
    id: 66,
    topic: "Tools",
    question: "SQLMap's --dump flag is used to:",
    options: [
      "Extract data from specified tables",
      "Delete database content",
      "Create database dumps for backup",
      "Analyze query performance",
    ],
    correctAnswer: 0,
    explanation: "--dump extracts data from discovered tables.",
  },
  {
    id: 67,
    topic: "Tools",
    question: "SQLMap's --proxy option is used to:",
    options: [
      "Route traffic through Burp or another proxy",
      "Speed up scanning",
      "Encrypt the connection",
      "Bypass authentication",
    ],
    correctAnswer: 0,
    explanation: "Proxy routing allows traffic inspection and modification.",
  },
  // ===== ADVANCED / WAF BYPASS (8 questions) =====
  {
    id: 68,
    topic: "Advanced",
    question: "What is the purpose of case manipulation in WAF bypass?",
    options: [
      "Evade simple pattern matching filters",
      "Encrypt the payload",
      "Speed up query execution",
      "Compress data",
    ],
    correctAnswer: 0,
    explanation: "Mixed case (SeLeCt) can bypass filters looking for specific patterns.",
  },
  {
    id: 69,
    topic: "Advanced",
    question: "Comment injection (SEL/**/ECT) works because:",
    options: [
      "SQL parsers ignore comments but execute the keywords",
      "It encrypts the query",
      "It creates a stored procedure",
      "It disables logging",
    ],
    correctAnswer: 0,
    explanation: "Comments break up keyword patterns while SQL processes the full statement.",
  },
  {
    id: 70,
    topic: "Advanced",
    question: "Double URL encoding (%2527) is useful when:",
    options: [
      "The application decodes input twice",
      "Using HTTPS",
      "Connecting to MongoDB",
      "Running local queries",
    ],
    correctAnswer: 0,
    explanation: "Multiple decoding passes can restore malicious characters.",
  },
  {
    id: 71,
    topic: "Advanced",
    question: "HTTP Parameter Pollution can bypass WAFs by:",
    options: [
      "Sending duplicate parameters that confuse parsers",
      "Encrypting the request",
      "Using HTTPS",
      "Changing the HTTP method",
    ],
    correctAnswer: 0,
    explanation: "Different components may parse duplicate parameters differently.",
  },
  {
    id: 72,
    topic: "Advanced",
    question: "CHAR(65,66,67) in SQL represents:",
    options: [
      "The string 'ABC' built from ASCII codes",
      "A table name",
      "A numeric calculation",
      "A date format",
    ],
    correctAnswer: 0,
    explanation: "CHAR() builds strings from ASCII values to bypass filters.",
  },
  {
    id: 73,
    topic: "Advanced",
    question: "Null byte injection (%00) can:",
    options: [
      "Terminate strings early in some parsers",
      "Speed up queries",
      "Encrypt payloads",
      "Create database backups",
    ],
    correctAnswer: 0,
    explanation: "Null bytes can confuse string handling in some languages.",
  },
  {
    id: 74,
    topic: "Advanced",
    question: "Using /*! MySQL-specific */ comments allows:",
    options: [
      "Executing code only on MySQL servers",
      "Commenting out all databases",
      "Encrypting queries",
      "Disabling logging",
    ],
    correctAnswer: 0,
    explanation: "MySQL executes content in /*! */ comments, others ignore it.",
  },
  {
    id: 75,
    topic: "Advanced",
    question: "Whitespace alternatives like %09 (tab) can:",
    options: [
      "Bypass filters looking for spaces",
      "Speed up queries",
      "Encrypt the payload",
      "Create indexes",
    ],
    correctAnswer: 0,
    explanation: "SQL treats tabs and newlines as whitespace, but filters may not.",
  },
];

// ========== DATA DEFINITIONS ==========
const sqliTypes = [
  {
    type: "Error-based",
    description: "Database errors leak details about the query or schema.",
    signals: "500 errors, SQL syntax messages, stack traces.",
    risk: "Fast data exposure and easy confirmation.",
    color: "#ef4444",
  },
  {
    type: "Union-based",
    description: "Attacker forces the query to merge extra results.",
    signals: "Unexpected data appearing in responses.",
    risk: "Direct data extraction if output is visible.",
    color: "#f97316",
  },
  {
    type: "Boolean-based (blind)",
    description: "Responses change when a condition is true or false.",
    signals: "Small but consistent response differences.",
    risk: "Slow, but reliable data extraction.",
    color: "#eab308",
  },
  {
    type: "Time-based (blind)",
    description: "The database delays responses to signal true conditions.",
    signals: "Consistent timing delays on specific inputs.",
    risk: "Harder to detect, can still extract data.",
    color: "#22c55e",
  },
  {
    type: "Out-of-band",
    description: "Database makes outbound requests to attacker-controlled systems.",
    signals: "Unexpected DNS or HTTP requests from database servers.",
    risk: "Bypasses normal response channels.",
    color: "#3b82f6",
  },
  {
    type: "Second-order",
    description: "Malicious input is stored first, then used later in a query.",
    signals: "Delayed effects, often in admin views or background jobs.",
    risk: "Harder to trace back to original input.",
    color: "#8b5cf6",
  },
];

const commonPayloads = [
  { category: "Authentication Bypass", payload: "' OR '1'='1", use: "Login forms" },
  { category: "Authentication Bypass", payload: "admin'--", use: "Comment out password check" },
  { category: "Authentication Bypass", payload: "' OR 1=1#", use: "MySQL specific" },
  { category: "Union Select", payload: "' UNION SELECT NULL--", use: "Find number of columns" },
  { category: "Union Select", payload: "' UNION SELECT NULL,NULL,NULL--", use: "Match column count" },
  { category: "Information Gathering", payload: "' UNION SELECT @@version--", use: "Get database version" },
  { category: "Information Gathering", payload: "' UNION SELECT user()--", use: "Get current user" },
  { category: "String Extraction", payload: "' UNION SELECT table_name FROM information_schema.tables--", use: "List tables" },
  { category: "Blind Test", payload: "' AND '1'='1", use: "Boolean true condition" },
  { category: "Blind Test", payload: "' AND '1'='2", use: "Boolean false condition" },
  { category: "Time-Based", payload: "' AND SLEEP(5)--", use: "MySQL time delay" },
  { category: "Time-Based", payload: "'; WAITFOR DELAY '0:0:5'--", use: "MSSQL time delay" },
];

const dbSpecificTechniques = [
  {
    database: "MySQL",
    versionQuery: "SELECT @@version",
    currentUser: "SELECT user(), current_user()",
    listDatabases: "SELECT schema_name FROM information_schema.schemata",
    listTables: "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
    timeBased: "SLEEP(5)",
    comments: "-- comment, # comment, /* comment */",
    stringConcat: "CONCAT(str1, str2)",
    color: "#00758f",
  },
  {
    database: "PostgreSQL",
    versionQuery: "SELECT version()",
    currentUser: "SELECT current_user, session_user",
    listDatabases: "SELECT datname FROM pg_database",
    listTables: "SELECT tablename FROM pg_tables WHERE schemaname='public'",
    timeBased: "pg_sleep(5)",
    comments: "-- comment, /* comment */",
    stringConcat: "string1 || string2",
    color: "#336791",
  },
  {
    database: "MSSQL",
    versionQuery: "SELECT @@version",
    currentUser: "SELECT SYSTEM_USER, USER_NAME()",
    listDatabases: "SELECT name FROM master..sysdatabases",
    listTables: "SELECT name FROM sysobjects WHERE xtype='U'",
    timeBased: "WAITFOR DELAY '0:0:5'",
    comments: "-- comment, /* comment */",
    stringConcat: "str1 + str2",
    color: "#cc2927",
  },
  {
    database: "Oracle",
    versionQuery: "SELECT banner FROM v$version",
    currentUser: "SELECT user FROM dual",
    listDatabases: "SELECT DISTINCT owner FROM all_tables",
    listTables: "SELECT table_name FROM all_tables",
    timeBased: "DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)",
    comments: "-- comment, /* comment */",
    stringConcat: "str1 || str2",
    color: "#f80000",
  },
  {
    database: "SQLite",
    versionQuery: "SELECT sqlite_version()",
    currentUser: "N/A (file-based)",
    listDatabases: "PRAGMA database_list",
    listTables: "SELECT name FROM sqlite_master WHERE type='table'",
    timeBased: "No native sleep",
    comments: "-- comment, /* comment */",
    stringConcat: "str1 || str2",
    color: "#003b57",
  },
];

const caseStudies = [
  {
    name: "Heartland Payment Systems (2008)",
    impact: "130 million credit card numbers stolen",
    technique: "SQL injection in payment processing system",
    lesson: "Even major payment processors can have SQLi vulnerabilities. Defense in depth and network segmentation are critical.",
    cost: "$140 million in fines and remediation",
  },
  {
    name: "Sony PlayStation Network (2011)",
    impact: "77 million user accounts compromised",
    technique: "SQL injection exploited to access user database",
    lesson: "Proper input validation and parameterized queries could have prevented the breach.",
    cost: "$171 million estimated total cost",
  },
  {
    name: "Yahoo Voices (2012)",
    impact: "450,000 plaintext passwords leaked",
    technique: "Union-based SQL injection",
    lesson: "Never store passwords in plaintext. Always use parameterized queries.",
    cost: "Significant reputation damage",
  },
  {
    name: "TalkTalk (2015)",
    impact: "157,000 customer records stolen",
    technique: "SQL injection in legacy web pages",
    lesson: "Legacy systems require security audits. Young attackers can exploit basic SQLi.",
    cost: "$77 million and CEO resignation",
  },
  {
    name: "Equifax (2017)",
    impact: "147 million people's data exposed",
    technique: "Struts vulnerability + SQL access",
    lesson: "Patch management is critical. SQLi can be part of chained attacks.",
    cost: "$1.4 billion in total costs",
  },
];

const preventionChecklist = [
  { item: "Use parameterized queries or prepared statements everywhere", priority: "Critical" },
  { item: "Never build SQL with string concatenation from user input", priority: "Critical" },
  { item: "Validate data types and use allowlists for enums", priority: "High" },
  { item: "Limit database account permissions to required tables", priority: "High" },
  { item: "Avoid exposing SQL errors to end users", priority: "High" },
  { item: "Keep ORM and database drivers up to date", priority: "Medium" },
  { item: "Add logging and alerting for SQL errors and anomalies", priority: "Medium" },
  { item: "Use WAF rules as defense in depth (not primary fix)", priority: "Medium" },
  { item: "Network segmentation to protect database servers", priority: "Medium" },
  { item: "Regular code reviews and SAST scanning", priority: "Medium" },
];

const wafBypassTechniques = [
  { technique: "Case Manipulation", description: "Mix uppercase/lowercase", example: "SeLeCt, uNiOn" },
  { technique: "URL Encoding", description: "Encode characters", example: "%27 for ', %20 for space" },
  { technique: "Double Encoding", description: "Double encode when apps decode twice", example: "%2527 = %27 = '" },
  { technique: "Comment Injection", description: "Use SQL comments to break up keywords", example: "SEL/**/ECT" },
  { technique: "Whitespace Alternatives", description: "Replace spaces with tabs, newlines", example: "SELECT%09*%09FROM" },
  { technique: "Null Byte Injection", description: "Insert null bytes", example: "%00 at strategic positions" },
  { technique: "HTTP Parameter Pollution", description: "Send duplicate parameters", example: "?id=1&id=2' OR '1'='1" },
];

const sqlmapCommands = [
  { command: "sqlmap -u 'http://target.com/page?id=1'", description: "Basic GET parameter test" },
  { command: "sqlmap -u 'http://target.com/page' --data='user=test&pass=test'", description: "POST parameter test" },
  { command: "sqlmap -r request.txt", description: "Test from saved HTTP request file" },
  { command: "sqlmap -u 'URL?id=1' --dbs", description: "Enumerate databases" },
  { command: "sqlmap -u 'URL?id=1' -D dbname --tables", description: "List tables in a database" },
  { command: "sqlmap -u 'URL?id=1' -D db -T table --columns", description: "List columns in a table" },
  { command: "sqlmap -u 'URL?id=1' -D db -T table -C col1,col2 --dump", description: "Dump specific columns" },
  { command: "sqlmap -u 'URL?id=1' --level=5 --risk=3", description: "Maximum testing depth" },
  { command: "sqlmap -u 'URL?id=1' --tamper=space2comment", description: "Apply tamper scripts" },
  { command: "sqlmap -u 'URL?id=1' --proxy='http://127.0.0.1:8080'", description: "Route through proxy" },
];

// ========== MAIN COMPONENT ==========
const SQLInjectionPage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const accent = "#f97316"; // Orange accent color for SQL Injection
  const isMobile = useMediaQuery(theme.breakpoints.down("lg"));

  // Navigation State
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("");

  const pageContext = `SQL Injection (SQLi) - A comprehensive guide covering injection attack types including Union-based SQLi, Blind SQLi (Boolean and Time-based), Error-based SQLi, Out-of-band SQLi. Topics include: query structure, parameter manipulation, authentication bypass, data extraction, second-order injection, stored procedures exploitation, prevention techniques like parameterized queries, prepared statements, input validation, and secure database design patterns.`;

  // Section Navigation Items
  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "how-it-works", label: "How It Works", icon: <CodeIcon /> },
    { id: "sqli-types", label: "Injection Types", icon: <BugReportIcon /> },
    { id: "entry-points", label: "Entry Points", icon: <ApiIcon /> },
    { id: "detection", label: "Detection", icon: <SearchIcon /> },
    { id: "prevention", label: "Prevention", icon: <ShieldIcon /> },
    { id: "secure-code", label: "Secure Code Examples", icon: <LockIcon /> },
    { id: "db-specific", label: "Database Specifics", icon: <StorageIcon /> },
    { id: "payloads", label: "Common Payloads", icon: <DataObjectIcon /> },
    { id: "waf-bypass", label: "WAF Bypass", icon: <TuneIcon /> },
    { id: "tools", label: "SQLMap & Tools", icon: <TerminalIcon /> },
    { id: "case-studies", label: "Case Studies", icon: <HistoryIcon /> },
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

  // Sidebar Navigation Component
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
        "&::-webkit-scrollbar": { width: 6 },
        "&::-webkit-scrollbar-thumb": { bgcolor: alpha(accent, 0.3), borderRadius: 3 },
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
            <Typography variant="caption" color="text.secondary">Progress</Typography>
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
              "& .MuiLinearProgress-bar": { bgcolor: accent, borderRadius: 3 },
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
                "&:hover": { bgcolor: alpha(accent, 0.08) },
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
    <LearnPageLayout pageTitle="SQL Injection (SQLi)" pageContext={pageContext}>
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
            "&:hover": { bgcolor: "#ea580c" },
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

          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">Progress</Typography>
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
                "& .MuiLinearProgress-bar": { bgcolor: accent, borderRadius: 3 },
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
                  bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                  "&:hover": { bgcolor: alpha(accent, 0.1) },
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
                    sx={{ height: 20, fontSize: "0.65rem", bgcolor: alpha(accent, 0.2), color: accent }}
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
          <Container maxWidth="lg" sx={{ py: 0, px: 0 }} id="top">
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
                background: `linear-gradient(135deg, ${alpha(accent, 0.15)} 0%, ${alpha("#f59e0b", 0.1)} 100%)`,
                border: `1px solid ${alpha(accent, 0.2)}`,
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
                  background: `linear-gradient(135deg, ${alpha(accent, 0.1)}, transparent)`,
                }}
              />
              <Box sx={{ display: "flex", alignItems: "center", gap: 3, position: "relative" }}>
                <Box
                  sx={{
                    width: 80,
                    height: 80,
                    borderRadius: 3,
                    background: `linear-gradient(135deg, ${accent}, #f59e0b)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 8px 32px ${alpha(accent, 0.3)}`,
                  }}
                >
                  <StorageIcon sx={{ fontSize: 45, color: "white" }} />
                </Box>
                <Box>
                  <Chip label="Web Security" size="small" sx={{ mb: 1, fontWeight: 600, bgcolor: alpha(accent, 0.1), color: accent }} />
                  <Typography variant="h3" sx={{ fontWeight: 800, mb: 1 }}>
                    SQL Injection (SQLi)
                  </Typography>
                  <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 600 }}>
                    Master database security from fundamentals to advanced techniques
                  </Typography>
                </Box>
              </Box>
            </Paper>

            {/* Warning Alert */}
            <Alert severity="warning" sx={{ mb: 4, borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Defensive Learning Only</AlertTitle>
              Use this material only for authorized testing, CTF challenges, and secure coding education.
              The focus is on prevention, detection, and safe verification techniques.
            </Alert>

            {/* ========== SECTION: INTRODUCTION ========== */}
            <Paper
              id="intro"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                scrollMarginTop: 96,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <InfoIcon sx={{ color: accent }} />
                Introduction to SQL Injection
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                SQL Injection (SQLi) is one of the oldest and most dangerous web application vulnerabilities. It occurs when
                an application builds database queries by concatenating user input directly into SQL commands. The database
                cannot distinguish between the developer's intended query and the attacker's malicious input, so it executes
                the entire string as code.
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                The core problem is simple: <strong>data is treated as code</strong>. When you type a search term into a web form,
                that text should be treated as data. But if the application inserts it directly into a SQL query string,
                an attacker can craft input that changes the query's meaning entirely.
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Consider a login form that checks credentials with this query: <code>SELECT * FROM users WHERE username='$input' AND password='$pass'</code>.
                An attacker entering <code>' OR '1'='1</code> as the username transforms the query into one that always returns true,
                bypassing authentication entirely.
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                SQLi is not just a web problem. APIs, mobile apps, internal dashboards, data pipelines, and any system
                that accepts input and builds SQL queries can be vulnerable. Attackers look for any path that lets them
                influence query structure - search forms, filters, sorting parameters, URL parameters, cookies, and HTTP headers.
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                The fix is not clever filtering or escaping. The real solution is to <strong>keep data and code separate</strong> using
                parameterized queries (prepared statements). When parameters are used, the database understands which parts
                are data and will never execute them as commands. This makes SQLi one of the most preventable vulnerabilities -
                yet it remains in the OWASP Top 10 year after year.
              </Typography>

              <Alert severity="success" sx={{ mt: 3, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>What You'll Learn</AlertTitle>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6} md={3}>
                    <Typography variant="body2">&#8226; How SQLi attacks work</Typography>
                    <Typography variant="body2">&#8226; Different injection types</Typography>
                    <Typography variant="body2">&#8226; Common entry points</Typography>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Typography variant="body2">&#8226; Detection techniques</Typography>
                    <Typography variant="body2">&#8226; Database-specific syntax</Typography>
                    <Typography variant="body2">&#8226; WAF bypass methods</Typography>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Typography variant="body2">&#8226; Prevention strategies</Typography>
                    <Typography variant="body2">&#8226; Secure code patterns</Typography>
                    <Typography variant="body2">&#8226; ORM best practices</Typography>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Typography variant="body2">&#8226; SQLMap usage</Typography>
                    <Typography variant="body2">&#8226; Real-world case studies</Typography>
                    <Typography variant="body2">&#8226; Testing methodologies</Typography>
                  </Grid>
                </Grid>
              </Alert>
            </Paper>

            {/* ========== SECTION: HOW IT WORKS ========== */}
            <Paper
              id="how-it-works"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                scrollMarginTop: 96,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <CodeIcon sx={{ color: accent }} />
                How SQL Injection Works
              </Typography>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                SQL injection exploits the way applications construct database queries. When user input is concatenated
                directly into SQL strings without proper handling, attackers can inject their own SQL code.
              </Typography>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accent }}>
                The Attack Flow
              </Typography>

              <Grid container spacing={2} sx={{ mb: 4 }}>
                {[
                  { step: 1, title: "Input Arrives", desc: "User input comes from a form, URL parameter, header, or API request" },
                  { step: 2, title: "Query Built", desc: "The application concatenates this input into a SQL query string" },
                  { step: 3, title: "Query Executed", desc: "The database receives and executes the full string as SQL code" },
                  { step: 4, title: "Attack Succeeds", desc: "If input changes query meaning, the attacker gains unauthorized access" },
                ].map((item) => (
                  <Grid item xs={12} sm={6} md={3} key={item.step}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(accent, 0.05), borderRadius: 2, height: "100%" }}>
                      <Chip label={`Step ${item.step}`} size="small" sx={{ mb: 1, bgcolor: accent, color: "white" }} />
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>{item.title}</Typography>
                      <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                Vulnerable Code Example
              </Typography>
              <CodeBlock
                language="javascript"
                title="INSECURE: String concatenation"
                code={`// VULNERABLE - Never do this!
const email = req.body.email;
const query = "SELECT * FROM users WHERE email = '" + email + "'";
db.query(query);

// If email = "' OR '1'='1" the query becomes:
// SELECT * FROM users WHERE email = '' OR '1'='1'
// This returns ALL users!`}
              />

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: "#22c55e" }}>
                Secure Code Example
              </Typography>
              <CodeBlock
                language="javascript"
                title="SECURE: Parameterized query"
                code={`// SECURE - Use parameterized queries
const email = req.body.email;
const query = "SELECT * FROM users WHERE email = ?";
db.query(query, [email]);

// The database treats email as DATA, not CODE
// Even if email = "' OR '1'='1", it searches for that literal string`}
              />

              <Alert severity="info" sx={{ mt: 3, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Why Parameterization Works</AlertTitle>
                <List dense>
                  <ListItem><ListItemText primary="The database parses the SQL structure FIRST, before seeing any data" /></ListItem>
                  <ListItem><ListItemText primary="Parameters are sent separately from the SQL command" /></ListItem>
                  <ListItem><ListItemText primary="The database knows parameters are DATA and cannot change query structure" /></ListItem>
                  <ListItem><ListItemText primary="Query plans can be safely cached for better performance" /></ListItem>
                </List>
              </Alert>
            </Paper>

            {/* ========== SECTION: SQLI TYPES ========== */}
            <Paper
              id="sqli-types"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                scrollMarginTop: 96,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: accent }} />
                SQL Injection Types
              </Typography>

              <Typography variant="body1" sx={{ mb: 3 }}>
                SQL injection attacks are categorized based on how data is extracted or how the attack is confirmed.
                Understanding these types helps in both detection and prevention.
              </Typography>

              <Grid container spacing={3}>
                {sqliTypes.map((type) => (
                  <Grid item xs={12} md={6} key={type.type}>
                    <Paper
                      sx={{
                        p: 3,
                        borderRadius: 3,
                        height: "100%",
                        borderLeft: `4px solid ${type.color}`,
                        bgcolor: alpha(type.color, 0.03),
                      }}
                    >
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: type.color }}>
                        {type.type}
                      </Typography>
                      <Typography variant="body2" sx={{ mb: 2 }}>{type.description}</Typography>
                      <Box sx={{ mb: 1 }}>
                        <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary" }}>SIGNALS:</Typography>
                        <Typography variant="body2" color="text.secondary">{type.signals}</Typography>
                      </Box>
                      <Box>
                        <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary" }}>RISK:</Typography>
                        <Typography variant="body2" color="text.secondary">{type.risk}</Typography>
                      </Box>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              <Accordion sx={{ mt: 3, borderRadius: "12px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha(accent, 0.05) }}>
                  <Typography sx={{ fontWeight: 700 }}>Blind SQL Injection Deep Dive</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    Blind SQL injection is used when the application doesn't display query results or database errors directly.
                    Attackers must infer information through indirect signals.
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: alpha("#eab308", 0.05), borderRadius: 2 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#eab308", mb: 1 }}>Boolean-Based</Typography>
                        <Typography variant="body2" sx={{ mb: 1 }}>
                          Send queries that produce different responses for true/false conditions.
                        </Typography>
                        <CodeBlock
                          language="sql"
                          code={`-- True condition (different response)
id=1 AND 1=1

-- False condition (different response)
id=1 AND 1=2

-- Extract data character by character
id=1 AND SUBSTRING(username,1,1)='a'`}
                        />
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Time-Based</Typography>
                        <Typography variant="body2" sx={{ mb: 1 }}>
                          Use database delay functions to confirm injection and extract data.
                        </Typography>
                        <CodeBlock
                          language="sql"
                          code={`-- MySQL: delay 5 seconds if true
id=1 AND SLEEP(5)

-- MSSQL: delay 5 seconds if true
id=1; WAITFOR DELAY '0:0:5'--

-- Extract data via timing
id=1 AND IF(SUBSTRING(user(),1,1)='r',SLEEP(5),0)`}
                        />
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* ========== SECTION: ENTRY POINTS ========== */}
            <Paper
              id="entry-points"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                scrollMarginTop: 96,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <ApiIcon sx={{ color: accent }} />
                Common Entry Points
              </Typography>

              <Typography variant="body1" sx={{ mb: 3 }}>
                SQL injection can occur anywhere user input flows into a database query. These are the most common entry points to audit.
              </Typography>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>High-Risk Entry Points</Typography>
                    <List dense>
                      {[
                        "Login and authentication forms",
                        "Search boxes and filters",
                        "URL query parameters (?id=1, ?sort=name)",
                        "POST body parameters (forms, JSON)",
                        "HTTP headers (User-Agent, Referer, X-Forwarded-For)",
                        "Cookies (session identifiers, preferences)",
                      ].map((item, idx) => (
                        <ListItem key={idx}>
                          <ListItemIcon><WarningIcon sx={{ color: "#ef4444" }} fontSize="small" /></ListItemIcon>
                          <ListItemText primary={item} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>Often Overlooked Vectors</Typography>
                    <List dense>
                      {[
                        "File upload names and metadata",
                        "CSV/Excel import fields",
                        "API endpoints with complex filters",
                        "GraphQL arguments",
                        "Admin panels and internal tools",
                        "Report builders with custom queries",
                      ].map((item, idx) => (
                        <ListItem key={idx}>
                          <ListItemIcon><VisibilityIcon sx={{ color: "#f59e0b" }} fontSize="small" /></ListItemIcon>
                          <ListItemText primary={item} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Alert severity="warning" sx={{ mt: 3, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Second-Order Injection</AlertTitle>
                <Typography variant="body2">
                  Second-order SQLi occurs when malicious input is stored first, then used later in a different query.
                  Example: A username containing SQL is stored during registration, then triggers injection when an admin
                  views the user list. Always parameterize queries even when using data from your own database.
                </Typography>
              </Alert>
            </Paper>

            {/* ========== SECTION: DETECTION ========== */}
            <Paper
              id="detection"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                scrollMarginTop: 96,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <SearchIcon sx={{ color: accent }} />
                Detection & Indicators
              </Typography>

              <Typography variant="body1" sx={{ mb: 3 }}>
                Detecting SQL injection attempts requires monitoring multiple signals across application logs,
                database audit logs, and network traffic.
              </Typography>

              <Grid container spacing={3}>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ef4444", 0.03), height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                      Error Signals
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="SQL syntax error messages in responses" /></ListItem>
                      <ListItem><ListItemText primary="Unexpected 500 errors on specific inputs" /></ListItem>
                      <ListItem><ListItemText primary="Stack traces mentioning database drivers" /></ListItem>
                      <ListItem><ListItemText primary="Database connection timeout spikes" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.03), height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                      Behavioral Signals
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary={`Unusual characters in input (' " -- #)`} /></ListItem>
                      <ListItem><ListItemText primary="Consistent timing delays after certain inputs" /></ListItem>
                      <ListItem><ListItemText primary="Response size changes based on input" /></ListItem>
                      <ListItem><ListItemText primary="Unexpected data appearing in responses" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.03), height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                      Database Signals
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="Queries accessing system tables" /></ListItem>
                      <ListItem><ListItemText primary="UNION SELECT in slow query logs" /></ListItem>
                      <ListItem><ListItemText primary="Unusual outbound DNS/HTTP from DB" /></ListItem>
                      <ListItem><ListItemText primary="Bulk data reads from sensitive tables" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4 }}>
                Database Error Signatures
              </Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Database</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Error Pattern</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {[
                      { db: "MySQL", error: "You have an error in your SQL syntax; near ..." },
                      { db: "PostgreSQL", error: "ERROR: syntax error at or near ..." },
                      { db: "MSSQL", error: "Unclosed quotation mark after the character string" },
                      { db: "Oracle", error: "ORA-01756: quoted string not properly terminated" },
                      { db: "SQLite", error: "SQLite error: near \"...\": syntax error" },
                    ].map((row) => (
                      <TableRow key={row.db}>
                        <TableCell sx={{ fontWeight: 600 }}>{row.db}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.error}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>

            {/* ========== SECTION: PREVENTION ========== */}
            <Paper
              id="prevention"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                scrollMarginTop: 96,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <ShieldIcon sx={{ color: accent }} />
                Prevention Strategies
              </Typography>

              <Typography variant="body1" sx={{ mb: 3 }}>
                SQL injection is preventable with proper coding practices. The key principle is to never trust user input
                and always keep data separate from code.
              </Typography>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                Prevention Checklist
              </Typography>

              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 4 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Priority</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Action Item</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {preventionChecklist.map((item, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Chip
                            label={item.priority}
                            size="small"
                            sx={{
                              bgcolor: item.priority === "Critical" ? alpha("#ef4444", 0.15) :
                                       item.priority === "High" ? alpha("#f59e0b", 0.15) : alpha("#3b82f6", 0.15),
                              color: item.priority === "Critical" ? "#ef4444" :
                                     item.priority === "High" ? "#f59e0b" : "#3b82f6",
                              fontWeight: 600,
                            }}
                          />
                        </TableCell>
                        <TableCell>{item.item}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                      Why Parameterization Works
                    </Typography>
                    <List dense>
                      <ListItem><CheckCircleIcon sx={{ color: "#22c55e", mr: 1 }} fontSize="small" /><ListItemText primary="Database parses SQL structure before seeing data" /></ListItem>
                      <ListItem><CheckCircleIcon sx={{ color: "#22c55e", mr: 1 }} fontSize="small" /><ListItemText primary="Parameters are sent separately from commands" /></ListItem>
                      <ListItem><CheckCircleIcon sx={{ color: "#22c55e", mr: 1 }} fontSize="small" /><ListItemText primary="Parameters treated as typed data, not executable" /></ListItem>
                      <ListItem><CheckCircleIcon sx={{ color: "#22c55e", mr: 1 }} fontSize="small" /><ListItemText primary="Query plans can be safely cached" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                      Why Escaping Is Not Enough
                    </Typography>
                    <List dense>
                      <ListItem><WarningIcon sx={{ color: "#ef4444", mr: 1 }} fontSize="small" /><ListItemText primary="Escaping rules differ across databases" /></ListItem>
                      <ListItem><WarningIcon sx={{ color: "#ef4444", mr: 1 }} fontSize="small" /><ListItemText primary="Doesn't protect non-string contexts (ORDER BY)" /></ListItem>
                      <ListItem><WarningIcon sx={{ color: "#ef4444", mr: 1 }} fontSize="small" /><ListItemText primary="Encoding edge cases can bypass escaping" /></ListItem>
                      <ListItem><WarningIcon sx={{ color: "#ef4444", mr: 1 }} fontSize="small" /><ListItemText primary="Hard to ensure consistent escaping everywhere" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>
            </Paper>

            {/* ========== SECTION: SECURE CODE EXAMPLES ========== */}
            <Paper
              id="secure-code"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                scrollMarginTop: 96,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <LockIcon sx={{ color: accent }} />
                Secure Code Examples
              </Typography>

              <Typography variant="body1" sx={{ mb: 3 }}>
                Here are examples of parameterized queries in popular languages and frameworks.
                Always use these patterns instead of string concatenation.
              </Typography>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <CodeBlock
                    language="python"
                    title="Python (psycopg2)"
                    code={`# SECURE: parameterized query
query = "SELECT * FROM users WHERE email = %s"
cursor.execute(query, (email,))

# SECURE: named parameters
query = "SELECT * FROM users WHERE id = %(user_id)s"
cursor.execute(query, {"user_id": user_id})`}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <CodeBlock
                    language="javascript"
                    title="Node.js (pg)"
                    code={`// SECURE: parameterized query
const query = "SELECT * FROM users WHERE id = $1";
const result = await client.query(query, [userId]);

// Multiple parameters
const query = "SELECT * FROM users WHERE id = $1 AND status = $2";
const result = await client.query(query, [userId, status]);`}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <CodeBlock
                    language="java"
                    title="Java (PreparedStatement)"
                    code={`// SECURE: PreparedStatement
String sql = "SELECT * FROM users WHERE email = ?";
PreparedStatement ps = conn.prepareStatement(sql);
ps.setString(1, email);
ResultSet rs = ps.executeQuery();`}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <CodeBlock
                    language="csharp"
                    title="C# (SqlCommand)"
                    code={`// SECURE: parameterized query
var sql = "SELECT * FROM users WHERE email = @email";
var cmd = new SqlCommand(sql, conn);
cmd.Parameters.AddWithValue("@email", email);
var reader = cmd.ExecuteReader();`}
                  />
                </Grid>
                <Grid item xs={12}>
                  <CodeBlock
                    language="javascript"
                    title="Dynamic Filters (Safe Pattern)"
                    code={`// SECURE: Building dynamic WHERE clauses safely
const filters = [];
const params = [];

if (status) {
  filters.push("status = ?");
  params.push(status);
}

if (ownerId) {
  filters.push("owner_id = ?");
  params.push(ownerId);
}

const whereClause = filters.length ? "WHERE " + filters.join(" AND ") : "";
const sql = "SELECT * FROM tickets " + whereClause + " ORDER BY created_at DESC";
const rows = await db.query(sql, params);`}
                  />
                </Grid>
                <Grid item xs={12}>
                  <CodeBlock
                    language="javascript"
                    title="Safe ORDER BY with Allowlist"
                    code={`// SECURE: Allowlist for dynamic sorting
const allowedColumns = ["name", "created_at", "status", "priority"];
const sortColumn = allowedColumns.includes(sort) ? sort : "created_at";
const sortDir = order === "asc" ? "ASC" : "DESC";

// Column name is from allowlist, not user input
const query = \`SELECT * FROM tickets ORDER BY \${sortColumn} \${sortDir} LIMIT ?\`;
db.query(query, [limit]);`}
                  />
                </Grid>
              </Grid>
            </Paper>

            {/* ========== SECTION: DATABASE SPECIFICS ========== */}
            <Paper
              id="db-specific"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                scrollMarginTop: 96,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <StorageIcon sx={{ color: accent }} />
                Database-Specific Techniques
              </Typography>

              <Typography variant="body1" sx={{ mb: 3 }}>
                Each database system has unique syntax and functions. Understanding these differences is crucial
                for both testing and defense.
              </Typography>

              {dbSpecificTechniques.map((db) => (
                <Accordion key={db.database} sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                  <AccordionSummary
                    expandIcon={<ExpandMoreIcon />}
                    sx={{ background: alpha(db.color, 0.1), borderRadius: 2 }}
                  >
                    <Typography sx={{ fontWeight: 700, color: db.color }}>{db.database}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <Typography variant="caption" sx={{ fontWeight: 700 }}>Version Query</Typography>
                        <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1 }}>{db.versionQuery}</Typography>

                        <Typography variant="caption" sx={{ fontWeight: 700 }}>Current User</Typography>
                        <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1 }}>{db.currentUser}</Typography>

                        <Typography variant="caption" sx={{ fontWeight: 700 }}>List Databases</Typography>
                        <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1, fontSize: "0.75rem" }}>{db.listDatabases}</Typography>
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Typography variant="caption" sx={{ fontWeight: 700 }}>List Tables</Typography>
                        <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1, fontSize: "0.75rem" }}>{db.listTables}</Typography>

                        <Typography variant="caption" sx={{ fontWeight: 700 }}>Time-Based Delay</Typography>
                        <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1 }}>{db.timeBased}</Typography>

                        <Typography variant="caption" sx={{ fontWeight: 700 }}>String Concatenation</Typography>
                        <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1 }}>{db.stringConcat}</Typography>

                        <Typography variant="caption" sx={{ fontWeight: 700 }}>Comments</Typography>
                        <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{db.comments}</Typography>
                      </Grid>
                    </Grid>
                  </AccordionDetails>
                </Accordion>
              ))}
            </Paper>

            {/* ========== SECTION: COMMON PAYLOADS ========== */}
            <Paper
              id="payloads"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                scrollMarginTop: 96,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <DataObjectIcon sx={{ color: accent }} />
                Common Payloads Reference
              </Typography>

              <Alert severity="warning" sx={{ mb: 3, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Educational Use Only</AlertTitle>
                These payloads are for authorized testing, CTF challenges, and understanding attack vectors.
                Never use on systems without explicit permission.
              </Alert>

              <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Payload</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Use Case</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {commonPayloads.map((row, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Chip label={row.category} size="small" sx={{ fontSize: "0.7rem" }} />
                        </TableCell>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.payload}</TableCell>
                        <TableCell sx={{ fontSize: "0.85rem" }}>{row.use}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>

            {/* ========== SECTION: WAF BYPASS ========== */}
            <Paper
              id="waf-bypass"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                scrollMarginTop: 96,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <TuneIcon sx={{ color: accent }} />
                WAF Bypass Techniques
              </Typography>

              <Typography variant="body1" sx={{ mb: 3 }}>
                Web Application Firewalls (WAFs) attempt to block SQL injection by pattern matching.
                Understanding bypass techniques helps in both testing and improving WAF rules.
              </Typography>

              <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Defense Note</AlertTitle>
                WAFs are defense-in-depth, not a primary fix. Proper parameterization is the real solution.
                If an attacker can bypass your WAF, parameterized queries still protect you.
              </Alert>

              <Grid container spacing={2}>
                {wafBypassTechniques.map((tech, idx) => (
                  <Grid item xs={12} sm={6} md={4} key={idx}>
                    <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(accent, 0.03), height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accent, mb: 1 }}>
                        {tech.technique}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        {tech.description}
                      </Typography>
                      <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem", bgcolor: alpha("#000", 0.2), p: 1, borderRadius: 1 }}>
                        {tech.example}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Paper>

            {/* ========== SECTION: TOOLS ========== */}
            <Paper
              id="tools"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                scrollMarginTop: 96,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon sx={{ color: accent }} />
                SQLMap & Testing Tools
              </Typography>

              <Typography variant="body1" sx={{ mb: 3 }}>
                SQLMap is the most popular automated SQL injection testing tool. It can detect and exploit
                SQL injection vulnerabilities, enumerate databases, and extract data.
              </Typography>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                Essential SQLMap Commands
              </Typography>

              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 4 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {sqlmapCommands.map((row, idx) => (
                      <TableRow key={idx}>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{row.command}</TableCell>
                        <TableCell sx={{ fontSize: "0.85rem" }}>{row.description}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                      Other Useful Tools
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="Burp Suite - Intercept and modify requests" secondary="Commercial with free community edition" /></ListItem>
                      <ListItem><ListItemText primary="OWASP ZAP - Free web security scanner" secondary="Open source alternative to Burp" /></ListItem>
                      <ListItem><ListItemText primary="Havij - Automated SQL injection tool" secondary="Point and click interface" /></ListItem>
                      <ListItem><ListItemText primary="jSQL Injection - Java-based SQLi tool" secondary="Cross-platform GUI tool" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                      Common Tamper Scripts
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="space2comment" secondary="Replace spaces with /**/ comments" /></ListItem>
                      <ListItem><ListItemText primary="randomcase" secondary="Random case for SQL keywords" /></ListItem>
                      <ListItem><ListItemText primary="between" secondary="Replace > with BETWEEN" /></ListItem>
                      <ListItem><ListItemText primary="charencode" secondary="URL encode all characters" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>
            </Paper>

            {/* ========== SECTION: CASE STUDIES ========== */}
            <Paper
              id="case-studies"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.6),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                scrollMarginTop: 96,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <HistoryIcon sx={{ color: accent }} />
                Real-World Case Studies
              </Typography>

              <Typography variant="body1" sx={{ mb: 3 }}>
                Learning from major breaches helps understand the real-world impact of SQL injection
                and the importance of proper security measures.
              </Typography>

              <Grid container spacing={3}>
                {caseStudies.map((study, idx) => (
                  <Grid item xs={12} md={6} key={idx}>
                    <Paper
                      sx={{
                        p: 3,
                        borderRadius: 3,
                        height: "100%",
                        bgcolor: alpha("#ef4444", 0.02),
                        borderLeft: `4px solid ${accent}`,
                      }}
                    >
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: accent }}>
                        {study.name}
                      </Typography>
                      <Chip label={study.impact} size="small" sx={{ mb: 2, bgcolor: alpha("#ef4444", 0.15), color: "#ef4444" }} />
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        <strong>Technique:</strong> {study.technique}
                      </Typography>
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        <strong>Cost:</strong> {study.cost}
                      </Typography>
                      <Alert severity="info" sx={{ mt: 2 }}>
                        <Typography variant="body2"><strong>Lesson:</strong> {study.lesson}</Typography>
                      </Alert>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Paper>

            {/* ========== SECTION: QUIZ ========== */}
            <Box id="quiz" sx={{ scrollMarginTop: 96 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
                <QuizIcon sx={{ color: accent, fontSize: 36 }} />
                Test Your Knowledge
              </Typography>
              <QuizSection
                questions={quizQuestions}
                questionsPerQuiz={QUIZ_QUESTION_COUNT}
                accentColor={QUIZ_ACCENT_COLOR}
              />
            </Box>

          </Container>
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default SQLInjectionPage;
