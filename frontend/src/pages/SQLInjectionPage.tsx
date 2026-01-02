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
  alpha,
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
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

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
        border: "1px solid rgba(249, 115, 22, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#f97316", color: "#0b1020" }} />
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

const SQLInjectionPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `SQL Injection (SQLi) - A comprehensive guide covering injection attack types including Union-based SQLi, Blind SQLi (Boolean and Time-based), Error-based SQLi, Out-of-band SQLi. Topics include: query structure, parameter manipulation, authentication bypass, data extraction, second-order injection, stored procedures exploitation, prevention techniques like parameterized queries, prepared statements, input validation, and secure database design patterns.`;

  const objectives = [
    "Explain SQL Injection (SQLi) in plain language.",
    "Identify where SQLi happens in real applications.",
    "Recognize common patterns and symptoms.",
    "Learn how to prevent SQLi with secure query design.",
    "Practice safe, defensive verification steps in a lab.",
  ];
  const beginnerPath = [
    "1) Read the short story explanation and glossary.",
    "2) Learn how SQL queries are built and executed.",
    "3) Review SQLi types and common entry points.",
    "4) Study detection signals and how to triage them.",
    "5) Apply the prevention checklist and code examples.",
  ];
  const keyIdeas = [
    "SQLi happens when user input is mixed into SQL commands as text.",
    "Attackers abuse database trust to read, change, or delete data.",
    "The safest fix is parameterized queries, not filtering.",
    "Defense in depth includes least privilege and monitoring.",
  ];
  const glossary = [
    { term: "SQL", desc: "Language used to query and modify databases." },
    { term: "Query", desc: "A command sent to the database to get or change data." },
    { term: "Parameter", desc: "A placeholder value supplied safely to a query." },
    { term: "Prepared statement", desc: "A query compiled first, with data inserted later." },
    { term: "Escaping", desc: "Replacing special characters to reduce risk; not enough alone." },
    { term: "Least privilege", desc: "Give the database account only the access it needs." },
  ];
  const misconceptions = [
    {
      myth: "SQLi only affects login forms.",
      reality: "Any input that becomes part of a query can be vulnerable.",
    },
    {
      myth: "Input validation alone stops SQLi.",
      reality: "Validation helps, but parameterization is the real fix.",
    },
    {
      myth: "Only web apps are at risk.",
      reality: "APIs, mobile apps, and internal tools can also be vulnerable.",
    },
  ];
  const parameterizationBenefits = [
    "The database parses the SQL once and locks the structure.",
    "Parameters are sent separately from the SQL text.",
    "Parameters are treated as typed data, not executable code.",
    "Query plans can be cached safely for performance.",
  ];
  const escapingLimitations = [
    "Escaping rules differ across databases and drivers.",
    "It does not protect non-string contexts like ORDER BY.",
    "Encoding edge cases can weaken escaping rules.",
    "It is difficult to ensure consistent escaping everywhere.",
  ];
  const commonPitfalls = [
    "String interpolation in WHERE clauses.",
    "Building IN lists by joining raw input values.",
    "Dynamic ORDER BY or LIMIT built from request parameters.",
    "Query fragments assembled from multiple sources.",
    "Raw SQL inside ORM helpers without parameters.",
    "Verbose SQL errors returned to users.",
  ];

  const flowSteps = [
    "User input arrives from a form, URL, or API request.",
    "The app builds a SQL query by combining strings.",
    "The database executes that full string as code.",
    "If input changes the query meaning, SQLi occurs.",
  ];
  const trustBoundaries = [
    "Inputs from browsers, mobile apps, or external APIs.",
    "Data pulled from other systems that could be manipulated.",
    "Search, filter, or sort parameters in analytics tools.",
    "Admin panels that assume data is trusted.",
  ];
  const entryPoints = [
    "Query parameters (search, filter, sort, page).",
    "Form fields (login, profile, contact).",
    "JSON bodies (API requests).",
    "Cookies and headers (locale, theme, tokens).",
    "File imports or CSV uploads.",
  ];
  const riskFactors = [
    "String concatenation or template building for SQL.",
    "Dynamic ORDER BY or LIMIT built directly from user input.",
    "Using raw SQL with an ORM without parameterization.",
    "Using database accounts with broad permissions.",
    "Verbose error messages shown to users.",
  ];
  const featureHotspots = [
    "Search bars and advanced filtering.",
    "Reporting and analytics dashboards.",
    "Admin panels with custom query builders.",
    "CSV import or export tools.",
    "Notification or rule engines that query data.",
    "Debug endpoints or temporary admin tools.",
  ];
  const riskyQueryShapes = [
    "WHERE clauses assembled with optional filters.",
    "Sorting or pagination fields built from user input.",
    "Bulk updates based on user-controlled IDs.",
    "Multi-tenant queries missing strict tenant scoping.",
    "Stored procedures that concatenate input strings.",
  ];
  const contextSafeguards = [
    {
      context: "Filtering",
      risk: "String concatenation in WHERE clauses.",
      safer: "Use parameters for values and allowlists for enums.",
    },
    {
      context: "Sorting",
      risk: "Dynamic column names from user input.",
      safer: "Allowlist valid columns and map inputs to names.",
    },
    {
      context: "Search",
      risk: "Wildcard handling changes query meaning.",
      safer: "Escape wildcards and parameterize the search value.",
    },
    {
      context: "Batch IDs",
      risk: "IN list built by joining strings.",
      safer: "Use driver support for array parameters.",
    },
    {
      context: "Reports",
      risk: "Ad hoc queries assembled at runtime.",
      safer: "Use predefined query templates with parameters.",
    },
  ];
  const queryContexts = [
    {
      context: "String values",
      risk: "Quotes plus concatenation can alter predicates.",
      safer: "Always parameterize values.",
    },
    {
      context: "Numeric values",
      risk: "Numbers can still become expressions when concatenated.",
      safer: "Use parameters and validate numeric ranges.",
    },
    {
      context: "Identifiers (columns/tables)",
      risk: "Identifiers cannot be parameterized safely.",
      safer: "Use allowlists and map inputs to known names.",
    },
    {
      context: "IN lists",
      risk: "Joined lists enable injection and parsing errors.",
      safer: "Use array parameters or repeated placeholders.",
    },
    {
      context: "LIKE search",
      risk: "Wildcards can change query meaning.",
      safer: "Escape wildcards and parameterize the search value.",
    },
    {
      context: "JSON or array fields",
      risk: "String-building JSON paths can be abused.",
      safer: "Use driver operators with bound values.",
    },
  ];

  const sqliTypes = [
    {
      type: "Error-based",
      description: "Database errors leak details about the query or schema.",
      signals: "500 errors, SQL syntax messages, stack traces.",
      risk: "Fast data exposure and easy confirmation.",
    },
    {
      type: "Union-based",
      description: "Attacker forces the query to merge extra results.",
      signals: "Unexpected data appearing in responses.",
      risk: "Direct data extraction if output is visible.",
    },
    {
      type: "Boolean-based (blind)",
      description: "Responses change when a condition is true or false.",
      signals: "Small but consistent response differences.",
      risk: "Slow, but reliable data extraction.",
    },
    {
      type: "Time-based (blind)",
      description: "The database delays responses to signal true conditions.",
      signals: "Consistent timing delays on specific inputs.",
      risk: "Harder to detect, can still extract data.",
    },
    {
      type: "Out-of-band",
      description: "Database makes outbound requests to attacker-controlled systems.",
      signals: "Unexpected DNS or HTTP requests from database servers.",
      risk: "Bypasses normal response channels.",
    },
  ];
  const secondOrderNotes = [
    "Malicious input is stored first, then used later in a query without parameters.",
    "Often appears in admin views, exports, analytics, or background jobs.",
    "Treat stored data as untrusted and parameterize every query that uses it.",
  ];

  const impactAreas = [
    "Data exposure (PII, credentials, financial records).",
    "Authentication bypass or privilege escalation.",
    "Data tampering (modifying or deleting records).",
    "Service disruption or corrupted datasets.",
    "Regulatory and compliance impact.",
  ];
  const detectionSignals = [
    "Repeated SQL errors or stack traces in logs.",
    "Requests that include unusual characters or patterns.",
    "Unexpected spikes in 500 errors on specific endpoints.",
    "Slow queries or timeouts on input-heavy endpoints.",
    "Database account performing unusual queries or scans.",
  ];
  const falsePositiveChecks = [
    "Was there a recent deploy or schema change?",
    "Did a traffic spike or crawler hit the endpoint?",
    "Are users submitting malformed input by accident?",
    "Do errors correlate with a new client or integration?",
  ];
  const telemetrySources = [
    "Application logs with query errors and stack traces.",
    "Database audit logs and slow query logs.",
    "WAF or API gateway alerts for injection patterns.",
    "SIEM correlation across app and DB events.",
    "Code scanning results from SAST tools.",
  ];
  const errorSignatures = [
    { db: "MySQL", examples: "You have an error in your SQL syntax; near ..." },
    { db: "PostgreSQL", examples: "ERROR: syntax error at or near ..." },
    { db: "MSSQL", examples: "Unclosed quotation mark after the character string" },
    { db: "Oracle", examples: "ORA-01756: quoted string not properly terminated" },
    { db: "SQLite", examples: "SQLite error: near \"...\": syntax error" },
  ];
  const baselineMetrics = [
    {
      metric: "SQL error rate",
      normal: "Low and stable for each endpoint.",
      investigate: "Sudden rise tied to specific inputs.",
    },
    {
      metric: "Slow query count",
      normal: "Stable within expected traffic patterns.",
      investigate: "Spikes after new feature or endpoint.",
    },
    {
      metric: "DB permissions usage",
      normal: "CRUD operations limited to app tables.",
      investigate: "Access to admin/system tables.",
    },
  ];
  const triageSteps = [
    "Confirm the endpoint and parameter involved.",
    "Check recent code changes to the query.",
    "Review error logs and stack traces for clues.",
    "Validate whether the query is parameterized.",
    "Check the database account permissions.",
  ];
  const responseSteps = [
    "Disable the vulnerable endpoint if impact is severe.",
    "Ship a hotfix with parameterized queries.",
    "Rotate database credentials if exposure is suspected.",
    "Review logs for data access and confirm scope.",
    "Document the incident and add regression tests.",
  ];

  const preventionChecklist = [
    "Use parameterized queries or prepared statements everywhere.",
    "Never build SQL with string concatenation from user input.",
    "Validate data types and use allowlists for enums.",
    "Limit database account permissions to required tables.",
    "Avoid exposing SQL errors to end users.",
    "Keep ORM and database drivers up to date.",
    "Add logging and alerting for SQL errors and anomalies.",
  ];
  const secureQueryPrinciples = [
    "Keep SQL structure static and pass user data as parameters.",
    "Use allowlists for any dynamic identifiers.",
    "Separate query building from request parsing.",
    "Fail closed on unknown or invalid inputs.",
  ];
  const ormGuidance = [
    "Use ORM query builders that parameterize by default.",
    "Avoid raw SQL unless parameters are required.",
    "Treat dynamic filters as data, not SQL fragments.",
    "Centralize query helpers to reduce copy-paste mistakes.",
  ];
  const dbRoleTable = [
    {
      role: "App runtime",
      permissions: "Read and write only required tables.",
      notes: "No admin or schema changes.",
    },
    {
      role: "Read-only reporting",
      permissions: "SELECT only on approved views.",
      notes: "Use for dashboards and exports.",
    },
    {
      role: "Migration",
      permissions: "Schema change permissions.",
      notes: "Use only in CI/CD or controlled tooling.",
    },
  ];
  const defenseInDepth = [
    "Input validation and normalization for expected formats.",
    "Stored procedures with strict parameter usage.",
    "WAF or API gateway rules to catch obvious probes.",
    "Database firewall or query allowlisting where possible.",
    "Network segmentation to protect database servers.",
  ];
  const tenantSafeguards = [
    "Always enforce tenant_id in every query and join.",
    "Prefer row-level security or scoped database views.",
    "Avoid accepting tenant_id directly from untrusted clients.",
    "Add tests that verify tenant isolation on common queries.",
  ];

  const insecureExample = `// Insecure: user input is concatenated into SQL
const query = "SELECT * FROM users WHERE email = '" + email + "'";
db.query(query);`;
  const secureExample = `// Secure: parameterized query
const query = "SELECT * FROM users WHERE email = ?";
db.query(query, [email]);`;
  const allowlistExample = `// Secure: allowlist for ORDER BY
const allowedSort = ["name", "created_at", "status"];
const sortColumn = allowedSort.includes(sort) ? sort : "created_at";
const query = "SELECT * FROM tickets ORDER BY " + sortColumn + " LIMIT ?";
db.query(query, [limit]);`;
  const safeQueryBuilderExample = `// Safe dynamic filters using parameters
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
const rows = await db.query(sql, params);`;

  const codeSamples = [
    {
      label: "Python (psycopg2)",
      language: "python",
      code: `query = "SELECT * FROM users WHERE email = %s"
cursor.execute(query, (email,))`,
    },
    {
      label: "Node.js (pg)",
      language: "javascript",
      code: `const query = "SELECT * FROM users WHERE id = $1";
const result = await client.query(query, [userId]);`,
    },
    {
      label: "Java (PreparedStatement)",
      language: "java",
      code: `String sql = "SELECT * FROM users WHERE email = ?";
PreparedStatement ps = conn.prepareStatement(sql);
ps.setString(1, email);
ResultSet rs = ps.executeQuery();`,
    },
    {
      label: "C# (SqlCommand)",
      language: "csharp",
      code: `var sql = "SELECT * FROM users WHERE email = @email";
var cmd = new SqlCommand(sql, conn);
cmd.Parameters.AddWithValue("@email", email);
var reader = cmd.ExecuteReader();`,
    },
    {
      label: "PHP (PDO)",
      language: "php",
      code: `$stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
$stmt->execute([":email" => $email]);`,
    },
  ];

  const labSteps = [
    "Use a local demo app and a disposable database.",
    "Identify where user input is used in SQL.",
    "Confirm parameterized queries are used end to end.",
    "Turn off verbose SQL errors in UI responses.",
    "Record baseline error rates and slow queries.",
  ];
  const labExercises = [
    "Inspect one endpoint and trace input to query.",
    "List all queries that use string concatenation.",
    "Verify database account permissions for the app.",
    "Add a log entry when query errors occur.",
  ];
  const codeReviewChecklist = [
    "Find all places that build SQL strings.",
    "Confirm parameters are used for values.",
    "Review any dynamic identifiers (ORDER BY, table names).",
    "Check for multi-tenant scoping in every query.",
    "Verify errors are logged but not shown to users.",
  ];
  const codeReviewCommands = `# Find raw SQL usage
rg -n \"SELECT|INSERT|UPDATE|DELETE\" src

# Look for concatenation around SQL keywords
rg -n \"SELECT.*\\+|\\+.*SELECT\" src`;
  const verificationChecklist = [
    "All queries use parameters, not string concatenation.",
    "Dynamic sorting uses allowlists, not raw input.",
    "SQL errors are logged but not shown to users.",
    "App DB account cannot access admin/system tables.",
    "Unit tests cover query builders and inputs.",
  ];
  const safeBoundaries = [
    "Only test in a lab or with written authorization.",
    "Do not attempt exploitation on production systems.",
    "Avoid destructive queries or payloads.",
    "Focus on detection, prevention, and secure code review.",
  ];
  const QUIZ_QUESTION_COUNT = 10;
  const QUIZ_ACCENT_COLOR = "#f97316";
  const quizQuestions: QuizQuestion[] = [
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
      question: "Least privilege for the database account means:",
      options: [
        "Use admin for all queries",
        "Grant only required permissions",
        "Disable logging",
        "Share credentials across services",
      ],
      correctAnswer: 1,
      explanation: "Limiting permissions reduces the damage from a compromise.",
    },
    {
      id: 7,
      topic: "Fundamentals",
      question: "SQL injection can happen in:",
      options: [
        "Only login forms",
        "Any input that reaches a query",
        "Only URLs",
        "Only cookies",
      ],
      correctAnswer: 1,
      explanation: "Any input that becomes part of a query can be a vector.",
    },
    {
      id: 8,
      topic: "Fundamentals",
      question: "A prepared statement:",
      options: [
        "Executes multiple statements at once",
        "Separates SQL structure from data with placeholders",
        "Is the same as escaping",
        "Disables indexes",
      ],
      correctAnswer: 1,
      explanation: "Prepared statements bind values instead of concatenating them.",
    },
    {
      id: 9,
      topic: "Fundamentals",
      question: "Second-order SQL injection is when:",
      options: [
        "Errors are hidden",
        "Stored input is later used in an unsafe query",
        "A query runs twice",
        "Only numeric fields are affected",
      ],
      correctAnswer: 1,
      explanation: "Stored data can still be untrusted when reused in queries.",
    },
    {
      id: 10,
      topic: "Fundamentals",
      question: "Which is NOT a SQL injection type?",
      options: [
        "Union-based",
        "Error-based",
        "Cross-site scripting",
        "Time-based blind",
      ],
      correctAnswer: 2,
      explanation: "Cross-site scripting is a different class of vulnerability.",
    },
    {
      id: 11,
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
      id: 12,
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
      id: 13,
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
      id: 14,
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
      id: 15,
      topic: "Injection Types",
      question: "Out-of-band SQL injection uses:",
      options: [
        "Local error messages",
        "External DNS/HTTP callbacks",
        "Only client-side code",
        "Browser storage",
      ],
      correctAnswer: 1,
      explanation: "The database calls out to an attacker-controlled host.",
    },
    {
      id: 16,
      topic: "Injection Types",
      question: "Stacked queries allow an attacker to:",
      options: [
        "Run multiple SQL statements in one request",
        "Read cookies",
        "Bypass TLS",
        "Modify HTML only",
      ],
      correctAnswer: 0,
      explanation: "Multiple statements can execute sequentially.",
    },
    {
      id: 17,
      topic: "Injection Types",
      question: "Stacked queries usually require:",
      options: [
        "Multiple statements enabled by the driver or server",
        "A UNION clause",
        "A view",
        "No semicolons",
      ],
      correctAnswer: 0,
      explanation: "Many drivers disable multi-statement execution by default.",
    },
    {
      id: 18,
      topic: "Injection Types",
      question: "A login bypass using ' OR '1'='1 is an example of:",
      options: [
        "Tautology-based injection",
        "Out-of-band injection",
        "Hash collision",
        "CSRF",
      ],
      correctAnswer: 0,
      explanation: "The condition is always true, bypassing checks.",
    },
    {
      id: 19,
      topic: "Injection Types",
      question: "Which SQLi type is hardest to confirm with visible output?",
      options: [
        "Error-based",
        "Union-based",
        "Blind",
        "Inline",
      ],
      correctAnswer: 2,
      explanation: "Blind SQLi requires inference from timing or subtle changes.",
    },
    {
      id: 20,
      topic: "Injection Types",
      question: "Second-order SQL injection most often appears in:",
      options: [
        "Admin panels or exports that reuse stored input",
        "Static landing pages",
        "CDN caches",
        "Client-only apps",
      ],
      correctAnswer: 0,
      explanation: "Stored input can become dangerous when used later.",
    },
    {
      id: 21,
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
      id: 22,
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
      id: 23,
      topic: "Detection",
      question: "Consistent delays after SLEEP(5) indicate:",
      options: [
        "Time-based blind SQL injection",
        "Rate limiting",
        "DNS caching",
        "TLS renegotiation",
      ],
      correctAnswer: 0,
      explanation: "Timing changes signal true/false evaluation in blind SQLi.",
    },
    {
      id: 24,
      topic: "Detection",
      question: "Which log is most useful for SQL injection triage?",
      options: [
        "Database error or audit logs",
        "Browser cache",
        "CSS files",
        "Image CDN logs only",
      ],
      correctAnswer: 0,
      explanation: "Database and app logs show the real query failures.",
    },
    {
      id: 25,
      topic: "Detection",
      question: "Outbound DNS lookups from a database host are a sign of:",
      options: [
        "Out-of-band SQL injection testing",
        "Normal backups",
        "User login",
        "Static content delivery",
      ],
      correctAnswer: 0,
      explanation: "OOB attacks use DNS or HTTP callbacks for confirmation.",
    },
    {
      id: 26,
      topic: "Detection",
      question: "A sudden spike in slow queries on one endpoint can mean:",
      options: [
        "Injection probes or heavy scans",
        "New CSS load",
        "Static asset optimization",
        "No issue",
      ],
      correctAnswer: 0,
      explanation: "Attackers often cause slow queries with time-based payloads.",
    },
    {
      id: 27,
      topic: "Detection",
      question: "A response that grows only when OR 1=1 is added suggests:",
      options: [
        "Boolean-based SQL injection",
        "CSRF",
        "JWT validation",
        "CORS issue",
      ],
      correctAnswer: 0,
      explanation: "A true condition increases results in boolean-based SQLi.",
    },
    {
      id: 28,
      topic: "Detection",
      question: "Which is a false positive to rule out first?",
      options: [
        "Recent deploy or schema change",
        "Any SQL error",
        "Any slow query",
        "Any 200 response",
      ],
      correctAnswer: 0,
      explanation: "Changes in code or schema can explain new errors.",
    },
    {
      id: 29,
      topic: "Detection",
      question: "Which signal is least likely to indicate SQL injection?",
      options: [
        "SQL syntax errors in responses",
        "Unexpected table names in logs",
        "Static asset 304 responses",
        "Time delays after SQL functions",
      ],
      correctAnswer: 2,
      explanation: "Static asset caching is unrelated to SQL injection.",
    },
    {
      id: 30,
      topic: "Detection",
      question: "First step in SQL injection triage is to:",
      options: [
        "Identify the endpoint and parameter",
        "Drop the database",
        "Disable TLS",
        "Ignore logs",
      ],
      correctAnswer: 0,
      explanation: "You need the exact entry point before investigating.",
    },
    {
      id: 31,
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
      id: 32,
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
      id: 33,
      topic: "Prevention",
      question: "ORMs reduce SQL injection risk only if you:",
      options: [
        "Avoid raw string concatenation",
        "Disable parameters",
        "Use admin DB accounts",
        "Return errors to users",
      ],
      correctAnswer: 0,
      explanation: "Raw SQL bypasses the ORM safety mechanisms.",
    },
    {
      id: 34,
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
      id: 35,
      topic: "Prevention",
      question: "For IN lists, a safe approach is:",
      options: [
        "Use array parameters or repeated placeholders",
        "Join strings with commas",
        "Trust JSON",
        "Disable validation",
      ],
      correctAnswer: 0,
      explanation: "Binding each value avoids injection in lists.",
    },
    {
      id: 36,
      topic: "Prevention",
      question: "Stored procedures are safe when they:",
      options: [
        "Use parameters and avoid dynamic SQL",
        "Concatenate strings",
        "Run as admin",
        "Return raw errors",
      ],
      correctAnswer: 0,
      explanation: "Dynamic SQL inside procedures can still be injectable.",
    },
    {
      id: 37,
      topic: "Prevention",
      question: "Hide SQL error details from users because:",
      options: [
        "They leak schema and query structure",
        "They slow the UI",
        "They break TLS",
        "They block cookies",
      ],
      correctAnswer: 0,
      explanation: "Detailed errors help attackers craft payloads.",
    },
    {
      id: 38,
      topic: "Prevention",
      question: "Input validation helps by:",
      options: [
        "Enforcing expected formats and types",
        "Replacing parameterization",
        "Adding encryption",
        "Disabling logs",
      ],
      correctAnswer: 0,
      explanation: "Validation reduces attack surface but does not stop SQLi alone.",
    },
    {
      id: 39,
      topic: "Prevention",
      question: "Which query is safest?",
      options: [
        "SELECT * FROM users WHERE id = ?",
        "SELECT * FROM users WHERE id = <user input>",
        "SELECT * FROM users WHERE <filter>",
        "SELECT * FROM users ORDER BY <user input>",
      ],
      correctAnswer: 0,
      explanation: "The safe query uses parameters instead of string concatenation.",
    },
    {
      id: 40,
      topic: "Prevention",
      question: "Dynamic table names should be:",
      options: [
        "Chosen from a strict allowlist",
        "Taken from user input",
        "Built with string replace",
        "Ignored",
      ],
      correctAnswer: 0,
      explanation: "Identifiers cannot be safely parameterized without an allowlist.",
    },
    {
      id: 41,
      topic: "Prevention",
      question: "Least privilege limits damage by:",
      options: [
        "Restricting accessible tables and actions",
        "Increasing permissions",
        "Disabling auditing",
        "Sharing credentials",
      ],
      correctAnswer: 0,
      explanation: "Lower privileges reduce the blast radius of a compromise.",
    },
    {
      id: 42,
      topic: "Prevention",
      question: "Query builders help because they:",
      options: [
        "Centralize parameterization and reduce string concatenation",
        "Disable indexes",
        "Avoid validation",
        "Require admin access",
      ],
      correctAnswer: 0,
      explanation: "Builders produce parameterized queries consistently.",
    },
    {
      id: 43,
      topic: "Prevention",
      question: "A safe way to handle LIMIT is to:",
      options: [
        "Validate numeric range and bind it",
        "Concatenate user input",
        "Allow any string",
        "Use UNION",
      ],
      correctAnswer: 0,
      explanation: "Validation and parameters prevent numeric injection tricks.",
    },
    {
      id: 44,
      topic: "Prevention",
      question: "WAF rules are best described as:",
      options: [
        "Defense in depth, not the primary fix",
        "A complete replacement for parameterization",
        "Only for logging",
        "A database feature",
      ],
      correctAnswer: 0,
      explanation: "WAFs help detect and block, but code fixes are required.",
    },
    {
      id: 45,
      topic: "Prevention",
      question: "Prepared statements protect against:",
      options: [
        "Injection in values, not in identifiers",
        "All SQLi including dynamic table names",
        "XSS only",
        "CSRF only",
      ],
      correctAnswer: 0,
      explanation: "Identifiers still need allowlists and safe mappings.",
    },
    {
      id: 46,
      topic: "Query Contexts",
      question: "SQL injection can still happen with numeric input because:",
      options: [
        "Concatenation allows expressions like 1 OR 1=1",
        "Numbers are always safe",
        "Databases ignore numbers",
        "Numeric input is encrypted",
      ],
      correctAnswer: 0,
      explanation: "Numbers can still change logic when concatenated.",
    },
    {
      id: 47,
      topic: "Query Contexts",
      question: "ORDER BY from user input is risky because:",
      options: [
        "Identifiers cannot be parameterized",
        "It is always safe",
        "It disables indexes",
        "It is ignored by the DB",
      ],
      correctAnswer: 0,
      explanation: "Only allowlisted identifiers should be used.",
    },
    {
      id: 48,
      topic: "Query Contexts",
      question: "LIKE searches are risky when:",
      options: [
        "Wildcards are not escaped and input is concatenated",
        "Parameters are used",
        "Only fixed strings are used",
        "Indexes exist",
      ],
      correctAnswer: 0,
      explanation: "Unescaped wildcards can alter the intended search logic.",
    },
    {
      id: 49,
      topic: "Query Contexts",
      question: "Multi-tenant queries must always:",
      options: [
        "Enforce tenant_id scoping",
        "Use admin accounts",
        "Disable indexes",
        "Return all tenants",
      ],
      correctAnswer: 0,
      explanation: "Tenant scoping prevents cross-tenant data access.",
    },
    {
      id: 50,
      topic: "Query Contexts",
      question: "CSV imports can lead to SQL injection when:",
      options: [
        "Stored data is later used in unsafe queries",
        "Files are compressed",
        "Headers are missing",
        "Encoding is UTF-8",
      ],
      correctAnswer: 0,
      explanation: "Second-order SQLi often starts with stored data.",
    },
    {
      id: 51,
      topic: "Query Contexts",
      question: "Safe dynamic filters are built by:",
      options: [
        "Collecting parameterized fragments and binding values",
        "Concatenating raw SQL",
        "Disabling validation",
        "Using eval",
      ],
      correctAnswer: 0,
      explanation: "Build the WHERE clause with placeholders and bound values.",
    },
    {
      id: 52,
      topic: "Query Contexts",
      question: "A report builder is risky when it:",
      options: [
        "Concatenates user-defined filters into SQL",
        "Uses predefined templates",
        "Uses parameters",
        "Limits output",
      ],
      correctAnswer: 0,
      explanation: "Ad hoc filters are a common source of injection.",
    },
    {
      id: 53,
      topic: "Query Contexts",
      question: "Dynamic column selection should use:",
      options: [
        "Allowlisted mappings",
        "User input directly",
        "Regex replaces",
        "Random columns",
      ],
      correctAnswer: 0,
      explanation: "Map user choices to known safe identifiers.",
    },
    {
      id: 54,
      topic: "Query Contexts",
      question: "The statement WHERE name = '<user input>' is:",
      options: [
        "Vulnerable to SQL injection",
        "Safe because of quotes",
        "Safe in all databases",
        "A prepared statement",
      ],
      correctAnswer: 0,
      explanation: "Concatenation creates an injection point.",
    },
    {
      id: 55,
      topic: "Query Contexts",
      question: "JSON path input should be:",
      options: [
        "Allowlisted or mapped to safe paths",
        "Concatenated directly",
        "Ignored",
        "Only base64 encoded",
      ],
      correctAnswer: 0,
      explanation: "Dynamic paths can be abused without strict control.",
    },
    {
      id: 56,
      topic: "Query Contexts",
      question: "Using ORM .where(\"id = \" + id) is:",
      options: [
        "Vulnerable",
        "Safe because ORM is used",
        "Equivalent to parameters",
        "Recommended",
      ],
      correctAnswer: 0,
      explanation: "String concatenation defeats ORM protections.",
    },
    {
      id: 57,
      topic: "Query Contexts",
      question: "If the DB user has DROP privileges, SQLi impact includes:",
      options: [
        "Data destruction",
        "Only read access",
        "UI glitches",
        "Cache invalidation",
      ],
      correctAnswer: 0,
      explanation: "Elevated privileges allow destructive statements.",
    },
    {
      id: 58,
      topic: "Query Contexts",
      question: "Second-order SQL injection is prevented by:",
      options: [
        "Parameterizing queries even for stored data",
        "Only validating on input",
        "Disabling indexes",
        "Using GET requests",
      ],
      correctAnswer: 0,
      explanation: "Stored data must be treated as untrusted.",
    },
    {
      id: 59,
      topic: "Query Contexts",
      question: "Which area often hides SQL injection?",
      options: [
        "Admin analytics with ad hoc filters",
        "Static help pages",
        "Image CDN",
        "Client-only apps",
      ],
      correctAnswer: 0,
      explanation: "Reporting and analytics commonly build dynamic SQL.",
    },
    {
      id: 60,
      topic: "Query Contexts",
      question: "SQL injection in stored procedures occurs when they:",
      options: [
        "Build dynamic SQL with concatenation",
        "Use fixed parameters",
        "Use typed parameters only",
        "Run in read-only mode",
      ],
      correctAnswer: 0,
      explanation: "Dynamic SQL inside procedures can still be injectable.",
    },
    {
      id: 61,
      topic: "Hardening",
      question: "After fixing SQL injection, the best validation is to:",
      options: [
        "Add regression tests for query paths",
        "Delete logs",
        "Disable monitoring",
        "Hide endpoints",
      ],
      correctAnswer: 0,
      explanation: "Tests confirm the fix and prevent regressions.",
    },
    {
      id: 62,
      topic: "Hardening",
      question: "Monitoring should alert on:",
      options: [
        "SQL errors and unusual query patterns",
        "Normal 200 responses",
        "Static asset cache hits",
        "CSS changes",
      ],
      correctAnswer: 0,
      explanation: "Error and anomaly detection helps spot active attacks.",
    },
    {
      id: 63,
      topic: "Hardening",
      question: "Rotating DB credentials after an incident helps:",
      options: [
        "Limit exposure from leaked credentials",
        "Increase privileges",
        "Disable TLS",
        "Slow queries",
      ],
      correctAnswer: 0,
      explanation: "Rotation cuts off attackers using stolen credentials.",
    },
    {
      id: 64,
      topic: "Hardening",
      question: "Read-only accounts are best for:",
      options: [
        "Reporting endpoints",
        "Schema migrations",
        "Admin tooling",
        "User management",
      ],
      correctAnswer: 0,
      explanation: "Read-only access reduces risk in reporting paths.",
    },
    {
      id: 65,
      topic: "Hardening",
      question: "Network segmentation helps by:",
      options: [
        "Limiting access to database servers",
        "Speeding up queries",
        "Disabling encryption",
        "Removing firewalls",
      ],
      correctAnswer: 0,
      explanation: "Segmentation reduces exposure to untrusted networks.",
    },
    {
      id: 66,
      topic: "Hardening",
      question: "Keeping drivers and ORMs updated helps because:",
      options: [
        "Security fixes and safer defaults",
        "It removes parameters",
        "It disables logging",
        "It breaks TLS",
      ],
      correctAnswer: 0,
      explanation: "Updates reduce vulnerabilities and improve safety.",
    },
    {
      id: 67,
      topic: "Hardening",
      question: "Logs should avoid:",
      options: [
        "Leaking secrets or full raw queries to users",
        "Capturing errors",
        "Capturing timings",
        "Capturing audit events",
      ],
      correctAnswer: 0,
      explanation: "Logs should be safe and not expose sensitive data.",
    },
    {
      id: 68,
      topic: "Hardening",
      question: "A safe proof of SQL injection is to:",
      options: [
        "Use non-destructive boolean or time-based checks",
        "Drop tables",
        "Dump all data",
        "Disable backups",
      ],
      correctAnswer: 0,
      explanation: "Safe testing demonstrates risk without harm.",
    },
    {
      id: 69,
      topic: "Hardening",
      question: "Which is NOT safe during testing?",
      options: [
        "DELETE FROM users",
        "Using a harmless sleep delay",
        "Testing in a sandbox",
        "Using least privilege",
      ],
      correctAnswer: 0,
      explanation: "Destructive queries should never be used in safe testing.",
    },
    {
      id: 70,
      topic: "Hardening",
      question: "Code scanning should look for:",
      options: [
        "String concatenation around SQL keywords",
        "Only CSS files",
        "Only images",
        "TLS certificates",
      ],
      correctAnswer: 0,
      explanation: "Concatenated SQL is a common source of injection.",
    },
    {
      id: 71,
      topic: "Hardening",
      question: "After patching, you should:",
      options: [
        "Verify all query paths are parameterized",
        "Remove validation",
        "Turn off logging",
        "Use admin accounts",
      ],
      correctAnswer: 0,
      explanation: "Verification ensures the fix is complete and consistent.",
    },
    {
      id: 72,
      topic: "Hardening",
      question: "Rate limiting helps by:",
      options: [
        "Slowing automated injection attempts",
        "Preventing all SQL injection",
        "Encrypting queries",
        "Hiding errors",
      ],
      correctAnswer: 0,
      explanation: "Rate limiting is a defense-in-depth control.",
    },
    {
      id: 73,
      topic: "Hardening",
      question: "Database audit logs are useful to:",
      options: [
        "Detect unusual query access and scanning",
        "Style the UI",
        "Compress images",
        "Generate CSS",
      ],
      correctAnswer: 0,
      explanation: "Audit logs show who accessed what data and when.",
    },
    {
      id: 74,
      topic: "Hardening",
      question: "When implementing pagination, you should:",
      options: [
        "Validate page size and bind parameters",
        "Concatenate raw input",
        "Allow any string",
        "Use UNION",
      ],
      correctAnswer: 0,
      explanation: "Validation and parameters prevent misuse of limits.",
    },
    {
      id: 75,
      topic: "Hardening",
      question: "Best long-term control against SQL injection is:",
      options: [
        "Consistent parameterization plus code review",
        "Blacklists only",
        "Security by obscurity",
        "Disabling logs",
      ],
      correctAnswer: 0,
      explanation: "A consistent secure pattern plus review prevents regressions.",
    },
  ];

  return (
    <LearnPageLayout pageTitle="SQL Injection (SQLi)" pageContext={pageContext}>
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
          <StorageIcon sx={{ fontSize: 42, color: "#f97316" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #f97316 0%, #f59e0b 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            SQL Injection (SQLi)
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          A beginner-friendly deep dive into how SQLi works, how to detect it, and how to fix it.
        </Typography>

        <Alert severity="warning" sx={{ mb: 3 }}>
          <AlertTitle>Defensive Learning Only</AlertTitle>
          Use this material only for authorized testing and secure coding. The focus here is prevention,
          detection, and safe verification.
        </Alert>

        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            SQL Injection happens when an application builds a database query by stitching together raw user
            input and SQL commands. The database cannot tell the difference between the developer's intended
            instructions and the user-supplied text, so it executes the whole string as code. That is the core
            problem: data is treated like instructions.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            Imagine a form where you type a name to search a customer list. If the app simply inserts your
            input into the SQL string, a malicious input could change the meaning of the query. Instead of
            searching for a name, it might request data the app never meant to expose. The database will
            happily obey because it only sees a final SQL command.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            The fix is not clever filtering. The fix is to keep data and code separate by using parameterized
            queries or prepared statements. When parameters are used, the database understands which parts are
            data and will not execute them as commands. This makes SQLi one of the most preventable but still
            common vulnerabilities.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            SQLi is not just a web problem. Any system that accepts input and builds SQL can be affected:
            APIs, mobile apps, internal dashboards, and data pipelines. Attackers look for any path that
            lets them influence query structure, especially around search, filters, and reporting.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            Modern frameworks help, but they are not magic. ORMs can be misused when developers drop down to
            raw SQL or build dynamic clauses. The safest approach is consistent, standardized query patterns
            and clear rules for which parts of a query are allowed to change.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            This guide explains SQLi with simple examples, shows where it hides in real systems, and gives a
            practical checklist for prevention, detection, and safe verification.
          </Typography>
        </Paper>

        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<StorageIcon />} label="Database" size="small" />
          <Chip icon={<BugReportIcon />} label="Injection" size="small" />
          <Chip icon={<SearchIcon />} label="Detection" size="small" />
          <Chip icon={<ShieldIcon />} label="Prevention" size="small" />
          <Chip icon={<CodeIcon />} label="Secure Queries" size="small" />
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
              "& .Mui-selected": { color: "#f97316" },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Overview" />
            <Tab icon={<CodeIcon />} label="How It Happens" />
            <Tab icon={<StorageIcon />} label="Types and Entry Points" />
            <Tab icon={<SearchIcon />} label="Impact and Detection" />
            <Tab icon={<ShieldIcon />} label="Prevention and Fixes" />
            <Tab icon={<BuildIcon />} label="Safe Lab" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Quick Glossary
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#f59e0b" }}>Term</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Meaning</TableCell>
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
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
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
                          border: "1px solid rgba(249, 115, 22, 0.25)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#f97316", mb: 1 }}>
                          Myth
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>
                          {item.myth}
                        </Typography>
                        <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 0.5 }}>
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
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
                  How SQL Injection Happens
                </Typography>
                <List dense>
                  {flowSteps.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
                  Trust Boundaries to Watch
                </Typography>
                <List dense>
                  {trustBoundaries.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Why Parameterization Works
                </Typography>
                <List dense>
                  {parameterizationBenefits.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Why Escaping Alone Is Not Enough
                </Typography>
                <List dense>
                  {escapingLimitations.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
                  Common SQLi Pitfalls
                </Typography>
                <List dense>
                  {commonPitfalls.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  SQL Contexts to Handle Safely
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#f59e0b" }}>Context</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Risk</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Safer Handling</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {queryContexts.map((item) => (
                        <TableRow key={item.context}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.context}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.risk}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.safer}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Unsafe vs Safe Query Building
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400" }}>
                  The unsafe pattern combines SQL and user input into one string. The safe pattern uses parameters
                  so the database treats input only as data.
                </Typography>
                <CodeBlock code={insecureExample} language="javascript" />
                <CodeBlock code={secureExample} language="javascript" />
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Safe Dynamic Sorting
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400" }}>
                  Some SQL parts cannot be parameterized (like column names). Use allowlists instead of raw input.
                </Typography>
                <CodeBlock code={allowlistExample} language="javascript" />
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
                  SQL Injection Types (High Level)
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#f59e0b" }}>Type</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Description</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Signals</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Risk</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {sqliTypes.map((item) => (
                        <TableRow key={item.type}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.type}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.description}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.signals}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.risk}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Second-Order SQL Injection
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                  Second-order SQLi happens when untrusted input is stored safely at first, but later reused in a
                  different query without parameters. It is easy to miss because the vulnerable query might live in
                  a separate workflow or admin feature.
                </Typography>
                <List dense>
                  {secondOrderNotes.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                    <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
                      Common Entry Points
                    </Typography>
                    <List dense>
                      {entryPoints.map((item) => (
                        <ListItem key={item}>
                          <ListItemIcon>
                            <SearchIcon color="info" fontSize="small" />
                          </ListItemIcon>
                          <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                    <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
                      Risk Factors
                    </Typography>
                    <List dense>
                      {riskFactors.map((item) => (
                        <ListItem key={item}>
                          <ListItemIcon>
                            <WarningIcon color="warning" fontSize="small" />
                          </ListItemIcon>
                          <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              </Grid>

              <Paper sx={{ p: 2.5, mt: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
                  Feature Hotspots
                </Typography>
                <List dense>
                  {featureHotspots.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <SearchIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mt: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Risky Query Shapes
                </Typography>
                <List dense>
                  {riskyQueryShapes.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mt: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Context Safeguards
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#f59e0b" }}>Context</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Risk</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Safer Approach</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {contextSafeguards.map((item) => (
                        <TableRow key={item.context}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.context}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.risk}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.safer}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
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

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  False Positives to Rule Out
                </Typography>
                <List dense>
                  {falsePositiveChecks.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Common Error Signatures
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#f59e0b" }}>Database</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Example Error</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {errorSignatures.map((item) => (
                        <TableRow key={item.db}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.db}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.examples}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Baseline Metrics
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#f59e0b" }}>Metric</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Normal</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Investigate When</TableCell>
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
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Secure Query Principles
                </Typography>
                <List dense>
                  {secureQueryPrinciples.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Defense in Depth
                </Typography>
                <List dense>
                  {defenseInDepth.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <ShieldIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  ORM Guidance
                </Typography>
                <List dense>
                  {ormGuidance.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Safe Dynamic Query Builder Pattern
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400" }}>
                  Build optional filters by collecting query fragments and binding every value as a parameter.
                  Avoid stitching user input into the SQL string directly.
                </Typography>
                <CodeBlock code={safeQueryBuilderExample} language="javascript" />
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Database Role Separation
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#f59e0b" }}>Role</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Permissions</TableCell>
                        <TableCell sx={{ color: "#f59e0b" }}>Notes</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dbRoleTable.map((item) => (
                        <TableRow key={item.role}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.role}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.permissions}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.notes}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Tenant Isolation Safeguards
                </Typography>
                <List dense>
                  {tenantSafeguards.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <LockIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Secure Coding Examples
                </Typography>
                {codeSamples.map((sample) => (
                  <Accordion key={sample.label} sx={{ bgcolor: "#0f1422", borderRadius: 2, mb: 1 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">{sample.label}</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock code={sample.code} language={sample.language} />
                    </AccordionDetails>
                  </Accordion>
                ))}
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
                  Extra Hardening Tips
                </Typography>
                <List dense>
                  {[
                    "Use read-only database accounts for reporting endpoints.",
                    "Separate write and read workloads with different credentials.",
                    "Audit any raw SQL usage in ORM codebases.",
                    "Rotate DB credentials and monitor unused accounts.",
                    "Add unit tests for query builders and filters.",
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
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
                  Mini Exercises
                </Typography>
                <List dense>
                  {labExercises.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 1 }}>
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
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
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
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: "#0f1422",
            border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
            Knowledge Check
          </Typography>
          <QuizSection
            questions={quizQuestions}
            accentColor={QUIZ_ACCENT_COLOR}
            title="SQL Injection Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
        </Paper>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#f97316", color: "#f97316" }}
          >
            Back to Learning Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default SQLInjectionPage;
