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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  alpha,
  useTheme,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CodeIcon from "@mui/icons-material/Code";
import WarningIcon from "@mui/icons-material/Warning";
import WebIcon from "@mui/icons-material/Web";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import SearchIcon from "@mui/icons-material/Search";
import ShieldIcon from "@mui/icons-material/Shield";
import QuizIcon from "@mui/icons-material/Quiz";
import { Link, useNavigate } from "react-router-dom";

interface XSSType {
  title: string;
  description: string;
  persistence: string;
  color: string;
}

const CodeBlock: React.FC<{ code: string; language?: string }> = ({
  code,
  language = "javascript",
}) => {
  return (
    <Paper
      sx={{
        p: 2,
        bgcolor: "#0f1422",
        borderRadius: 2,
        border: "1px solid rgba(245, 158, 11, 0.2)",
      }}
    >
      <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: alpha("#f59e0b", 0.2), color: "#f59e0b" }} />
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          overflow: "auto",
          fontFamily: "monospace",
          fontSize: "0.85rem",
          color: "grey.200",
          lineHeight: 1.6,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const xssTypes: XSSType[] = [
  { title: "Reflected XSS", description: "Payload in URL/request, reflected back in response", persistence: "Non-persistent", color: "#f59e0b" },
  { title: "Stored XSS", description: "Payload saved in database, executes for all users", persistence: "Persistent", color: "#ef4444" },
  { title: "DOM-Based XSS", description: "Payload manipulates DOM directly via client-side JS", persistence: "Client-side", color: "#8b5cf6" },
];

const xssFlow = [
  "Untrusted input enters the app (URL, form, API, or stored data).",
  "The app inserts that input into the page without proper encoding.",
  "The browser interprets the input as HTML or JavaScript.",
  "The injected code runs with the site's permissions.",
  "The attacker can read data or perform actions as the user.",
];

const entryPoints = [
  "Search, filter, and sort parameters in URLs",
  "Comment fields, profile bios, and support tickets",
  "Markdown or rich text editors",
  "File names and metadata rendered in the UI",
  "JSON values rendered into templates",
  "Single-page app routes using URL fragments",
];

const highRiskFeatures = [
  "User-generated content feeds",
  "Admin dashboards with custom queries or notes",
  "Preview pages or content moderation queues",
  "Notifications and email template previews",
  "Analytics dashboards with custom filters",
];

const domSources = [
  "location.search, location.hash, location.pathname",
  "document.cookie (if not HttpOnly)",
  "localStorage and sessionStorage",
  "postMessage event data",
  "document.referrer",
  "window.name or injected JSON blobs",
];

const safeDomPractices = [
  "Prefer textContent or innerText over innerHTML",
  "Use createElement + appendChild for DOM building",
  "Sanitize HTML with DOMPurify before insertion",
  "Validate URL schemes before setting href or src",
  "Avoid eval or new Function for dynamic code",
];

const commonPayloads = [
  { payload: "<script>alert(1)</script>", context: "Basic test" },
  { payload: "<img src=x onerror=alert(1)>", context: "Event handler" },
  { payload: "<svg onload=alert(1)>", context: "SVG element" },
  { payload: "javascript:alert(1)", context: "URL scheme" },
  { payload: "'-alert(1)-'", context: "Attribute breakout" },
  { payload: "</script><script>alert(1)</script>", context: "Tag escape" },
  { payload: "\"><img src=x onerror=alert(1)>", context: "Quote escape" },
  { payload: "<a href=javascript:alert(1)>link</a>", context: "Link injection" },
];

const impactScenarios = [
  "Session hijacking (steal cookies)",
  "Keylogging user input",
  "Phishing via page modification",
  "Cryptocurrency mining",
  "Malware distribution",
  "Credential theft via fake login forms",
];

const preventionMethods = [
  "Context-aware output encoding (HTML, JS, URL, CSS)",
  "Content Security Policy (CSP) headers",
  "HttpOnly and Secure cookie flags",
  "Input validation (whitelist allowed chars)",
  "Use frameworks with auto-escaping (React, Angular)",
  "Sanitize HTML with DOMPurify or similar",
];

const dangerousSinks = [
  "innerHTML, outerHTML",
  "insertAdjacentHTML",
  "document.write()",
  "eval(), setTimeout(), setInterval()",
  "new Function()",
  "location.href, location.assign()",
  "setAttribute with untrusted href or src",
  "jQuery .html(), .append()",
];

const encodingContexts = [
  { context: "HTML body", risk: "Injected tags become real elements", safe: "Use HTML encoding or textContent" },
  { context: "HTML attribute", risk: "Quote breaking or event handler injection", safe: "Attribute encoding + allowlists" },
  { context: "URL", risk: "javascript: or data: schemes", safe: "Validate scheme with URL API" },
  { context: "JavaScript string", risk: "Break out of quotes", safe: "Avoid inline JS, use data attributes" },
  { context: "CSS", risk: "url() or expression injection", safe: "Avoid dynamic CSS or allowlist values" },
  { context: "JSON in HTML", risk: "Script breakouts in templates", safe: "Use JSON.stringify and escape safely" },
];

const detectionSignals = [
  "Unexpected HTML tags rendered in user content",
  "CSP reports blocking inline scripts",
  "WAF alerts for script or event handler patterns",
  "DOM changes after input is rendered",
  "User reports of popups or page tampering",
];

const testingChecklist = [
  "Map all input fields and where they render",
  "Identify the output context (HTML, attribute, URL, JS, CSS)",
  "Verify if output is encoded or sanitized",
  "Inspect the DOM in dev tools, not only the response",
  "Review client-side code for unsafe sinks",
  "Confirm CSP behavior in Report-Only mode",
];

const cspGuidelines = [
  "Start with default-src 'self' and add sources slowly",
  "Use nonces or hashes for scripts instead of unsafe-inline",
  "Avoid unsafe-eval unless absolutely required",
  "Set object-src 'none' and base-uri 'none'",
  "Enable Report-Only before enforcing blocking",
];

const responseSteps = [
  "Fix output encoding in the vulnerable context",
  "Remove or refactor unsafe DOM sinks",
  "Add a CSP policy and validate coverage",
  "Rotate sessions if exposure is suspected",
  "Add regression tests for the vulnerable view",
];

const frameworkNotes = [
  "React escapes by default; avoid dangerouslySetInnerHTML without sanitization.",
  "Angular sanitizes templates; avoid bypassSecurityTrust unless required.",
  "Vue escapes by default; v-html requires sanitization.",
  "Template engines with auto-escape can be bypassed with unsafe flags.",
];

const codeSamples = [
  {
    title: "Unsafe DOM injection",
    language: "javascript",
    code: `// Bad: user input becomes HTML
const input = location.hash.slice(1);
element.innerHTML = input;`,
  },
  {
    title: "Safe text rendering",
    language: "javascript",
    code: `// Good: user input becomes plain text
const input = location.hash.slice(1);
element.textContent = input;`,
  },
  {
    title: "Safe URL handling",
    language: "javascript",
    code: `const url = new URL(input, window.location.origin);
const allowed = ["http:", "https:"];
link.href = allowed.includes(url.protocol) ? url.href : "#";`,
  },
  {
    title: "React safe rendering",
    language: "jsx",
    code: `// Safe: React escapes by default
return <div>{comment}</div>;

// Risky: only use with sanitizer
return <div dangerouslySetInnerHTML={{ __html: comment }} />;`,
  },
  {
    title: "Sanitize rich HTML",
    language: "javascript",
    code: `import DOMPurify from "dompurify";
element.innerHTML = DOMPurify.sanitize(html);`,
  },
];

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#ef4444";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "XSS stands for:",
    options: ["Cross-Site Scripting", "Cross-Site Security", "Cross-Session Scripting", "Cross-Server Syncing"],
    correctAnswer: 0,
    explanation: "XSS is short for Cross-Site Scripting.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "XSS allows attackers to:",
    options: ["Run script in a victim's browser", "Bypass TLS", "Escalate OS kernel privileges", "Disable firewalls"],
    correctAnswer: 0,
    explanation: "XSS executes attacker-controlled script in the victim context.",
  },
  {
    id: 3,
    topic: "Types",
    question: "Reflected XSS occurs when:",
    options: ["Input is reflected in a response and executed", "Payload is stored on the server", "Only the DOM is affected", "No user interaction is required"],
    correctAnswer: 0,
    explanation: "Reflected XSS is immediate and request/response based.",
  },
  {
    id: 4,
    topic: "Types",
    question: "Stored XSS occurs when:",
    options: ["Payload is persisted and served to users later", "The payload only lives in the URL", "Only the browser cache is used", "The payload is blocked by default"],
    correctAnswer: 0,
    explanation: "Stored XSS is persisted in a database or storage.",
  },
  {
    id: 5,
    topic: "Types",
    question: "DOM-based XSS occurs when:",
    options: ["Client-side code writes unsafe data into the DOM", "The server stores the payload", "Only a WAF is bypassed", "A CSP header is missing"],
    correctAnswer: 0,
    explanation: "DOM XSS happens entirely in client-side code.",
  },
  {
    id: 6,
    topic: "Impact",
    question: "A common impact of XSS is:",
    options: ["Session theft and account takeover", "Disk encryption", "Router compromise", "Kernel panic"],
    correctAnswer: 0,
    explanation: "XSS can steal tokens or act as the victim user.",
  },
  {
    id: 7,
    topic: "Impact",
    question: "XSS can be used to:",
    options: ["Perform actions as the victim", "Bypass TLS certificates", "Disable DNSSEC", "Patch applications"],
    correctAnswer: 0,
    explanation: "Scripts run with the victim's browser privileges.",
  },
  {
    id: 8,
    topic: "Impact",
    question: "Stored XSS is often more severe because:",
    options: ["It can affect many users who view the content", "It never executes", "It requires no permissions", "It only targets admins"],
    correctAnswer: 0,
    explanation: "Stored payloads execute for every viewer.",
  },
  {
    id: 9,
    topic: "Sinks",
    question: "Which is a dangerous sink for untrusted input?",
    options: ["innerHTML", "textContent", "createTextNode", "appendChild with text"],
    correctAnswer: 0,
    explanation: "innerHTML parses and executes HTML.",
  },
  {
    id: 10,
    topic: "Sinks",
    question: "A safer alternative to innerHTML is:",
    options: ["textContent", "document.write", "eval", "outerHTML"],
    correctAnswer: 0,
    explanation: "textContent inserts text without HTML parsing.",
  },
  {
    id: 11,
    topic: "Sinks",
    question: "document.write is dangerous because it:",
    options: ["Parses HTML from untrusted input", "Encrypts output", "Validates input automatically", "Escapes by default"],
    correctAnswer: 0,
    explanation: "document.write injects raw HTML.",
  },
  {
    id: 12,
    topic: "Sinks",
    question: "Using eval on untrusted input can lead to:",
    options: ["XSS or code execution in the browser", "Safer parsing", "Automatic escaping", "Input validation"],
    correctAnswer: 0,
    explanation: "eval executes attacker-controlled code.",
  },
  {
    id: 13,
    topic: "Sinks",
    question: "Which is a common DOM XSS sink?",
    options: ["insertAdjacentHTML", "textContent", "appendChild", "setAttribute with fixed values"],
    correctAnswer: 0,
    explanation: "insertAdjacentHTML parses HTML and scripts.",
  },
  {
    id: 14,
    topic: "Sources",
    question: "Which is a common DOM XSS source?",
    options: ["location.hash", "Math.random()", "Date.now()", "console.log()"],
    correctAnswer: 0,
    explanation: "location.* values are user-controlled.",
  },
  {
    id: 15,
    topic: "Sources",
    question: "Another common DOM XSS source is:",
    options: ["document.URL", "document.title", "navigator.platform", "screen.width"],
    correctAnswer: 0,
    explanation: "document.URL can contain user input.",
  },
  {
    id: 16,
    topic: "Sources",
    question: "document.referrer is risky because it:",
    options: ["May contain attacker-controlled data", "Is always empty", "Is always trusted", "Is encrypted"],
    correctAnswer: 0,
    explanation: "Referrer can be set by external pages.",
  },
  {
    id: 17,
    topic: "Contexts",
    question: "Output encoding must be:",
    options: ["Context-specific", "Always the same", "Skipped for JSON", "Used only on input"],
    correctAnswer: 0,
    explanation: "HTML, JS, URL, and CSS contexts differ.",
  },
  {
    id: 18,
    topic: "Contexts",
    question: "HTML body context should use:",
    options: ["HTML entity encoding", "URL encoding", "Base64 only", "No encoding"],
    correctAnswer: 0,
    explanation: "HTML entity encoding is correct for body text.",
  },
  {
    id: 19,
    topic: "Contexts",
    question: "URL components should use:",
    options: ["encodeURIComponent", "HTML encoding", "No encoding", "Base64 only"],
    correctAnswer: 0,
    explanation: "encodeURIComponent is for URL components.",
  },
  {
    id: 20,
    topic: "Contexts",
    question: "JavaScript string context requires:",
    options: ["Escaping quotes and backslashes", "Only HTML encoding", "Only URL encoding", "No encoding"],
    correctAnswer: 0,
    explanation: "JS strings need JS-specific escaping.",
  },
  {
    id: 21,
    topic: "Contexts",
    question: "Attribute context requires:",
    options: ["Escaping quotes and special characters", "Only URL encoding", "No encoding", "Only base64"],
    correctAnswer: 0,
    explanation: "Attribute values must be properly escaped.",
  },
  {
    id: 22,
    topic: "Mitigation",
    question: "The primary defense against XSS is:",
    options: ["Output encoding/escaping", "Only input validation", "Only WAFs", "Only logging"],
    correctAnswer: 0,
    explanation: "Proper output encoding prevents script execution.",
  },
  {
    id: 23,
    topic: "Mitigation",
    question: "Input validation alone is:",
    options: ["Not sufficient to prevent XSS", "Always sufficient", "The only defense needed", "More important than encoding"],
    correctAnswer: 0,
    explanation: "Validation helps but output encoding is required.",
  },
  {
    id: 24,
    topic: "Mitigation",
    question: "A Content Security Policy (CSP) helps by:",
    options: ["Restricting where scripts can load from", "Encoding output", "Validating input", "Disabling JavaScript"],
    correctAnswer: 0,
    explanation: "CSP limits script sources and execution.",
  },
  {
    id: 25,
    topic: "Mitigation",
    question: "A strong CSP usually avoids:",
    options: ["unsafe-inline", "script-src 'self'", "object-src 'none'", "nonce-based policies"],
    correctAnswer: 0,
    explanation: "unsafe-inline weakens CSP protections.",
  },
  {
    id: 26,
    topic: "Mitigation",
    question: "CSP nonces should be:",
    options: ["Random per response", "Static and reused", "Hard-coded", "Publicly documented"],
    correctAnswer: 0,
    explanation: "Nonces must be unpredictable to be effective.",
  },
  {
    id: 27,
    topic: "Mitigation",
    question: "CSP hash-based policies allow:",
    options: ["Specific inline scripts by hash", "All inline scripts", "All external scripts", "No scripts at all"],
    correctAnswer: 0,
    explanation: "Hashes allow only matching inline scripts.",
  },
  {
    id: 28,
    topic: "Cookies",
    question: "HttpOnly cookies:",
    options: ["Cannot be read by JavaScript", "Prevent all XSS", "Encrypt the cookie", "Disable sessions"],
    correctAnswer: 0,
    explanation: "HttpOnly blocks JS access to cookies.",
  },
  {
    id: 29,
    topic: "Cookies",
    question: "HttpOnly does not prevent XSS because:",
    options: ["Attackers can still act as the user in the browser", "It disables cookies", "It blocks all requests", "It encodes input"],
    correctAnswer: 0,
    explanation: "XSS can still perform actions without reading cookies.",
  },
  {
    id: 30,
    topic: "Headers",
    question: "The X-XSS-Protection header is:",
    options: ["Deprecated and not reliable", "Required in all browsers", "A complete fix", "A replacement for CSP"],
    correctAnswer: 0,
    explanation: "Modern browsers have deprecated this header.",
  },
  {
    id: 31,
    topic: "Headers",
    question: "CSP report-only mode is used to:",
    options: ["Test policies without breaking pages", "Block all scripts", "Enable unsafe-inline", "Disable logging"],
    correctAnswer: 0,
    explanation: "Report-only helps evaluate a CSP safely.",
  },
  {
    id: 32,
    topic: "Frameworks",
    question: "Template engines that auto-escape:",
    options: ["Reduce XSS risk by default", "Eliminate need for encoding", "Make XSS impossible", "Disable JavaScript"],
    correctAnswer: 0,
    explanation: "Auto-escaping helps but context matters.",
  },
  {
    id: 33,
    topic: "Frameworks",
    question: "React's dangerouslySetInnerHTML is risky because it:",
    options: ["Injects raw HTML into the DOM", "Sanitizes automatically", "Escapes by default", "Blocks scripts"],
    correctAnswer: 0,
    explanation: "It bypasses React's built-in escaping.",
  },
  {
    id: 34,
    topic: "Frameworks",
    question: "Using a sanitizer like DOMPurify helps by:",
    options: ["Removing dangerous HTML and attributes", "Encrypting input", "Skipping encoding", "Adding scripts"],
    correctAnswer: 0,
    explanation: "Sanitizers remove risky markup and attributes.",
  },
  {
    id: 35,
    topic: "Frameworks",
    question: "Allowlist-based sanitization is:",
    options: ["Safer than a denylist", "Less safe than a denylist", "Equivalent always", "Not recommended"],
    correctAnswer: 0,
    explanation: "Allowlists reduce unknown dangerous elements.",
  },
  {
    id: 36,
    topic: "Payloads",
    question: "A basic XSS test payload is:",
    options: ["<script>alert(1)</script>", "SELECT * FROM users", "127.0.0.1", "DROP TABLE"],
    correctAnswer: 0,
    explanation: "A simple alert payload is common for testing.",
  },
  {
    id: 37,
    topic: "Payloads",
    question: "Event handler attributes like onclick are:",
    options: ["Common XSS vectors", "Always safe", "Blocked by HTML", "Only for CSS"],
    correctAnswer: 0,
    explanation: "Event handlers execute JavaScript.",
  },
  {
    id: 38,
    topic: "Payloads",
    question: "A javascript: URL can cause:",
    options: ["Script execution when clicked", "TLS errors only", "Safe navigation only", "No effect"],
    correctAnswer: 0,
    explanation: "javascript: URLs execute code in the browser.",
  },
  {
    id: 39,
    topic: "Payloads",
    question: "SVG files can be risky because they:",
    options: ["Can contain script and event handlers", "Are always safe images", "Cannot run scripts", "Are text-only"],
    correctAnswer: 0,
    explanation: "SVG supports scripting and events.",
  },
  {
    id: 40,
    topic: "Payloads",
    question: "Markdown renderers are risky when they:",
    options: ["Allow raw HTML without sanitization", "Only render text", "Escape HTML by default", "Disable links"],
    correctAnswer: 0,
    explanation: "Raw HTML in Markdown can enable XSS.",
  },
  {
    id: 41,
    topic: "Contexts",
    question: "Encoding must happen:",
    options: ["At the point of output", "Only at input", "Only in the database", "Only in the browser"],
    correctAnswer: 0,
    explanation: "Output encoding should be applied when rendering.",
  },
  {
    id: 42,
    topic: "Contexts",
    question: "Double-encoding user input can:",
    options: ["Break rendering and create bypasses", "Always improve safety", "Prevent XSS", "Encrypt data"],
    correctAnswer: 0,
    explanation: "Improper encoding order can cause issues.",
  },
  {
    id: 43,
    topic: "DOM",
    question: "Writing location.hash directly to innerHTML is:",
    options: ["A DOM XSS vulnerability", "Always safe", "Only a logging issue", "Required for routing"],
    correctAnswer: 0,
    explanation: "location.hash is attacker-controlled.",
  },
  {
    id: 44,
    topic: "DOM",
    question: "Using textContent with location.hash is:",
    options: ["Safer than innerHTML", "More dangerous", "Equivalent to eval", "A CSP violation"],
    correctAnswer: 0,
    explanation: "textContent treats input as text.",
  },
  {
    id: 45,
    topic: "DOM",
    question: "setTimeout(userInput) is risky because it:",
    options: ["Evaluates input as code", "Encodes input", "Prevents execution", "Blocks scripts"],
    correctAnswer: 0,
    explanation: "setTimeout with strings behaves like eval.",
  },
  {
    id: 46,
    topic: "DOM",
    question: "new Function(userInput) is risky because it:",
    options: ["Compiles and executes attacker input", "Escapes automatically", "Is ignored by browsers", "Only logs input"],
    correctAnswer: 0,
    explanation: "new Function executes provided code.",
  },
  {
    id: 47,
    topic: "Defense",
    question: "A WAF is:",
    options: ["A helpful layer but not a full fix", "A complete XSS solution", "A replacement for encoding", "Not useful at all"],
    correctAnswer: 0,
    explanation: "WAFs help but cannot replace secure coding.",
  },
  {
    id: 48,
    topic: "Defense",
    question: "Security testing for XSS should include:",
    options: ["Manual and automated testing", "Only unit tests", "Only code review", "Only penetration tests"],
    correctAnswer: 0,
    explanation: "A mix of testing approaches works best.",
  },
  {
    id: 49,
    topic: "Defense",
    question: "A good output encoding library should:",
    options: ["Be context-aware", "Only support HTML", "Avoid updates", "Be custom and untested"],
    correctAnswer: 0,
    explanation: "Libraries should support multiple contexts safely.",
  },
  {
    id: 50,
    topic: "Defense",
    question: "Context-aware encoding means:",
    options: ["Different encoding for HTML, JS, URL, CSS", "One encoding for all outputs", "Only input encoding", "No encoding needed"],
    correctAnswer: 0,
    explanation: "Each context needs a specific encoding.",
  },
  {
    id: 51,
    topic: "XSS vs Other",
    question: "XSS differs from CSRF because XSS:",
    options: ["Runs attacker script in the victim browser", "Only sends requests without scripts", "Only affects servers", "Requires no user interaction"],
    correctAnswer: 0,
    explanation: "CSRF is request forgery; XSS is script injection.",
  },
  {
    id: 52,
    topic: "XSS vs Other",
    question: "JSONP is risky because it:",
    options: ["Executes JSON as script", "Encrypts responses", "Blocks scripts", "Requires CSP"],
    correctAnswer: 0,
    explanation: "JSONP uses script tags, enabling XSS.",
  },
  {
    id: 53,
    topic: "XSS vs Other",
    question: "Using innerText is generally:",
    options: ["Safer for untrusted text", "More dangerous than innerHTML", "Equivalent to eval", "Only for CSS"],
    correctAnswer: 0,
    explanation: "innerText does not parse HTML.",
  },
  {
    id: 54,
    topic: "XSS vs Other",
    question: "Using setAttribute with untrusted URL is risky because:",
    options: ["It can allow javascript: URLs", "It always encodes", "It blocks navigation", "It prevents XSS"],
    correctAnswer: 0,
    explanation: "URL schemes must be validated.",
  },
  {
    id: 55,
    topic: "Testing",
    question: "A safe way to test for XSS is to use:",
    options: ["Non-destructive payloads like alert(1)", "Real credential theft", "Phishing pages", "Malware"],
    correctAnswer: 0,
    explanation: "Testing should be safe and controlled.",
  },
  {
    id: 56,
    topic: "Testing",
    question: "When testing reflected XSS, you often look for:",
    options: ["Unsafely reflected input in responses", "Stored comments only", "DB corruption", "DNS changes"],
    correctAnswer: 0,
    explanation: "Reflected input in HTML can execute scripts.",
  },
  {
    id: 57,
    topic: "Testing",
    question: "When testing stored XSS, you often look for:",
    options: ["Payloads saved and shown to other users", "Only query parameters", "Only headers", "Only redirects"],
    correctAnswer: 0,
    explanation: "Stored payloads persist and execute later.",
  },
  {
    id: 58,
    topic: "Testing",
    question: "When testing DOM XSS, you focus on:",
    options: ["Client-side sources and sinks", "Server logs only", "Database queries only", "TLS settings only"],
    correctAnswer: 0,
    explanation: "DOM XSS happens in JavaScript.",
  },
  {
    id: 59,
    topic: "Mitigation",
    question: "A secure CSP often sets object-src to:",
    options: ["none", "self", "unsafe-inline", "data"],
    correctAnswer: 0,
    explanation: "object-src none blocks plugins and risky content.",
  },
  {
    id: 60,
    topic: "Mitigation",
    question: "Using strict-dynamic in CSP:",
    options: ["Allows trusted scripts to load others", "Disables all scripts", "Removes nonces", "Enables unsafe-inline"],
    correctAnswer: 0,
    explanation: "strict-dynamic trusts scripts with a nonce or hash.",
  },
  {
    id: 61,
    topic: "Data Handling",
    question: "Sanitization should be done:",
    options: ["Before inserting HTML into the DOM", "Only at input time", "Only in the database", "Only after rendering"],
    correctAnswer: 0,
    explanation: "Sanitize before any HTML insertion.",
  },
  {
    id: 62,
    topic: "Data Handling",
    question: "Allowing users to upload HTML content requires:",
    options: ["Strict sanitization and review", "No controls", "Only encryption", "Disabling CSP"],
    correctAnswer: 0,
    explanation: "User HTML is risky without sanitization.",
  },
  {
    id: 63,
    topic: "Data Handling",
    question: "Escaping should be applied:",
    options: ["Every time data is rendered", "Only once when saved", "Only in logs", "Only in CSS"],
    correctAnswer: 0,
    explanation: "Encoding should be applied at each render.",
  },
  {
    id: 64,
    topic: "Defense",
    question: "A defense-in-depth approach includes:",
    options: ["Encoding, sanitization, and CSP", "Only logging", "Only encryption", "Only WAFs"],
    correctAnswer: 0,
    explanation: "Combine multiple layers for best protection.",
  },
  {
    id: 65,
    topic: "Defense",
    question: "Trusted Types can help by:",
    options: ["Restricting DOM sinks to safe values", "Disabling all scripts", "Replacing CSP", "Removing sanitization"],
    correctAnswer: 0,
    explanation: "Trusted Types reduce DOM XSS in modern browsers.",
  },
  {
    id: 66,
    topic: "Defense",
    question: "Avoiding inline scripts helps because:",
    options: ["It enables stricter CSP", "It disables cookies", "It removes HTML", "It forces eval"],
    correctAnswer: 0,
    explanation: "Strict CSP is easier without inline scripts.",
  },
  {
    id: 67,
    topic: "Defense",
    question: "Using template literals with untrusted input can:",
    options: ["Introduce XSS if inserted into HTML", "Prevent injection", "Encrypt data", "Disable scripts"],
    correctAnswer: 0,
    explanation: "Templates do not sanitize automatically.",
  },
  {
    id: 68,
    topic: "Defense",
    question: "Escaping for CSS context should:",
    options: ["Use CSS-specific escaping", "Use HTML escaping only", "Use URL encoding only", "Be skipped"],
    correctAnswer: 0,
    explanation: "CSS context requires CSS escaping.",
  },
  {
    id: 69,
    topic: "Defense",
    question: "Escaping for URL context should:",
    options: ["Validate scheme and encode components", "Only escape HTML", "Ignore protocol", "Always allow javascript:"],
    correctAnswer: 0,
    explanation: "Validate schemes and encode safely.",
  },
  {
    id: 70,
    topic: "Defense",
    question: "XSS in JSON responses can be avoided by:",
    options: ["Setting correct Content-Type and not executing JSON", "Wrapping JSON in script tags", "Using JSONP", "Disabling CSP"],
    correctAnswer: 0,
    explanation: "Serve JSON with application/json and parse safely.",
  },
  {
    id: 71,
    topic: "Defense",
    question: "If you must render HTML from users, you should:",
    options: ["Sanitize and allowlist tags and attributes", "Trust input", "Disable all checks", "Only escape once"],
    correctAnswer: 0,
    explanation: "Allowlist-based sanitization is required.",
  },
  {
    id: 72,
    topic: "Defense",
    question: "Browser auto-escaping features are:",
    options: ["Not a replacement for proper encoding", "Always sufficient", "Guaranteed protection", "A CSP substitute"],
    correctAnswer: 0,
    explanation: "Do not rely on browser heuristics.",
  },
  {
    id: 73,
    topic: "Detection",
    question: "XSS detection in logs can include:",
    options: ["Suspicious tags or event handlers in input", "Only normal requests", "Only status codes", "Only TLS errors"],
    correctAnswer: 0,
    explanation: "Look for script-like payloads in input.",
  },
  {
    id: 74,
    topic: "Detection",
    question: "A CSP violation report can help:",
    options: ["Identify attempted script execution", "Encrypt responses", "Disable logging", "Remove HTML"],
    correctAnswer: 0,
    explanation: "Reports show blocked script sources.",
  },
  {
    id: 75,
    topic: "Summary",
    question: "The safest approach to prevent XSS is:",
    options: ["Context-aware output encoding plus CSP", "Only input validation", "Only WAF rules", "Only logging"],
    correctAnswer: 0,
    explanation: "Encoding and strong CSP provide robust protection.",
  },
];

export default function XSSGuidePage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Cross-Site Scripting (XSS) Guide - Covers reflected, stored, and DOM-based XSS types, attack flow, entry points, sources and sinks, context-aware encoding, detection signals, safe testing checklist, CSP guidance, and secure coding examples.`;

  return (
    <LearnPageLayout pageTitle="Cross-Site Scripting (XSS)" pageContext={pageContext}>
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
                bgcolor: alpha("#f59e0b", 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <CodeIcon sx={{ fontSize: 36, color: "#f59e0b" }} />
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Cross-Site Scripting (XSS)
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Client-Side Code Injection
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Web Security" color="warning" size="small" />
            <Chip label="OWASP A03" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
            <Chip label="Client-Side" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
          </Box>
        </Box>

        {/* Overview */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WebIcon color="warning" /> What is XSS?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other 
            users. The victim's browser executes the script in the context of the vulnerable site, enabling session 
            hijacking, data theft, and account takeover.
          </Typography>
        </Paper>

        {/* How XSS Happens */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon sx={{ color: "#f59e0b" }} /> How XSS Works (Step-by-Step)
              </Typography>
              <List dense>
                {xssFlow.map((step) => (
                  <ListItem key={step} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={step} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SearchIcon sx={{ color: "#8b5cf6" }} /> Common Entry Points
              </Typography>
              <List dense>
                {entryPoints.map((item) => (
                  <ListItem key={item} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.04) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            High-Risk Features to Review
          </Typography>
          <Grid container spacing={1}>
            {highRiskFeatures.map((item) => (
              <Grid item xs={12} sm={6} key={item}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <WarningIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                  <Typography variant="body2">{item}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Sources and Sinks */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SearchIcon sx={{ color: "#3b82f6" }} /> Untrusted Sources
              </Typography>
              <List dense>
                {domSources.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2", fontFamily: "monospace", fontSize: "0.8rem" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ color: "#8b5cf6" }} /> Safer DOM Practices
              </Typography>
              <List dense>
                {safeDomPractices.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* XSS Types */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 XSS Types</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {xssTypes.map((type) => (
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
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: type.color }}>
                    {type.title}
                  </Typography>
                  <Chip label={type.persistence} size="small" sx={{ fontSize: "0.65rem", height: 20 }} />
                </Box>
                <Typography variant="body2" color="text.secondary">
                  {type.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Context-Aware Encoding */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            Context-Aware Encoding Cheat Sheet
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            The safe fix depends on where the data is placed. Always encode for the correct context.
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Context</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Risk</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Safer Handling</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {encodingContexts.map((row) => (
                  <TableRow key={row.context}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.context}</TableCell>
                    <TableCell>{row.risk}</TableCell>
                    <TableCell>{row.safe}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* Common Payloads */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.05)}, ${alpha("#ef4444", 0.05)})`,
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <BugReportIcon sx={{ color: "#f59e0b" }} /> Common Payloads
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Use these only in authorized environments. They help identify the context (HTML, attribute, URL) and confirm
            whether encoding or sanitization is working as expected.
          </Typography>
          <Grid container spacing={1}>
            {commonPayloads.map((p, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Box sx={{ p: 0.5, px: 1, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem", flexShrink: 0 }}>
                    {p.payload}
                  </Box>
                  <Typography variant="caption" color="text.secondary">{p.context}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Dangerous Sinks & Impact */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ color: "#8b5cf6" }} /> Dangerous Sinks (DOM XSS)
              </Typography>
              <List dense>
                {dangerousSinks.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2", fontFamily: "monospace", fontSize: "0.8rem" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: "#ef4444" }} /> Impact Scenarios
              </Typography>
              <List dense>
                {impactScenarios.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Detection and Testing */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SearchIcon sx={{ color: "#3b82f6" }} /> Detection Signals
              </Typography>
              <List dense>
                {detectionSignals.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <TipsAndUpdatesIcon sx={{ color: "#10b981" }} /> Safe Testing Checklist
              </Typography>
              <List dense>
                {testingChecklist.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Prevention */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#10b981" }} /> Prevention Methods
          </Typography>
          <Grid container spacing={1}>
            {preventionMethods.map((m, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                  <Typography variant="body2">{m}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <ShieldIcon sx={{ color: "#f59e0b" }} /> CSP Essentials
              </Typography>
              <List dense>
                {cspGuidelines.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <CodeIcon sx={{ color: "#8b5cf6" }} /> Framework Notes
              </Typography>
              <List dense>
                {frameworkNotes.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon sx={{ color: "#f59e0b" }} /> Secure Coding Examples
          </Typography>
          <Grid container spacing={2}>
            {codeSamples.map((sample) => (
              <Grid item xs={12} md={6} key={sample.title}>
                <Box sx={{ mb: 1 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                    {sample.title}
                  </Typography>
                </Box>
                <CodeBlock code={sample.code} language={sample.language} />
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.05) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#3b82f6" }} /> Response Steps
          </Typography>
          <Grid container spacing={1}>
            {responseSteps.map((m, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                  <Typography variant="body2">{m}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Tip */}
        <Paper
          sx={{
            p: 2,
            mb: 4,
            borderRadius: 2,
            bgcolor: alpha("#3b82f6", 0.05),
            border: `1px solid ${alpha("#3b82f6", 0.2)}`,
            display: "flex",
            alignItems: "center",
            gap: 2,
          }}
        >
          <TipsAndUpdatesIcon sx={{ color: "#3b82f6" }} />
          <Typography variant="body2">
            <strong>CSP Tip:</strong> Start with <code>Content-Security-Policy: default-src 'self'</code> and gradually add trusted sources.
          </Typography>
        </Paper>

        {/* Related */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📚 Related Learning</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Command Injection →" clickable onClick={() => navigate("/learn/command-injection")} sx={{ fontWeight: 600 }} />
            <Chip label="SQL Injection →" clickable onClick={() => navigate("/learn/sql-injection")} sx={{ fontWeight: 600 }} />
            <Chip label="OWASP Top 10 →" clickable onClick={() => navigate("/learn/owasp")} sx={{ fontWeight: 600 }} />
          </Box>
        </Paper>
        <Paper
          id="quiz-section"
          sx={{
            mt: 4,
            p: 4,
            borderRadius: 3,
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
            title="Cross-Site Scripting Knowledge Check"
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
