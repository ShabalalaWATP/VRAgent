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
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from "@mui/material";
import { useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import LockIcon from "@mui/icons-material/Lock";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import SecurityIcon from "@mui/icons-material/Security";
import HttpsIcon from "@mui/icons-material/Https";
import KeyIcon from "@mui/icons-material/Key";
import TokenIcon from "@mui/icons-material/Token";
import AccountCircleIcon from "@mui/icons-material/AccountCircle";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import ChecklistIcon from "@mui/icons-material/Checklist";
import SchoolIcon from "@mui/icons-material/School";
import BugReportIcon from "@mui/icons-material/BugReport";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import InfoIcon from "@mui/icons-material/Info";
import PersonSearchIcon from "@mui/icons-material/PersonSearch";
import CookieIcon from "@mui/icons-material/Cookie";
import EnhancedEncryptionIcon from "@mui/icons-material/EnhancedEncryption";
import StorageIcon from "@mui/icons-material/Storage";
import LoginIcon from "@mui/icons-material/Login";
import LinkIcon from "@mui/icons-material/Link";

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

interface Section {
  id: string;
  title: string;
  icon: React.ReactNode;
  color: string;
  teachContent: TeachBlock[];
  attackerContent: AttackerBlock[];
}

interface TeachBlock {
  subtitle?: string;
  points?: string[];
  code?: string;
  table?: { headers: string[]; rows: string[][] };
}

interface AttackerBlock {
  subtitle?: string;
  points?: string[];
  testIdeas?: string[];
}

const sections: Section[] = [
  {
    id: "auth-surface",
    title: "1. Mapping the Authentication Surface",
    icon: <PersonSearchIcon />,
    color: "#3b82f6",
    teachContent: [
      {
        subtitle: "What is an Authentication Surface?",
        points: [
          "The authentication surface is every endpoint, flow, and mechanism that handles identity verification",
          "It includes all ways a user can become authenticated or modify their authentication state",
          "A larger surface = more potential attack vectors",
        ],
      },
      {
        subtitle: "Typical Auth-Related Endpoints",
        points: [
          "Login (POST /login, /api/auth/login, /oauth/token)",
          "Registration (POST /register, /signup, /api/users)",
          "Password reset / recovery (POST /forgot-password, /reset-password)",
          "MFA setup / change (POST /mfa/setup, /2fa/enable)",
          "Change email / change password (PUT /account/email, /account/password)",
          "API login / token endpoints (POST /api/token, /oauth/authorize)",
          "Mobile-specific flows (deep links, biometric auth, device binding)",
          "Session management (POST /logout, DELETE /sessions)",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "Attacker Methodology",
        points: [
          "List every single way a user can become 'logged in'",
          "Map the complete authentication flow from start to finish",
          "Document all state changes (anonymous → authenticated → elevated)",
        ],
      },
      {
        subtitle: "What to Look For",
        testIdeas: [
          "Old or undocumented endpoints (check JavaScript files, mobile app binaries)",
          "Differences between web and mobile authentication flows",
          "Admin or support-only flows that are still accessible",
          "Legacy API versions with weaker security",
          "Debug endpoints left in production (/api/v1/debug/login)",
          "Inconsistent auth requirements across endpoints",
        ],
      },
    ],
  },
  {
    id: "credentials",
    title: "2. Credentials, Enumeration and Brute Force",
    icon: <VpnKeyIcon />,
    color: "#ef4444",
    teachContent: [
      {
        subtitle: "What Are Credentials?",
        points: [
          "Username or email - the identifier",
          "Password - the secret (something you know)",
          "Sometimes device ID, API key, or certificate (something you have)",
          "Biometrics in mobile apps (something you are)",
        ],
      },
      {
        subtitle: "How Apps Should Behave",
        points: [
          "Same error message for valid and invalid users: 'Invalid credentials'",
          "Same response time regardless of whether user exists",
          "Rate limiting: slow down after N failed attempts",
          "Account lockout: temporary or permanent after threshold",
          "Audit logging: record all auth attempts with metadata",
          "CAPTCHA after suspicious activity",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "Spotting Username Enumeration",
        points: [
          "Different error text: 'User not found' vs 'Wrong password'",
          "Different HTTP status codes: 404 vs 401",
          "Different response times (database lookup vs immediate rejection)",
          "Different response sizes (subtle byte differences)",
          "Registration telling you 'email already exists'",
          "Password reset saying 'no account with this email'",
        ],
      },
      {
        subtitle: "Brute Force Strategies",
        testIdeas: [
          "Password spraying: few passwords against many accounts",
          "Single account brute force: many passwords against one account",
          "Test rate limits: what happens at 10, 50, 100 attempts?",
          "Test lockout duration: how long until retry?",
          "Watch reset flows under load: do tokens become predictable?",
          "Try from different IPs: is rate limiting per-IP or per-account?",
          "Check mobile vs web: same rate limits?",
        ],
      },
    ],
  },
  {
    id: "sessions",
    title: "3. Sessions, Cookies and Token Basics",
    icon: <CookieIcon />,
    color: "#f59e0b",
    teachContent: [
      {
        subtitle: "What is a Session?",
        points: [
          "A session ties multiple HTTP requests to a single authenticated user",
          "Server creates session on login, stores state, gives client an identifier",
          "Every subsequent request includes this identifier to prove identity",
          "Sessions can be server-side (state in database) or client-side (state in token)",
        ],
      },
      {
        subtitle: "Session Cookie Attributes",
        table: {
          headers: ["Attribute", "Purpose", "Security Impact"],
          rows: [
            ["Secure", "Only send over HTTPS", "Prevents interception on HTTP"],
            ["HttpOnly", "JavaScript cannot read", "Prevents XSS cookie theft"],
            ["SameSite=Strict", "Only same-site requests", "Prevents CSRF attacks"],
            ["SameSite=Lax", "Same-site + top-level nav", "Balanced CSRF protection"],
            ["Domain", "Which domains receive cookie", "Scope of cookie exposure"],
            ["Path", "Which paths receive cookie", "Limits cookie scope"],
            ["Expires/Max-Age", "When cookie expires", "Session lifetime control"],
          ],
        },
      },
      {
        subtitle: "Basic Token Types",
        points: [
          "Random opaque tokens: meaningless string, server looks up meaning",
          "Structured tokens (JWT): data encoded in token itself, signed",
          "API keys: long-lived credentials for programmatic access",
          "Refresh tokens: used to get new access tokens without re-auth",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "Where to Find Session IDs",
        points: [
          "Cookies (most common): check all cookie values",
          "localStorage / sessionStorage: inspect browser dev tools",
          "HTTP headers: Authorization, X-Auth-Token, custom headers",
          "Query strings: session_id=xxx (very bad practice)",
          "Request body: hidden form fields",
        ],
      },
      {
        subtitle: "Session Testing Checklist",
        testIdeas: [
          "Is the cookie sent over HTTP as well as HTTPS?",
          "Are Secure, HttpOnly, SameSite flags set correctly?",
          "Is session ID regenerated on login? (prevents fixation)",
          "Is session ID regenerated on privilege change?",
          "What does logout actually do? (client-side only or server invalidation?)",
          "Can you use old session IDs after logout?",
          "What's the session timeout? Too long?",
          "Can sessions be used from multiple IPs simultaneously?",
        ],
      },
    ],
  },
  {
    id: "tls-crypto",
    title: "4. TLS, Certificates and Crypto Fundamentals",
    icon: <HttpsIcon />,
    color: "#10b981",
    teachContent: [
      {
        subtitle: "Symmetric vs Asymmetric Encryption",
        points: [
          "Symmetric: One shared secret key (AES, ChaCha20)",
          "  → Fast, used for bulk data encryption",
          "  → Problem: how do you share the key securely?",
          "Asymmetric: Public key + Private key pair (RSA, ECDSA)",
          "  → Public key encrypts, only private key decrypts",
          "  → Slower, used for key exchange and digital signatures",
          "In practice: Asymmetric negotiates a symmetric key, then symmetric encrypts data",
        ],
      },
      {
        subtitle: "How TLS Works (Simplified)",
        points: [
          "1. Client Hello: 'I want to talk to example.com, I support these ciphers'",
          "2. Server Hello: 'Here's my certificate and chosen cipher'",
          "3. Key Exchange: Both sides agree on a symmetric session key",
          "4. Encrypted Channel: All traffic now encrypted with session key",
          "TLS protects: Confidentiality, Integrity, Server Identity",
        ],
      },
      {
        subtitle: "Certificates and Chain of Trust",
        points: [
          "Certificate contains: Public key, Subject (who), Issuer (CA), Validity dates",
          "Chain: Root CA → Intermediate CA → Site Certificate",
          "Browser checks: Valid chain, Not expired, Hostname matches, Not revoked",
          "Root CAs are pre-installed in browsers/OS (trust anchors)",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "Crypto Attack Angles",
        points: [
          "Steal symmetric key = read all encrypted data",
          "Trick client into trusting your public key = man-in-the-middle",
          "Compromise CA = issue fake certificates",
          "Downgrade attack = force weaker encryption",
        ],
      },
      {
        subtitle: "TLS Testing Points",
        testIdeas: [
          "No TLS at all on login or API endpoints?",
          "Mixed content: HTTPS page loading HTTP resources?",
          "HTTP downgrade: can you strip HTTPS from redirects?",
          "Old TLS versions enabled (TLS 1.0, 1.1)?",
          "Weak cipher suites (RC4, DES, export ciphers)?",
          "Invalid/self-signed certs in production?",
          "Mobile apps with 'accept any certificate' code?",
          "Certificate pinning done badly or bypassable?",
          "HSTS header present and with long max-age?",
        ],
      },
    ],
  },
  {
    id: "password-storage",
    title: "5. Password Storage and Hashing",
    icon: <StorageIcon />,
    color: "#8b5cf6",
    teachContent: [
      {
        subtitle: "Hashing vs Encryption",
        points: [
          "Hashing: One-way function, cannot be reversed",
          "Encryption: Two-way, can decrypt with key",
          "Passwords MUST be hashed, NEVER encrypted",
          "If passwords are encrypted, someone has the decryption key",
        ],
      },
      {
        subtitle: "Good Password Storage",
        table: {
          headers: ["Component", "Purpose", "Example"],
          rows: [
            ["Slow hash algorithm", "Makes brute force expensive", "bcrypt, Argon2, scrypt"],
            ["Unique salt per password", "Prevents rainbow tables", "Random 16+ bytes"],
            ["High work factor", "Increases computation time", "bcrypt cost=12+"],
            ["Optional pepper", "Server-side secret added", "Environment variable"],
          ],
        },
      },
      {
        subtitle: "Red Flags in Password Handling",
        points: [
          "'Password reminder' emails that contain your actual password",
          "Support staff can tell you what your password is",
          "Password length limits (suggests poor storage)",
          "Passwords visible in account settings",
          "Login is instant even with complex passwords (no slow hashing)",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "What Leaked Hashes Mean",
        points: [
          "MD5/SHA1 hashes: cracked in seconds with rainbow tables",
          "Unsalted hashes: one crack = all identical passwords found",
          "Fast hashing (SHA256): GPU can try billions per second",
          "Weak passwords fall in minutes even with bcrypt",
        ],
      },
      {
        subtitle: "Testing Password Storage",
        testIdeas: [
          "Look for passwords in logs and debug output",
          "Check data exports for password fields",
          "Watch for passwords in error messages",
          "Test password reset: does it show old password?",
          "Check admin panels: can admins see passwords?",
          "Review API responses for password leakage",
          "Analyze backup files for plain text passwords",
        ],
      },
    ],
  },
  {
    id: "login-flows",
    title: "6. Attacking Login, Reset and MFA Flows",
    icon: <LoginIcon />,
    color: "#ec4899",
    teachContent: [
      {
        subtitle: "Normal Login Flow",
        points: [
          "User submits credentials → Server validates → Server creates session → Client receives session ID",
          "Each step must be server-validated, never client-only",
        ],
      },
      {
        subtitle: "Common Login Logic Mistakes",
        points: [
          "Client-side only validation (JavaScript checks)",
          "Hidden fields controlling access level",
          "Role/admin flag in cookies or localStorage",
          "Inconsistent validation between endpoints",
          "Race conditions in multi-step flows",
        ],
      },
      {
        subtitle: "Secure Password Reset",
        points: [
          "One-time token, unique per request",
          "Short expiry (15-60 minutes)",
          "Tied to specific account",
          "Invalidated after use",
          "Sent only to verified email/phone",
        ],
      },
      {
        subtitle: "MFA Types and Strengths",
        table: {
          headers: ["Type", "Security Level", "Weaknesses"],
          rows: [
            ["SMS OTP", "Low", "SIM swap, SS7 attacks, interception"],
            ["TOTP Apps", "Medium", "Seed theft, phishing"],
            ["Push Notifications", "Medium", "MFA fatigue, phishing"],
            ["Hardware Keys (FIDO2)", "High", "Physical theft only"],
            ["Backup Codes", "Varies", "Often stored insecurely"],
          ],
        },
      },
    ],
    attackerContent: [
      {
        subtitle: "Login Flow Attacks",
        testIdeas: [
          "Remove or change hidden fields (isAdmin, role)",
          "Skip steps in multi-step login",
          "Replay successful responses to different requests",
          "Change redirect URLs after login",
          "Try OAuth flows without completing all steps",
        ],
      },
      {
        subtitle: "Password Reset Attacks",
        testIdeas: [
          "Use the same reset link more than once",
          "Change user identifiers in reset URLs",
          "Request multiple resets: are old tokens invalidated?",
          "Guess or brute force short tokens",
          "Check if reset works for other users",
          "Test token expiry: does it actually expire?",
        ],
      },
      {
        subtitle: "MFA Bypass Techniques",
        testIdeas: [
          "Disable MFA without re-entering password",
          "Change email/phone without re-authentication",
          "Use existing sessions that never had MFA",
          "Skip MFA step by directly accessing post-MFA URLs",
          "Brute force short OTP codes (4-6 digits)",
          "Test backup code reuse",
          "MFA fatigue: spam push notifications until user approves",
        ],
      },
    ],
  },
  {
    id: "tokens-jwt",
    title: "7. Tokens, JWTs and API Authentication",
    icon: <TokenIcon />,
    color: "#06b6d4",
    teachContent: [
      {
        subtitle: "Opaque vs Structured Tokens",
        points: [
          "Opaque: Random string, meaning stored server-side",
          "  → Server must lookup token in database",
          "  → Easy to revoke, harder to scale",
          "Structured (JWT): Data encoded in token itself",
          "  → Stateless, server validates signature",
          "  → Harder to revoke, scales better",
        ],
      },
      {
        subtitle: "JWT Structure",
        code: `// Header (algorithm and type)
{
  "alg": "RS256",
  "typ": "JWT"
}

// Payload (claims)
{
  "sub": "user123",        // Subject (user ID)
  "iat": 1234567890,       // Issued at
  "exp": 1234571490,       // Expiration
  "role": "admin",         // Custom claim
  "scope": "read write"    // Permissions
}

// Signature
RSASHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  privateKey
)`,
      },
      {
        subtitle: "JWT Signing Methods",
        table: {
          headers: ["Algorithm", "Type", "Key"],
          rows: [
            ["HS256", "Symmetric", "Shared secret (HMAC)"],
            ["RS256", "Asymmetric", "RSA private/public key pair"],
            ["ES256", "Asymmetric", "ECDSA private/public key pair"],
            ["none", "NONE", "No signature (DANGEROUS)"],
          ],
        },
      },
    ],
    attackerContent: [
      {
        subtitle: "JWT Inspection",
        points: [
          "Base64 decode header and payload (jwt.io)",
          "Check claims: role, user_id, tenant_id, scopes",
          "Note algorithm in header",
          "Check expiration time (exp claim)",
        ],
      },
      {
        subtitle: "JWT Attack Techniques",
        testIdeas: [
          "Change alg to 'none' and remove signature",
          "Switch RS256 to HS256, sign with public key as secret",
          "Modify claims (role: admin) and re-sign if key known",
          "Brute force weak HMAC secrets",
          "Replay tokens across different users/devices/apps",
          "Use expired tokens: does server actually check exp?",
          "Test token revocation: can you use token after logout?",
          "Check for kid (key ID) injection vulnerabilities",
          "Look for jku header pointing to attacker-controlled JWKS",
        ],
      },
    ],
  },
  {
    id: "oauth-sso",
    title: "8. OAuth, SSO and Third-Party Identity",
    icon: <LinkIcon />,
    color: "#f97316",
    teachContent: [
      {
        subtitle: "OAuth 2.0 Roles",
        points: [
          "Resource Owner: The user who owns the data",
          "Client: The app wanting to access data",
          "Authorization Server: Issues tokens (Google, Okta)",
          "Resource Server: Hosts the protected data/API",
        ],
      },
      {
        subtitle: "OAuth Flows",
        table: {
          headers: ["Flow", "Use Case", "Security"],
          rows: [
            ["Authorization Code", "Server-side apps", "Most secure"],
            ["Authorization Code + PKCE", "Mobile/SPA apps", "Secure for public clients"],
            ["Implicit (Legacy)", "SPAs (deprecated)", "Token in URL, avoid"],
            ["Client Credentials", "Machine-to-machine", "No user involved"],
            ["Device Code", "Smart TVs, CLI", "User approves on another device"],
          ],
        },
      },
      {
        subtitle: "SSO Basics",
        points: [
          "Single Sign-On: One login for multiple applications",
          "Identity Provider (IdP): Manages user identities",
          "Service Provider (SP): Your application",
          "SAML: XML-based, enterprise-focused",
          "OIDC: OAuth 2.0 + identity layer, modern apps",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "Common OAuth Vulnerabilities",
        points: [
          "Open redirect via redirect_uri manipulation",
          "Missing or weak state parameter (CSRF)",
          "Access tokens in URL fragments (leakage)",
          "Token exposure in Referer headers",
          "Insufficient scope validation",
        ],
      },
      {
        subtitle: "OAuth Testing",
        testIdeas: [
          "Modify redirect_uri: subdomain, path traversal, parameter pollution",
          "Remove or reuse state parameter",
          "Swap authorization codes between users",
          "Use tokens from one client in another",
          "Check if implicit tokens work on code endpoints",
          "Test scope escalation: request more than granted",
          "PKCE bypass: try without code_verifier",
          "Check token exposure in browser history, logs",
        ],
      },
    ],
  },
  {
    id: "access-control",
    title: "9. Access Control and Privilege Escalation",
    icon: <AdminPanelSettingsIcon />,
    color: "#84cc16",
    teachContent: [
      {
        subtitle: "AuthN vs AuthZ",
        points: [
          "Authentication (AuthN): Who are you? (Identity verification)",
          "Authorization (AuthZ): What can you do? (Permission checking)",
          "Both must be checked on every request",
          "Common mistake: checking AuthN but not AuthZ",
        ],
      },
      {
        subtitle: "Access Control Models",
        table: {
          headers: ["Model", "Description", "Example"],
          rows: [
            ["RBAC", "Role-Based Access Control", "admin, user, guest roles"],
            ["ABAC", "Attribute-Based Access Control", "department=finance AND level>5"],
            ["ReBAC", "Relationship-Based Access Control", "owner, editor, viewer of resource"],
            ["ACL", "Access Control List", "Per-resource permission lists"],
          ],
        },
      },
      {
        subtitle: "IDOR / BOLA",
        points: [
          "Insecure Direct Object Reference (IDOR)",
          "Broken Object Level Authorization (BOLA) - API equivalent",
          "User A can access User B's data by changing an ID",
          "Example: GET /api/orders/123 → GET /api/orders/124",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "Horizontal Privilege Escalation",
        testIdeas: [
          "Replace object IDs with another user's ID",
          "Swap GUIDs, emails, or usernames in requests",
          "Use another user's token on your resources",
          "Check bulk operations for authorization",
          "Test GraphQL queries with other users' IDs",
        ],
      },
      {
        subtitle: "Vertical Privilege Escalation",
        testIdeas: [
          "Call admin endpoints as normal user",
          "Modify role/isAdmin parameters in requests",
          "Access /admin paths without admin role",
          "Change plan/tier identifiers (free → premium)",
          "Test feature flags for premium features",
          "Check if client-side role checks exist server-side",
        ],
      },
    ],
  },
  {
    id: "checklists",
    title: "10. Attacker Checklists",
    icon: <ChecklistIcon />,
    color: "#dc2626",
    teachContent: [
      {
        subtitle: "Systematic Approach",
        points: [
          "Never test randomly - follow a methodology",
          "Document everything as you go",
          "Test authenticated and unauthenticated flows",
          "Test from different privilege levels",
          "Compare web vs mobile vs API behavior",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "New Application Quick Checklist",
        testIdeas: [
          "□ Can I enumerate users? (login, register, reset)",
          "□ What are all the authentication endpoints?",
          "□ Are all endpoints using TLS?",
          "□ Are certificates valid and properly configured?",
          "□ Where do session tokens live? (cookies, storage, headers)",
          "□ What cookie flags are set? (Secure, HttpOnly, SameSite)",
          "□ Is there rate limiting on auth endpoints?",
          "□ What happens when I change object IDs?",
          "□ Can I access admin functions as normal user?",
          "□ Does logout actually invalidate the session?",
          "□ Are JWTs properly signed and validated?",
          "□ Is MFA bypassable?",
          "□ Are password reset tokens secure?",
        ],
      },
      {
        subtitle: "Authentication Testing Summary",
        points: [
          "Enumeration → Brute Force → Session Analysis → Token Inspection",
          "Login Bypass → Reset Flow Abuse → MFA Bypass",
          "Horizontal Access → Vertical Access → Role Manipulation",
          "Always test: What if I skip this step? What if I change this value?",
        ],
      },
    ],
  },
];

const tabSections = [
  { label: "Auth Surface", icon: <PersonSearchIcon />, sections: ["auth-surface"] },
  { label: "Credentials", icon: <VpnKeyIcon />, sections: ["credentials"] },
  { label: "Sessions", icon: <CookieIcon />, sections: ["sessions"] },
  { label: "TLS & Crypto", icon: <HttpsIcon />, sections: ["tls-crypto"] },
  { label: "Passwords", icon: <StorageIcon />, sections: ["password-storage"] },
  { label: "Login Flows", icon: <LoginIcon />, sections: ["login-flows"] },
  { label: "Tokens & JWT", icon: <TokenIcon />, sections: ["tokens-jwt"] },
  { label: "OAuth & SSO", icon: <LinkIcon />, sections: ["oauth-sso"] },
  { label: "Access Control", icon: <AdminPanelSettingsIcon />, sections: ["access-control"] },
  { label: "Checklists", icon: <ChecklistIcon />, sections: ["checklists"] },
];

function SectionContent({ section }: { section: Section }) {
  const theme = useTheme();

  return (
    <Box sx={{ mb: 4 }}>
      {/* Teach Section */}
      <Paper
        sx={{
          p: 3,
          mb: 3,
          borderRadius: 3,
          border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`,
          background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.03)}, transparent)`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
          <SchoolIcon sx={{ color: "info.main" }} />
          <Typography variant="h6" sx={{ fontWeight: 700, color: "info.main" }}>
            📚 Learn
          </Typography>
        </Box>

        {section.teachContent.map((block, i) => (
          <Box key={i} sx={{ mb: 3 }}>
            {block.subtitle && (
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1.5 }}>
                {block.subtitle}
              </Typography>
            )}

            {block.points && (
              <List dense disablePadding>
                {block.points.map((point, j) => (
                  <ListItem key={j} disableGutters sx={{ py: 0.25, pl: point.startsWith("  ") ? 3 : 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      {point.startsWith("  ") ? (
                        <Box sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: "info.main", ml: 0.5 }} />
                      ) : (
                        <CheckCircleIcon sx={{ fontSize: 16, color: "info.main" }} />
                      )}
                    </ListItemIcon>
                    <ListItemText
                      primary={point.trim()}
                      primaryTypographyProps={{ variant: "body2" }}
                    />
                  </ListItem>
                ))}
              </List>
            )}

            {block.code && (
              <Paper
                component="pre"
                sx={{
                  p: 2,
                  mt: 2,
                  bgcolor: alpha(theme.palette.background.default, 0.5),
                  borderRadius: 2,
                  overflow: "auto",
                  fontSize: "0.75rem",
                  fontFamily: "monospace",
                  border: `1px solid ${theme.palette.divider}`,
                }}
              >
                {block.code}
              </Paper>
            )}

            {block.table && (
              <TableContainer component={Paper} sx={{ mt: 2, borderRadius: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha(theme.palette.info.main, 0.1) }}>
                      {block.table.headers.map((h, hi) => (
                        <TableCell key={hi} sx={{ fontWeight: 700 }}>{h}</TableCell>
                      ))}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {block.table.rows.map((row, ri) => (
                      <TableRow key={ri}>
                        {row.map((cell, ci) => (
                          <TableCell key={ci} sx={{ fontSize: "0.8rem" }}>{cell}</TableCell>
                        ))}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Box>
        ))}
      </Paper>

      {/* Attacker Section */}
      <Paper
        sx={{
          p: 3,
          borderRadius: 3,
          border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`,
          background: `linear-gradient(135deg, ${alpha(theme.palette.error.main, 0.03)}, transparent)`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
          <BugReportIcon sx={{ color: "error.main" }} />
          <Typography variant="h6" sx={{ fontWeight: 700, color: "error.main" }}>
            🎯 Attacker's View
          </Typography>
        </Box>

        {section.attackerContent.map((block, i) => (
          <Box key={i} sx={{ mb: 3 }}>
            {block.subtitle && (
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1.5 }}>
                {block.subtitle}
              </Typography>
            )}

            {block.points && (
              <List dense disablePadding>
                {block.points.map((point, j) => (
                  <ListItem key={j} disableGutters sx={{ py: 0.25 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "error.main" }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={point}
                      primaryTypographyProps={{ variant: "body2" }}
                    />
                  </ListItem>
                ))}
              </List>
            )}

            {block.testIdeas && (
              <Paper
                sx={{
                  p: 2,
                  mt: 1,
                  bgcolor: alpha(theme.palette.error.main, 0.03),
                  border: `1px solid ${alpha(theme.palette.error.main, 0.15)}`,
                  borderRadius: 2,
                }}
              >
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "error.main" }}>
                  💡 Test Ideas
                </Typography>
                {block.testIdeas.map((idea, j) => (
                  <Typography key={j} variant="body2" sx={{ mb: 0.5, fontFamily: "monospace", fontSize: "0.8rem" }}>
                    → {idea}
                  </Typography>
                ))}
              </Paper>
            )}
          </Box>
        ))}
      </Paper>
    </Box>
  );
}

export default function AuthCryptoGuidePage() {
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
              width: 72,
              height: 72,
              borderRadius: 3,
              background: `linear-gradient(135deg, #10b981, #3b82f6)`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: `0 8px 32px ${alpha("#10b981", 0.3)}`,
            }}
          >
            <EnhancedEncryptionIcon sx={{ fontSize: 36, color: "white" }} />
          </Box>
          <Box>
            <Typography
              variant="h3"
              sx={{
                fontWeight: 800,
                background: `linear-gradient(135deg, #10b981, #3b82f6)`,
                backgroundClip: "text",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
              }}
            >
              Authentication & Crypto Deep Dive
            </Typography>
            <Typography variant="h6" color="text.secondary">
              From TLS handshakes to token attacks — learn then hack
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* Stats */}
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {[
          { value: "10", label: "Core Topics", color: "#3b82f6" },
          { value: "50+", label: "Attack Techniques", color: "#ef4444" },
          { value: "30+", label: "Test Ideas", color: "#f59e0b" },
          { value: "∞", label: "Things to Break", color: "#10b981" },
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

      {/* Info Box */}
      <Alert
        severity="info"
        icon={<InfoIcon />}
        sx={{ mb: 4, borderRadius: 3 }}
      >
        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
          📖 How to Use This Guide
        </Typography>
        <Typography variant="body2">
          Each section has two parts: <strong>Learn</strong> explains the concept, then <strong>Attacker's View</strong> shows how to test and exploit it.
          Work through sequentially or jump to specific topics using the tabs.
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
              minHeight: 56,
              textTransform: "none",
              fontWeight: 600,
              fontSize: "0.8rem",
            },
          }}
        >
          {tabSections.map((tab, i) => (
            <Tab
              key={tab.label}
              label={
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                  <Box sx={{ color: tabValue === i ? sections.find(s => tab.sections.includes(s.id))?.color : "text.secondary", fontSize: 18 }}>
                    {tab.icon}
                  </Box>
                  <span>{tab.label}</span>
                </Box>
              }
            />
          ))}
        </Tabs>

        <Box sx={{ p: 3 }}>
          {tabSections.map((tab, i) => (
            <TabPanel key={i} value={tabValue} index={i}>
              {tab.sections.map((sectionId) => {
                const section = sections.find((s) => s.id === sectionId);
                if (!section) return null;
                return (
                  <Box key={section.id}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
                      <Box
                        sx={{
                          width: 48,
                          height: 48,
                          borderRadius: 2,
                          bgcolor: alpha(section.color, 0.1),
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          color: section.color,
                        }}
                      >
                        {section.icon}
                      </Box>
                      <Typography variant="h5" sx={{ fontWeight: 700 }}>
                        {section.title}
                      </Typography>
                    </Box>
                    <SectionContent section={section} />
                  </Box>
                );
              })}
            </TabPanel>
          ))}
        </Box>
      </Paper>

      {/* Quick Navigation */}
      <Paper sx={{ mt: 4, p: 3, borderRadius: 3 }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          🗺️ Quick Navigation
        </Typography>
        <Grid container spacing={1}>
          {sections.map((section, i) => (
            <Grid item xs={6} sm={4} md={2.4} key={section.id}>
              <Chip
                label={`${i + 1}. ${section.title.split(". ")[1]?.split(" ")[0] || section.title}`}
                onClick={() => setTabValue(i)}
                sx={{
                  width: "100%",
                  bgcolor: tabValue === i ? section.color : alpha(section.color, 0.1),
                  color: tabValue === i ? "white" : section.color,
                  fontWeight: 600,
                  cursor: "pointer",
                  "&:hover": {
                    bgcolor: tabValue === i ? section.color : alpha(section.color, 0.2),
                  },
                }}
              />
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Resources */}
      <Paper sx={{ mt: 4, p: 4, borderRadius: 3, bgcolor: alpha(theme.palette.success.main, 0.02) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          📚 Further Reading
        </Typography>
        <Grid container spacing={2}>
          {[
            { name: "OWASP Authentication Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
            { name: "OWASP Session Management Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" },
            { name: "JWT Security Best Practices", url: "https://curity.io/resources/learn/jwt-best-practices/" },
            { name: "OAuth 2.0 Security Best Practices", url: "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics" },
            { name: "PortSwigger Authentication Labs", url: "https://portswigger.net/web-security/authentication" },
            { name: "Mozilla TLS Guidelines", url: "https://wiki.mozilla.org/Security/Server_Side_TLS" },
          ].map((resource) => (
            <Grid item xs={12} sm={6} key={resource.name}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  cursor: "pointer",
                  transition: "all 0.2s",
                  "&:hover": { transform: "translateY(-2px)", borderColor: "primary.main" },
                  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                }}
                onClick={() => window.open(resource.url, "_blank")}
              >
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main" }}>
                  {resource.name} ↗
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Paper>
    </Container>
  );
}
