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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Drawer,
  Fab,
  LinearProgress,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import LockIcon from "@mui/icons-material/Lock";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import SecurityIcon from "@mui/icons-material/Security";
import HttpsIcon from "@mui/icons-material/Https";
import TokenIcon from "@mui/icons-material/Token";
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
import QuizIcon from "@mui/icons-material/Quiz";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import ListAltIcon from "@mui/icons-material/ListAlt";
import DescriptionIcon from "@mui/icons-material/Description";
import AssignmentIcon from "@mui/icons-material/Assignment";
import HttpIcon from "@mui/icons-material/Http";
import TerminalIcon from "@mui/icons-material/Terminal";
import JavascriptIcon from "@mui/icons-material/Javascript";

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

// Section Navigation Items for sidebar
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <EnhancedEncryptionIcon /> },
  { id: "auth-surface", label: "Auth Surface", icon: <PersonSearchIcon /> },
  { id: "credentials", label: "Credentials & Brute Force", icon: <VpnKeyIcon /> },
  { id: "sessions", label: "Sessions & Cookies", icon: <CookieIcon /> },
  { id: "tls-crypto", label: "TLS & Crypto", icon: <HttpsIcon /> },
  { id: "password-storage", label: "Password Storage", icon: <StorageIcon /> },
  { id: "login-flows", label: "Login & MFA Flows", icon: <LoginIcon /> },
  { id: "tokens-jwt", label: "Tokens & JWT", icon: <TokenIcon /> },
  { id: "oauth-sso", label: "OAuth & SSO", icon: <LinkIcon /> },
  { id: "access-control", label: "Access Control", icon: <AdminPanelSettingsIcon /> },
  { id: "checklists", label: "Attacker Checklists", icon: <ChecklistIcon /> },
  { id: "resources", label: "Resources", icon: <DescriptionIcon /> },
  { id: "quiz", label: "Knowledge Check", icon: <SchoolIcon /> },
];

const ACCENT_COLOR = "#10b981";

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
          "Modern applications often have multiple auth surfaces: web, mobile API, admin panel, partner APIs",
          "Each entry point must be secured consistently - attackers look for the weakest link",
        ],
      },
      {
        subtitle: "Understanding the Authentication Lifecycle",
        points: [
          "Registration: Creating a new identity in the system",
          "Authentication: Proving you are who you claim to be",
          "Session Management: Maintaining authenticated state across requests",
          "Re-authentication: Proving identity again for sensitive actions",
          "Logout: Properly terminating the authenticated session",
          "Account Recovery: Regaining access when credentials are lost",
          "Account Modification: Changing email, password, or security settings",
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
          "Social login callbacks (/auth/google/callback, /auth/facebook/callback)",
          "API key management (/api/keys, /developer/credentials)",
        ],
      },
      {
        subtitle: "Why Mapping Matters",
        points: [
          "You cannot secure what you don't know exists",
          "Legacy endpoints often have weaker security controls",
          "Different teams may implement auth differently across services",
          "API versioning can create parallel auth implementations",
          "Mobile apps may use different auth flows than web",
          "Internal tools and admin panels are often overlooked",
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
          "Compare authentication between different clients (web, mobile, API)",
          "Look for consistency - inconsistencies often indicate vulnerabilities",
        ],
      },
      {
        subtitle: "Discovery Techniques",
        points: [
          "Spider the application and note all forms requiring credentials",
          "Analyze JavaScript files for hidden API endpoints",
          "Check robots.txt and sitemap.xml for admin/auth paths",
          "Review mobile app binaries for API endpoints",
          "Use tools like ffuf, gobuster for directory enumeration",
          "Check wayback machine for old endpoints",
          "Analyze error messages that may reveal endpoint names",
        ],
      },
      {
        subtitle: "What to Look For",
        testIdeas: [
          "Old or undocumented endpoints (check JavaScript files, mobile app binaries)",
          "Differences between web and mobile authentication flows",
          "Admin or support-only flows that are still accessible",
          "Legacy API versions with weaker security (v1 vs v2)",
          "Debug endpoints left in production (/api/v1/debug/login)",
          "Inconsistent auth requirements across endpoints",
          "Different auth mechanisms for different user types",
          "SSO endpoints and their fallback mechanisms",
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
        subtitle: "Understanding Credentials",
        points: [
          "Credentials are the proof that you are who you claim to be",
          "They typically consist of an identifier (who) and a secret (proof)",
          "The strength of authentication depends on the strength of credentials",
          "Compromised credentials are the #1 cause of data breaches",
        ],
      },
      {
        subtitle: "Types of Credentials",
        points: [
          "Something you know: Passwords, PINs, security questions",
          "Something you have: Phone, hardware token, smart card, authenticator app",
          "Something you are: Fingerprint, face recognition, voice pattern",
          "Somewhere you are: Geolocation, IP address, network",
          "Something you do: Typing patterns, behavioral biometrics",
        ],
      },
      {
        subtitle: "The Password Problem",
        points: [
          "Humans are bad at creating and remembering strong passwords",
          "The same passwords are reused across multiple sites",
          "Password breaches create lists used for credential stuffing",
          "Users often follow predictable patterns (Password1!, Summer2024!)",
          "Password managers help but adoption is still low",
          "Password policies can backfire (forced rotations lead to weaker passwords)",
        ],
      },
      {
        subtitle: "How Apps Should Behave",
        points: [
          "Same error message for valid and invalid users: 'Invalid credentials'",
          "Same response time regardless of whether user exists (constant-time comparison)",
          "Rate limiting: slow down after N failed attempts",
          "Account lockout: temporary or permanent after threshold",
          "Audit logging: record all auth attempts with metadata",
          "CAPTCHA after suspicious activity",
          "Notify users of suspicious login attempts",
          "Support for password managers (no paste blocking)",
        ],
      },
      {
        subtitle: "Password Policy Best Practices",
        points: [
          "Minimum 12+ characters (length > complexity)",
          "Check against known breached password lists (HIBP API)",
          "Allow all printable characters including spaces",
          "No arbitrary complexity rules (they reduce entropy)",
          "No periodic password rotation (NIST 800-63B)",
          "Encourage passphrases over complex passwords",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "Username Enumeration Techniques",
        points: [
          "Different error text: 'User not found' vs 'Wrong password'",
          "Different HTTP status codes: 404 vs 401 vs 403",
          "Different response times (database lookup vs immediate rejection)",
          "Different response sizes (even a few bytes difference)",
          "Registration telling you 'email already exists'",
          "Password reset saying 'no account with this email'",
          "Forgot password response time differences",
          "API responses with different structures",
        ],
      },
      {
        subtitle: "Understanding Brute Force Attacks",
        points: [
          "Online brute force: Trying passwords against live system",
          "Offline brute force: Cracking stolen password hashes",
          "Dictionary attacks: Using common password lists",
          "Hybrid attacks: Combining dictionary words with variations",
          "Rule-based attacks: Applying transformations to words",
          "Mask attacks: When you know part of the password pattern",
        ],
      },
      {
        subtitle: "Brute Force Strategies",
        testIdeas: [
          "Password spraying: few passwords against many accounts (avoids lockout)",
          "Single account brute force: many passwords against one account",
          "Test rate limits: what happens at 10, 50, 100 attempts?",
          "Test lockout duration: how long until retry?",
          "Watch reset flows under load: do tokens become predictable?",
          "Try from different IPs: is rate limiting per-IP or per-account?",
          "Check mobile vs web: same rate limits?",
          "Test after hours: are security controls weaker?",
          "Try different user agents: does it affect rate limiting?",
          "Distributed attacks: low and slow from many IPs",
        ],
      },
      {
        subtitle: "Credential Stuffing",
        points: [
          "Using leaked username/password pairs from other breaches",
          "Highly effective because of password reuse",
          "Tools: Sentry MBA, SNIPR, OpenBullet",
          "Defenses: rate limiting, device fingerprinting, CAPTCHA",
          "Check if the app detects known-breached credentials",
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
        subtitle: "Why Sessions Exist",
        points: [
          "HTTP is stateless - each request is independent",
          "Sessions add state to a stateless protocol",
          "Without sessions, you'd need to authenticate every single request",
          "Sessions allow the server to remember who you are",
        ],
      },
      {
        subtitle: "How Sessions Work",
        points: [
          "User authenticates successfully",
          "Server creates session and stores state (user ID, permissions, etc.)",
          "Server gives client a session identifier (usually in a cookie)",
          "Client sends identifier with every subsequent request",
          "Server looks up session data and processes request accordingly",
          "On logout, session is destroyed server-side",
        ],
      },
      {
        subtitle: "Server-Side vs Client-Side Sessions",
        points: [
          "Server-side: State stored in database/cache, client has only an ID",
          "  → Pros: Full control, easy revocation, sensitive data stays on server",
          "  → Cons: Requires storage, harder to scale, database lookups",
          "Client-side (JWT): All state encoded in the token itself",
          "  → Pros: Stateless, scales easily, no server storage",
          "  → Cons: Can't revoke easily, larger tokens, all data travels with request",
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
        subtitle: "Session ID Security Requirements",
        points: [
          "Must be random and unpredictable (cryptographically secure random)",
          "Must be long enough to prevent brute force (128+ bits of entropy)",
          "Must be transmitted securely (HTTPS only)",
          "Must be stored securely (HttpOnly cookies preferred)",
          "Must be regenerated on authentication state changes",
          "Must be invalidated properly on logout",
        ],
      },
      {
        subtitle: "Basic Token Types",
        points: [
          "Random opaque tokens: meaningless string, server looks up meaning",
          "Structured tokens (JWT): data encoded in token itself, signed",
          "API keys: long-lived credentials for programmatic access",
          "Refresh tokens: used to get new access tokens without re-auth",
          "Bearer tokens: presented in Authorization header",
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
          "Query strings: session_id=xxx (very bad practice - leaks in logs/referer)",
          "Request body: hidden form fields",
          "WebSocket connection parameters",
          "Mobile app secure storage",
        ],
      },
      {
        subtitle: "Session Fixation Attack",
        points: [
          "Attacker sets a known session ID before victim logs in",
          "Victim authenticates, but session ID doesn't change",
          "Attacker now has access to authenticated session",
          "Prevention: ALWAYS regenerate session ID on login",
          "Test: Login with a pre-set session ID, check if it changes",
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
          "Can you hijack a session with a stolen cookie?",
          "Is the session ID predictable or sequential?",
          "Are sessions properly isolated in multi-tenant apps?",
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
        subtitle: "Why Cryptography Matters",
        points: [
          "Cryptography is the mathematical foundation of all security",
          "It provides: Confidentiality (secrets stay secret), Integrity (data isn't tampered), Authentication (prove identity)",
          "Without crypto, all network traffic could be read and modified",
          "Understanding crypto helps you identify weaknesses and misconfigurations",
        ],
      },
      {
        subtitle: "Symmetric vs Asymmetric Encryption",
        points: [
          "Symmetric: One shared secret key (AES, ChaCha20)",
          "  → Fast, used for bulk data encryption",
          "  → Problem: how do you share the key securely?",
          "  → Common algorithms: AES-256-GCM, ChaCha20-Poly1305",
          "Asymmetric: Public key + Private key pair (RSA, ECDSA, Ed25519)",
          "  → Public key encrypts, only private key decrypts",
          "  → Can also be used for digital signatures",
          "  → Slower, used for key exchange and authentication",
          "In practice: Asymmetric negotiates a symmetric key, then symmetric encrypts data",
        ],
      },
      {
        subtitle: "Hashing: One-Way Functions",
        points: [
          "Hashes convert any input into a fixed-size output",
          "Same input always produces same output (deterministic)",
          "Cannot reverse a hash to get the original input",
          "Small input change = completely different output (avalanche effect)",
          "Common hashes: SHA-256, SHA-3, BLAKE2",
          "NEVER use for passwords: MD5, SHA-1 (too fast, collision attacks)",
        ],
      },
      {
        subtitle: "How TLS Works (The Handshake)",
        points: [
          "1. Client Hello: 'I want to talk to example.com, I support these ciphers'",
          "2. Server Hello: 'Here's my certificate and chosen cipher suite'",
          "3. Certificate Verification: Client validates cert chain, hostname, expiration",
          "4. Key Exchange: Both sides derive the same session key (Diffie-Hellman)",
          "5. Finished: Both sides confirm the handshake succeeded",
          "6. Encrypted Channel: All traffic now encrypted with session key",
          "TLS protects: Confidentiality, Integrity, Server Authentication",
        ],
      },
      {
        subtitle: "TLS Versions and Cipher Suites",
        table: {
          headers: ["Version", "Status", "Notes"],
          rows: [
            ["TLS 1.3", "Current standard", "Faster handshake, mandatory PFS, fewer options"],
            ["TLS 1.2", "Still acceptable", "Widely supported, configure carefully"],
            ["TLS 1.1", "Deprecated", "Do not use, browser warnings"],
            ["TLS 1.0", "Deprecated", "Do not use, known vulnerabilities"],
            ["SSL 3.0", "Broken", "POODLE attack, must be disabled"],
          ],
        },
      },
      {
        subtitle: "Certificates and Chain of Trust",
        points: [
          "Certificate contains: Public key, Subject (who), Issuer (CA), Validity dates",
          "Chain: Root CA → Intermediate CA → Site Certificate",
          "Browser checks: Valid chain, Not expired, Hostname matches, Not revoked",
          "Root CAs are pre-installed in browsers/OS (trust anchors)",
          "Let's Encrypt made certificates free and automated (ACME protocol)",
          "Certificate Transparency logs track all issued certificates",
        ],
      },
      {
        subtitle: "Perfect Forward Secrecy (PFS)",
        points: [
          "PFS ensures past sessions can't be decrypted even if private key is later compromised",
          "Uses ephemeral (one-time) keys for each session",
          "Enabled by DHE or ECDHE key exchange",
          "Critical for protecting historical traffic from future key compromise",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "Crypto Attack Categories",
        points: [
          "Implementation attacks: Bugs in crypto code (padding oracles, timing)",
          "Configuration attacks: Weak settings (old TLS, weak ciphers)",
          "Protocol attacks: Flaws in protocol design (BEAST, POODLE, Heartbleed)",
          "Key management: Poor key storage, weak key generation, no rotation",
          "Social attacks: Tricking users to accept invalid certificates",
        ],
      },
      {
        subtitle: "Man-in-the-Middle Attacks",
        points: [
          "Attacker intercepts communication between client and server",
          "Can read, modify, or inject traffic if TLS is misconfigured",
          "Requires: network position + certificate the client trusts",
          "Common vectors: rogue WiFi, ARP poisoning, DNS hijacking",
          "TLS prevents MITM when certificate validation is correct",
        ],
      },
      {
        subtitle: "TLS Testing Points",
        testIdeas: [
          "No TLS at all on login or API endpoints?",
          "Mixed content: HTTPS page loading HTTP resources?",
          "HTTP downgrade: can you strip HTTPS from redirects?",
          "Old TLS versions enabled (TLS 1.0, 1.1)?",
          "Weak cipher suites (RC4, DES, export ciphers, NULL)?",
          "Invalid/self-signed certs in production?",
          "Mobile apps with 'accept any certificate' code?",
          "Certificate pinning done badly or bypassable?",
          "HSTS header present and with long max-age?",
          "HSTS preload list inclusion?",
          "Certificate expiration monitoring?",
          "Use testssl.sh or SSL Labs for comprehensive testing",
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
        subtitle: "The Cardinal Rule",
        points: [
          "NEVER store passwords in plain text - ever",
          "NEVER store passwords encrypted (reversible)",
          "ALWAYS hash passwords with a slow, salted algorithm",
          "If you can recover a user's password, you're doing it wrong",
        ],
      },
      {
        subtitle: "Hashing vs Encryption",
        points: [
          "Hashing: One-way function, cannot be reversed",
          "Encryption: Two-way, can decrypt with key",
          "Passwords MUST be hashed, NEVER encrypted",
          "If passwords are encrypted, someone has the decryption key",
          "That key becomes a single point of compromise",
        ],
      },
      {
        subtitle: "Why Slow Hashing?",
        points: [
          "Fast hashes (MD5, SHA) can be tried billions of times per second on GPUs",
          "Slow hashes (bcrypt, Argon2) are intentionally expensive",
          "A hash that takes 100ms instead of 1µs is 100,000x more expensive to crack",
          "The work factor can be increased as hardware gets faster",
          "This makes brute force attacks impractical even with powerful hardware",
        ],
      },
      {
        subtitle: "Why Salting?",
        points: [
          "A salt is random data added to each password before hashing",
          "Same password + different salt = different hash",
          "Without salts, identical passwords have identical hashes",
          "Salts defeat rainbow tables (precomputed hash lookups)",
          "Salts defeat reverse-lookup attacks across users",
          "Each user MUST have a unique salt (stored alongside the hash)",
        ],
      },
      {
        subtitle: "Modern Password Hashing Algorithms",
        table: {
          headers: ["Algorithm", "Recommendation", "Notes"],
          rows: [
            ["Argon2id", "Best choice", "Memory-hard, won Password Hashing Competition"],
            ["bcrypt", "Excellent", "Time-tested, widely supported, max 72 bytes input"],
            ["scrypt", "Good", "Memory-hard, harder to configure correctly"],
            ["PBKDF2", "Acceptable", "Not memory-hard, needs high iterations (600k+)"],
            ["SHA-256/512", "NEVER for passwords", "Too fast, even with salt"],
            ["MD5/SHA-1", "NEVER", "Broken, extremely fast"],
          ],
        },
      },
      {
        subtitle: "Configuration Best Practices",
        points: [
          "bcrypt: cost factor of 12+ (adjust so hash takes ~250ms)",
          "Argon2id: memory 64MB+, time cost 3+, parallelism 1",
          "Increase work factor over time as hardware improves",
          "Consider adding a pepper (server-side secret) for defense in depth",
          "Pepper should be stored separately from the database",
        ],
      },
      {
        subtitle: "Red Flags in Password Handling",
        points: [
          "'Password reminder' emails that contain your actual password",
          "Support staff can tell you what your password is",
          "Password length limits (max 20 chars suggests poor storage)",
          "Passwords visible in account settings",
          "Login is instant even with complex passwords (no slow hashing)",
          "Blocking paste in password fields (hurts password managers)",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "What Leaked Hashes Mean",
        points: [
          "MD5/SHA1 hashes: cracked in seconds with rainbow tables",
          "Unsalted hashes: one crack = all identical passwords found",
          "Fast hashing (SHA256): GPU can try 10+ billion per second",
          "Weak passwords fall in minutes even with bcrypt",
          "Strong, unique passwords resist even offline attacks",
        ],
      },
      {
        subtitle: "Hash Cracking Tools & Techniques",
        points: [
          "Hashcat: GPU-accelerated, supports most hash types",
          "John the Ripper: CPU-focused, great for complex rules",
          "Dictionary attacks: Common passwords and leaked lists",
          "Rule-based attacks: Append numbers, l33t speak, case changes",
          "Mask attacks: When you know the pattern (e.g., 8 chars starting with capital)",
          "Combinator attacks: Joining wordlists together",
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
          "Check if password appears in email confirmations",
          "Monitor network traffic for password transmission",
          "SQL injection to extract password hashes for analysis",
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
        subtitle: "Understanding Authentication Flows",
        points: [
          "Authentication is rarely a single step - it's a flow with multiple states",
          "Each step in the flow is a potential point of failure",
          "State transitions must be validated server-side, not client-side",
          "Attackers look for ways to skip, repeat, or manipulate steps",
        ],
      },
      {
        subtitle: "Normal Login Flow",
        points: [
          "1. User submits credentials (username + password)",
          "2. Server validates credentials against stored hash",
          "3. If MFA enabled: Server challenges for second factor",
          "4. User provides MFA code",
          "5. Server creates authenticated session",
          "6. Client receives session identifier",
          "CRITICAL: Each step must be server-validated, never client-only",
        ],
      },
      {
        subtitle: "Common Login Logic Mistakes",
        points: [
          "Client-side only validation (JavaScript checks that can be bypassed)",
          "Hidden fields controlling access level (isAdmin=true)",
          "Role/admin flag in cookies or localStorage",
          "Inconsistent validation between endpoints",
          "Race conditions in multi-step flows",
          "Trusting client-provided redirect URLs",
          "Not invalidating previous sessions on password change",
        ],
      },
      {
        subtitle: "Password Reset Security",
        points: [
          "Reset flow is often weaker than login - it's a backdoor",
          "Token requirements: unique, random, time-limited, single-use",
          "Token should be tied to specific account (can't change user_id)",
          "Old tokens should be invalidated when new one is requested",
          "Should require re-authentication for email change",
          "Rate limit reset requests to prevent email bombing",
        ],
      },
      {
        subtitle: "Secure Password Reset Implementation",
        points: [
          "One-time token, unique per request (128+ bits random)",
          "Short expiry (15-60 minutes maximum)",
          "Tied to specific account (validated server-side)",
          "Invalidated immediately after use",
          "Invalidated when new reset is requested",
          "Sent only to verified email/phone",
          "Log all reset attempts for audit trail",
        ],
      },
      {
        subtitle: "Multi-Factor Authentication (MFA)",
        points: [
          "MFA adds a second verification factor beyond password",
          "Dramatically reduces account takeover risk",
          "Should be required for sensitive operations (step-up auth)",
          "MFA is only as strong as its weakest recovery option",
          "Implementation details matter - MFA can be bypassed if done wrong",
        ],
      },
      {
        subtitle: "MFA Types and Strengths",
        table: {
          headers: ["Type", "Security Level", "Weaknesses"],
          rows: [
            ["SMS OTP", "Low", "SIM swap, SS7 attacks, interception, social engineering"],
            ["TOTP Apps", "Medium", "Seed theft, phishing (real-time relay), device compromise"],
            ["Push Notifications", "Medium", "MFA fatigue, phishing, malware on device"],
            ["Hardware Keys (FIDO2)", "High", "Physical theft only, phishing resistant"],
            ["Backup Codes", "Varies", "Often stored insecurely, may not expire"],
            ["Biometrics", "Medium", "Can't be changed if compromised, spoofing attacks"],
          ],
        },
      },
      {
        subtitle: "Step-Up Authentication",
        points: [
          "Normal actions: Standard session authentication",
          "Sensitive actions: Require re-authentication or MFA",
          "Examples: Changing email, changing password, viewing PII, making payments",
          "Prevents attackers from abusing stolen sessions for high-value actions",
          "Time-limited: Step-up token should expire quickly (5-15 minutes)",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "Login Flow Attacks",
        testIdeas: [
          "Remove or change hidden fields (isAdmin, role, accessLevel)",
          "Skip steps in multi-step login (go directly to step 3)",
          "Replay successful responses to different requests",
          "Change redirect URLs after login (open redirect)",
          "Try OAuth flows without completing all steps",
          "Modify session state between steps",
          "Test for race conditions (parallel requests)",
          "Check if failed login reveals state about the account",
        ],
      },
      {
        subtitle: "Password Reset Attacks",
        testIdeas: [
          "Use the same reset link more than once",
          "Change user identifiers in reset URLs (user_id, email)",
          "Request multiple resets: are old tokens invalidated?",
          "Guess or brute force short/predictable tokens",
          "Check if reset works for other users (parameter tampering)",
          "Test token expiry: does it actually expire?",
          "Reset flow CSRF: can you reset someone else's password?",
          "Test rate limiting on reset endpoint",
          "Check if reset token leaks in Referer header",
        ],
      },
      {
        subtitle: "MFA Bypass Techniques",
        testIdeas: [
          "Disable MFA without re-entering password",
          "Change email/phone without re-authentication",
          "Use existing sessions that were created before MFA was enabled",
          "Skip MFA step by directly accessing post-MFA URLs",
          "Brute force short OTP codes (4-6 digits = 1M combinations)",
          "Test backup code reuse (should be single-use)",
          "MFA fatigue: spam push notifications until user approves",
          "Check if MFA can be bypassed via API vs web",
          "Test account recovery flow for MFA bypass",
          "Social engineering: 'I lost my phone' scenarios",
          "Real-time phishing: relay OTP codes in real-time",
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
        subtitle: "Why Tokens?",
        points: [
          "APIs often can't use cookies (mobile apps, SPAs, cross-domain)",
          "Tokens provide a portable way to prove authentication",
          "Can be sent in headers, making them work across different contexts",
          "Enable stateless authentication when designed correctly",
        ],
      },
      {
        subtitle: "Opaque vs Structured Tokens",
        points: [
          "Opaque: Random string, meaning stored server-side",
          "  → Server must lookup token in database for every request",
          "  → Easy to revoke (just delete from database)",
          "  → Harder to scale (database dependency)",
          "Structured (JWT): All data encoded in the token itself",
          "  → Stateless: server validates signature, no database lookup",
          "  → Scales easily (no shared state needed)",
          "  → Harder to revoke (must track blacklist or use short expiration)",
          "  → Token contains readable data (base64, not encrypted)",
        ],
      },
      {
        subtitle: "JWT Structure Explained",
        points: [
          "JWT = Header + Payload + Signature, separated by dots",
          "Header: Algorithm (alg) and token type (typ)",
          "Payload: Claims about the user and token",
          "Signature: Cryptographic proof that header+payload weren't tampered",
          "Anyone can READ a JWT (it's just base64), but only the issuer can CREATE a valid one",
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
  "iat": 1234567890,       // Issued at (Unix timestamp)
  "exp": 1234571490,       // Expiration (Unix timestamp)
  "iss": "myapp.com",      // Issuer
  "aud": "api.myapp.com",  // Audience (intended recipient)
  "role": "admin",         // Custom claim
  "scope": "read write"    // Permissions
}

// Signature = Algorithm(
//   base64UrlEncode(header) + "." + base64UrlEncode(payload),
//   secret or privateKey
// )`,
      },
      {
        subtitle: "JWT Signing Methods",
        table: {
          headers: ["Algorithm", "Type", "Key", "Use Case"],
          rows: [
            ["HS256", "Symmetric", "Shared secret (HMAC)", "Single service, simple setup"],
            ["RS256", "Asymmetric", "RSA private/public", "Multiple services can verify"],
            ["ES256", "Asymmetric", "ECDSA keys", "Smaller keys, same security"],
            ["none", "NONE", "No signature", "DANGEROUS - never accept"],
          ],
        },
      },
      {
        subtitle: "Access Tokens vs Refresh Tokens",
        points: [
          "Access Token: Short-lived (minutes to hours), used for API requests",
          "Refresh Token: Long-lived (days to weeks), used to get new access tokens",
          "Why separate? Limits damage if access token is stolen",
          "Refresh tokens should be stored more securely than access tokens",
          "Refresh token rotation: issue new refresh token with each use",
        ],
      },
      {
        subtitle: "Token Best Practices",
        points: [
          "Keep access tokens short-lived (5-15 minutes)",
          "Validate ALL claims: exp, nbf, iss, aud, not just signature",
          "Use asymmetric signing (RS256/ES256) when multiple services verify",
          "Never put sensitive data in JWT payload (it's readable)",
          "Implement token revocation strategy (blacklist or short expiry)",
          "Transmit over HTTPS only",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "JWT Inspection",
        points: [
          "Base64 decode header and payload (jwt.io, jwt_tool)",
          "Check claims: role, user_id, tenant_id, scopes",
          "Note algorithm in header (look for 'none' or symmetric when asymmetric expected)",
          "Check expiration time (exp claim) - is it reasonable?",
          "Look for sensitive data exposed in payload",
          "Check issuer (iss) and audience (aud) claims",
        ],
      },
      {
        subtitle: "Classic JWT Vulnerabilities",
        points: [
          "Algorithm None: Change alg to 'none', remove signature",
          "Algorithm Confusion: Change RS256 to HS256, sign with public key",
          "Weak HMAC Secret: Brute force with common passwords/keys",
          "Missing Signature Verification: Server doesn't check signature at all",
          "Missing Claim Validation: exp, iss, aud not checked",
          "Key ID (kid) Injection: SQL injection, path traversal via kid header",
          "JKU/X5U Attacks: Point to attacker-controlled key URL",
        ],
      },
      {
        subtitle: "JWT Attack Techniques",
        testIdeas: [
          "Change alg to 'none' and remove signature",
          "Switch RS256 to HS256, sign with public key as secret",
          "Modify claims (role: admin) and re-sign if key known",
          "Brute force weak HMAC secrets (use hashcat mode 16500)",
          "Replay tokens across different users/devices/apps",
          "Use expired tokens: does server actually check exp?",
          "Test token revocation: can you use token after logout?",
          "Check for kid (key ID) injection vulnerabilities",
          "Look for jku header pointing to attacker-controlled JWKS",
          "Test x5u for certificate URL injection",
          "Check if same token works across different environments (dev/prod)",
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
        subtitle: "What is OAuth?",
        points: [
          "OAuth is an AUTHORIZATION framework (not authentication)",
          "Allows apps to access user data without knowing user's password",
          "Example: 'Sign in with Google' - Google gives app a token to access your data",
          "The app never sees your Google password",
          "OAuth 2.0 is the current standard (OAuth 1.0 is deprecated)",
        ],
      },
      {
        subtitle: "OAuth 2.0 Roles",
        points: [
          "Resource Owner: The user who owns the data (you)",
          "Client: The app wanting to access data (third-party app)",
          "Authorization Server: Issues tokens (Google, Okta, Auth0)",
          "Resource Server: Hosts the protected data/API",
          "The user authorizes the client to access resources on their behalf",
        ],
      },
      {
        subtitle: "OAuth vs OpenID Connect (OIDC)",
        points: [
          "OAuth 2.0: Authorization only ('can this app access my photos?')",
          "OIDC: OAuth 2.0 + Authentication ('who is this user?')",
          "OIDC adds ID Token: a JWT containing user identity info",
          "Use OIDC when you need to know WHO the user is",
          "Use OAuth when you just need ACCESS to resources",
        ],
      },
      {
        subtitle: "OAuth Flows",
        table: {
          headers: ["Flow", "Use Case", "Security Level"],
          rows: [
            ["Authorization Code", "Server-side apps", "Most secure - code exchanged server-side"],
            ["Authorization Code + PKCE", "Mobile/SPA apps", "Secure for public clients"],
            ["Implicit (Legacy)", "SPAs (deprecated)", "Token in URL fragment, avoid"],
            ["Client Credentials", "Machine-to-machine", "No user involved, service-to-service"],
            ["Device Code", "Smart TVs, CLI", "User approves on another device"],
            ["Resource Owner Password", "Legacy only", "Anti-pattern, avoid"],
          ],
        },
      },
      {
        subtitle: "Authorization Code Flow (Most Common)",
        points: [
          "1. App redirects user to authorization server with client_id, redirect_uri, scope, state",
          "2. User logs in and consents to permissions",
          "3. Auth server redirects back with authorization code",
          "4. App exchanges code for tokens (server-to-server, includes client_secret)",
          "5. App receives access_token (and optionally refresh_token, id_token)",
          "The code is short-lived and can only be used once",
        ],
      },
      {
        subtitle: "PKCE: Protecting Public Clients",
        points: [
          "PKCE = Proof Key for Code Exchange (pronounced 'pixy')",
          "Problem: Mobile/SPA apps can't keep client_secret secret",
          "Solution: Generate random code_verifier, send hash (code_challenge) with auth request",
          "When exchanging code, prove you have the original code_verifier",
          "Prevents authorization code interception attacks",
          "REQUIRED for mobile apps and SPAs, recommended for all OAuth flows",
        ],
      },
      {
        subtitle: "SSO Basics",
        points: [
          "Single Sign-On: One login for multiple applications",
          "Identity Provider (IdP): Manages user identities (Okta, Azure AD)",
          "Service Provider (SP): Your application",
          "SAML: XML-based, enterprise-focused, more complex",
          "OIDC: Modern, JSON-based, built on OAuth 2.0",
          "When user logs into IdP, all SPs trust that authentication",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "Common OAuth Vulnerabilities",
        points: [
          "Open redirect via redirect_uri manipulation",
          "Missing or weak state parameter (CSRF)",
          "Authorization code leakage (Referer header, logs)",
          "Access tokens in URL fragments (Implicit flow)",
          "Token exposure in browser history",
          "Insufficient scope validation",
          "Client impersonation (weak client authentication)",
        ],
      },
      {
        subtitle: "Redirect URI Attacks",
        points: [
          "Goal: Steal authorization code or token via malicious redirect",
          "Subdomain takeover: redirect to attacker-controlled subdomain",
          "Path traversal: /callback/../../../attacker",
          "Parameter pollution: redirect_uri=legit.com&redirect_uri=evil.com",
          "Open redirects on legitimate domain: /redirect?url=evil.com",
          "Fragment injection: legitimate.com#@evil.com",
        ],
      },
      {
        subtitle: "OAuth Testing",
        testIdeas: [
          "Modify redirect_uri: subdomain, path traversal, parameter pollution",
          "Remove or reuse state parameter (test for CSRF)",
          "Swap authorization codes between users",
          "Use tokens from one client in another",
          "Check if implicit tokens work on code endpoints",
          "Test scope escalation: request more than granted",
          "PKCE bypass: try without code_verifier",
          "Check token exposure in browser history, logs",
          "Test authorization code reuse",
          "Look for open redirects on the redirect_uri domain",
          "Test IdP confusion in multi-tenant scenarios",
          "Check for account linking vulnerabilities",
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
        subtitle: "AuthN vs AuthZ: The Critical Distinction",
        points: [
          "Authentication (AuthN): Who are you? (Identity verification)",
          "Authorization (AuthZ): What can you do? (Permission checking)",
          "Both must be checked on EVERY request, not just at login",
          "Common mistake: checking AuthN but not AuthZ",
          "Authentication says 'this is user 123' - Authorization says 'user 123 can view orders but not delete them'",
        ],
      },
      {
        subtitle: "Why Access Control Fails",
        points: [
          "Developers assume checked once = checked always (it's not)",
          "Frontend hides buttons, but API is still accessible",
          "Object IDs are guessable or sequential",
          "Roles/permissions stored client-side or in JWTs",
          "Inconsistent enforcement across endpoints",
          "'Security by obscurity' - assuming attackers won't find the endpoint",
          "Testing only happy paths, not adversarial scenarios",
        ],
      },
      {
        subtitle: "Access Control Models",
        table: {
          headers: ["Model", "Description", "Example", "Best For"],
          rows: [
            ["RBAC", "Role-Based Access Control", "admin, editor, viewer roles", "Simple hierarchical permissions"],
            ["ABAC", "Attribute-Based Access Control", "department=finance AND level>5", "Complex, context-aware rules"],
            ["ReBAC", "Relationship-Based Access Control", "owner, editor, viewer of resource", "Document/resource sharing (Google Docs)"],
            ["ACL", "Access Control List", "Per-resource permission lists", "File system style permissions"],
            ["PBAC", "Policy-Based Access Control", "Centralized policy engine", "Enterprise, audit requirements"],
          ],
        },
      },
      {
        subtitle: "Understanding IDOR / BOLA",
        points: [
          "IDOR = Insecure Direct Object Reference (OWASP Top 10)",
          "BOLA = Broken Object Level Authorization (OWASP API Security #1)",
          "Same vulnerability, different names - extremely common",
          "User A can access User B's data by changing an ID",
          "Example: GET /api/orders/123 → GET /api/orders/124",
          "Any identifier can be vulnerable: order IDs, user IDs, file paths, UUIDs",
          "Even UUIDs aren't safe if they leak via logs, URLs, or responses",
        ],
      },
      {
        subtitle: "Types of Privilege Escalation",
        points: [
          "Horizontal: Access another user's resources at same privilege level",
          "  → User A reads User B's private messages",
          "Vertical: Gain higher privileges than you should have",
          "  → Normal user gains admin access",
          "Context: Access resources outside your scope",
          "  → Tenant A accesses Tenant B's data in multi-tenant app",
        ],
      },
      {
        subtitle: "Secure Access Control Patterns",
        points: [
          "Server-side enforcement: NEVER trust client-side checks alone",
          "Check ownership: Does this user own this resource?",
          "Check permissions: Is this user allowed to perform this action?",
          "Indirect references: Map user-specific IDs to internal IDs server-side",
          "Centralized enforcement: Use middleware/interceptors, not per-endpoint checks",
          "Fail closed: If permission check fails, deny access",
          "Log and alert: Monitor for access control violations",
        ],
      },
      {
        subtitle: "Mass Assignment Vulnerability",
        points: [
          "Also called 'Auto-binding' or 'Object Injection'",
          "User sends extra fields that get bound to internal objects",
          "Example: POST /api/users with body {name: 'John', isAdmin: true}",
          "Server trusts all input fields and sets user as admin",
          "Prevention: Explicitly whitelist allowed fields, use DTOs",
        ],
      },
    ],
    attackerContent: [
      {
        subtitle: "Horizontal Privilege Escalation Testing",
        testIdeas: [
          "Replace numeric IDs with another user's ID (123 → 124)",
          "Swap GUIDs, emails, or usernames in requests",
          "Use your token to access another user's resources",
          "Check bulk operations: can you include others' IDs?",
          "Test GraphQL queries with other users' IDs",
          "Test with negative numbers, zero, or very large numbers",
          "Try parameter pollution: ?id=123&id=456",
          "Check if deleted resources are still accessible",
          "Test file download endpoints with path traversal",
        ],
      },
      {
        subtitle: "Vertical Privilege Escalation Testing",
        testIdeas: [
          "Call admin endpoints as normal user (guess /admin/, /api/admin/)",
          "Modify role/isAdmin/privilege parameters in requests",
          "Access /admin paths without admin role",
          "Change plan/tier identifiers (free → premium, plan_id=1 → plan_id=3)",
          "Test feature flags for premium features",
          "Check if client-side role checks exist server-side",
          "Try adding admin-only parameters to normal requests",
          "Test HTTP method swapping (GET vs POST vs PUT vs DELETE)",
          "Check if debug endpoints are accessible in production",
        ],
      },
      {
        subtitle: "Multi-Tenancy Testing",
        testIdeas: [
          "Access resources using other tenant's identifiers",
          "Check if tenant isolation exists at database level",
          "Test shared resources across tenants",
          "Try tenant header manipulation (X-Tenant-ID)",
          "Check subdomain-based tenant isolation",
          "Test cross-tenant API key usage",
        ],
      },
      {
        subtitle: "Mass Assignment Testing",
        testIdeas: [
          "Add role/isAdmin/privilege fields to user update requests",
          "Include internal fields: id, createdAt, updatedAt, deletedAt",
          "Try nested objects: profile.role, user.permissions[]",
          "Test array parameters: roles[]=admin",
          "Check if GraphQL mutations allow extra fields",
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
        subtitle: "Why Checklists Matter",
        points: [
          "Security testing requires systematic coverage",
          "Memory isn't reliable - checklists ensure consistency",
          "Helps communicate what was tested (and what wasn't)",
          "Provides evidence for compliance and audits",
          "Ensures you don't miss obvious issues under time pressure",
        ],
      },
      {
        subtitle: "Testing Methodology",
        points: [
          "1. Reconnaissance: Map all auth endpoints and flows",
          "2. Analysis: Understand how authentication works",
          "3. Testing: Systematically test each component",
          "4. Documentation: Record findings with evidence",
          "5. Verification: Confirm fixes actually work",
          "Test from multiple perspectives: unauthenticated, user, admin",
          "Compare web vs mobile vs API behavior",
        ],
      },
      {
        subtitle: "Tools for Auth Testing",
        table: {
          headers: ["Tool", "Purpose", "Key Features"],
          rows: [
            ["Burp Suite", "HTTP interception", "Repeater, Intruder, proxy"],
            ["jwt_tool", "JWT analysis", "Attack modes, key cracking"],
            ["Hashcat", "Password cracking", "GPU acceleration, rule-based"],
            ["ffuf/gobuster", "Directory enumeration", "Fast, customizable wordlists"],
            ["Postman", "API testing", "Collections, environments"],
            ["OWASP ZAP", "Automated scanning", "Free, active scanning"],
            ["Hydra", "Online brute force", "Multiple protocols"],
            ["CyberChef", "Data encoding", "Decode/encode chains"],
          ],
        },
      },
    ],
    attackerContent: [
      {
        subtitle: "🔍 Reconnaissance Checklist",
        testIdeas: [
          "□ Map all auth endpoints: /login, /register, /reset, /logout, /verify",
          "□ Find API auth endpoints: /api/auth/, /api/v1/login",
          "□ Check for legacy endpoints: /auth-old, /login_v1",
          "□ Identify session storage: cookies, localStorage, sessionStorage",
          "□ Note token types: JWT, opaque, API keys",
          "□ Check TLS configuration: version, ciphers, certificates",
          "□ Find OAuth/SSO providers in use",
          "□ Identify MFA mechanisms",
          "□ Map admin/privileged endpoints",
        ],
      },
      {
        subtitle: "🔐 Authentication Checklist",
        testIdeas: [
          "□ User enumeration via login, register, reset responses/timing",
          "□ Rate limiting on login endpoint",
          "□ Account lockout after failed attempts",
          "□ Password complexity requirements",
          "□ Brute force protection effectiveness",
          "□ Default credentials (admin/admin)",
          "□ Case sensitivity issues (Admin vs admin)",
          "□ Whitespace handling (password vs ' password ')",
          "□ Unicode normalization attacks",
        ],
      },
      {
        subtitle: "🍪 Session & Cookie Checklist",
        testIdeas: [
          "□ Secure flag on cookies (HTTPS only)",
          "□ HttpOnly flag (no JavaScript access)",
          "□ SameSite attribute (CSRF protection)",
          "□ Session ID randomness (entropy)",
          "□ Session regeneration after login",
          "□ Session timeout (idle and absolute)",
          "□ Logout invalidates session server-side",
          "□ Concurrent session handling",
          "□ Session fixation resistance",
        ],
      },
      {
        subtitle: "🎟️ Token & JWT Checklist",
        testIdeas: [
          "□ Algorithm 'none' attack",
          "□ Algorithm confusion (RS256 → HS256)",
          "□ Weak HMAC secret brute force",
          "□ Signature verification present",
          "□ Expiration (exp) claim validated",
          "□ Issuer (iss) and audience (aud) validated",
          "□ Sensitive data not in payload",
          "□ Token revocation works",
          "□ kid/jku/x5u injection",
        ],
      },
      {
        subtitle: "🔄 Password Reset Checklist",
        testIdeas: [
          "□ Token entropy (randomness)",
          "□ Token expiration enforced",
          "□ Single-use (token invalidated after use)",
          "□ Old tokens invalidated on new request",
          "□ User ID can't be changed in reset request",
          "□ Rate limiting on reset endpoint",
          "□ Token not leaked in Referer header",
          "□ Email/account enumeration via reset",
          "□ Reset flow CSRF protection",
        ],
      },
      {
        subtitle: "🔑 MFA Checklist",
        testIdeas: [
          "□ MFA can't be disabled without re-auth",
          "□ MFA step can't be skipped",
          "□ OTP brute force protection",
          "□ Backup codes are single-use",
          "□ Recovery flow doesn't bypass MFA",
          "□ Push notification fatigue resistance",
          "□ MFA required for sensitive operations",
          "□ API endpoints require MFA same as web",
        ],
      },
      {
        subtitle: "🚪 Access Control Checklist",
        testIdeas: [
          "□ IDOR on all object ID parameters",
          "□ Horizontal escalation (user to user)",
          "□ Vertical escalation (user to admin)",
          "□ Admin endpoints accessible to users",
          "□ Mass assignment on create/update",
          "□ Function-level access control",
          "□ Multi-tenant isolation",
          "□ Feature/plan restrictions enforced",
          "□ Delete/archive permissions",
        ],
      },
      {
        subtitle: "🌐 OAuth/SSO Checklist",
        testIdeas: [
          "□ redirect_uri validation strictness",
          "□ State parameter present and validated",
          "□ PKCE for public clients",
          "□ Authorization code reuse",
          "□ Token leakage in logs/history",
          "□ Scope escalation",
          "□ Client credential security",
          "□ SAML signature validation",
          "□ IdP confusion attacks",
        ],
      },
      {
        subtitle: "Post-Testing Summary",
        points: [
          "Document all findings with reproduction steps",
          "Rate severity: Critical > High > Medium > Low > Info",
          "Provide remediation recommendations",
          "Note what WAS tested (coverage evidence)",
          "Note what WASN'T tested and why",
          "Schedule re-test after fixes are applied",
        ],
      },
    ],
  },
];

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#10b981";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "What is the difference between authentication and authorization?",
    options: [
      "Authentication checks permissions, authorization checks identity",
      "Authentication verifies identity, authorization checks permissions",
      "They are the same thing",
      "Authorization happens before authentication",
    ],
    correctAnswer: 1,
    explanation: "Authentication proves who you are; authorization decides what you can access.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "Multi-factor authentication (MFA) means:",
    options: [
      "Using multiple passwords",
      "Using two or more verification factors",
      "Logging in from multiple devices",
      "Disabling password resets",
    ],
    correctAnswer: 1,
    explanation: "MFA combines factors like something you know, have, or are.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "Credential stuffing is:",
    options: [
      "A secure password vault",
      "Reusing stolen credentials across sites",
      "A rate limiting technique",
      "A password hashing method",
    ],
    correctAnswer: 1,
    explanation: "Attackers try breached username/password pairs on other services.",
  },
  {
    id: 4,
    topic: "Fundamentals",
    question: "Session fixation occurs when:",
    options: [
      "A session never expires",
      "An attacker sets a known session ID before login",
      "A cookie is HttpOnly",
      "A token is signed with RSA",
    ],
    correctAnswer: 1,
    explanation: "Attackers try to force victims to use a session ID they control.",
  },
  {
    id: 5,
    topic: "Fundamentals",
    question: "Password spraying is:",
    options: [
      "Trying many passwords on a single account",
      "Trying a few common passwords across many accounts",
      "Resetting passwords for all users",
      "Using a password manager",
    ],
    correctAnswer: 1,
    explanation: "Spraying avoids lockouts by using a small set of common passwords.",
  },
  {
    id: 6,
    topic: "Fundamentals",
    question: "Rate limiting on authentication endpoints is used to:",
    options: [
      "Improve UI performance",
      "Slow brute force attempts",
      "Encrypt passwords",
      "Disable MFA",
    ],
    correctAnswer: 1,
    explanation: "Rate limiting reduces automated guessing speed.",
  },
  {
    id: 7,
    topic: "Fundamentals",
    question: "Why should login error messages be generic?",
    options: [
      "To improve SEO",
      "To prevent user enumeration",
      "To speed up responses",
      "To disable logging",
    ],
    correctAnswer: 1,
    explanation: "Different messages leak which users exist.",
  },
  {
    id: 8,
    topic: "Fundamentals",
    question: "The authentication surface is:",
    options: [
      "Only the login page",
      "All endpoints and flows that verify identity",
      "Only the database",
      "Only mobile apps",
    ],
    correctAnswer: 1,
    explanation: "Any auth flow or endpoint expands the attack surface.",
  },
  {
    id: 9,
    topic: "Fundamentals",
    question: "Client-side authentication checks are insufficient because:",
    options: [
      "They are too fast",
      "They can be bypassed or modified",
      "They require TLS",
      "They always fail",
    ],
    correctAnswer: 1,
    explanation: "Attackers can skip or alter client-side checks.",
  },
  {
    id: 10,
    topic: "Fundamentals",
    question: "Least privilege in access control means:",
    options: [
      "Everyone is an admin",
      "Users get only the permissions they need",
      "Permissions never change",
      "No one can log in",
    ],
    correctAnswer: 1,
    explanation: "Reducing permissions limits blast radius.",
  },
  {
    id: 11,
    topic: "Sessions",
    question: "A session is:",
    options: [
      "A random password",
      "Server-side state tied to an authenticated user",
      "A TLS certificate",
      "A public key",
    ],
    correctAnswer: 1,
    explanation: "Sessions associate multiple requests with one user identity.",
  },
  {
    id: 12,
    topic: "Sessions",
    question: "The HttpOnly cookie flag prevents:",
    options: [
      "Cookies being sent over HTTPS",
      "JavaScript access to cookies",
      "Cookies being stored",
      "Session expiration",
    ],
    correctAnswer: 1,
    explanation: "HttpOnly protects cookies from XSS-based theft.",
  },
  {
    id: 13,
    topic: "Sessions",
    question: "The Secure cookie flag means:",
    options: [
      "Send only over HTTPS",
      "Send only over HTTP",
      "Never send the cookie",
      "Encrypt the cookie",
    ],
    correctAnswer: 0,
    explanation: "Secure cookies are restricted to HTTPS.",
  },
  {
    id: 14,
    topic: "Sessions",
    question: "SameSite=Strict helps prevent:",
    options: [
      "SQL injection",
      "CSRF",
      "XSS",
      "RCE",
    ],
    correctAnswer: 1,
    explanation: "SameSite limits cross-site requests that carry cookies.",
  },
  {
    id: 15,
    topic: "Sessions",
    question: "Regenerating session IDs on login prevents:",
    options: [
      "Session fixation",
      "Password spraying",
      "TLS downgrade",
      "Token refresh",
    ],
    correctAnswer: 0,
    explanation: "New session IDs stop attackers from using a fixed ID.",
  },
  {
    id: 16,
    topic: "Sessions",
    question: "Where is the safest place to store web session tokens?",
    options: [
      "localStorage",
      "HttpOnly cookies",
      "URL query parameters",
      "SessionStorage without HttpOnly",
    ],
    correctAnswer: 1,
    explanation: "HttpOnly cookies reduce XSS token theft risk.",
  },
  {
    id: 17,
    topic: "Sessions",
    question: "Session timeouts are used to:",
    options: [
      "Increase session lifetime",
      "Limit how long a session stays valid",
      "Disable logging",
      "Avoid MFA",
    ],
    correctAnswer: 1,
    explanation: "Shorter lifetimes reduce exposure from stolen sessions.",
  },
  {
    id: 18,
    topic: "Sessions",
    question: "Logout should ideally:",
    options: [
      "Only clear client cookies",
      "Invalidate the server-side session",
      "Do nothing",
      "Change the password",
    ],
    correctAnswer: 1,
    explanation: "Server invalidation prevents reuse of stolen tokens.",
  },
  {
    id: 19,
    topic: "Sessions",
    question: "Session IDs in URLs are risky because:",
    options: [
      "They are encrypted",
      "They leak via logs and referrers",
      "They improve caching",
      "They are required by OAuth",
    ],
    correctAnswer: 1,
    explanation: "URLs are shared and logged, exposing session IDs.",
  },
  {
    id: 20,
    topic: "Sessions",
    question: "CSRF tokens protect against:",
    options: [
      "Cross-site request forgery",
      "Brute force",
      "SQL injection",
      "Credential stuffing",
    ],
    correctAnswer: 0,
    explanation: "CSRF tokens ensure requests are intentional and same-site.",
  },
  {
    id: 21,
    topic: "Passwords",
    question: "Hashing vs encryption: hashing is:",
    options: [
      "Reversible with a key",
      "One-way and not reversible",
      "The same as encoding",
      "Only for TLS",
    ],
    correctAnswer: 1,
    explanation: "Password hashes should not be reversible.",
  },
  {
    id: 22,
    topic: "Passwords",
    question: "Recommended password hashing algorithms are:",
    options: [
      "MD5 and SHA1",
      "bcrypt, Argon2, or scrypt",
      "Base64",
      "ROT13",
    ],
    correctAnswer: 1,
    explanation: "These are slow, adaptive hashing algorithms designed for passwords.",
  },
  {
    id: 23,
    topic: "Passwords",
    question: "The purpose of a salt is to:",
    options: [
      "Encrypt the password",
      "Make each hash unique and prevent rainbow tables",
      "Speed up hashing",
      "Replace the password",
    ],
    correctAnswer: 1,
    explanation: "Salts make precomputed attacks ineffective.",
  },
  {
    id: 24,
    topic: "Passwords",
    question: "A pepper is:",
    options: [
      "A client-side secret",
      "A server-side secret added before hashing",
      "A type of MFA token",
      "A TLS extension",
    ],
    correctAnswer: 1,
    explanation: "Peppers add a server-held secret to each hash.",
  },
  {
    id: 25,
    topic: "Passwords",
    question: "MD5 and SHA1 are poor for passwords because:",
    options: [
      "They are too slow",
      "They are fast and easily brute forced",
      "They are encrypted",
      "They require TLS",
    ],
    correctAnswer: 1,
    explanation: "Fast hashes enable high-speed offline cracking.",
  },
  {
    id: 26,
    topic: "Passwords",
    question: "Slow password hashing reduces risk by:",
    options: [
      "Making brute force attempts expensive",
      "Disabling MFA",
      "Increasing cookie size",
      "Turning off logging",
    ],
    correctAnswer: 0,
    explanation: "Higher cost slows attackers trying many guesses.",
  },
  {
    id: 27,
    topic: "Passwords",
    question: "A rainbow table is:",
    options: [
      "A list of encrypted emails",
      "Precomputed hash values used for cracking",
      "A TLS cipher suite",
      "A session store",
    ],
    correctAnswer: 1,
    explanation: "Rainbow tables map common passwords to hashes.",
  },
  {
    id: 28,
    topic: "Passwords",
    question: "Password reset tokens should be:",
    options: [
      "Short and predictable",
      "Random, short-lived, and one-time",
      "Stored in URLs for weeks",
      "Reused across users",
    ],
    correctAnswer: 1,
    explanation: "Reset tokens must be unguessable and expire quickly.",
  },
  {
    id: 29,
    topic: "Passwords",
    question: "Storing passwords with reversible encryption is risky because:",
    options: [
      "It improves UX",
      "If the key leaks, all passwords are exposed",
      "It slows logins",
      "It blocks MFA",
    ],
    correctAnswer: 1,
    explanation: "Encryption can be reversed if keys are compromised.",
  },
  {
    id: 30,
    topic: "Passwords",
    question: "Password hints are discouraged because they:",
    options: [
      "Increase password entropy",
      "Leak information about the password",
      "Stop brute force",
      "Enable MFA",
    ],
    correctAnswer: 1,
    explanation: "Hints give attackers clues for guessing.",
  },
  {
    id: 31,
    topic: "MFA",
    question: "TOTP stands for:",
    options: [
      "Time-based One-Time Password",
      "Tokenized Online Password Transfer",
      "Temporary OAuth Token",
      "Trusted One-Time Protocol",
    ],
    correctAnswer: 0,
    explanation: "TOTP uses the current time and a shared secret.",
  },
  {
    id: 32,
    topic: "MFA",
    question: "A common weakness of SMS OTP is:",
    options: [
      "It is too long",
      "SIM swap and interception attacks",
      "It requires HTTPS",
      "It uses strong cryptography",
    ],
    correctAnswer: 1,
    explanation: "SMS can be intercepted or hijacked via SIM swaps.",
  },
  {
    id: 33,
    topic: "MFA",
    question: "MFA fatigue refers to:",
    options: [
      "Users ignoring strong passwords",
      "Repeated push prompts until a user approves",
      "Rate limiting failures",
      "Strong token rotation",
    ],
    correctAnswer: 1,
    explanation: "Attackers spam push approvals hoping for a mistake.",
  },
  {
    id: 34,
    topic: "MFA",
    question: "Hardware security keys are strong because they are:",
    options: [
      "Phishing resistant and use cryptographic challenges",
      "Easy to copy",
      "Based on SMS",
      "Stored in localStorage",
    ],
    correctAnswer: 0,
    explanation: "FIDO2/WebAuthn keys verify origin and resist phishing.",
  },
  {
    id: 35,
    topic: "MFA",
    question: "Backup codes should be:",
    options: [
      "Reused across logins",
      "Single-use and stored securely",
      "Posted in plain text",
      "Shared with support",
    ],
    correctAnswer: 1,
    explanation: "Backup codes act like passwords and must be protected.",
  },
  {
    id: 36,
    topic: "MFA",
    question: "Rate limiting should typically apply to:",
    options: [
      "Only one IP address",
      "Both account and IP behavior",
      "Only admins",
      "Only GET requests",
    ],
    correctAnswer: 1,
    explanation: "Combining signals reduces bypass options.",
  },
  {
    id: 37,
    topic: "MFA",
    question: "Step-up authentication is used for:",
    options: [
      "Viewing a public page",
      "Sensitive actions like changing email or payout details",
      "Loading images",
      "Logging out",
    ],
    correctAnswer: 1,
    explanation: "High-risk actions should require stronger verification.",
  },
  {
    id: 38,
    topic: "MFA",
    question: "Remembered devices should:",
    options: [
      "Never expire",
      "Expire and be revocable",
      "Skip logging",
      "Disable MFA entirely",
    ],
    correctAnswer: 1,
    explanation: "Long-lived trusted devices increase risk if stolen.",
  },
  {
    id: 39,
    topic: "MFA",
    question: "Account lockout is helpful but can be abused for:",
    options: [
      "Denial of service against users",
      "Password hashing",
      "TLS downgrade",
      "Session fixation",
    ],
    correctAnswer: 0,
    explanation: "Attackers can intentionally lock out victims.",
  },
  {
    id: 40,
    topic: "MFA",
    question: "Adaptive authentication uses:",
    options: [
      "Only a password",
      "Risk signals like device, IP, or location",
      "Static passwords only",
      "Base64 tokens",
    ],
    correctAnswer: 1,
    explanation: "Risk-based signals adjust authentication requirements.",
  },
  {
    id: 41,
    topic: "OAuth",
    question: "OAuth 2.0 is primarily an:",
    options: [
      "Authentication protocol",
      "Authorization framework for delegated access",
      "Encryption standard",
      "Password hashing method",
    ],
    correctAnswer: 1,
    explanation: "OAuth is designed for delegated authorization.",
  },
  {
    id: 42,
    topic: "OAuth",
    question: "OpenID Connect (OIDC) adds:",
    options: [
      "Identity layer on top of OAuth",
      "A new hashing algorithm",
      "TLS certificates",
      "Database encryption",
    ],
    correctAnswer: 0,
    explanation: "OIDC provides authentication on top of OAuth.",
  },
  {
    id: 43,
    topic: "OAuth",
    question: "Validating redirect URIs prevents:",
    options: [
      "Token leakage to attacker-controlled sites",
      "Password hashing errors",
      "TLS expiration",
      "MFA fatigue",
    ],
    correctAnswer: 0,
    explanation: "Open redirects can steal authorization codes or tokens.",
  },
  {
    id: 44,
    topic: "OAuth",
    question: "The authorization code flow is recommended for:",
    options: [
      "Server-side applications with a backend",
      "Legacy browsers only",
      "Static HTML without a backend",
      "Email clients",
    ],
    correctAnswer: 0,
    explanation: "It keeps tokens off the front end and supports secure exchanges.",
  },
  {
    id: 45,
    topic: "OAuth",
    question: "The implicit flow is discouraged because:",
    options: [
      "Tokens are exposed in URLs and clients cannot keep secrets",
      "It uses HTTPS",
      "It requires PKCE",
      "It rotates keys too often",
    ],
    correctAnswer: 0,
    explanation: "Modern guidance prefers code flow with PKCE.",
  },
  {
    id: 46,
    topic: "OAuth",
    question: "PKCE protects against:",
    options: [
      "Authorization code interception attacks",
      "SQL injection",
      "CSRF in forms",
      "XSS in HTML",
    ],
    correctAnswer: 0,
    explanation: "PKCE binds the code to the original client request.",
  },
  {
    id: 47,
    topic: "OAuth",
    question: "The state parameter in OAuth defends against:",
    options: [
      "CSRF",
      "Brute force",
      "Hash collisions",
      "TLS downgrade",
    ],
    correctAnswer: 0,
    explanation: "State ensures the callback matches the original request.",
  },
  {
    id: 48,
    topic: "OAuth",
    question: "Refresh tokens should be:",
    options: [
      "Stored securely and rotated",
      "Publicly logged",
      "Short and guessable",
      "Embedded in URLs",
    ],
    correctAnswer: 0,
    explanation: "Refresh tokens are powerful and must be protected.",
  },
  {
    id: 49,
    topic: "OAuth",
    question: "OAuth scopes should follow:",
    options: [
      "Least privilege",
      "Maximum privilege",
      "No restrictions",
      "Random selection",
    ],
    correctAnswer: 0,
    explanation: "Limit access to only what the client needs.",
  },
  {
    id: 50,
    topic: "OAuth",
    question: "SSO token misuse is reduced by validating:",
    options: [
      "Audience (aud) and issuer (iss) claims",
      "CSS files",
      "Cache headers",
      "Image sizes",
    ],
    correctAnswer: 0,
    explanation: "Audience and issuer validation ensures correct token use.",
  },
  {
    id: 51,
    topic: "JWT",
    question: "A JWT is:",
    options: [
      "A signed token containing claims",
      "A password hashing algorithm",
      "An encryption key",
      "A TLS certificate",
    ],
    correctAnswer: 0,
    explanation: "JWTs carry claims and are protected by signatures.",
  },
  {
    id: 52,
    topic: "JWT",
    question: "Base64 encoding in JWTs is:",
    options: [
      "Encryption",
      "Not encryption, just encoding",
      "A signature",
      "A hash function",
    ],
    correctAnswer: 1,
    explanation: "JWT payloads are readable without the signing key.",
  },
  {
    id: 53,
    topic: "JWT",
    question: "The 'alg=none' issue refers to:",
    options: [
      "Disabling signatures entirely",
      "Using RSA keys",
      "Adding encryption",
      "Using PKCE",
    ],
    correctAnswer: 0,
    explanation: "Tokens must never be accepted without signature validation.",
  },
  {
    id: 54,
    topic: "JWT",
    question: "HS256 vs RS256 means:",
    options: [
      "Symmetric secret vs asymmetric key pair",
      "Two different hashing algorithms only",
      "Both are encryption modes",
      "RS256 uses no signatures",
    ],
    correctAnswer: 0,
    explanation: "HS256 uses a shared secret; RS256 uses a private/public key pair.",
  },
  {
    id: 55,
    topic: "JWT",
    question: "A strong HMAC secret should be:",
    options: [
      "Short and memorable",
      "Long, random, and stored securely",
      "Stored in client-side code",
      "Reused across all apps",
    ],
    correctAnswer: 1,
    explanation: "Weak secrets can be brute forced and forged.",
  },
  {
    id: 56,
    topic: "JWT",
    question: "Token validation should always check:",
    options: [
      "exp and nbf claims",
      "Only the user name",
      "Only the issuer text",
      "Only the UI theme",
    ],
    correctAnswer: 0,
    explanation: "Expiration and not-before limits prevent replay.",
  },
  {
    id: 57,
    topic: "JWT",
    question: "You should only trust JWT claims after:",
    options: [
      "Signature verification",
      "Base64 decoding",
      "Adding a cookie",
      "Checking HTTP status",
    ],
    correctAnswer: 0,
    explanation: "Claims are untrusted until the signature is validated.",
  },
  {
    id: 58,
    topic: "JWT",
    question: "A common challenge with stateless JWTs is:",
    options: [
      "Revocation and logout",
      "TLS encryption",
      "Cookie size limits",
      "OAuth state",
    ],
    correctAnswer: 0,
    explanation: "Stateless tokens are harder to revoke instantly.",
  },
  {
    id: 59,
    topic: "JWT",
    question: "Short-lived access tokens reduce:",
    options: [
      "The window of abuse if stolen",
      "The need for TLS",
      "The need for logging",
      "The need for MFA",
    ],
    correctAnswer: 0,
    explanation: "Short TTL limits exposure from stolen tokens.",
  },
  {
    id: 60,
    topic: "JWT",
    question: "The 'aud' claim is used to:",
    options: [
      "Identify the intended audience of the token",
      "Encrypt the payload",
      "Store the password",
      "Disable MFA",
    ],
    correctAnswer: 0,
    explanation: "Audience validation prevents token replay across services.",
  },
  {
    id: 61,
    topic: "TLS",
    question: "Symmetric encryption uses:",
    options: [
      "The same key for encrypt and decrypt",
      "A public and private key",
      "No keys",
      "Only passwords",
    ],
    correctAnswer: 0,
    explanation: "Symmetric algorithms use a shared secret key.",
  },
  {
    id: 62,
    topic: "TLS",
    question: "Symmetric encryption is typically used for:",
    options: [
      "Bulk data because it is fast",
      "Key exchange only",
      "Certificates",
      "Hashing",
    ],
    correctAnswer: 0,
    explanation: "Symmetric ciphers are efficient for large data.",
  },
  {
    id: 63,
    topic: "TLS",
    question: "TLS provides:",
    options: [
      "Confidentiality, integrity, and server authentication",
      "Only compression",
      "Only DNS security",
      "Only password hashing",
    ],
    correctAnswer: 0,
    explanation: "TLS secures data in transit and verifies the server.",
  },
  {
    id: 64,
    topic: "TLS",
    question: "A certificate chain of trust means:",
    options: [
      "Certificates are validated through trusted CAs",
      "All certificates are self-signed",
      "TLS is optional",
      "Only mobile apps use TLS",
    ],
    correctAnswer: 0,
    explanation: "Browsers trust roots and validate intermediates to the site.",
  },
  {
    id: 65,
    topic: "TLS",
    question: "HSTS is used to:",
    options: [
      "Force browsers to use HTTPS",
      "Disable cookies",
      "Encrypt passwords at rest",
      "Rotate keys",
    ],
    correctAnswer: 0,
    explanation: "HSTS prevents HTTP downgrade attacks.",
  },
  {
    id: 66,
    topic: "TLS",
    question: "Certificate pinning helps prevent:",
    options: [
      "Man-in-the-middle attacks with fake certs",
      "SQL injection",
      "CSRF",
      "Brute force",
    ],
    correctAnswer: 0,
    explanation: "Pinning ensures the server uses expected certificates.",
  },
  {
    id: 67,
    topic: "TLS",
    question: "TLS 1.0 and 1.1 should be disabled because they are:",
    options: [
      "Obsolete and weak",
      "Faster and safer",
      "Required for OAuth",
      "Used by JWTs",
    ],
    correctAnswer: 0,
    explanation: "Old TLS versions have known weaknesses.",
  },
  {
    id: 68,
    topic: "TLS",
    question: "AEAD ciphers like AES-GCM provide:",
    options: [
      "Encryption plus integrity protection",
      "Only hashing",
      "Only compression",
      "Only key exchange",
    ],
    correctAnswer: 0,
    explanation: "AEAD modes provide confidentiality and integrity together.",
  },
  {
    id: 69,
    topic: "TLS",
    question: "Key exchange establishes:",
    options: [
      "A shared session key",
      "A password reset token",
      "A database schema",
      "A new username",
    ],
    correctAnswer: 0,
    explanation: "Key exchange creates the symmetric key for the session.",
  },
  {
    id: 70,
    topic: "TLS",
    question: "Perfect forward secrecy means:",
    options: [
      "Compromise of long-term keys does not expose past sessions",
      "Passwords are stored in plaintext",
      "Sessions never expire",
      "TLS is optional",
    ],
    correctAnswer: 0,
    explanation: "Ephemeral keys prevent retroactive decryption.",
  },
  {
    id: 71,
    topic: "Crypto Hygiene",
    question: "Key rotation reduces risk by:",
    options: [
      "Limiting impact of compromised keys",
      "Removing MFA",
      "Disabling TLS",
      "Increasing token lifetime",
    ],
    correctAnswer: 0,
    explanation: "Regular rotation shortens the exposure window.",
  },
  {
    id: 72,
    topic: "Crypto Hygiene",
    question: "Hardcoded keys are risky because:",
    options: [
      "They are easy to extract from code",
      "They improve performance",
      "They prevent brute force",
      "They rotate automatically",
    ],
    correctAnswer: 0,
    explanation: "Hardcoded secrets are often leaked via code or binaries.",
  },
  {
    id: 73,
    topic: "Crypto Hygiene",
    question: "Reusing an IV or nonce with AEAD can:",
    options: [
      "Break confidentiality and integrity",
      "Increase security",
      "Enable hashing",
      "Fix JWTs",
    ],
    correctAnswer: 0,
    explanation: "Nonce reuse can reveal plaintext or allow forgeries.",
  },
  {
    id: 74,
    topic: "Crypto Hygiene",
    question: "A KDF like PBKDF2 or Argon2 is used to:",
    options: [
      "Derive keys from passwords securely",
      "Encrypt TLS traffic",
      "Generate JWTs",
      "Store cookies",
    ],
    correctAnswer: 0,
    explanation: "KDFs slow down password-based key derivation.",
  },
  {
    id: 75,
    topic: "Crypto Hygiene",
    question: "HMAC provides:",
    options: [
      "Integrity and authenticity, not confidentiality",
      "Encryption of data",
      "TLS certificates",
      "Password hashing",
    ],
    correctAnswer: 0,
    explanation: "HMAC verifies data integrity and origin.",
  },
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
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [activeSection, setActiveSection] = useState("intro");
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);

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
      const sectionIds = sectionNavItems.map((s) => s.id);
      for (const id of sectionIds) {
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

  const pageContext = `This page covers authentication and cryptography security concepts. Topics include: authentication mechanisms (passwords, MFA, biometrics), session management, OAuth/OIDC, JWT security, cryptographic algorithms (symmetric/asymmetric), hashing, key management, TLS/SSL, and common vulnerabilities. Current section: ${activeSection}. Covers secure implementation patterns and common attack vectors.`;

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
    <LearnPageLayout pageTitle="Authentication & Cryptography Guide" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0a0f", py: 4 }}>
      <Container maxWidth="xl">
        <Grid container spacing={3}>
          {/* Sidebar Navigation - Desktop */}
          {!isMobile && (
            <Grid item md={2.5} sx={{ display: { xs: "none", md: "block" } }}>
              {sidebarNav}
            </Grid>
          )}

          {/* Main Content */}
          <Grid item xs={12} md={9.5}>
            {/* Header Section */}
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
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip icon={<LockIcon />} label="Authentication" size="small" />
                <Chip icon={<TokenIcon />} label="JWT Security" size="small" />
                <Chip icon={<HttpsIcon />} label="TLS/Crypto" size="small" />
                <Chip icon={<LinkIcon />} label="OAuth/OIDC" size="small" />
              </Box>
            </Box>

            {/* Introduction */}
            <Paper
              sx={{
                p: 4,
                mb: 4,
                borderRadius: 3,
                background: `linear-gradient(135deg, ${alpha("#10b981", 0.15)} 0%, ${alpha("#3b82f6", 0.1)} 50%, ${alpha("#10b981", 0.05)} 100%)`,
                border: `1px solid ${alpha("#10b981", 0.3)}`,
              }}
            >
              <Typography variant="h5" gutterBottom sx={{ fontWeight: 700, color: "#e0e0e0" }}>
                What is Authentication & Cryptography Security?
              </Typography>
              <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, color: "grey.300" }}>
                <strong>Authentication</strong> is the process of verifying identity - proving you are who you claim to be.
                <strong> Cryptography</strong> is the mathematical foundation that makes secure authentication possible,
                protecting data confidentiality and integrity.
              </Typography>
              <Typography paragraph sx={{ fontSize: "1.05rem", lineHeight: 1.8, color: "grey.300" }}>
                Together, they form the backbone of application security. Understanding both the defensive concepts and
                attack techniques is essential for security professionals.
              </Typography>

              {/* Stats */}
              <Grid container spacing={2} sx={{ mt: 2 }}>
                {[
                  { value: "10", label: "Core Topics", color: "#3b82f6" },
                  { value: "50+", label: "Attack Techniques", color: "#ef4444" },
                  { value: "30+", label: "Test Ideas", color: "#f59e0b" },
                  { value: "75", label: "Quiz Questions", color: "#10b981" },
                ].map((stat) => (
                  <Grid item xs={6} md={3} key={stat.label}>
                    <Paper
                      sx={{
                        p: 2,
                        textAlign: "center",
                        borderRadius: 2,
                        border: `1px solid ${alpha(stat.color, 0.2)}`,
                        background: `linear-gradient(135deg, ${alpha(stat.color, 0.08)}, transparent)`,
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
            </Paper>

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
                Use the sidebar navigation to jump to specific topics or work through sequentially.
              </Typography>
            </Alert>

            {/* ==================== COMPREHENSIVE CRYPTOGRAPHY DEEP DIVE ==================== */}

            {/* Cryptographic Foundations Section */}
            <Paper
              sx={{
                p: 4,
                mb: 4,
                borderRadius: 3,
                bgcolor: "#0f1024",
                border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
              }}
            >
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#8b5cf6", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
                <LockIcon sx={{ fontSize: 40 }} />
                Cryptographic Foundations: A Comprehensive Theory
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Cryptography, derived from the Greek words "kryptos" (hidden) and "graphein" (to write), represents one of humanity's oldest
                and most sophisticated intellectual achievements. From the simple substitution ciphers used by Julius Caesar to the complex
                mathematical constructions that protect modern digital communications, cryptography has evolved from an art practiced by
                spies and diplomats into a rigorous mathematical science that underpins virtually every aspect of our digital lives.
                Understanding cryptography is not merely an academic exercise—it is essential for anyone who seeks to understand how
                security works at its most fundamental level.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The fundamental purpose of cryptography is to provide security guarantees in the presence of adversaries. These guarantees
                are typically categorized into several core properties. <strong>Confidentiality</strong> ensures that information remains
                accessible only to authorized parties—even if an adversary intercepts the communication, they cannot understand its contents.
                <strong> Integrity</strong> guarantees that information has not been altered in transit or storage—any modification, whether
                accidental or malicious, will be detected. <strong>Authentication</strong> verifies the identity of parties involved in a
                communication—you can be certain that a message truly came from who claims to have sent it. <strong>Non-repudiation</strong> prevents
                a party from denying their involvement in a transaction—digital signatures provide mathematical proof that a specific
                private key was used to sign a particular message.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Modern cryptography rests on a principle articulated by Auguste Kerckhoffs in 1883: a cryptographic system should be secure
                even if everything about the system, except the key, is public knowledge. This principle, often paraphrased as "security
                should not depend on the secrecy of the algorithm," stands in stark contrast to the older paradigm of "security through
                obscurity." Kerckhoffs' principle has profound implications: it means that cryptographic algorithms can and should be
                publicly scrutinized, allowing the worldwide community of mathematicians and security researchers to search for weaknesses.
                Algorithms that survive this scrutiny can be trusted; those that rely on secrecy inevitably fall when their details leak.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The strength of a cryptographic system is measured by the computational effort required to break it. Modern cryptography
                does not typically prove that breaking a cipher is impossible—rather, it proves that breaking the cipher is equivalent to
                solving a mathematical problem believed to be computationally intractable. For example, the security of RSA encryption
                depends on the difficulty of factoring large composite numbers into their prime components. While factoring is easy for
                small numbers, the computational cost grows exponentially with the size of the number. A 2048-bit RSA key requires
                factoring a number with over 600 decimal digits—a task that would take all the computing power on Earth longer than the
                age of the universe using current algorithms. This is what cryptographers mean by "computationally secure": not impossible
                to break, but so difficult that breaking it is practically equivalent to impossible.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The distinction between <strong>unconditional security</strong> and <strong>computational security</strong> is fundamental
                to understanding cryptographic guarantees. A system is unconditionally secure if it cannot be broken even with infinite
                computational resources. The one-time pad (OTP) is the only known encryption scheme with this property: when a truly random
                key of the same length as the message is used exactly once, the ciphertext reveals absolutely no information about the
                plaintext, regardless of the adversary's computational power. However, the practical limitations of OTP—the need to securely
                share keys as long as every message, and never reuse them—make it impractical for most applications. Computational security,
                in contrast, assumes adversaries have bounded computational resources. All practical cryptographic systems used today rely
                on computational security assumptions, betting that certain mathematical problems will remain difficult to solve.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#a78bfa", mb: 2, mt: 4 }}>
                The Historical Evolution of Cryptographic Thought
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The history of cryptography is a fascinating arms race between codemakers and codebreakers, each advance on one side
                prompting innovation on the other. Ancient civilizations employed various techniques to conceal messages: the Spartans
                used the scytale, a cylindrical device around which strips of leather were wound to reveal hidden messages; the Romans
                employed simple substitution ciphers; and medieval Arab scholars developed sophisticated frequency analysis techniques
                that could break substitution ciphers by analyzing the statistical distribution of letters. For millennia, cryptography
                remained an art rather than a science, its practitioners developing techniques through intuition and trial-and-error
                rather than rigorous mathematical analysis.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The transformation of cryptography from art to science began in the 20th century, catalyzed by two world wars that
                demonstrated the strategic importance of secure communications. The breaking of the German Enigma machine by Allied
                cryptanalysts at Bletchley Park—most famously Alan Turing—shortened World War II by an estimated two years and saved
                countless lives. This success demonstrated both the power of mathematical analysis applied to cryptographic problems
                and the consequences of cryptographic failure. The subsequent development of the first electronic computers was driven
                in part by cryptanalytic needs, establishing a connection between cryptography and computing that continues to this day.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Claude Shannon's 1949 paper "Communication Theory of Secrecy Systems" is widely considered the founding document of
                modern cryptography as a mathematical discipline. Shannon, building on his earlier groundbreaking work in information
                theory, established rigorous definitions of security and proved fundamental results about what cryptographic systems
                could and could not achieve. He demonstrated that perfect secrecy required keys at least as long as the messages being
                encrypted, effectively proving the optimality of the one-time pad. Shannon's information-theoretic approach provided
                the conceptual framework that all subsequent cryptographic research would build upon.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The 1970s witnessed two revolutionary developments that shaped modern cryptography. First, the Data Encryption Standard
                (DES), developed by IBM and standardized by the U.S. government in 1977, became the first publicly available,
                rigorously-designed encryption algorithm. DES introduced the concept of a "block cipher" that processes data in
                fixed-size blocks using a series of complex transformations, and its design principles influenced virtually every
                subsequent symmetric cipher. Second, and even more transformative, was the invention of public-key cryptography.
                Whitfield Diffie and Martin Hellman's 1976 paper "New Directions in Cryptography" proposed an entirely new paradigm:
                cryptographic systems using two mathematically related keys, one public and one private. This seemingly impossible
                idea—that you could publish one key freely while keeping another secret, and that the two could work together to
                enable secure communication—revolutionized the field and made secure communication between parties who had never
                previously shared a secret practically possible for the first time.
              </Typography>
            </Paper>

            {/* Mathematical Foundations Section */}
            <Paper
              sx={{
                p: 4,
                mb: 4,
                borderRadius: 3,
                bgcolor: "#0f1024",
                border: `1px solid ${alpha("#3b82f6", 0.3)}`,
              }}
            >
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#3b82f6", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
                <SecurityIcon sx={{ fontSize: 40 }} />
                Mathematical Foundations of Cryptography
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The mathematical foundations of modern cryptography draw from several branches of mathematics, including number theory,
                abstract algebra, probability theory, and computational complexity theory. Understanding these foundations is essential
                for anyone who wants to move beyond using cryptographic tools as black boxes to truly understanding why they work and
                what their limitations are. While a complete treatment would require years of graduate study, the core concepts can be
                understood at an intuitive level and provide valuable insight into cryptographic security.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#60a5fa", mb: 2, mt: 4 }}>
                Modular Arithmetic: The Algebra of Remainders
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Modular arithmetic, often called "clock arithmetic," is perhaps the most fundamental mathematical tool in cryptography.
                When we say "a ≡ b (mod n)," we mean that a and b have the same remainder when divided by n—equivalently, that n divides
                (a - b) evenly. For example, 17 ≡ 5 (mod 12) because both leave remainder 5 when divided by 12, just as 5 o'clock and
                17:00 refer to the same position on a 12-hour clock. This seemingly simple concept has profound implications for
                cryptography because operations in modular arithmetic wrap around at the modulus, creating mathematical structures
                with useful properties.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The properties of modular arithmetic enable efficient computation with very large numbers—numbers with hundreds or
                thousands of digits that would be unwieldy in ordinary arithmetic. Addition, subtraction, and multiplication can be
                performed by first computing the result in ordinary arithmetic and then taking the remainder when dividing by the
                modulus. Because we only need to keep track of remainders, intermediate results never grow larger than the modulus,
                allowing computation with numbers that would otherwise exceed any computer's capacity. Modular exponentiation—computing
                a^b mod n—can be performed efficiently using the "square-and-multiply" algorithm, which reduces the number of
                multiplications from b (potentially astronomical) to approximately log₂(b). This efficiency is crucial for cryptographic
                systems like RSA, which routinely work with exponents hundreds of digits long.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#60a5fa", mb: 2, mt: 4 }}>
                Prime Numbers: The Atoms of Arithmetic
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Prime numbers—integers greater than 1 that are divisible only by 1 and themselves—occupy a central position in
                cryptography. The Fundamental Theorem of Arithmetic states that every positive integer greater than 1 can be expressed
                as a unique product of prime numbers (up to the order of the factors). This factorization, while unique, becomes
                extraordinarily difficult to compute as numbers grow large. While multiplying two 500-digit primes together takes a
                fraction of a second, factoring the resulting 1000-digit product back into its prime components would take longer than
                the age of the universe using the best known algorithms on the fastest computers.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                This asymmetry—the vast difference in difficulty between multiplication and factoring—is an example of a
                <strong> trapdoor one-way function</strong>, a concept central to public-key cryptography. A one-way function is easy
                to compute in one direction but practically impossible to reverse. A trapdoor one-way function adds an additional
                element: knowledge of a secret "trapdoor" makes the reverse computation easy. In RSA, the trapdoor is knowledge of the
                prime factors; if you know p and q, computing the private key from the public key is straightforward, but without that
                knowledge, you face the intractable factoring problem.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#60a5fa", mb: 2, mt: 4 }}>
                Group Theory and Algebraic Structures
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Abstract algebra provides the language and framework for describing many cryptographic constructions. A <strong>group</strong> is
                a set equipped with an operation that combines any two elements to produce a third element, satisfying certain axioms:
                closure (the result is always in the set), associativity, the existence of an identity element, and the existence of
                inverses for every element. The integers modulo n under addition form a group, as do the nonzero elements modulo a
                prime p under multiplication. These algebraic structures provide the mathematical foundation for understanding why
                cryptographic operations work and what properties they guarantee.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Elliptic curves</strong> provide another algebraic structure with powerful cryptographic applications. An elliptic
                curve is the set of points (x, y) satisfying an equation of the form y² = x³ + ax + b, along with a special "point at
                infinity." Remarkably, these points form a group under an operation called "point addition," defined geometrically by
                drawing a line through two points and finding where it intersects the curve again. The discrete logarithm problem on
                elliptic curves—given points P and Q, find the integer k such that Q = kP—is believed to be even harder than the discrete
                logarithm problem in multiplicative groups, allowing elliptic curve cryptography (ECC) to achieve equivalent security
                with much smaller key sizes. A 256-bit ECC key provides security comparable to a 3072-bit RSA key.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#60a5fa", mb: 2, mt: 4 }}>
                Computational Complexity and Security Proofs
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Computational complexity theory provides the framework for reasoning about the difficulty of computational problems and,
                by extension, the security of cryptographic systems. Problems are classified by the resources (time, space, etc.) required
                to solve them as a function of input size. A problem is in class P if it can be solved in polynomial time—that is, the
                running time is bounded by some polynomial function of the input size. A problem is in class NP if proposed solutions can
                be verified in polynomial time, even if finding such solutions may be much harder. The famous P ≠ NP conjecture—one of the
                great open problems in mathematics—asserts that there exist problems whose solutions can be quickly verified but not
                quickly found.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Modern cryptographic security proofs typically follow a pattern called <strong>reduction</strong>. To prove that a
                cryptographic scheme is secure, we show that any efficient adversary capable of breaking the scheme could be transformed
                into an efficient algorithm for solving some underlying "hard" problem believed to be intractable. For example, we might
                prove that any algorithm that can break RSA encryption can be efficiently converted into an algorithm that factors large
                integers. Since we believe factoring is hard (no efficient algorithm is known despite centuries of effort), we conclude
                that breaking RSA must also be hard. This approach doesn't prove security absolutely—it reduces the security question to
                an assumption about the hardness of the underlying problem—but it provides strong evidence and allows us to understand
                exactly what assumptions our security depends on.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The concept of <strong>semantic security</strong>, introduced by Goldwasser and Micali, provides a rigorous definition of
                what it means for an encryption scheme to be "secure." Roughly, a scheme is semantically secure if an adversary who sees
                a ciphertext cannot learn any information about the corresponding plaintext that they couldn't have computed without
                seeing the ciphertext. This is formalized using the concept of <strong>computational indistinguishability</strong>: the
                adversary cannot distinguish between encryptions of different messages with probability significantly better than random
                guessing. Modern encryption schemes are designed and proven to achieve semantic security under appropriate computational
                assumptions.
              </Typography>
            </Paper>

            {/* Symmetric Encryption Deep Dive */}
            <Paper
              sx={{
                p: 4,
                mb: 4,
                borderRadius: 3,
                bgcolor: "#0f1024",
                border: `1px solid ${alpha("#10b981", 0.3)}`,
              }}
            >
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#10b981", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
                <VpnKeyIcon sx={{ fontSize: 40 }} />
                Symmetric Encryption: The Art of Shared Secrets
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Symmetric encryption, the oldest and most intuitive form of encryption, uses the same secret key for both encryption
                and decryption. The sender transforms plaintext into ciphertext using the key, and the recipient reverses the process
                using the identical key. This model mirrors the intuition behind physical locks: the same key that locks a container
                can unlock it. Despite—or perhaps because of—this conceptual simplicity, symmetric encryption remains the workhorse
                of modern cryptography, encrypting the vast majority of data both in transit and at rest. Its efficiency makes it
                suitable for bulk data encryption where public-key methods would be prohibitively slow.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#34d399", mb: 2, mt: 4 }}>
                Block Ciphers: The Foundation of Symmetric Encryption
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                A <strong>block cipher</strong> is a deterministic algorithm that operates on fixed-size groups of bits, called blocks,
                transforming a plaintext block into a ciphertext block of the same size under the control of a secret key. The Advanced
                Encryption Standard (AES), the dominant block cipher in use today, processes 128-bit blocks using keys of 128, 192, or
                256 bits. The transformation must be invertible—given the key and ciphertext block, the original plaintext can be
                recovered—while appearing completely random to anyone without the key. A well-designed block cipher should behave like
                a random permutation: every possible key defines a different scrambling of the 2¹²⁸ possible 128-bit blocks, and without
                the key, there should be no detectable pattern or structure in this scrambling.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The internal structure of AES illustrates the principles of modern block cipher design. AES processes data through
                multiple rounds (10, 12, or 14 rounds depending on key size), each round applying four transformations: <strong>SubBytes</strong>
                (a nonlinear substitution using a carefully designed lookup table), <strong>ShiftRows</strong> (a permutation that shifts
                bytes within rows), <strong>MixColumns</strong> (a linear transformation that mixes bytes within columns), and
                <strong> AddRoundKey</strong> (XOR with a portion of the expanded key). These operations are designed to achieve two
                crucial properties articulated by Claude Shannon: <strong>confusion</strong> (making the relationship between the
                ciphertext and key as complex as possible) and <strong>diffusion</strong> (spreading the influence of each plaintext
                and key bit across many ciphertext bits). After sufficient rounds, changing a single bit of plaintext or key changes
                approximately half the bits of the ciphertext—the avalanche effect.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#34d399", mb: 2, mt: 4 }}>
                Modes of Operation: Using Block Ciphers Safely
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                A block cipher alone can only encrypt single blocks; encrypting messages longer than one block requires a
                <strong> mode of operation</strong> that specifies how to combine block cipher invocations. The choice of mode has
                profound security implications. <strong>Electronic Codebook (ECB) mode</strong>, the simplest approach of independently
                encrypting each block, is insecure for most purposes because identical plaintext blocks produce identical ciphertext
                blocks, leaking patterns in the data. The famous "ECB penguin"—an image encrypted with ECB that clearly shows the
                outline of the original picture—dramatically illustrates this weakness.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Cipher Block Chaining (CBC) mode</strong> addresses ECB's pattern leakage by XORing each plaintext block with
                the previous ciphertext block before encryption, creating a dependency chain where each ciphertext block depends on all
                previous blocks. An unpredictable <strong>Initialization Vector (IV)</strong> starts the chain, ensuring that encrypting
                the same message twice produces different ciphertexts. However, CBC has its own vulnerabilities: it is susceptible to
                padding oracle attacks, where an adversary can exploit error messages about invalid padding to decrypt ciphertexts
                byte-by-byte without knowing the key. The BEAST and Lucky13 attacks against TLS exploited CBC weaknesses, driving the
                migration to more secure modes.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Modern cryptographic practice strongly favors <strong>Authenticated Encryption with Associated Data (AEAD)</strong> modes,
                which provide both confidentiality and integrity protection in a single, hard-to-misuse construction. <strong>AES-GCM</strong>
                (Galois/Counter Mode) is the most widely deployed AEAD mode, combining CTR mode encryption with a polynomial-based
                authentication tag computed using Galois field arithmetic. GCM produces a ciphertext that is exactly as long as the
                plaintext plus a fixed-size authentication tag (typically 128 bits). Any modification to the ciphertext—even a single
                bit flip—will cause authentication to fail with overwhelming probability. <strong>ChaCha20-Poly1305</strong>, developed
                by Daniel Bernstein, provides an alternative AEAD construction that achieves excellent performance in software without
                requiring hardware acceleration, making it popular on mobile devices and in protocols like TLS 1.3 and WireGuard.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#34d399", mb: 2, mt: 4 }}>
                Stream Ciphers: Continuous Encryption
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Unlike block ciphers that process fixed-size chunks, <strong>stream ciphers</strong> generate a continuous stream of
                pseudorandom bits (the <strong>keystream</strong>) that is XORed with the plaintext bit-by-bit or byte-by-byte. The
                keystream is generated deterministically from the key and a nonce/IV, creating a sequence that appears random to anyone
                without the key. Stream ciphers are particularly well-suited for applications where data arrives in small, unpredictable
                chunks or where latency is critical, as they can encrypt each bit immediately without waiting for a full block to
                accumulate.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The security of stream ciphers critically depends on <strong>never reusing a nonce with the same key</strong>. If two
                messages M1 and M2 are encrypted with the same keystream K, the XOR of the ciphertexts equals the XOR of the plaintexts:
                (M1 ⊕ K) ⊕ (M2 ⊕ K) = M1 ⊕ M2. This leaks information about both messages and, given enough ciphertext pairs encrypted
                with the same keystream, often allows complete recovery of all plaintexts. This is why WEP wireless encryption, which
                used RC4 with a 24-bit IV that frequently repeated, was catastrophically broken. Modern protocols carefully manage
                nonces to ensure uniqueness—often using a counter that increments with each message—and specify what happens if the
                nonce space is exhausted (typically: rotate the key).
              </Typography>
            </Paper>

            {/* Asymmetric Cryptography Section */}
            <Paper
              sx={{
                p: 4,
                mb: 4,
                borderRadius: 3,
                bgcolor: "#0f1024",
                border: `1px solid ${alpha("#f59e0b", 0.3)}`,
              }}
            >
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#f59e0b", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
                <HttpsIcon sx={{ fontSize: 40 }} />
                Asymmetric Cryptography: Public-Key Revolution
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The invention of public-key cryptography in the 1970s solved a problem that had plagued cryptography for millennia:
                how can two parties establish a shared secret when they've never met and have no secure channel to exchange keys?
                The symmetric encryption model requires both parties to possess the same secret key, but if they could securely share
                that key, they wouldn't need encryption in the first place—a chicken-and-egg problem that seemed insurmountable.
                Public-key cryptography cuts through this Gordian knot by using two mathematically related keys: a <strong>public key</strong>
                that can be freely published and a <strong>private key</strong> that must be kept secret. Messages encrypted with the
                public key can only be decrypted with the corresponding private key, enabling secure communication without any prior
                key exchange.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#fbbf24", mb: 2, mt: 4 }}>
                RSA: The First Practical Public-Key System
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The RSA cryptosystem, invented by Ron Rivest, Adi Shamir, and Leonard Adleman in 1977, was the first practical
                public-key encryption scheme and remains widely used today. RSA's security rests on the difficulty of factoring
                large composite numbers. Key generation begins by selecting two large prime numbers p and q (each typically 1024 bits
                or larger for modern security) and computing their product n = p × q. The number n is published as part of the public
                key, but recovering p and q from n requires solving the factoring problem—believed to be computationally intractable
                for sufficiently large n. The mathematical details involve computing the "Euler totient" φ(n) = (p-1)(q-1), choosing
                a public exponent e (commonly 65537), and computing the private exponent d such that e × d ≡ 1 (mod φ(n)).
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                RSA encryption transforms a message m into ciphertext c by computing c = m^e mod n using the public key (n, e).
                Decryption recovers the message by computing m = c^d mod n using the private key d. The mathematical magic that makes
                this work is Euler's theorem, which guarantees that m^(ed) ≡ m (mod n) for any message m. Without knowing the private
                exponent d—which requires knowing φ(n), which requires knowing p and q—an adversary cannot decrypt messages, even though
                they have the public key used to create them. RSA can also be used for digital signatures by "signing" with the private
                key and "verifying" with the public key, reversing the roles of encryption and decryption.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#fbbf24", mb: 2, mt: 4 }}>
                Elliptic Curve Cryptography: Smaller Keys, Same Security
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Elliptic Curve Cryptography (ECC)</strong>, developed independently by Neal Koblitz and Victor Miller in 1985,
                provides an alternative foundation for public-key cryptography based on the algebraic structure of elliptic curves over
                finite fields. The key advantage of ECC is that it achieves equivalent security to RSA with dramatically smaller key
                sizes. A 256-bit ECC key provides roughly the same security as a 3072-bit RSA key, resulting in faster computation,
                lower bandwidth requirements, and reduced storage needs. These advantages have made ECC the preferred choice for
                resource-constrained environments like mobile devices and IoT systems, and it has become the default for new
                cryptographic deployments.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The mathematical structure underlying ECC is the group of points on an elliptic curve, defined by an equation of the
                form y² = x³ + ax + b over a finite field. Points on the curve can be "added" using a geometric construction: draw a
                line through two points, find where it intersects the curve again, and reflect across the x-axis. This operation,
                remarkably, satisfies the group axioms. The <strong>Elliptic Curve Discrete Logarithm Problem (ECDLP)</strong>—given
                points P and Q on the curve, find the integer k such that Q = kP (meaning P added to itself k times)—is believed to be
                even harder than the ordinary discrete logarithm problem, explaining ECC's security advantage. The specific curves used
                in practice, such as P-256 (NIST), Curve25519 (Bernstein), and secp256k1 (Bitcoin), are carefully chosen to resist known
                attacks while enabling efficient implementation.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#fbbf24", mb: 2, mt: 4 }}>
                Diffie-Hellman Key Exchange: Sharing Secrets Publicly
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The <strong>Diffie-Hellman key exchange</strong> protocol, published in 1976, was the first practical method for two
                parties to establish a shared secret over an insecure channel. The protocol is beautifully simple. Alice and Bob agree
                on a large prime p and a generator g. Alice chooses a secret random number a, computes A = g^a mod p, and sends A to
                Bob. Bob chooses his own secret b, computes B = g^b mod p, and sends B to Alice. Now Alice computes s = B^a mod p =
                g^(ab) mod p, and Bob computes s = A^b mod p = g^(ab) mod p. Both arrive at the same shared secret s, but an
                eavesdropper who observed A and B cannot compute s without solving the discrete logarithm problem—finding a from A
                (or b from B) requires computations believed to be intractable.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Modern cryptographic protocols use <strong>Elliptic Curve Diffie-Hellman (ECDH)</strong>, which performs the same key
                exchange using elliptic curve operations instead of modular exponentiation. In ECDH, Alice chooses a random integer a
                and computes public value A = aG (where G is a standard base point on the curve), Bob chooses b and computes B = bG,
                and both can derive the shared secret S = abG = aB = bA. The shared point's x-coordinate (possibly processed through a
                key derivation function) serves as the shared secret. ECDH is the key exchange mechanism used in TLS 1.3, Signal
                Protocol, and countless other modern cryptographic systems. The related protocol X25519, using Curve25519 with specific
                implementation choices that resist common implementation errors, has become particularly popular due to its combination
                of security, performance, and resistance to implementation mistakes.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#fbbf24", mb: 2, mt: 4 }}>
                Digital Signatures: Unforgeable Authentication
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Digital signatures</strong> provide the cryptographic equivalent of a handwritten signature, with even stronger
                properties. A digital signature binds a message to the identity of the signer in a way that anyone can verify but only
                the signer can create. Unlike physical signatures, digital signatures change with every message (preventing cut-and-paste
                attacks) and can detect any modification to the signed message. The properties of digital signatures enable applications
                far beyond simple authentication: software updates can be verified as coming from the legitimate developer, financial
                transactions can be authorized without repudiation, and legal contracts can be signed remotely with mathematical certainty.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The most widely used signature algorithms include <strong>RSA signatures</strong>, <strong>ECDSA</strong> (Elliptic Curve
                Digital Signature Algorithm), and <strong>EdDSA</strong> (Edwards-curve Digital Signature Algorithm, particularly the
                Ed25519 instantiation). RSA signatures work by applying the private key operation to a hash of the message—essentially
                "encrypting" the hash with the private key—and verification applies the public key operation and checks that the result
                matches the hash. ECDSA uses elliptic curve mathematics to achieve equivalent security with shorter signatures. EdDSA,
                a newer design, is deterministic (the same message always produces the same signature, simplifying implementation and
                avoiding vulnerabilities from poor random number generation) and has been designed to resist implementation attacks that
                have affected ECDSA in practice. Ed25519, the most popular EdDSA variant, is used in SSH, TLS, Signal, and many
                cryptocurrency systems.
              </Typography>
            </Paper>

            {/* Cryptographic Hash Functions Section */}
            <Paper
              sx={{
                p: 4,
                mb: 4,
                borderRadius: 3,
                bgcolor: "#0f1024",
                border: `1px solid ${alpha("#ef4444", 0.3)}`,
              }}
            >
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#ef4444", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
                <StorageIcon sx={{ fontSize: 40 }} />
                Cryptographic Hash Functions: Digital Fingerprints
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                A <strong>cryptographic hash function</strong> takes an input of arbitrary length and produces a fixed-size output,
                called the hash, digest, or fingerprint. Unlike encryption, hashing is a one-way process: there is no key and no way
                to recover the input from the output. The same input always produces the same output (determinism), but even the
                smallest change to the input produces a completely different output (the avalanche effect). These properties make hash
                functions indispensable building blocks for countless cryptographic constructions, from password storage to digital
                signatures to blockchain technology.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#f87171", mb: 2, mt: 4 }}>
                Security Properties of Hash Functions
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                A cryptographic hash function must satisfy three security properties. <strong>Preimage resistance</strong> (one-wayness)
                means that given a hash value h, it should be computationally infeasible to find any input m such that hash(m) = h.
                This property ensures that seeing a hash doesn't reveal the original input. <strong>Second preimage resistance</strong>
                means that given an input m1, it should be infeasible to find a different input m2 such that hash(m1) = hash(m2). This
                prevents an attacker who sees a message and its hash from finding a different message with the same hash.
                <strong> Collision resistance</strong> is the strongest property: it should be infeasible to find any two distinct
                inputs m1 and m2 such that hash(m1) = hash(m2). Note that collisions must exist (by the pigeonhole principle—there are
                more possible inputs than possible outputs), but they should be practically impossible to find.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The <strong>birthday attack</strong> demonstrates that collision resistance is harder to achieve than preimage resistance.
                Named after the birthday paradox—in a group of just 23 people, there's a 50% chance two share a birthday—this attack
                exploits the fact that the probability of finding a collision among randomly chosen inputs grows much faster than
                intuition suggests. For a hash function with n-bit output, finding a collision requires only about 2^(n/2) operations
                on average, not 2^n as might be expected. This is why modern hash functions use larger outputs: SHA-256's 256-bit output
                provides 128 bits of security against collision attacks, requiring about 2^128 operations—far beyond any foreseeable
                computational capability.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#f87171", mb: 2, mt: 4 }}>
                Modern Hash Functions: SHA-2 and SHA-3
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The <strong>SHA-2 family</strong> (SHA-256, SHA-384, SHA-512) represents the current standard for cryptographic hashing,
                designed by the NSA and published by NIST in 2001. SHA-256, the most commonly used variant, processes messages in 512-bit
                blocks through 64 rounds of mixing operations involving bitwise operations, modular addition, and fixed constants derived
                from the fractional parts of the cube roots of the first 64 primes. The design draws on the Merkle-Damgård construction,
                which builds a hash function for arbitrary-length inputs from a compression function that processes fixed-size blocks.
                Despite its age, SHA-256 remains secure with no practical attacks known against its collision resistance.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>SHA-3</strong>, standardized by NIST in 2015 after a multi-year public competition, represents a fundamentally
                different design approach. Based on the Keccak algorithm developed by a team led by Joan Daemen (co-inventor of AES),
                SHA-3 uses a "sponge construction" rather than Merkle-Damgård. The sponge metaphor captures how the function alternately
                absorbs input blocks into its internal state (like a sponge absorbing water) and squeezes output bits from the state.
                This design provides security against certain theoretical attacks that could affect Merkle-Damgård functions and enables
                flexible output lengths. While SHA-3 hasn't replaced SHA-2 (both remain secure and standardized), having two completely
                different secure hash function families provides valuable diversity—if a breakthrough attack affects one design, the
                other serves as a fallback.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#f87171", mb: 2, mt: 4 }}>
                Password Hashing: A Special Case
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Password hashing</strong> has requirements that differ significantly from general-purpose cryptographic hashing.
                While SHA-256 is designed to be fast (processing gigabytes per second on modern hardware), password hashing should be
                deliberately slow to resist brute-force attacks against stolen password databases. If an attacker obtains a database of
                SHA-256 hashed passwords, they can try billions of password guesses per second; if the same passwords were hashed with
                a properly configured password-specific function, they might manage only thousands per second—a million-fold difference
                that can transform a practical attack into an impractical one.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Modern password hashing functions are designed to be <strong>memory-hard</strong>, meaning they require significant
                amounts of memory to compute. This property specifically targets password cracking hardware: while GPUs and ASICs can
                perform billions of simple computations per second, they have limited memory and memory bandwidth, making memory-hard
                functions expensive to accelerate. <strong>Argon2</strong>, winner of the 2015 Password Hashing Competition, is the
                current best practice. It comes in three variants: Argon2d (optimized for resistance to GPU attacks, suitable for
                cryptocurrency mining), Argon2i (optimized for resistance to side-channel attacks, suitable for password hashing in
                hostile environments), and Argon2id (a hybrid that provides both properties and is recommended for password hashing).
                Parameters control memory usage, time cost, and parallelism, allowing security to be tuned to available resources.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>bcrypt</strong>, dating from 1999, remains widely used and trusted despite its age. Based on the Blowfish cipher,
                bcrypt incorporates a cost factor that can be increased as hardware improves, and its design makes it resistant to
                GPU acceleration. A limitation is that bcrypt processes only the first 72 bytes of a password, and some implementations
                truncate silently. <strong>scrypt</strong>, designed in 2009 by Colin Percival, was the first memory-hard password
                hashing function and remains a solid choice, though Argon2 is generally preferred for new applications due to its more
                flexible tuning options and broader security analysis from the Password Hashing Competition.
              </Typography>
            </Paper>

            {/* Quantum Cryptography Section */}
            <Paper
              sx={{
                p: 4,
                mb: 4,
                borderRadius: 3,
                bgcolor: "#0f1024",
                border: `1px solid ${alpha("#06b6d4", 0.3)}`,
              }}
            >
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#06b6d4", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
                <EnhancedEncryptionIcon sx={{ fontSize: 40 }} />
                Quantum Cryptography: The Coming Revolution
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Quantum computing represents both the greatest threat and greatest opportunity in the history of cryptography. On one
                hand, sufficiently powerful quantum computers could break most public-key cryptography in use today, rendering RSA,
                ECDH, and ECDSA insecure. On the other hand, quantum mechanics enables fundamentally new cryptographic capabilities,
                including key distribution with information-theoretic security guarantees impossible to achieve classically.
                Understanding this quantum landscape is essential for anyone concerned with the long-term security of cryptographic
                systems.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#22d3ee", mb: 2, mt: 4 }}>
                The Quantum Threat to Classical Cryptography
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The threat from quantum computing stems from two quantum algorithms developed in the 1990s. <strong>Shor's algorithm</strong>,
                discovered by Peter Shor in 1994, can factor integers and compute discrete logarithms in polynomial time on a quantum
                computer. This would completely break RSA (which relies on factoring difficulty), Diffie-Hellman (discrete logarithm),
                and elliptic curve cryptography (elliptic curve discrete logarithm). A cryptographically relevant quantum computer—one
                large and reliable enough to run Shor's algorithm against real cryptographic keys—doesn't exist today, but significant
                progress continues, and most experts believe such machines will eventually be built.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Grover's algorithm</strong>, discovered by Lov Grover in 1996, provides a quadratic speedup for unstructured
                search problems, including brute-force attacks on symmetric encryption and hash functions. Where a classical computer
                requires 2^n operations to search through 2^n possibilities, a quantum computer using Grover's algorithm requires only
                2^(n/2). This means that AES-128, which provides 128 bits of security against classical attacks, would provide only
                64 bits of security against quantum attacks—potentially vulnerable to determined attackers. The solution is
                straightforward: double the key sizes. AES-256 provides 128-bit security against quantum adversaries, which remains
                far beyond practical attack. Similarly, SHA-256's collision resistance drops from 128 bits to 85 bits against quantum
                adversaries, while SHA-512 provides 170-bit quantum collision resistance.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#22d3ee", mb: 2, mt: 4 }}>
                Post-Quantum Cryptography: Preparing for the Future
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Post-quantum cryptography</strong> (PQC), also called quantum-resistant or quantum-safe cryptography, refers to
                cryptographic algorithms believed to be secure against both classical and quantum computers. These algorithms are based
                on mathematical problems that quantum computers don't appear to solve efficiently. NIST has been running a standardization
                process since 2016, and in 2022-2024 announced the first standards: <strong>CRYSTALS-Kyber</strong> for key encapsulation
                and <strong>CRYSTALS-Dilithium</strong>, <strong>FALCON</strong>, and <strong>SPHINCS+</strong> for digital signatures.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Lattice-based cryptography</strong> underlies most of the selected algorithms. These schemes derive their security
                from the difficulty of problems involving mathematical lattices—regular arrangements of points in n-dimensional space.
                The <strong>Learning With Errors (LWE)</strong> problem, central to lattice cryptography, asks to recover a secret vector
                s from noisy linear equations of the form b = As + e (mod q), where e is a small error vector. Despite extensive study,
                no efficient quantum algorithm for LWE is known, and the problem has been shown equivalent to worst-case hard problems on
                lattices. Kyber, the selected key encapsulation mechanism, is based on a structured variant called Module-LWE that enables
                practical key sizes (public keys around 1 kilobyte) and fast operations.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Hash-based signatures</strong>, represented by SPHINCS+, take a different approach: their security relies only on
                the security of the underlying hash function. If the hash function is secure (including against quantum attacks), so is
                the signature scheme. This minimal assumption makes hash-based signatures especially trustworthy—we're confident that
                secure hash functions exist because we have multiple candidates and no quantum algorithm that threatens them significantly.
                The tradeoff is larger signatures (SPHINCS+ signatures are tens of kilobytes compared to hundreds of bytes for
                Dilithium), but for applications where signature size isn't critical, the conservative security assumptions are appealing.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#22d3ee", mb: 2, mt: 4 }}>
                Quantum Key Distribution: Physics-Based Security
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Quantum Key Distribution (QKD)</strong> uses the laws of quantum mechanics, rather than computational assumptions,
                to enable secure key exchange. The fundamental insight is that quantum mechanics prohibits certain actions: the
                <strong> no-cloning theorem</strong> proves that an unknown quantum state cannot be copied perfectly, and any measurement
                of a quantum system generally disturbs it in detectable ways. QKD protocols like <strong>BB84</strong> (proposed by
                Bennett and Brassard in 1984) exploit these properties to detect eavesdropping. Alice sends quantum bits (qubits) to
                Bob in random bases; any attempt by an eavesdropper to measure these qubits introduces errors that Alice and Bob can
                detect by comparing a portion of their measurements.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                QKD systems have been commercially deployed and even demonstrated over satellite links spanning thousands of kilometers.
                However, they have significant limitations. QKD requires a dedicated quantum channel (typically a fiber optic link or
                free-space optical path) that cannot be amplified or repeated through classical switches, limiting range. The technology
                is expensive and requires specialized hardware. Most critically, QKD only addresses key distribution; it still requires
                classical authenticated channels to prevent man-in-the-middle attacks, and the distributed keys are still used with
                classical symmetric encryption. For most applications, post-quantum cryptographic algorithms running on standard
                hardware provide a more practical path to quantum-resistant security.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#22d3ee", mb: 2, mt: 4 }}>
                Crypto Agility: Preparing for Cryptographic Transitions
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Crypto agility</strong>—the ability to quickly swap cryptographic algorithms in response to new threats or
                requirements—has become a crucial design principle given the quantum threat. Organizations should audit their
                cryptographic dependencies, understanding which algorithms they use and where, so they can prioritize migration efforts.
                Protocol designers should avoid hardcoding specific algorithms, instead using negotiation mechanisms that allow endpoints
                to agree on the strongest mutually supported option. The transition to post-quantum cryptography will likely take years
                or decades (the transition from SHA-1 to SHA-256 is still incomplete after being deprecated in 2011), so planning and
                early adoption of agility principles is essential.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Hybrid approaches</strong> combining classical and post-quantum algorithms provide a belt-and-suspenders approach
                during the transition period. A hybrid key exchange might combine ECDH (proven secure against classical attackers) with
                Kyber (believed secure against quantum attackers), deriving the final key from both. This provides security as long as
                either algorithm remains unbroken—hedging against the possibility that our confidence in the new post-quantum algorithms
                might be misplaced. Chrome, Signal, and other major applications have begun deploying such hybrid approaches, protecting
                against "harvest now, decrypt later" attacks where adversaries record encrypted traffic today hoping to decrypt it with
                future quantum computers.
              </Typography>
            </Paper>

            {/* Key Management Section */}
            <Paper
              sx={{
                p: 4,
                mb: 4,
                borderRadius: 3,
                bgcolor: "#0f1024",
                border: `1px solid ${alpha("#ec4899", 0.3)}`,
              }}
            >
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#ec4899", mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
                <AdminPanelSettingsIcon sx={{ fontSize: 40 }} />
                Key Management: The Human Factor in Cryptography
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                The most mathematically elegant cryptographic algorithm is worthless if its keys are poorly managed. History is littered
                with cryptographic failures that resulted not from breaking the algorithm but from compromising its keys: shared secrets
                transmitted in plaintext, private keys stored in version control, encryption keys derived from predictable sources, and
                certificates issued to the wrong parties. Understanding key management—the generation, distribution, storage, usage,
                rotation, and destruction of cryptographic keys—is at least as important as understanding the algorithms themselves.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#f472b6", mb: 2, mt: 4 }}>
                Key Generation: The Foundation of Security
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Cryptographic keys must be generated from high-quality random sources. The entire security of a cryptographic system
                can collapse if its keys are predictable. In 2012, researchers analyzing millions of RSA public keys found that thousands
                shared common prime factors due to faulty random number generation on embedded devices, allowing those keys to be trivially
                factored. The Debian OpenSSL vulnerability of 2006-2008 reduced the entropy of generated keys to just 32,767 possibilities
                due to a coding error, making all keys generated on affected systems completely insecure. These incidents demonstrate that
                proper randomness is not optional—it is a security-critical requirement.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Cryptographic random number generators must satisfy requirements far stricter than those for statistical applications.
                A <strong>Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)</strong> must produce output that is
                computationally indistinguishable from true randomness, meaning no efficient algorithm can predict future outputs even
                given knowledge of past outputs. Modern operating systems provide secure random sources: /dev/urandom on Linux (which is
                now equivalent to /dev/random for most purposes), CryptGenRandom on Windows, and SecRandomCopyBytes on Apple platforms.
                These implementations gather entropy from hardware events (timing variations, interrupt arrival times, user input) and
                process it through CSPRNG algorithms to produce output suitable for key generation. Applications should always use these
                system-provided sources rather than implementing their own randomness.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#f472b6", mb: 2, mt: 4 }}>
                Key Storage and Protection
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Private keys and symmetric keys require careful protection throughout their lifecycle. The threat model includes both
                external attackers who might compromise systems and insider threats from authorized personnel. Defense in depth
                principles suggest multiple layers of protection: encryption of keys at rest, access controls limiting who can use keys,
                audit logging of all key operations, and physical security for hardware storing keys. For the most sensitive applications,
                keys should never exist in plaintext outside of protected hardware boundaries.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Hardware Security Modules (HSMs)</strong> are specialized devices designed to generate, store, and use
                cryptographic keys within tamper-resistant boundaries. An HSM can perform cryptographic operations (signing, encrypting,
                decrypting) without ever exposing the keys to the outside system—even administrators cannot extract key material.
                HSMs typically include tamper detection that zeroizes keys if physical intrusion is detected. Cloud providers offer
                HSM services (AWS CloudHSM, Azure Dedicated HSM, Google Cloud HSM), and FIPS 140-2/140-3 certification provides
                assurance of security validation. For less demanding applications, software-based key management services provide
                centralized key storage with access controls and audit logging, though without the hardware-level protection of
                true HSMs.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#f472b6", mb: 2, mt: 4 }}>
                Key Rotation and Cryptographic Periods
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Cryptographic keys should not be used indefinitely. <strong>Key rotation</strong>—periodically replacing keys with fresh
                ones—limits the damage from undetected key compromise (the new key is secure even if the old one was compromised),
                reduces the amount of data encrypted under any single key (limiting exposure if that key is later broken), and ensures
                that cryptographic algorithms can be updated as security requirements evolve. The appropriate rotation frequency depends
                on the key type, the sensitivity of protected data, and the threat model: TLS session keys might last minutes, data
                encryption keys might rotate monthly, and root CA certificates might be valid for decades.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Key rotation must be planned and tested carefully. Rotating keys in a distributed system requires coordinated updates
                across all components that use those keys—a process that can fail in complex and unexpected ways. Best practices
                include supporting multiple active keys during transition periods (so encrypted data remains accessible even if some
                systems haven't received the new key yet), maintaining key version metadata alongside encrypted data, and testing
                rotation procedures regularly before they're needed in production. Automated key management systems can handle rotation
                according to policy, reducing the operational burden and the risk of human error.
              </Typography>

              <Typography variant="h5" sx={{ fontWeight: 700, color: "#f472b6", mb: 2, mt: 4 }}>
                Certificate Management and PKI
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                <strong>Public Key Infrastructure (PKI)</strong> provides the framework for managing digital certificates that bind
                public keys to identities. The centerpiece of PKI is the <strong>Certificate Authority (CA)</strong>, a trusted entity
                that vouches for the binding between a public key and its owner by digitally signing a certificate. Browsers and
                operating systems ship with pre-installed root CA certificates, and any certificate that chains back to one of these
                trusted roots is accepted. This hierarchy enables the internet-scale trust that makes HTTPS possible: your browser trusts
                certificates for millions of websites because they're signed by intermediate CAs that are signed by root CAs that your
                browser trusts.
              </Typography>

              <Typography variant="body1" sx={{ color: "grey.300", mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
                Certificate management includes obtaining certificates (either from public CAs like Let's Encrypt or internal enterprise
                CAs), deploying them to servers, monitoring expiration dates, and renewing before expiration. Certificate expiration is
                a common cause of service outages—expired certificates cause browsers to display scary warnings and APIs to reject
                connections. Automation through protocols like ACME (used by Let's Encrypt) and tools like certbot can handle certificate
                lifecycle automatically, renewing certificates weeks before expiration. <strong>Certificate Transparency (CT)</strong> logs
                provide an additional layer of security by recording all issued certificates in publicly auditable logs, enabling
                detection of certificates issued without the domain owner's authorization.
              </Typography>
            </Paper>

            {/* All Section Content */}
            {sections.map((section) => (
              <Box id={section.id} key={section.id} sx={{ mt: 4 }}>
                <Paper
                  sx={{
                    p: 4,
                    borderRadius: 3,
                    bgcolor: "#0f1024",
                    border: `1px solid ${alpha(section.color, 0.3)}`,
                  }}
                >
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
                </Paper>
              </Box>
            ))}

            {/* Resources Section */}
            <Box id="resources" sx={{ mt: 4 }}>
              <Paper sx={{ p: 4, borderRadius: 3, bgcolor: "#0f1024", border: `1px solid ${alpha("#3b82f6", 0.3)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#e0e0e0", display: "flex", alignItems: "center", gap: 2 }}>
                  <DescriptionIcon sx={{ color: "#3b82f6" }} />
                  Essential Resources
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { name: "OWASP Authentication Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", desc: "Best practices for authentication", color: "#ef4444" },
                    { name: "OWASP Session Management Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html", desc: "Session handling security guide", color: "#f59e0b" },
                    { name: "JWT Security Best Practices", url: "https://curity.io/resources/learn/jwt-best-practices/", desc: "Secure JWT implementation guide", color: "#22c55e" },
                    { name: "OAuth 2.0 Security Best Practices", url: "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics", desc: "OAuth security considerations", color: "#8b5cf6" },
                    { name: "PortSwigger Authentication Labs", url: "https://portswigger.net/web-security/authentication", desc: "Interactive authentication labs", color: "#06b6d4" },
                    { name: "Mozilla TLS Guidelines", url: "https://wiki.mozilla.org/Security/Server_Side_TLS", desc: "Server-side TLS configuration", color: "#ec4899" },
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

              {/* Related Learning Topics */}
              <Paper
                sx={{
                  p: 4,
                  mt: 3,
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
                      title: "Web Pentesting Guide",
                      desc: "Comprehensive web application security testing methodology",
                      link: "/learn/web-pentesting",
                      color: "#ef4444",
                      icon: <SecurityIcon />,
                    },
                    {
                      title: "API Security Testing",
                      desc: "REST, GraphQL, and API authentication security",
                      link: "/learn/api-testing",
                      color: "#06b6d4",
                      icon: <HttpIcon />,
                    },
                    {
                      title: "SQL Injection Guide",
                      desc: "SQL injection techniques and prevention",
                      link: "/learn/sql-injection",
                      color: "#f59e0b",
                      icon: <StorageIcon />,
                    },
                    {
                      title: "XSS Attack Guide",
                      desc: "Cross-site scripting attacks and defenses",
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
                      desc: "Understanding the most critical web security risks",
                      link: "/learn/owasp-top-10",
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
                questions={quizQuestions}
                accentColor={QUIZ_ACCENT_COLOR}
                title="Authentication and Crypto Knowledge Check"
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
                sx={{ borderColor: ACCENT_COLOR, color: ACCENT_COLOR, "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.1), borderColor: "#22c55e" } }}
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
          display: { xs: "block", md: "none" },
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
      {isMobile && (
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
