import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  IconButton,
  Chip,
  Grid,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Link,
  Alert,
  LinearProgress,
  Button,
} from "@mui/material";
import { useState } from "react";
import { Link as RouterLink, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import LaunchIcon from "@mui/icons-material/Launch";
import WarningIcon from "@mui/icons-material/Warning";
import SecurityIcon from "@mui/icons-material/Security";
import QuizIcon from "@mui/icons-material/Quiz";

interface OwaspItem {
  id: string;
  rank: number;
  name: string;
  shortName: string;
  color: string;
  prevalence: number;
  description: string;
  impact: string;
  examples: string[];
  prevention: string[];
  cwes: { id: string; name: string }[];
  realWorldIncident: string;
}

const owaspTop10: OwaspItem[] = [
  {
    id: "A01",
    rank: 1,
    name: "Broken Access Control",
    shortName: "Access Control",
    color: "#dc2626",
    prevalence: 94,
    description: "Failures in enforcing restrictions on what authenticated users are allowed to do. Attackers exploit these flaws to access unauthorized functionality and/or data, such as accessing other users' accounts, viewing sensitive files, or modifying other users' data.",
    impact: "Attackers can act as users or administrators, create, access, update, or delete any record, or gain unauthorized access to data.",
    examples: [
      "Modifying URL parameters to access other users' data (IDOR)",
      "Elevation of privilege by modifying JWT tokens or cookies",
      "Force browsing to authenticated pages as unauthenticated user",
      "Accessing API endpoints with missing access controls",
      "CORS misconfiguration allowing unauthorized API access",
    ],
    prevention: [
      "Deny access by default (except for public resources)",
      "Implement access control mechanisms once and reuse throughout the application",
      "Model access controls should enforce record ownership",
      "Disable directory listing and ensure metadata/backup files aren't in web roots",
      "Log access control failures and alert admins on repeated failures",
      "Rate limit API and controller access to minimize automated attack damage",
    ],
    cwes: [
      { id: "CWE-200", name: "Exposure of Sensitive Information" },
      { id: "CWE-201", name: "Insertion of Sensitive Information Into Sent Data" },
      { id: "CWE-352", name: "Cross-Site Request Forgery (CSRF)" },
    ],
    realWorldIncident: "2019 Capital One breach: SSRF combined with overly permissive IAM roles exposed 100M+ customer records.",
  },
  {
    id: "A02",
    rank: 2,
    name: "Cryptographic Failures",
    shortName: "Crypto Failures",
    color: "#ea580c",
    prevalence: 89,
    description: "Failures related to cryptography (or lack thereof), which often lead to exposure of sensitive data. Previously known as 'Sensitive Data Exposure'. Includes data transmitted in clear text, weak cryptographic algorithms, and improper key management.",
    impact: "Exposure of sensitive data including passwords, credit card numbers, health records, personal information, and business secrets.",
    examples: [
      "Transmitting data in clear text (HTTP, SMTP, FTP)",
      "Using old or weak cryptographic algorithms (MD5, SHA1, DES)",
      "Using default, weak, or re-used cryptographic keys",
      "Not enforcing encryption with proper headers (HSTS)",
      "Improper certificate validation",
    ],
    prevention: [
      "Classify data processed, stored, or transmitted and identify which is sensitive",
      "Apply controls per classification, don't store sensitive data unnecessarily",
      "Encrypt all sensitive data at rest using strong algorithms (AES-256)",
      "Encrypt all data in transit with secure protocols (TLS 1.2+)",
      "Use authenticated encryption instead of just encryption",
      "Generate cryptographically strong random keys, store keys securely",
    ],
    cwes: [
      { id: "CWE-259", name: "Use of Hard-coded Password" },
      { id: "CWE-327", name: "Use of Broken or Risky Cryptographic Algorithm" },
      { id: "CWE-331", name: "Insufficient Entropy" },
    ],
    realWorldIncident: "2017 Equifax: Unencrypted data at rest meant 143M people's SSNs, birth dates, and addresses were exposed.",
  },
  {
    id: "A03",
    rank: 3,
    name: "Injection",
    shortName: "Injection",
    color: "#d97706",
    prevalence: 84,
    description: "User-supplied data is not validated, filtered, or sanitized by the application, allowing attackers to inject malicious code. Includes SQL, NoSQL, OS command, ORM, LDAP, and Expression Language injection.",
    impact: "Data loss, corruption, or disclosure to unauthorized parties. Loss of accountability. Denial of access. Complete host takeover.",
    examples: [
      "SQL injection: SELECT * FROM users WHERE id = '" + "user_input" + "'",
      "Command injection: system('ping ' + user_input)",
      "LDAP injection in authentication queries",
      "XPath injection for XML data queries",
      "Template injection (SSTI) in server-side templates",
    ],
    prevention: [
      "Use parameterized queries or prepared statements for all database access",
      "Use positive server-side input validation",
      "Escape special characters for interpreters",
      "Use LIMIT and other SQL controls to prevent mass disclosure",
      "Use safe APIs that provide parameterized interfaces",
    ],
    cwes: [
      { id: "CWE-79", name: "Cross-site Scripting (XSS)" },
      { id: "CWE-89", name: "SQL Injection" },
      { id: "CWE-73", name: "External Control of File Name or Path" },
    ],
    realWorldIncident: "2008 Heartland Payment Systems: SQL injection exposed 134M credit cards, largest payment card breach at the time.",
  },
  {
    id: "A04",
    rank: 4,
    name: "Insecure Design",
    shortName: "Insecure Design",
    color: "#ca8a04",
    prevalence: 78,
    description: "Focuses on risks related to design and architectural flaws. Calls for more use of threat modeling, secure design patterns, and reference architectures. A secure implementation cannot fix an insecure design.",
    impact: "Systemic vulnerabilities that cannot be fixed by better implementation. Requires architectural changes to remediate.",
    examples: [
      "No rate limiting on sensitive operations (account creation, password reset)",
      "Missing business logic validation (negative quantities, prices)",
      "Trust boundaries not properly defined",
      "Lack of segregation of duties",
      "Credential recovery mechanism reveals user existence",
    ],
    prevention: [
      "Establish and use a secure development lifecycle with security professionals",
      "Use threat modeling for critical authentication, access control, business logic",
      "Integrate security language and controls into user stories",
      "Write unit and integration tests to validate all critical flows",
      "Segregate tier layers on system and network level",
    ],
    cwes: [
      { id: "CWE-209", name: "Generation of Error Message Containing Sensitive Info" },
      { id: "CWE-256", name: "Plaintext Storage of a Password" },
      { id: "CWE-501", name: "Trust Boundary Violation" },
    ],
    realWorldIncident: "Twitter API design flaw allowed enumeration of all phone numbers linked to accounts (2019 vulnerability).",
  },
  {
    id: "A05",
    rank: 5,
    name: "Security Misconfiguration",
    shortName: "Misconfig",
    color: "#65a30d",
    prevalence: 71,
    description: "Application is vulnerable due to missing appropriate security hardening, improperly configured permissions, unnecessary features enabled, default accounts/passwords, overly informative error messages, or disabled security features.",
    impact: "Unauthorized access to systems or data, sometimes full system compromise. Often easy to detect and exploit.",
    examples: [
      "Default credentials not changed (admin/admin)",
      "Unnecessary features enabled (ports, services, pages, accounts)",
      "Error handling reveals stack traces to users",
      "Cloud storage buckets publicly accessible",
      "Security headers missing or misconfigured",
      "Directory listing enabled on web server",
    ],
    prevention: [
      "Repeatable hardening process making it fast to deploy secure environments",
      "Minimal platform without unnecessary features or frameworks",
      "Review and update configurations as part of patch management",
      "Segmented application architecture with secure separation",
      "Automated process to verify configuration effectiveness",
    ],
    cwes: [
      { id: "CWE-16", name: "Configuration" },
      { id: "CWE-611", name: "Improper Restriction of XML External Entity Reference" },
      { id: "CWE-1188", name: "Initialization with Hard-Coded Network Resource Configuration" },
    ],
    realWorldIncident: "2019 Facebook: 540M records exposed due to misconfigured third-party app storage on AWS.",
  },
  {
    id: "A06",
    rank: 6,
    name: "Vulnerable and Outdated Components",
    shortName: "Components",
    color: "#16a34a",
    prevalence: 67,
    description: "Using components (libraries, frameworks, software modules) with known vulnerabilities or that are unsupported/out of date. Includes operating systems, web servers, databases, APIs, and all components/libraries.",
    impact: "Can range from minimal impact to full server compromise and data breach, depending on the vulnerable component.",
    examples: [
      "Using libraries with known CVEs (Log4Shell in Log4j)",
      "Running outdated OS versions without security patches",
      "Using frameworks past end-of-life without updates",
      "Not scanning dependencies for vulnerabilities",
      "Failing to fix/upgrade underlying platform in a timely fashion",
    ],
    prevention: [
      "Remove unused dependencies, features, components, files, and documentation",
      "Continuously inventory component versions (SBOM)",
      "Only obtain components from official sources over secure links",
      "Monitor for unmaintained libraries without security patches",
      "Subscribe to security bulletins for components you use",
    ],
    cwes: [
      { id: "CWE-1104", name: "Use of Unmaintained Third Party Components" },
      { id: "CWE-937", name: "Using Components with Known Vulnerabilities" },
    ],
    realWorldIncident: "2017 Equifax: Failed to patch known Apache Struts vulnerability (CVE-2017-5638), leading to breach of 143M records.",
  },
  {
    id: "A07",
    rank: 7,
    name: "Identification and Authentication Failures",
    shortName: "Auth Failures",
    color: "#0891b2",
    prevalence: 62,
    description: "Confirmation of the user's identity, authentication, and session management is critical. Weaknesses can allow attackers to compromise passwords, keys, or session tokens, or exploit implementation flaws to assume other users' identities.",
    impact: "Account takeover, identity theft, unauthorized access to sensitive functions and data.",
    examples: [
      "Permitting brute force or credential stuffing attacks",
      "Using weak or well-known passwords (Password1, admin123)",
      "Using weak or ineffective credential recovery",
      "Exposing session ID in URL",
      "Not properly invalidating sessions on logout",
      "Not rotating session IDs after successful login",
    ],
    prevention: [
      "Implement multi-factor authentication (MFA)",
      "Do not deploy with default credentials",
      "Implement weak password checks against common password lists",
      "Align password policies with NIST 800-63 guidelines",
      "Harden against credential enumeration attacks",
      "Limit failed login attempts with exponential backoff",
    ],
    cwes: [
      { id: "CWE-287", name: "Improper Authentication" },
      { id: "CWE-297", name: "Improper Validation of Certificate with Host Mismatch" },
      { id: "CWE-384", name: "Session Fixation" },
    ],
    realWorldIncident: "2012 LinkedIn: 117M password hashes stolen due to unsalted SHA-1 hashing, later cracked and leaked.",
  },
  {
    id: "A08",
    rank: 8,
    name: "Software and Data Integrity Failures",
    shortName: "Integrity",
    color: "#2563eb",
    prevalence: 55,
    description: "Code and infrastructure that does not protect against integrity violations. Includes using untrusted plugins/libraries/modules, insecure CI/CD pipelines, and auto-update functionality without integrity verification.",
    impact: "Supply chain compromise, malicious updates, unauthorized code execution.",
    examples: [
      "Using CDNs or package managers without integrity verification (SRI)",
      "Insecure deserialization from untrusted sources",
      "CI/CD pipeline without proper access controls and verification",
      "Auto-update functionality without signed updates",
      "Object serialization used for state or communication",
    ],
    prevention: [
      "Use digital signatures to verify software/data from expected source",
      "Use software composition analysis tools",
      "Ensure CI/CD pipeline has proper segregation and access control",
      "Review code and config changes for malicious content",
      "Ensure unsigned or unencrypted serialized data isn't sent to untrusted clients",
    ],
    cwes: [
      { id: "CWE-829", name: "Inclusion of Functionality from Untrusted Control Sphere" },
      { id: "CWE-494", name: "Download of Code Without Integrity Check" },
      { id: "CWE-502", name: "Deserialization of Untrusted Data" },
    ],
    realWorldIncident: "2020 SolarWinds: Nation-state actors compromised build process, distributing malware to 18,000+ organizations.",
  },
  {
    id: "A09",
    rank: 9,
    name: "Security Logging and Monitoring Failures",
    shortName: "Logging",
    color: "#7c3aed",
    prevalence: 48,
    description: "Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response allows attackers to maintain persistence, pivot to more systems, and tamper with, extract, or destroy data.",
    impact: "Delayed or failed breach detection, inability to respond to incidents, no forensic evidence for investigation.",
    examples: [
      "Login, failed logins, and high-value transactions not logged",
      "Logs not monitored for suspicious activity",
      "Logs only stored locally",
      "Inappropriate alerting thresholds or no alerting",
      "Penetration testing doesn't trigger alerts",
    ],
    prevention: [
      "Log all login, access control, and server-side input validation failures",
      "Ensure logs are generated in format easily consumed by log management",
      "Ensure high-value transactions have audit trail with integrity controls",
      "Establish effective monitoring and alerting",
      "Establish or adopt incident response and recovery plan (NIST 800-61r2)",
    ],
    cwes: [
      { id: "CWE-778", name: "Insufficient Logging" },
      { id: "CWE-117", name: "Improper Output Neutralization for Logs" },
      { id: "CWE-223", name: "Omission of Security-relevant Information" },
    ],
    realWorldIncident: "2013 Target: Attackers in network for 2 weeks; security alerts were generated but not acted upon. 40M cards compromised.",
  },
  {
    id: "A10",
    rank: 10,
    name: "Server-Side Request Forgery (SSRF)",
    shortName: "SSRF",
    color: "#c026d3",
    prevalence: 43,
    description: "SSRF occurs when a web application fetches a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send crafted requests to unexpected destinations.",
    impact: "Internal service enumeration, reading internal files, accessing cloud metadata, pivoting to internal systems.",
    examples: [
      "Fetching URL from user input: fetch(user_url)",
      "Accessing cloud metadata (169.254.169.254)",
      "Port scanning internal network through vulnerable app",
      "Reading local files via file:// protocol",
      "Accessing internal admin interfaces",
    ],
    prevention: [
      "Segment remote resource access functionality in separate networks",
      "Enforce 'deny by default' firewall policies",
      "Sanitize and validate all client-supplied URLs",
      "Disable HTTP redirections",
      "Don't return raw responses to clients",
      "Use allowlists for URL schemas, ports, and destinations",
    ],
    cwes: [
      { id: "CWE-918", name: "Server-Side Request Forgery (SSRF)" },
    ],
    realWorldIncident: "2019 Capital One: SSRF in WAF allowed attacker to access AWS metadata and steal credentials, exposing 106M records.",
  },
];

const ACCENT_COLOR = "#dc2626";
const QUIZ_QUESTION_COUNT = 10;

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Overview",
    question: "What is the OWASP Top 10?",
    options: [
      "A list of the ten most critical web application security risks",
      "A certification program for developers",
      "A vulnerability scanner maintained by OWASP",
      "A compliance standard for payment systems",
    ],
    correctAnswer: 0,
    explanation: "The OWASP Top 10 is an awareness list of the most critical web application security risks.",
  },
  {
    id: 2,
    topic: "Overview",
    question: "What is the primary purpose of the OWASP Top 10?",
    options: [
      "A compliance requirement for all web apps",
      "A developer awareness and prioritization guide",
      "A complete list of every vulnerability",
      "A replacement for threat modeling",
    ],
    correctAnswer: 1,
    explanation: "The Top 10 is an awareness document used to prioritize the most critical risks.",
  },
  {
    id: 3,
    topic: "Overview",
    question: "What does OWASP stand for?",
    options: [
      "Open Web Application Security Project",
      "Online Web App Security Program",
      "Open Web App Standards Program",
      "Operational Web App Security Practice",
    ],
    correctAnswer: 0,
    explanation: "OWASP is the Open Web Application Security Project.",
  },
  {
    id: 4,
    topic: "Overview",
    question: "Which OWASP Top 10 edition is covered on this page?",
    options: ["2017", "2019", "2021", "2023"],
    correctAnswer: 2,
    explanation: "The page focuses on the OWASP Top 10 (2021).",
  },
  {
    id: 5,
    topic: "Overview",
    question: "The 2021 Top 10 is based on data from roughly:",
    options: ["50,000 apps", "500,000 apps and APIs", "5 million apps", "10,000 apps"],
    correctAnswer: 1,
    explanation: "The 2021 edition is based on data from over 500,000 applications and APIs.",
  },
  {
    id: 6,
    topic: "A01: Broken Access Control",
    question: "Which risk is ranked A01 in the 2021 OWASP Top 10?",
    options: ["Broken Access Control", "Security Misconfiguration", "Injection", "SSRF"],
    correctAnswer: 0,
    explanation: "A01 is Broken Access Control.",
  },
  {
    id: 7,
    topic: "A01: Broken Access Control",
    question: "IDOR (Insecure Direct Object Reference) is an example of:",
    options: ["Broken Access Control", "Insecure Design", "SSRF", "Cryptographic Failures"],
    correctAnswer: 0,
    explanation: "IDOR is a classic access control failure.",
  },
  {
    id: 8,
    topic: "A01: Broken Access Control",
    question: "Access control checks should be:",
    options: [
      "Implemented only in the UI",
      "Enforced server-side and consistently",
      "Optional for trusted users",
      "Handled only in the database",
    ],
    correctAnswer: 1,
    explanation: "Access control must be enforced on the server and applied consistently.",
  },
  {
    id: 9,
    topic: "A01: Broken Access Control",
    question: "The principle of 'deny by default' means:",
    options: [
      "Allow everything unless blocked",
      "Block everything unless explicitly allowed",
      "Log and allow all requests",
      "Require user consent only",
    ],
    correctAnswer: 1,
    explanation: "Deny by default blocks access unless it is explicitly allowed.",
  },
  {
    id: 10,
    topic: "A01: Broken Access Control",
    question: "Which control helps reduce automated access control abuse?",
    options: ["Rate limiting sensitive endpoints", "Verbose error messages", "Client-side validation only", "Disabling logging"],
    correctAnswer: 0,
    explanation: "Rate limiting reduces automated attacks against access control.",
  },
  {
    id: 11,
    topic: "A01: Broken Access Control",
    question: "CORS misconfiguration enabling unauthorized API access falls under:",
    options: ["Broken Access Control", "Cryptographic Failures", "Insecure Design", "SSRF"],
    correctAnswer: 0,
    explanation: "CORS misconfigurations can result in access control failures.",
  },
  {
    id: 12,
    topic: "A01: Broken Access Control",
    question: "Which practice helps prevent users accessing other users' data?",
    options: [
      "Enforce record ownership in the model layer",
      "Rely on hidden form fields",
      "Only validate on the client",
      "Store IDs in cookies only",
    ],
    correctAnswer: 0,
    explanation: "Model-layer ownership checks enforce proper authorization for each record.",
  },
  {
    id: 13,
    topic: "A02: Cryptographic Failures",
    question: "A02:2021 is named:",
    options: ["Cryptographic Failures", "Sensitive Data Exposure", "Security Misconfiguration", "Injection"],
    correctAnswer: 0,
    explanation: "A02 is Cryptographic Failures in the 2021 list.",
  },
  {
    id: 14,
    topic: "A02: Cryptographic Failures",
    question: "Which is an example of a cryptographic failure?",
    options: ["Using MD5 or SHA-1 for passwords", "Enforcing MFA", "Using TLS 1.2", "Rotating encryption keys"],
    correctAnswer: 0,
    explanation: "Weak hashing algorithms like MD5 or SHA-1 are cryptographic failures.",
  },
  {
    id: 15,
    topic: "A02: Cryptographic Failures",
    question: "Best practice for protecting data in transit is:",
    options: ["HTTP only", "TLS 1.2+ with strong ciphers", "Base64 encoding", "Gzip compression"],
    correctAnswer: 1,
    explanation: "TLS 1.2+ provides secure transport encryption.",
  },
  {
    id: 16,
    topic: "A02: Cryptographic Failures",
    question: "HSTS primarily helps by:",
    options: ["Encrypting databases", "Forcing browsers to use HTTPS", "Rotating keys", "Preventing SQL injection"],
    correctAnswer: 1,
    explanation: "HSTS tells browsers to always use HTTPS for a site.",
  },
  {
    id: 17,
    topic: "A02: Cryptographic Failures",
    question: "Which is poor key management?",
    options: ["Hardcoded or reused keys", "Key rotation", "Using an HSM", "Unique per-environment keys"],
    correctAnswer: 0,
    explanation: "Hardcoded or reused keys are a common crypto failure.",
  },
  {
    id: 18,
    topic: "A02: Cryptographic Failures",
    question: "Authenticated encryption provides:",
    options: ["Confidentiality only", "Integrity only", "Confidentiality and integrity", "Compression only"],
    correctAnswer: 2,
    explanation: "Authenticated encryption protects both confidentiality and integrity.",
  },
  {
    id: 19,
    topic: "A02: Cryptographic Failures",
    question: "Which storage practice aligns with A02 prevention?",
    options: [
      "Store only necessary sensitive data",
      "Store all data for convenience",
      "Log plaintext secrets",
      "Disable encryption at rest",
    ],
    correctAnswer: 0,
    explanation: "Minimizing stored sensitive data reduces exposure and risk.",
  },
  {
    id: 20,
    topic: "A03: Injection",
    question: "A03:2021 focuses on:",
    options: ["Injection", "Logging Failures", "Insecure Design", "Security Misconfiguration"],
    correctAnswer: 0,
    explanation: "A03 covers injection flaws such as SQL, NoSQL, and command injection.",
  },
  {
    id: 21,
    topic: "A03: Injection",
    question: "Parameterized queries are most effective against:",
    options: ["SQL injection", "XSS", "SSRF", "CSRF"],
    correctAnswer: 0,
    explanation: "Parameterized queries separate code from data to prevent SQL injection.",
  },
  {
    id: 22,
    topic: "A03: Injection",
    question: "Which code pattern is a command injection risk?",
    options: ["system('ping ' + userInput)", "Math.random()", "JSON.stringify(userInput)", "encodeURIComponent(userInput)"],
    correctAnswer: 0,
    explanation: "Concatenating user input into OS commands enables command injection.",
  },
  {
    id: 23,
    topic: "A03: Injection",
    question: "Server-side template injection (SSTI) is categorized as:",
    options: ["Injection", "Cryptographic Failures", "Access Control", "Logging Failures"],
    correctAnswer: 0,
    explanation: "SSTI is a type of injection vulnerability.",
  },
  {
    id: 24,
    topic: "A03: Injection",
    question: "Positive (allowlist) input validation means:",
    options: [
      "Allow only expected formats",
      "Allow any input",
      "Reject only known bad inputs",
      "Sanitize on the client only",
    ],
    correctAnswer: 0,
    explanation: "Allowlist validation accepts only expected, safe input formats.",
  },
  {
    id: 25,
    topic: "A03: Injection",
    question: "Injection attacks can lead to:",
    options: ["Data loss or host takeover", "Faster performance", "Only cosmetic issues", "No impact if logged"],
    correctAnswer: 0,
    explanation: "Injection can cause data loss, corruption, or full system compromise.",
  },
  {
    id: 26,
    topic: "A03: Injection",
    question: "Which is a recommended mitigation for injection?",
    options: ["Escape special characters for interpreters", "Hide error messages only", "Rely on client validation", "Allow dynamic SQL"],
    correctAnswer: 0,
    explanation: "Escaping input for interpreters reduces injection risk.",
  },
  {
    id: 27,
    topic: "A04: Insecure Design",
    question: "A04:2021 is:",
    options: ["Insecure Design", "Security Misconfiguration", "Broken Access Control", "SSRF"],
    correctAnswer: 0,
    explanation: "A04 covers Insecure Design.",
  },
  {
    id: 28,
    topic: "A04: Insecure Design",
    question: "Which is an insecure design example?",
    options: [
      "No rate limiting on password reset",
      "Missing log rotation",
      "Outdated library in production",
      "Weak hashing algorithm",
    ],
    correctAnswer: 0,
    explanation: "Missing rate limiting on critical flows is an insecure design decision.",
  },
  {
    id: 29,
    topic: "A04: Insecure Design",
    question: "Threat modeling is used to:",
    options: [
      "Identify risks early and design controls",
      "Speed up coding",
      "Replace security testing",
      "Avoid documentation",
    ],
    correctAnswer: 0,
    explanation: "Threat modeling helps identify and address risks during design.",
  },
  {
    id: 30,
    topic: "A04: Insecure Design",
    question: "The statement 'secure implementation cannot fix insecure design' implies:",
    options: [
      "Architectural changes are required",
      "Code review is enough",
      "Unit tests fix everything",
      "Encryption is optional",
    ],
    correctAnswer: 0,
    explanation: "Insecure design requires design-level changes, not just code fixes.",
  },
  {
    id: 31,
    topic: "A04: Insecure Design",
    question: "Which practice directly addresses insecure design?",
    options: [
      "Secure SDLC with security input",
      "Client-side validation only",
      "Disable logs",
      "Skip requirements",
    ],
    correctAnswer: 0,
    explanation: "A secure SDLC and early security input help prevent design flaws.",
  },
  {
    id: 32,
    topic: "A04: Insecure Design",
    question: "Allowing negative quantities or prices in checkout is an example of:",
    options: ["Missing business logic validation", "Cryptographic failure", "SSRF", "Logging failure"],
    correctAnswer: 0,
    explanation: "Business logic validation prevents invalid or abusive workflows.",
  },
  {
    id: 33,
    topic: "A04: Insecure Design",
    question: "Segregation of duties helps by:",
    options: [
      "Reducing design flaws through separated responsibilities",
      "Increasing feature speed",
      "Removing the need for access control",
      "Eliminating logging",
    ],
    correctAnswer: 0,
    explanation: "Segregation of duties reduces systemic design weaknesses.",
  },
  {
    id: 34,
    topic: "A05: Security Misconfiguration",
    question: "A05:2021 is:",
    options: ["Security Misconfiguration", "Insecure Design", "Injection", "Broken Access Control"],
    correctAnswer: 0,
    explanation: "A05 is Security Misconfiguration.",
  },
  {
    id: 35,
    topic: "A05: Security Misconfiguration",
    question: "Which is a typical security misconfiguration?",
    options: ["Default admin/admin credentials", "Enforced MFA", "Parameterized queries", "SRI checks"],
    correctAnswer: 0,
    explanation: "Default credentials are a common misconfiguration.",
  },
  {
    id: 36,
    topic: "A05: Security Misconfiguration",
    question: "Missing security headers like CSP or HSTS is considered:",
    options: ["Misconfiguration", "Injection", "Access Control", "Integrity Failure"],
    correctAnswer: 0,
    explanation: "Missing security headers are configuration issues.",
  },
  {
    id: 37,
    topic: "A05: Security Misconfiguration",
    question: "A repeatable hardening process is important because it:",
    options: [
      "Makes secure deployments consistent",
      "Replaces patching",
      "Avoids logging",
      "Blocks all traffic",
    ],
    correctAnswer: 0,
    explanation: "Hardening ensures consistent, secure configuration across environments.",
  },
  {
    id: 38,
    topic: "A05: Security Misconfiguration",
    question: "Directory listing enabled on a web server is:",
    options: ["Misconfiguration", "Cryptographic Failure", "Injection", "Secure by Design"],
    correctAnswer: 0,
    explanation: "Directory listing exposes sensitive files and is a misconfiguration.",
  },
  {
    id: 39,
    topic: "A05: Security Misconfiguration",
    question: "Publicly accessible cloud storage buckets are an example of:",
    options: ["Misconfiguration", "Authentication Failure", "SSRF", "Logging Failure"],
    correctAnswer: 0,
    explanation: "Public buckets often result from improper configuration.",
  },
  {
    id: 40,
    topic: "A05: Security Misconfiguration",
    question: "Which action helps prevent configuration drift?",
    options: ["Automated configuration verification", "Disabling updates", "Storing secrets in code", "Leaving defaults"],
    correctAnswer: 0,
    explanation: "Automated checks help ensure secure configuration remains intact.",
  },
  {
    id: 41,
    topic: "A06: Vulnerable and Outdated Components",
    question: "A06:2021 addresses:",
    options: ["Vulnerable and Outdated Components", "Insecure Design", "SSRF", "Logging Failures"],
    correctAnswer: 0,
    explanation: "A06 is Vulnerable and Outdated Components.",
  },
  {
    id: 42,
    topic: "A06: Vulnerable and Outdated Components",
    question: "Log4Shell is an example of:",
    options: ["Vulnerable component risk", "Broken access control", "Cryptographic failure", "SSRF"],
    correctAnswer: 0,
    explanation: "Log4Shell was a critical vulnerability in a widely used component.",
  },
  {
    id: 43,
    topic: "A06: Vulnerable and Outdated Components",
    question: "SBOM stands for:",
    options: ["Software Bill of Materials", "Secure Backup of Modules", "System Boundary Operations Manual", "Standard Build Output Manifest"],
    correctAnswer: 0,
    explanation: "An SBOM is a Software Bill of Materials.",
  },
  {
    id: 44,
    topic: "A06: Vulnerable and Outdated Components",
    question: "Which practice reduces component risk?",
    options: ["Remove unused dependencies", "Ignore updates", "Use unofficial mirrors", "Disable inventory"],
    correctAnswer: 0,
    explanation: "Removing unused dependencies reduces the attack surface.",
  },
  {
    id: 45,
    topic: "A06: Vulnerable and Outdated Components",
    question: "Components should be obtained:",
    options: [
      "From official sources over secure links",
      "From random forums",
      "Via copy-paste from blogs",
      "From unknown binaries",
    ],
    correctAnswer: 0,
    explanation: "Use trusted, official sources to reduce supply chain risks.",
  },
  {
    id: 46,
    topic: "A06: Vulnerable and Outdated Components",
    question: "Why is end-of-life software risky?",
    options: [
      "No security patches are provided",
      "It runs faster",
      "It is more compatible",
      "It prevents injection",
    ],
    correctAnswer: 0,
    explanation: "EOL software no longer receives security updates.",
  },
  {
    id: 47,
    topic: "A06: Vulnerable and Outdated Components",
    question: "Which tool or process helps find vulnerable dependencies?",
    options: ["Software composition analysis (SCA)", "Only manual code review", "Client-side validation", "Input encoding"],
    correctAnswer: 0,
    explanation: "SCA tools scan dependencies for known vulnerabilities.",
  },
  {
    id: 48,
    topic: "A07: Identification and Authentication Failures",
    question: "A07:2021 is:",
    options: ["Identification and Authentication Failures", "Insecure Design", "Security Misconfiguration", "Injection"],
    correctAnswer: 0,
    explanation: "A07 covers authentication and session management failures.",
  },
  {
    id: 49,
    topic: "A07: Identification and Authentication Failures",
    question: "Credential stuffing is primarily a risk in:",
    options: [
      "Identification and Authentication Failures",
      "SSRF",
      "Cryptographic Failures",
      "Integrity Failures",
    ],
    correctAnswer: 0,
    explanation: "Credential stuffing targets weak authentication defenses.",
  },
  {
    id: 50,
    topic: "A07: Identification and Authentication Failures",
    question: "MFA helps mitigate:",
    options: ["Account takeover from stolen passwords", "SSRF", "SQL injection", "Logging failures"],
    correctAnswer: 0,
    explanation: "MFA reduces the impact of stolen passwords.",
  },
  {
    id: 51,
    topic: "A07: Identification and Authentication Failures",
    question: "Session IDs in URLs are risky because:",
    options: [
      "They can leak via logs or referrers",
      "They encrypt traffic",
      "They enforce access control",
      "They speed up sessions",
    ],
    correctAnswer: 0,
    explanation: "URLs are logged and shared, which can expose session IDs.",
  },
  {
    id: 52,
    topic: "A07: Identification and Authentication Failures",
    question: "A weak password recovery process can lead to:",
    options: ["Account compromise", "Faster login", "Encrypted storage", "Better auditing"],
    correctAnswer: 0,
    explanation: "Weak recovery mechanisms can be abused to take over accounts.",
  },
  {
    id: 53,
    topic: "A07: Identification and Authentication Failures",
    question: "After successful login, session identifiers should be:",
    options: ["Rotated to prevent fixation", "Kept the same forever", "Stored in localStorage only", "Displayed to users"],
    correctAnswer: 0,
    explanation: "Rotating session IDs reduces session fixation risks.",
  },
  {
    id: 54,
    topic: "A07: Identification and Authentication Failures",
    question: "Limiting failed login attempts primarily helps reduce:",
    options: ["Brute force attacks", "SQL injection", "SSRF", "Logging noise only"],
    correctAnswer: 0,
    explanation: "Rate limiting reduces brute force and credential stuffing attempts.",
  },
  {
    id: 55,
    topic: "A08: Software and Data Integrity Failures",
    question: "A08:2021 focuses on:",
    options: ["Software and Data Integrity Failures", "Misconfiguration", "Access Control", "Cryptographic Failures"],
    correctAnswer: 0,
    explanation: "A08 covers integrity risks across software and data pipelines.",
  },
  {
    id: 56,
    topic: "A08: Software and Data Integrity Failures",
    question: "Unsigned updates or untrusted plugins are examples of:",
    options: ["Integrity failures", "Logging failures", "Injection", "Access control issues"],
    correctAnswer: 0,
    explanation: "Unsigned or untrusted updates can be tampered with.",
  },
  {
    id: 57,
    topic: "A08: Software and Data Integrity Failures",
    question: "Subresource Integrity (SRI) is used to:",
    options: ["Verify integrity of CDN assets", "Enforce MFA", "Encrypt databases", "Validate JWTs"],
    correctAnswer: 0,
    explanation: "SRI verifies that CDN-delivered files have not been tampered with.",
  },
  {
    id: 58,
    topic: "A08: Software and Data Integrity Failures",
    question: "Insecure deserialization risk is included in:",
    options: ["A08", "A05", "A02", "A01"],
    correctAnswer: 0,
    explanation: "Insecure deserialization is part of integrity failures in A08.",
  },
  {
    id: 59,
    topic: "A08: Software and Data Integrity Failures",
    question: "A secure CI/CD pipeline should include:",
    options: [
      "Access controls and signed artifacts",
      "Public write access",
      "No reviews",
      "Disabled logging",
    ],
    correctAnswer: 0,
    explanation: "Secure pipelines require access controls and integrity checks.",
  },
  {
    id: 60,
    topic: "A08: Software and Data Integrity Failures",
    question: "Digital signatures primarily provide:",
    options: ["Integrity and authenticity", "Compression", "Confidentiality only", "Rate limiting"],
    correctAnswer: 0,
    explanation: "Signatures verify integrity and authenticity of data and code.",
  },
  {
    id: 61,
    topic: "A08: Software and Data Integrity Failures",
    question: "Why should serialized data not be accepted unsigned from untrusted clients?",
    options: [
      "It can be tampered with to alter behavior",
      "It improves performance too much",
      "It prevents logging",
      "It guarantees integrity",
    ],
    correctAnswer: 0,
    explanation: "Unsigned serialized data can be modified to trigger unexpected behavior.",
  },
  {
    id: 62,
    topic: "A09: Security Logging and Monitoring Failures",
    question: "A09:2021 is:",
    options: ["Security Logging and Monitoring Failures", "Insecure Design", "Injection", "SSRF"],
    correctAnswer: 0,
    explanation: "A09 covers insufficient logging, monitoring, and response.",
  },
  {
    id: 63,
    topic: "A09: Security Logging and Monitoring Failures",
    question: "Which events should always be logged?",
    options: [
      "Login attempts and access control failures",
      "Only UI clicks",
      "Only successful logins",
      "Only client-side errors",
    ],
    correctAnswer: 0,
    explanation: "Authentication and access control failures are critical security events.",
  },
  {
    id: 64,
    topic: "A09: Security Logging and Monitoring Failures",
    question: "Why is storing logs only locally risky?",
    options: [
      "Attackers can tamper with or erase them",
      "It improves integrity",
      "It enables MFA",
      "It prevents SSRF",
    ],
    correctAnswer: 0,
    explanation: "Local-only logs are easier for attackers to delete or alter.",
  },
  {
    id: 65,
    topic: "A09: Security Logging and Monitoring Failures",
    question: "Lack of alerting thresholds leads to:",
    options: ["Delayed breach detection", "Faster authentication", "Fewer vulnerabilities", "Stronger encryption"],
    correctAnswer: 0,
    explanation: "Without alerting, attacks can go unnoticed for long periods.",
  },
  {
    id: 66,
    topic: "A09: Security Logging and Monitoring Failures",
    question: "Logs should be formatted to be consumed by:",
    options: ["Centralized log management or SIEM", "Only plain text viewers", "Client browsers", "QR codes"],
    correctAnswer: 0,
    explanation: "Centralized logging makes monitoring and alerting practical.",
  },
  {
    id: 67,
    topic: "A09: Security Logging and Monitoring Failures",
    question: "An incident response plan helps by:",
    options: [
      "Enabling faster detection and recovery",
      "Disabling access controls",
      "Replacing encryption",
      "Eliminating logs",
    ],
    correctAnswer: 0,
    explanation: "Response plans help teams detect, contain, and recover from incidents.",
  },
  {
    id: 68,
    topic: "A09: Security Logging and Monitoring Failures",
    question: "Without monitoring, attackers can often:",
    options: ["Persist and pivot undetected", "Fix vulnerabilities", "Improve performance", "Reduce risk automatically"],
    correctAnswer: 0,
    explanation: "Poor monitoring allows attackers to stay hidden and move laterally.",
  },
  {
    id: 69,
    topic: "A10: Server-Side Request Forgery (SSRF)",
    question: "A10:2021 refers to:",
    options: ["Server-Side Request Forgery (SSRF)", "SQL Injection", "Insecure Design", "Misconfiguration"],
    correctAnswer: 0,
    explanation: "A10 is Server-Side Request Forgery (SSRF).",
  },
  {
    id: 70,
    topic: "A10: Server-Side Request Forgery (SSRF)",
    question: "SSRF lets attackers make the server:",
    options: [
      "Request internal or unintended resources",
      "Encrypt all traffic",
      "Log out users",
      "Disable CSP",
    ],
    correctAnswer: 0,
    explanation: "SSRF abuses server-side fetching to reach internal resources.",
  },
  {
    id: 71,
    topic: "A10: Server-Side Request Forgery (SSRF)",
    question: "The IP 169.254.169.254 is commonly used for:",
    options: ["Cloud instance metadata", "Public DNS", "Time servers", "CDN edge nodes"],
    correctAnswer: 0,
    explanation: "Cloud metadata services often use 169.254.169.254.",
  },
  {
    id: 72,
    topic: "A10: Server-Side Request Forgery (SSRF)",
    question: "Which control is recommended to mitigate SSRF?",
    options: [
      "Allowlists for URL schemes, hosts, and ports",
      "Client-side validation only",
      "Disable TLS",
      "Expose raw responses",
    ],
    correctAnswer: 0,
    explanation: "Allowlists restrict where server-side requests can go.",
  },
  {
    id: 73,
    topic: "A10: Server-Side Request Forgery (SSRF)",
    question: "Disabling HTTP redirects helps because:",
    options: [
      "It prevents SSRF chaining to unintended targets",
      "It enforces MFA",
      "It fixes SQL injection",
      "It increases latency",
    ],
    correctAnswer: 0,
    explanation: "Redirects can be abused to reach disallowed targets.",
  },
  {
    id: 74,
    topic: "A10: Server-Side Request Forgery (SSRF)",
    question: "Why segment remote resource access into separate networks?",
    options: [
      "To limit SSRF impact and access to internal systems",
      "To speed up requests",
      "To avoid logging",
      "To remove authentication",
    ],
    correctAnswer: 0,
    explanation: "Segmentation limits the blast radius of SSRF.",
  },
  {
    id: 75,
    topic: "A10: Server-Side Request Forgery (SSRF)",
    question: "Why avoid returning raw SSRF responses to clients?",
    options: [
      "They can reveal internal data",
      "They are always encrypted",
      "They improve UX",
      "They prevent injection",
    ],
    correctAnswer: 0,
    explanation: "Raw responses can leak sensitive internal information.",
  },
];

export default function OwaspTop10Page() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [expandedItem, setExpandedItem] = useState<string | false>("A01");

  const pageContext = `OWASP Top 10 (2021) - The definitive web application security risks document. Covers: A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection (SQL, NoSQL, OS, LDAP), A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable and Outdated Components, A07 Identification and Authentication Failures, A08 Software and Data Integrity Failures, A09 Security Logging and Monitoring Failures, A10 Server-Side Request Forgery (SSRF). Each risk includes description, impact, examples, prevention strategies, and related CWEs.`;

  return (
    <LearnPageLayout pageTitle="OWASP Top 10 Web Security Risks" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Button */}
      <Chip
        component={RouterLink}
        to="/learn"
        icon={<ArrowBackIcon />}
        label="Back to Learning Hub"
        clickable
        variant="outlined"
        sx={{ borderRadius: 2, mb: 3 }}
      />

      {/* Header */}
      <Box sx={{ mb: 5 }}>
        <Typography
          variant="h3"
          sx={{
            fontWeight: 800,
            mb: 2,
            background: `linear-gradient(135deg, #dc2626, #7c3aed)`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          🛡️ OWASP Top 10 (2021)
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 900 }}>
          The definitive awareness document for web application security, representing the most critical security risks to web applications.
        </Typography>
      </Box>

      {/* Overview */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#dc2626", 0.05)}, ${alpha("#7c3aed", 0.05)})` }}>
        <Grid container spacing={4}>
          <Grid item xs={12} md={8}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
              What is the OWASP Top 10?
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
              The <strong>OWASP Top 10</strong> is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications, published by the Open Web Application Security Project (OWASP).
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
              The 2021 edition includes three new categories (A04, A08, A10), merges several previous categories, and is based on data from over 500,000 applications and APIs. It's the industry standard reference for prioritizing web security efforts.
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              <Chip label="2021 Edition" sx={{ bgcolor: alpha("#dc2626", 0.1), color: "#dc2626", fontWeight: 600 }} />
              <Chip label="10 Categories" variant="outlined" />
              <Chip label="500K+ Apps Analyzed" variant="outlined" />
              <Chip label="Industry Standard" variant="outlined" />
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <Alert severity="info" sx={{ mb: 2, borderRadius: 2 }}>
              <Typography variant="body2">
                <strong>💡 Pro Tip:</strong> Use OWASP Top 10 for prioritization, not as an exhaustive checklist. Many important vulnerabilities aren't in the Top 10.
              </Typography>
            </Alert>
            <Link
              href="https://owasp.org/Top10/"
              target="_blank"
              rel="noopener"
              sx={{ display: "flex", alignItems: "center", gap: 0.5 }}
            >
              Official OWASP Top 10 Site <LaunchIcon fontSize="small" />
            </Link>
          </Grid>
        </Grid>
      </Paper>

      {/* Risk Visualization */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
        📊 Prevalence Overview
      </Typography>
      <Paper sx={{ p: 3, mb: 5, borderRadius: 3 }}>
        <Grid container spacing={2}>
          {owaspTop10.map((item) => (
            <Grid item xs={12} key={item.id}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <Box sx={{ minWidth: 40, textAlign: "center" }}>
                  <Typography variant="h6" sx={{ fontWeight: 800, color: item.color }}>
                    #{item.rank}
                  </Typography>
                </Box>
                <Box sx={{ flex: 1 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      {item.name}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {item.prevalence}% of apps affected
                    </Typography>
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={item.prevalence}
                    sx={{
                      height: 8,
                      borderRadius: 4,
                      bgcolor: alpha(item.color, 0.1),
                      "& .MuiLinearProgress-bar": { bgcolor: item.color, borderRadius: 4 },
                    }}
                  />
                </Box>
              </Box>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Detailed Breakdown */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
        📋 Detailed Breakdown
      </Typography>
      {owaspTop10.map((item) => (
        <Accordion
          key={item.id}
          expanded={expandedItem === item.id}
          onChange={(_, expanded) => setExpandedItem(expanded ? item.id : false)}
          sx={{
            mb: 2,
            borderRadius: 2,
            "&:before": { display: "none" },
            border: `1px solid ${alpha(item.color, 0.2)}`,
            "&.Mui-expanded": { border: `2px solid ${item.color}` },
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{
              bgcolor: alpha(item.color, 0.05),
              borderRadius: "8px 8px 0 0",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
              <Chip
                label={item.id}
                size="small"
                sx={{ bgcolor: item.color, color: "white", fontWeight: 700, minWidth: 50 }}
              />
              <Box sx={{ flex: 1 }}>
                <Typography variant="h6" sx={{ fontWeight: 700 }}>
                  {item.name}
                </Typography>
              </Box>
              <Chip
                label={`${item.prevalence}%`}
                size="small"
                variant="outlined"
                sx={{ borderColor: item.color, color: item.color }}
              />
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ p: 4 }}>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              {item.description}
            </Typography>

            <Alert severity="error" sx={{ mb: 3, borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Impact</Typography>
              <Typography variant="body2">{item.impact}</Typography>
            </Alert>

            <Grid container spacing={4}>
              {/* Examples */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <WarningIcon fontSize="small" /> Common Examples
                  </Typography>
                  <List dense>
                    {item.examples.map((example, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <Typography variant="body2">•</Typography>
                        </ListItemIcon>
                        <ListItemText primary={example} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>

              {/* Prevention */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <SecurityIcon fontSize="small" /> Prevention Measures
                  </Typography>
                  <List dense>
                    {item.prevention.map((prev, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <Typography variant="body2" color="success.main">✓</Typography>
                        </ListItemIcon>
                        <ListItemText primary={prev} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            </Grid>

            <Divider sx={{ my: 3 }} />

            {/* CWEs and Incident */}
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>📌 Related CWEs</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                  {item.cwes.map((cwe) => (
                    <Link
                      key={cwe.id}
                      href={`https://cwe.mitre.org/data/definitions/${cwe.id.split("-")[1]}.html`}
                      target="_blank"
                      rel="noopener"
                      underline="none"
                    >
                      <Chip
                        label={`${cwe.id}: ${cwe.name}`}
                        size="small"
                        clickable
                        sx={{ fontSize: "0.75rem", bgcolor: alpha(item.color, 0.1), color: item.color }}
                      />
                    </Link>
                  ))}
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>🔥 Real-World Incident</Typography>
                <Typography variant="body2" color="text.secondary">
                  {item.realWorldIncident}
                </Typography>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>
      ))}

      {/* Resources */}
      <Paper sx={{ p: 4, mt: 4, borderRadius: 3, bgcolor: alpha(theme.palette.info.main, 0.05), border: `1px solid ${alpha(theme.palette.info.main, 0.2)}` }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          🔗 Additional Resources
        </Typography>
        <Grid container spacing={2}>
          {[
            { title: "OWASP Top 10 Official", url: "https://owasp.org/Top10/" },
            { title: "OWASP Testing Guide", url: "https://owasp.org/www-project-web-security-testing-guide/" },
            { title: "OWASP Cheat Sheet Series", url: "https://cheatsheetseries.owasp.org/" },
            { title: "OWASP ASVS", url: "https://owasp.org/www-project-application-security-verification-standard/" },
          ].map((resource) => (
            <Grid item xs={12} sm={6} md={3} key={resource.title}>
              <Link href={resource.url} target="_blank" rel="noopener" underline="none">
                <Paper
                  sx={{
                    p: 2,
                    textAlign: "center",
                    bgcolor: "background.paper",
                    transition: "all 0.2s",
                    "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) },
                  }}
                >
                  <Typography variant="body2" sx={{ fontWeight: 600, color: "primary.main", display: "flex", alignItems: "center", justifyContent: "center", gap: 0.5 }}>
                    {resource.title} <LaunchIcon fontSize="small" />
                  </Typography>
                </Paper>
              </Link>
            </Grid>
          ))}
        </Grid>
      </Paper>

      <Paper
        id="quiz-section"
        sx={{
          mt: 4,
          p: 4,
          borderRadius: 3,
          border: `1px solid ${alpha(ACCENT_COLOR, 0.2)}`,
        }}
      >
        <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <QuizIcon sx={{ color: ACCENT_COLOR }} />
          Knowledge Check
        </Typography>
        <QuizSection
          questions={quizQuestions}
          accentColor={ACCENT_COLOR}
          title="OWASP Top 10 Knowledge Check"
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
