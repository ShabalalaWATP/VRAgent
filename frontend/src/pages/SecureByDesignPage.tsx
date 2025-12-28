import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Typography,
  Paper,
  Chip,
  Button,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Alert,
  AlertTitle,
  Radio,
  RadioGroup,
  FormControlLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  alpha,
  useTheme,
  Fab,
  Drawer,
  IconButton,
  Tooltip,
  useMediaQuery,
  LinearProgress,
  Avatar,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SecurityIcon from "@mui/icons-material/Security";
import ShieldIcon from "@mui/icons-material/Shield";
import LockIcon from "@mui/icons-material/Lock";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import BugReportIcon from "@mui/icons-material/BugReport";
import CodeIcon from "@mui/icons-material/Code";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import StorageIcon from "@mui/icons-material/Storage";
import CloudIcon from "@mui/icons-material/Cloud";
import PolicyIcon from "@mui/icons-material/Policy";
import GppGoodIcon from "@mui/icons-material/GppGood";
import GppBadIcon from "@mui/icons-material/GppBad";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import KeyIcon from "@mui/icons-material/Key";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import HttpsIcon from "@mui/icons-material/Https";
import { useNavigate } from "react-router-dom";

interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

const questionBank: QuizQuestion[] = [
  // Topic 1: Core Principles (1-15)
  { id: 1, question: "What does 'Secure by Design' mean?", options: ["Adding security after development", "Building security into software from the start", "Using only paid security tools", "Hiring external auditors"], correctAnswer: 1, explanation: "Secure by Design means integrating security considerations from the earliest stages of development, not as an afterthought.", topic: "Core Principles" },
  { id: 2, question: "What is the 'Principle of Least Privilege'?", options: ["Giving all users admin access", "Granting minimum permissions needed for a task", "Using only one password", "Disabling all security features"], correctAnswer: 1, explanation: "Least privilege means users and systems should only have the minimum permissions necessary to perform their functions.", topic: "Core Principles" },
  { id: 3, question: "What does 'Defense in Depth' refer to?", options: ["Using one strong firewall", "Multiple overlapping security controls", "Deep packet inspection only", "Defensive coding comments"], correctAnswer: 1, explanation: "Defense in Depth uses multiple layers of security controls so that if one fails, others still protect the system.", topic: "Core Principles" },
  { id: 4, question: "What is 'Fail Secure' design?", options: ["System crashes on any error", "System defaults to a secure state on failure", "Failing tests are ignored", "Security features are disabled on failure"], correctAnswer: 1, explanation: "Fail Secure means when a system fails, it should default to a secure state rather than an insecure one.", topic: "Core Principles" },
  { id: 5, question: "Why is 'Security by Obscurity' considered weak?", options: ["It's too expensive", "Secrets eventually leak; real security doesn't depend on hidden implementation", "It requires too many developers", "It only works for web apps"], correctAnswer: 1, explanation: "Security by Obscurity relies on attackers not knowing how something works. True security should work even if the design is known.", topic: "Core Principles" },
  { id: 6, question: "What is the 'Zero Trust' security model?", options: ["Trust all internal network traffic", "Never verify user identity", "Never trust, always verify - regardless of location", "Trust but verify later"], correctAnswer: 2, explanation: "Zero Trust assumes no implicit trust based on network location. Every request must be authenticated and authorized.", topic: "Core Principles" },
  { id: 7, question: "What does 'Attack Surface Reduction' mean?", options: ["Making UI simpler", "Minimizing entry points and exposure to reduce attack vectors", "Reducing code comments", "Lowering server count only"], correctAnswer: 1, explanation: "Attack Surface Reduction minimizes the number of potential entry points attackers could exploit.", topic: "Core Principles" },
  { id: 8, question: "What is 'Secure by Default'?", options: ["Security must be manually enabled", "Systems ship with secure settings out of the box", "Default passwords are secure enough", "Users choose security level"], correctAnswer: 1, explanation: "Secure by Default means software should be configured securely when first installed, not requiring users to enable security.", topic: "Core Principles" },
  { id: 9, question: "What is separation of duties?", options: ["One person does everything", "Critical tasks require multiple people/approvals", "Separating frontend and backend", "Using different databases"], correctAnswer: 1, explanation: "Separation of duties ensures no single person can complete a sensitive action alone, reducing fraud and error risk.", topic: "Core Principles" },
  { id: 10, question: "What is the principle of 'Complete Mediation'?", options: ["Every access to a resource should be checked", "Caching authorization decisions", "Mediating only failed requests", "Using proxy servers"], correctAnswer: 0, explanation: "Complete Mediation means every access to every object must be checked for authorization, with no caching of permissions.", topic: "Core Principles" },
  { id: 11, question: "What is 'Economy of Mechanism'?", options: ["Reducing costs", "Keep security mechanisms simple and small", "Using cheap hosting", "Minimal security spending"], correctAnswer: 1, explanation: "Economy of Mechanism means simpler designs are easier to verify, test, and trust. Complexity breeds vulnerabilities.", topic: "Core Principles" },
  { id: 12, question: "What does 'Psychological Acceptability' mean in security?", options: ["Security should be invisible to users", "Security should not unnecessarily burden legitimate users", "Users enjoy complex security", "Forcing users to memorize policies"], correctAnswer: 1, explanation: "Security mechanisms should be user-friendly enough that users will actually use them correctly.", topic: "Core Principles" },
  { id: 13, question: "What is 'Open Design' in security principles?", options: ["Open source only", "Security shouldn't depend on design secrecy", "Public code repositories", "No access controls"], correctAnswer: 1, explanation: "Open Design means the security of a mechanism should not depend on the secrecy of its design, only on the secrecy of keys.", topic: "Core Principles" },
  { id: 14, question: "What is 'Compartmentalization'?", options: ["Organizing code into folders", "Isolating components to limit breach impact", "Compressing data", "Using containers only"], correctAnswer: 1, explanation: "Compartmentalization isolates system components so a breach in one area doesn't compromise the entire system.", topic: "Core Principles" },
  { id: 15, question: "What is the 'Weakest Link' principle?", options: ["Use only weak passwords", "Security is only as strong as its weakest component", "Links in HTML are weak", "Chain networks together"], correctAnswer: 1, explanation: "A system's security is determined by its weakest component, so all parts must be adequately secured.", topic: "Core Principles" },
  // Topic 2: Threat Modeling (16-30)
  { id: 16, question: "What is Threat Modeling?", options: ["Creating 3D models of hackers", "Systematically identifying and addressing security threats", "Modeling user behavior", "Threat detection software"], correctAnswer: 1, explanation: "Threat Modeling is a structured approach to identifying, quantifying, and addressing security risks in a system.", topic: "Threat Modeling" },
  { id: 17, question: "What does STRIDE stand for in threat modeling?", options: ["Security Testing Review IDE", "Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege", "Standard Threat Response IDE", "Security Threat Response Integration"], correctAnswer: 1, explanation: "STRIDE is a threat classification: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.", topic: "Threat Modeling" },
  { id: 18, question: "What is 'Spoofing' in the STRIDE model?", options: ["Slow performance", "Pretending to be someone or something else", "Deleting data", "Network congestion"], correctAnswer: 1, explanation: "Spoofing involves impersonating another user, system, or component to gain unauthorized access.", topic: "Threat Modeling" },
  { id: 19, question: "What is 'Tampering' in STRIDE?", options: ["Installing updates", "Unauthorized modification of data or code", "Using tampons", "Debugging code"], correctAnswer: 1, explanation: "Tampering is the unauthorized modification of data in transit, at rest, or in processing.", topic: "Threat Modeling" },
  { id: 20, question: "What is 'Repudiation' in security?", options: ["Accepting responsibility", "Denying having performed an action without proof otherwise", "Reporting bugs", "Updating software"], correctAnswer: 1, explanation: "Repudiation is when a user denies performing an action and there's no way to prove they did.", topic: "Threat Modeling" },
  { id: 21, question: "What is a Data Flow Diagram (DFD) used for in threat modeling?", options: ["Showing user interfaces", "Visualizing how data moves through a system to identify threats", "Database design", "Network topology"], correctAnswer: 1, explanation: "DFDs show how data flows between processes, stores, and external entities, helping identify where threats may exist.", topic: "Threat Modeling" },
  { id: 22, question: "What is a 'Trust Boundary' in threat modeling?", options: ["Physical walls", "Where data crosses between different trust levels", "User interface border", "Network firewall only"], correctAnswer: 1, explanation: "Trust boundaries are where data or control passes between entities with different trust levels, requiring security checks.", topic: "Threat Modeling" },
  { id: 23, question: "What is the purpose of identifying 'Assets' in threat modeling?", options: ["Financial planning", "Understanding what needs protection", "Hardware inventory", "Software licensing"], correctAnswer: 1, explanation: "Identifying assets helps prioritize what needs protection and understand the impact of potential breaches.", topic: "Threat Modeling" },
  { id: 24, question: "What is DREAD used for?", options: ["Creating horror games", "Rating the severity of threats", "Database design", "Deployment readiness"], correctAnswer: 1, explanation: "DREAD (Damage, Reproducibility, Exploitability, Affected users, Discoverability) is a risk rating methodology.", topic: "Threat Modeling" },
  { id: 25, question: "What is an 'Attack Tree'?", options: ["A data structure", "Hierarchical diagram showing how an attack goal might be achieved", "Firewall logs", "Server cluster"], correctAnswer: 1, explanation: "Attack Trees visually represent different paths an attacker might take to achieve a malicious goal.", topic: "Threat Modeling" },
  { id: 26, question: "When should threat modeling be performed?", options: ["Only after a breach", "Early in design and throughout development", "Only before release", "Never, it's obsolete"], correctAnswer: 1, explanation: "Threat modeling should start early in design and continue throughout development as the system evolves.", topic: "Threat Modeling" },
  { id: 27, question: "What is a 'Threat Agent'?", options: ["Security software", "An entity that can carry out a threat", "Threat documentation", "Antivirus program"], correctAnswer: 1, explanation: "A threat agent is any entity (person, organization, or automated process) capable of carrying out a threat.", topic: "Threat Modeling" },
  { id: 28, question: "What does 'Elevation of Privilege' mean in STRIDE?", options: ["Getting a promotion", "Gaining higher permissions than authorized", "Improving code quality", "Upgrading software"], correctAnswer: 1, explanation: "Elevation of Privilege occurs when an attacker gains capabilities beyond what they're authorized for.", topic: "Threat Modeling" },
  { id: 29, question: "What is the PASTA threat modeling methodology?", options: ["Food-based security", "Process for Attack Simulation and Threat Analysis", "Password Testing Application", "Protocol Analysis System"], correctAnswer: 1, explanation: "PASTA is a risk-centric threat modeling methodology that aligns business objectives with technical requirements.", topic: "Threat Modeling" },
  { id: 30, question: "What is a 'Kill Chain' in security?", options: ["Stopping all processes", "Stages of a cyber attack from reconnaissance to objective", "Server shutdown procedure", "Removing malware"], correctAnswer: 1, explanation: "The Kill Chain describes the stages of a cyber attack, helping defenders understand and disrupt attacks.", topic: "Threat Modeling" },
  // Topic 3: Secure Coding (31-50)
  { id: 31, question: "What is Input Validation?", options: ["Checking user forms are filled", "Verifying input meets expected format before processing", "Validating output", "Testing performance"], correctAnswer: 1, explanation: "Input validation ensures all input data conforms to expected types, formats, and ranges before processing.", topic: "Secure Coding" },
  { id: 32, question: "What is SQL Injection?", options: ["Injecting new SQL features", "Inserting malicious SQL through user input", "Database optimization", "SQL formatting"], correctAnswer: 1, explanation: "SQL Injection occurs when malicious SQL code is inserted into queries through unvalidated user input.", topic: "Secure Coding" },
  { id: 33, question: "How do you prevent SQL Injection?", options: ["Using longer passwords", "Using parameterized queries/prepared statements", "Encrypting the database", "Disabling SQL"], correctAnswer: 1, explanation: "Parameterized queries separate SQL code from data, preventing malicious input from being executed as code.", topic: "Secure Coding" },
  { id: 34, question: "What is Cross-Site Scripting (XSS)?", options: ["Writing code for multiple sites", "Injecting malicious scripts into web pages viewed by others", "Cross-platform development", "Site performance optimization"], correctAnswer: 1, explanation: "XSS allows attackers to inject malicious scripts into web pages viewed by other users.", topic: "Secure Coding" },
  { id: 35, question: "How do you prevent XSS attacks?", options: ["Using HTTPS only", "Output encoding and Content Security Policy", "Faster servers", "More RAM"], correctAnswer: 1, explanation: "XSS is prevented by encoding output, using CSP headers, and validating/sanitizing input.", topic: "Secure Coding" },
  { id: 36, question: "What is CSRF (Cross-Site Request Forgery)?", options: ["Forging site certificates", "Tricking users into making unwanted requests while authenticated", "Creating fake websites", "Cross-site coding"], correctAnswer: 1, explanation: "CSRF tricks authenticated users into performing unwanted actions on a site where they're logged in.", topic: "Secure Coding" },
  { id: 37, question: "How do you prevent CSRF attacks?", options: ["Using cookies only", "Using anti-CSRF tokens and SameSite cookies", "Longer session timeouts", "Removing authentication"], correctAnswer: 1, explanation: "CSRF protection uses unique tokens per request and SameSite cookie attributes to verify request origin.", topic: "Secure Coding" },
  { id: 38, question: "What is 'Output Encoding'?", options: ["Compressing output", "Converting output to prevent it from being interpreted as code", "Encoding video files", "Base64 encoding all data"], correctAnswer: 1, explanation: "Output encoding converts special characters to safe representations so they're displayed, not executed.", topic: "Secure Coding" },
  { id: 39, question: "What is the purpose of 'Allowlisting' vs 'Blocklisting'?", options: ["Network configuration", "Allowlist permits known-good items; blocklist denies known-bad items", "Email filtering only", "User management"], correctAnswer: 1, explanation: "Allowlisting (whitelisting) is more secure because it only permits known-good inputs rather than trying to block known-bad ones.", topic: "Secure Coding" },
  { id: 40, question: "What is 'Path Traversal' vulnerability?", options: ["Slow navigation", "Accessing files outside intended directories using ../", "Walking through code paths", "Network routing issues"], correctAnswer: 1, explanation: "Path Traversal exploits inadequate input validation to access files outside the intended directory.", topic: "Secure Coding" },
  { id: 41, question: "What is 'Command Injection'?", options: ["Injecting new features", "Inserting malicious OS commands through application input", "Adding comments", "Command-line optimization"], correctAnswer: 1, explanation: "Command Injection occurs when an attacker can execute arbitrary OS commands through application input.", topic: "Secure Coding" },
  { id: 42, question: "What is a Buffer Overflow?", options: ["Too much data in a stream", "Writing data beyond allocated memory boundaries", "Too many buffers", "Memory optimization"], correctAnswer: 1, explanation: "Buffer Overflow writes data beyond allocated memory, potentially overwriting critical data or executing code.", topic: "Secure Coding" },
  { id: 43, question: "What is 'Insecure Deserialization'?", options: ["Slow parsing", "Deserializing untrusted data that can execute malicious code", "Incorrect serialization", "Data compression issues"], correctAnswer: 1, explanation: "Insecure Deserialization processes untrusted serialized data that can trigger remote code execution.", topic: "Secure Coding" },
  { id: 44, question: "What is the principle of 'Secure Error Handling'?", options: ["Showing all error details to users", "Logging errors internally while showing generic messages externally", "Ignoring all errors", "Crashing on errors"], correctAnswer: 1, explanation: "Secure Error Handling logs detailed errors internally but shows generic messages to users to avoid information disclosure.", topic: "Secure Coding" },
  { id: 45, question: "Why should you avoid storing secrets in code?", options: ["Makes code longer", "Code is often shared, versioned, and visible; secrets should use secure storage", "Secrets make code slower", "Comments are enough"], correctAnswer: 1, explanation: "Secrets in code can be exposed through version control, code sharing, or decompilation. Use secure secret management.", topic: "Secure Coding" },
  { id: 46, question: "What is 'Hardcoded Credentials'?", options: ["Strong passwords", "Embedding usernames/passwords directly in source code", "Hardware-based auth", "Credential rotation"], correctAnswer: 1, explanation: "Hardcoded credentials are usernames/passwords embedded in code, creating serious security risks if code is exposed.", topic: "Secure Coding" },
  { id: 47, question: "What is Content Security Policy (CSP)?", options: ["Content management", "HTTP header that controls which resources can be loaded", "Copyright policy", "Content compression"], correctAnswer: 1, explanation: "CSP is an HTTP header that restricts which resources (scripts, styles, etc.) can be loaded, preventing XSS.", topic: "Secure Coding" },
  { id: 48, question: "What is 'Race Condition' vulnerability?", options: ["Fast code execution", "Security flaw when timing affects behavior unexpectedly", "Competitive programming", "Performance optimization"], correctAnswer: 1, explanation: "Race conditions occur when the timing of events affects security-critical behavior in unexpected ways.", topic: "Secure Coding" },
  { id: 49, question: "What does 'Sanitization' mean in security?", options: ["Cleaning servers", "Removing or encoding dangerous characters from input", "Deleting old data", "System cleanup"], correctAnswer: 1, explanation: "Sanitization removes or neutralizes potentially dangerous characters or patterns from input data.", topic: "Secure Coding" },
  { id: 50, question: "What is 'Broken Access Control'?", options: ["Non-working permissions UI", "Failing to enforce authorization, allowing unauthorized access", "Slow authentication", "Missing login page"], correctAnswer: 1, explanation: "Broken Access Control occurs when authorization isn't properly enforced, allowing users to access unauthorized resources.", topic: "Secure Coding" },
  // Topic 4: Authentication & Cryptography (51-65)
  { id: 51, question: "What is Multi-Factor Authentication (MFA)?", options: ["Multiple passwords", "Using two or more verification factors for authentication", "Many user accounts", "Multiple login pages"], correctAnswer: 1, explanation: "MFA requires two or more factors: something you know, have, or are, significantly improving security.", topic: "Auth & Crypto" },
  { id: 52, question: "Why should passwords be hashed, not encrypted?", options: ["Hashing is faster", "Passwords don't need to be decrypted, only compared", "Encryption is illegal", "Hashing uses less storage"], correctAnswer: 1, explanation: "Passwords should be hashed because you only need to compare hashes, never retrieve the original password.", topic: "Auth & Crypto" },
  { id: 53, question: "What is a 'Salt' in password hashing?", options: ["Seasoning for security", "Random data added before hashing to prevent rainbow table attacks", "Password strength indicator", "Encryption key"], correctAnswer: 1, explanation: "A salt is random data added to each password before hashing, making rainbow table attacks ineffective.", topic: "Auth & Crypto" },
  { id: 54, question: "Which hashing algorithms are recommended for passwords?", options: ["MD5 and SHA1", "bcrypt, Argon2, or scrypt", "Base64", "ROT13"], correctAnswer: 1, explanation: "bcrypt, Argon2, and scrypt are designed for passwords with built-in salting and configurable work factors.", topic: "Auth & Crypto" },
  { id: 55, question: "What is 'Session Fixation'?", options: ["Fixing broken sessions", "Attacker sets a known session ID before victim authenticates", "Session timeout settings", "Fixing session cookies"], correctAnswer: 1, explanation: "Session Fixation tricks victims into using an attacker-known session ID, giving the attacker access after login.", topic: "Auth & Crypto" },
  { id: 56, question: "What is JWT (JSON Web Token)?", options: ["JavaScript testing", "A compact token for securely transmitting claims", "Java Web Technology", "JSON Web Transfer"], correctAnswer: 1, explanation: "JWT is a compact, URL-safe token format for securely transmitting claims between parties.", topic: "Auth & Crypto" },
  { id: 57, question: "What is the difference between authentication and authorization?", options: ["They're the same", "Authentication verifies identity; authorization checks permissions", "Authentication is for APIs only", "Authorization comes first"], correctAnswer: 1, explanation: "Authentication verifies WHO you are; Authorization determines WHAT you can access.", topic: "Auth & Crypto" },
  { id: 58, question: "What is HTTPS?", options: ["Fast HTTP", "HTTP with TLS encryption", "HTTP version 2", "Hyper Text Transfer Protocol Secure"], correctAnswer: 1, explanation: "HTTPS is HTTP encrypted with TLS, protecting data in transit from eavesdropping and tampering.", topic: "Auth & Crypto" },
  { id: 59, question: "What is Certificate Pinning?", options: ["Pinning certificates to walls", "Associating a host with expected certificates to prevent MITM", "Certificate decoration", "SSL optimization"], correctAnswer: 1, explanation: "Certificate Pinning validates that a server's certificate matches expected values, preventing MITM attacks.", topic: "Auth & Crypto" },
  { id: 60, question: "What is 'Key Rotation'?", options: ["Rotating keyboard keys", "Periodically changing cryptographic keys", "Key backup process", "Keyboard shortcuts"], correctAnswer: 1, explanation: "Key Rotation periodically changes cryptographic keys to limit exposure if a key is compromised.", topic: "Auth & Crypto" },
  { id: 61, question: "What is Symmetric vs Asymmetric encryption?", options: ["Same key for encrypt/decrypt vs different keys", "Fast vs slow encryption", "Old vs new encryption", "Simple vs complex algorithms"], correctAnswer: 0, explanation: "Symmetric uses the same key for both operations; Asymmetric uses a public/private key pair.", topic: "Auth & Crypto" },
  { id: 62, question: "What is OAuth 2.0?", options: ["Authentication protocol", "Authorization framework for third-party access", "Encryption standard", "Password manager"], correctAnswer: 1, explanation: "OAuth 2.0 is an authorization framework that enables third-party applications to obtain limited access to user accounts.", topic: "Auth & Crypto" },
  { id: 63, question: "What is 'Credential Stuffing'?", options: ["Filling out forms", "Using stolen credentials from one breach on other sites", "Strong password creation", "Credential backup"], correctAnswer: 1, explanation: "Credential Stuffing uses breached username/password pairs to try logging into other services.", topic: "Auth & Crypto" },
  { id: 64, question: "What is HSTS (HTTP Strict Transport Security)?", options: ["HTML security tag", "Header forcing browsers to use HTTPS only", "Security testing tool", "HTTP version"], correctAnswer: 1, explanation: "HSTS tells browsers to only connect via HTTPS, preventing protocol downgrade attacks.", topic: "Auth & Crypto" },
  { id: 65, question: "What is 'Time-based One-Time Password' (TOTP)?", options: ["Temporary passwords", "OTP generated using current time as input", "Password expiration", "Timed login attempts"], correctAnswer: 1, explanation: "TOTP generates temporary passwords using the current time, commonly used in authenticator apps.", topic: "Auth & Crypto" },
  // Topic 5: Security Testing (66-75)
  { id: 66, question: "What is Penetration Testing?", options: ["Testing network cables", "Simulating attacks to find vulnerabilities", "Performance testing", "Unit testing"], correctAnswer: 1, explanation: "Penetration Testing simulates real-world attacks to identify security vulnerabilities before malicious actors do.", topic: "Security Testing" },
  { id: 67, question: "What is Static Application Security Testing (SAST)?", options: ["Testing static websites", "Analyzing source code without running it", "Server testing", "Static IP testing"], correctAnswer: 1, explanation: "SAST analyzes source code or binaries without execution to find security vulnerabilities.", topic: "Security Testing" },
  { id: 68, question: "What is Dynamic Application Security Testing (DAST)?", options: ["Testing animations", "Testing running applications for vulnerabilities", "Database testing", "Dynamic DNS testing"], correctAnswer: 1, explanation: "DAST tests running applications from the outside, simulating how attackers would probe for vulnerabilities.", topic: "Security Testing" },
  { id: 69, question: "What is a Security Code Review?", options: ["Rating code quality", "Examining code specifically for security issues", "Code formatting check", "Performance review"], correctAnswer: 1, explanation: "Security Code Review manually examines source code to identify security vulnerabilities and weaknesses.", topic: "Security Testing" },
  { id: 70, question: "What is Fuzzing?", options: ["Making things fuzzy", "Sending random/malformed data to find crashes or vulnerabilities", "Load testing", "Image processing"], correctAnswer: 1, explanation: "Fuzzing bombards applications with random or malformed input to discover crashes and vulnerabilities.", topic: "Security Testing" },
  { id: 71, question: "What is a Bug Bounty program?", options: ["Bug tracking software", "Paying external researchers for finding vulnerabilities", "QA team bonuses", "Bug fixing rewards"], correctAnswer: 1, explanation: "Bug Bounty programs reward external security researchers for responsibly disclosing vulnerabilities.", topic: "Security Testing" },
  { id: 72, question: "What is Software Composition Analysis (SCA)?", options: ["Analyzing code structure", "Identifying vulnerabilities in third-party dependencies", "Composing software music", "Code compilation analysis"], correctAnswer: 1, explanation: "SCA identifies known vulnerabilities in open source and third-party components used in applications.", topic: "Security Testing" },
  { id: 73, question: "What is the OWASP Top 10?", options: ["Top 10 developers", "List of most critical web application security risks", "10 best practices", "Top 10 tools"], correctAnswer: 1, explanation: "OWASP Top 10 is a regularly updated list of the most critical web application security risks.", topic: "Security Testing" },
  { id: 74, question: "What is Red Team vs Blue Team?", options: ["Sports teams", "Attack simulation team vs defense team", "Development teams", "Color preferences"], correctAnswer: 1, explanation: "Red Team simulates attackers; Blue Team defends. Together they improve organizational security.", topic: "Security Testing" },
  { id: 75, question: "What is Vulnerability Scanning?", options: ["Scanning documents", "Automated tools checking for known vulnerabilities", "Visual inspection", "QR code scanning"], correctAnswer: 1, explanation: "Vulnerability Scanning uses automated tools to identify known vulnerabilities in systems and applications.", topic: "Security Testing" },
];

const QuizSection: React.FC = () => {
  const [quizState, setQuizState] = useState<"start" | "active" | "results">("start");
  const [questions, setQuestions] = useState<QuizQuestion[]>([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<{ [key: number]: number }>({});
  const [showExplanation, setShowExplanation] = useState(false);
  const [score, setScore] = useState(0);

  const QUESTIONS_PER_QUIZ = 10;
  const accent = "#dc2626";
  const accentDark = "#b91c1c";
  const success = "#22c55e";
  const error = "#ef4444";

  const startQuiz = () => {
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    setQuestions(shuffled.slice(0, QUESTIONS_PER_QUIZ));
    setCurrentQuestionIndex(0);
    setSelectedAnswers({});
    setShowExplanation(false);
    setScore(0);
    setQuizState("active");
  };

  const handleAnswerSelect = (answerIndex: number) => {
    if (showExplanation) return;
    setSelectedAnswers(prev => ({
      ...prev,
      [currentQuestionIndex]: answerIndex,
    }));
  };

  const handleSubmitAnswer = () => {
    if (selectedAnswers[currentQuestionIndex] === undefined) return;
    setShowExplanation(true);
    if (selectedAnswers[currentQuestionIndex] === questions[currentQuestionIndex].correctAnswer) {
      setScore(prev => prev + 1);
    }
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex < questions.length - 1) {
      setCurrentQuestionIndex(prev => prev + 1);
      setShowExplanation(false);
    } else {
      setQuizState("results");
    }
  };

  const currentQuestion = questions[currentQuestionIndex];
  const selectedAnswer = selectedAnswers[currentQuestionIndex];
  const isCorrect = selectedAnswer === currentQuestion?.correctAnswer;

  if (quizState === "start") {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <QuizIcon sx={{ fontSize: 64, color: accent, mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          Secure by Design Quiz
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 520, mx: "auto" }}>
          Test your understanding with {QUESTIONS_PER_QUIZ} randomly selected questions from a 75-question bank. Topics include security principles, threat modeling, secure coding, authentication, cryptography, and security testing.
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          sx={{
            bgcolor: accent,
            "&:hover": { bgcolor: accentDark },
            px: 4,
            py: 1.5,
            fontWeight: 700,
          }}
        >
          Start Quiz ({QUESTIONS_PER_QUIZ} Questions)
        </Button>
      </Box>
    );
  }

  if (quizState === "results") {
    const percentage = Math.round((score / QUESTIONS_PER_QUIZ) * 100);
    const isPassing = percentage >= 70;
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <EmojiEventsIcon sx={{ fontSize: 80, color: isPassing ? success : accent, mb: 2 }} />
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          Quiz Complete
        </Typography>
        <Typography variant="h5" sx={{ fontWeight: 700, color: isPassing ? success : accent, mb: 2 }}>
          {score} / {QUESTIONS_PER_QUIZ} ({percentage}%)
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 420, mx: "auto" }}>
          {isPassing
            ? "Excellent! You have a solid understanding of secure design principles."
            : "Keep learning. Review the sections above and try again."}
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          startIcon={<RefreshIcon />}
          sx={{
            bgcolor: accent,
            "&:hover": { bgcolor: accentDark },
            px: 4,
            py: 1.5,
            fontWeight: 700,
          }}
        >
          Try Again
        </Button>
      </Box>
    );
  }

  if (!currentQuestion) return null;

  return (
    <Box sx={{ py: 2 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
          <Chip
            label={`Question ${currentQuestionIndex + 1}/${QUESTIONS_PER_QUIZ}`}
            size="small"
            sx={{ bgcolor: alpha(accent, 0.15), color: accent, fontWeight: 700 }}
          />
          <Chip label={currentQuestion.topic} size="small" variant="outlined" />
        </Box>
        <Chip
          label={`Score: ${score}/${currentQuestionIndex + (showExplanation ? 1 : 0)}`}
          size="small"
          sx={{ bgcolor: alpha(success, 0.15), color: success, fontWeight: 600 }}
        />
      </Box>

      <Box sx={{ mb: 3, bgcolor: alpha(accent, 0.1), borderRadius: 1, height: 8 }}>
        <Box
          sx={{
            width: `${((currentQuestionIndex + (showExplanation ? 1 : 0)) / QUESTIONS_PER_QUIZ) * 100}%`,
            bgcolor: accent,
            borderRadius: 1,
            height: "100%",
            transition: "width 0.3s ease",
          }}
        />
      </Box>

      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
        {currentQuestion.question}
      </Typography>

      <RadioGroup value={selectedAnswer ?? ""} onChange={(e) => handleAnswerSelect(parseInt(e.target.value, 10))}>
        {currentQuestion.options.map((option, idx) => (
          <Paper
            key={option}
            sx={{
              p: 2,
              mb: 1.5,
              borderRadius: 2,
              cursor: showExplanation ? "default" : "pointer",
              border: `2px solid ${
                showExplanation
                  ? idx === currentQuestion.correctAnswer
                    ? success
                    : idx === selectedAnswer
                    ? error
                    : "transparent"
                  : selectedAnswer === idx
                  ? accent
                  : "transparent"
              }`,
              bgcolor: showExplanation
                ? idx === currentQuestion.correctAnswer
                  ? alpha(success, 0.1)
                  : idx === selectedAnswer
                  ? alpha(error, 0.1)
                  : "transparent"
                : selectedAnswer === idx
                ? alpha(accent, 0.1)
                : "transparent",
              transition: "all 0.2s ease",
              "&:hover": {
                bgcolor: showExplanation ? undefined : alpha(accent, 0.05),
              },
            }}
            onClick={() => handleAnswerSelect(idx)}
          >
            <FormControlLabel
              value={idx}
              control={<Radio sx={{ color: accent, "&.Mui-checked": { color: accent } }} />}
              label={option}
              sx={{ m: 0, width: "100%" }}
              disabled={showExplanation}
            />
          </Paper>
        ))}
      </RadioGroup>

      {!showExplanation ? (
        <Button
          variant="contained"
          fullWidth
          onClick={handleSubmitAnswer}
          disabled={selectedAnswer === undefined}
          sx={{
            mt: 2,
            bgcolor: accent,
            "&:hover": { bgcolor: accentDark },
            "&:disabled": { bgcolor: alpha(accent, 0.3) },
            py: 1.5,
            fontWeight: 700,
          }}
        >
          Submit Answer
        </Button>
      ) : (
        <Box sx={{ mt: 3 }}>
          <Alert severity={isCorrect ? "success" : "error"} sx={{ mb: 2, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>
              {isCorrect ? "Correct" : "Incorrect"}
            </AlertTitle>
            {currentQuestion.explanation}
          </Alert>
          <Button
            variant="contained"
            fullWidth
            onClick={handleNextQuestion}
            sx={{
              bgcolor: accent,
              "&:hover": { bgcolor: accentDark },
              py: 1.5,
              fontWeight: 700,
            }}
          >
            {currentQuestionIndex < questions.length - 1 ? "Next Question" : "See Results"}
          </Button>
        </Box>
      )}
    </Box>
  );
};

export default function SecureByDesignPage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Secure by Design learning page. Covers security principles (least privilege, defense in depth, zero trust), threat modeling (STRIDE, DREAD, attack trees), secure coding practices (input validation, SQL injection prevention, XSS prevention), authentication and cryptography (MFA, password hashing, JWT, HTTPS), and security testing (penetration testing, SAST, DAST, fuzzing). Includes a randomized 75-question quiz.`;

  const quickStats = [
    { label: "Modules", value: "16", color: "#dc2626" },
    { label: "Principles", value: "15+", color: "#7c3aed" },
    { label: "Quiz Questions", value: "75", color: "#22c55e" },
    { label: "Difficulty", value: "Intermediate", color: "#0ea5e9" },
  ];

  const securityPrinciples = [
    { name: "Least Privilege", description: "Grant minimum permissions needed for tasks.", color: "#dc2626", icon: <LockIcon /> },
    { name: "Defense in Depth", description: "Multiple overlapping security layers.", color: "#7c3aed", icon: <ShieldIcon /> },
    { name: "Zero Trust", description: "Never trust, always verify every request.", color: "#0ea5e9", icon: <VerifiedUserIcon /> },
    { name: "Fail Secure", description: "Default to secure state on failures.", color: "#22c55e", icon: <GppGoodIcon /> },
    { name: "Attack Surface Reduction", description: "Minimize exposed entry points.", color: "#f59e0b", icon: <SecurityIcon /> },
    { name: "Secure by Default", description: "Ship with secure configurations.", color: "#ec4899", icon: <AdminPanelSettingsIcon /> },
  ];

  const strideThreats = [
    { letter: "S", name: "Spoofing", description: "Pretending to be someone or something else", mitigation: "Strong authentication, MFA" },
    { letter: "T", name: "Tampering", description: "Unauthorized modification of data", mitigation: "Integrity checks, digital signatures" },
    { letter: "R", name: "Repudiation", description: "Denying actions without proof", mitigation: "Audit logging, non-repudiation" },
    { letter: "I", name: "Information Disclosure", description: "Exposing data to unauthorized parties", mitigation: "Encryption, access controls" },
    { letter: "D", name: "Denial of Service", description: "Making resources unavailable", mitigation: "Rate limiting, redundancy" },
    { letter: "E", name: "Elevation of Privilege", description: "Gaining higher permissions", mitigation: "Authorization checks, sandboxing" },
  ];

  const owaspTop10 = [
    { rank: "A01", name: "Broken Access Control", description: "Failing to properly enforce access restrictions" },
    { rank: "A02", name: "Cryptographic Failures", description: "Weak or missing encryption for sensitive data" },
    { rank: "A03", name: "Injection", description: "SQL, NoSQL, OS command, LDAP injection attacks" },
    { rank: "A04", name: "Insecure Design", description: "Missing or ineffective security controls in design" },
    { rank: "A05", name: "Security Misconfiguration", description: "Insecure default or incomplete configurations" },
    { rank: "A06", name: "Vulnerable Components", description: "Using components with known vulnerabilities" },
    { rank: "A07", name: "Auth Failures", description: "Broken authentication and session management" },
    { rank: "A08", name: "Data Integrity Failures", description: "Software and data integrity verification issues" },
    { rank: "A09", name: "Logging Failures", description: "Insufficient logging and monitoring" },
    { rank: "A10", name: "SSRF", description: "Server-Side Request Forgery vulnerabilities" },
  ];

  const secureCodePractices = [
    { title: "Input Validation", items: ["Validate all input on the server", "Use allowlists over blocklists", "Validate type, length, format, range"] },
    { title: "Output Encoding", items: ["Encode output for the context (HTML, JS, SQL)", "Use framework-provided encoding functions", "Never trust user input in output"] },
    { title: "Error Handling", items: ["Log detailed errors internally", "Show generic messages to users", "Never expose stack traces"] },
    { title: "Secrets Management", items: ["Never hardcode secrets", "Use environment variables or vaults", "Rotate secrets regularly"] },
  ];

  const authBestPractices = [
    "Use MFA for sensitive operations",
    "Hash passwords with bcrypt, Argon2, or scrypt",
    "Implement account lockout after failed attempts",
    "Use secure session management",
    "Regenerate session IDs after login",
    "Set proper cookie flags (HttpOnly, Secure, SameSite)",
    "Implement proper logout (invalidate sessions)",
    "Use HTTPS everywhere",
  ];

  const securityTestingTypes = [
    { name: "SAST", full: "Static Application Security Testing", description: "Analyze source code without execution", when: "During development" },
    { name: "DAST", full: "Dynamic Application Security Testing", description: "Test running applications externally", when: "Before deployment" },
    { name: "SCA", full: "Software Composition Analysis", description: "Check dependencies for vulnerabilities", when: "Continuous" },
    { name: "Penetration Testing", full: "Ethical Hacking", description: "Simulate real attacks", when: "Periodic" },
    { name: "Fuzzing", full: "Fuzz Testing", description: "Send malformed data to find crashes", when: "Continuous" },
  ];

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  // Module navigation items
  const moduleNavItems = [
    { id: "introduction", label: "Introduction", icon: "🛡️" },
    { id: "principles", label: "Security Principles", icon: "🔐" },
    { id: "threat-modeling", label: "Threat Modeling", icon: "🎯" },
    { id: "stride", label: "STRIDE Framework", icon: "⚡" },
    { id: "secure-coding", label: "Secure Coding", icon: "💻" },
    { id: "injection-attacks", label: "Injection Attacks", icon: "💉" },
    { id: "xss-csrf", label: "XSS & CSRF", icon: "🌐" },
    { id: "owasp-top10", label: "OWASP Top 10", icon: "📋" },
    { id: "authentication", label: "Authentication", icon: "🔑" },
    { id: "cryptography", label: "Cryptography", icon: "🔒" },
    { id: "secrets-management", label: "Secrets Management", icon: "🗝️" },
    { id: "security-testing", label: "Security Testing", icon: "🧪" },
    { id: "secure-sdlc", label: "Secure SDLC", icon: "🔄" },
    { id: "checklist", label: "Security Checklist", icon: "✅" },
    { id: "quiz-section", label: "Quiz", icon: "❓" },
  ];

  // Scroll to section
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setNavDrawerOpen(false);
    }
  };

  // Track active section on scroll
  useEffect(() => {
    const handleScroll = () => {
      const sections = moduleNavItems.map(item => item.id);
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

  const currentIndex = moduleNavItems.findIndex(item => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / moduleNavItems.length) * 100 : 0;

  const accent = "#dc2626";

  // Desktop sidebar
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
        border: `1px solid ${alpha(accent, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": { width: 6 },
        "&::-webkit-scrollbar-thumb": { bgcolor: alpha(accent, 0.3), borderRadius: 3 },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}>
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">Progress</Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>{Math.round(progressPercent)}%</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": { bgcolor: accent, borderRadius: 3 },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {moduleNavItems.map((item) => (
            <ListItem
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1.5,
                mb: 0.25,
                py: 0.5,
                cursor: "pointer",
                bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                "&:hover": { bgcolor: alpha(accent, 0.08) },
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
                      color: activeSection === item.id ? accent : "text.secondary",
                      fontSize: "0.75rem",
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
    <LearnPageLayout pageTitle="Secure by Design" pageContext={pageContext}>
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
            bgcolor: accent,
            "&:hover": { bgcolor: "#b91c1c" },
            boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
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
            bgcolor: alpha(accent, 0.15),
            color: accent,
            "&:hover": { bgcolor: alpha(accent, 0.25) },
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
          sx: { width: isMobile ? "85%" : 320, bgcolor: theme.palette.background.paper, backgroundImage: "none" },
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <ListAltIcon sx={{ color: accent }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>
          <Divider sx={{ mb: 2 }} />
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">Progress</Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>{Math.round(progressPercent)}%</Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(accent, 0.1),
                "& .MuiLinearProgress-bar": { bgcolor: accent, borderRadius: 3 },
              }}
            />
          </Box>
          <List dense sx={{ mx: -1 }}>
            {moduleNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                  "&:hover": { bgcolor: alpha(accent, 0.1) },
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
                        color: activeSection === item.id ? accent : "text.primary",
                      }}
                    >
                      {item.label}
                    </Typography>
                  }
                />
                {activeSection === item.id && (
                  <Chip label="Current" size="small" sx={{ height: 20, fontSize: "0.65rem", bgcolor: alpha(accent, 0.2), color: accent }} />
                )}
              </ListItem>
            ))}
          </List>
          <Divider sx={{ my: 2 }} />
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button size="small" variant="outlined" onClick={scrollToTop} startIcon={<KeyboardArrowUpIcon />} sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}>
              Top
            </Button>
            <Button size="small" variant="outlined" onClick={() => scrollToSection("quiz-section")} startIcon={<QuizIcon />} sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}>
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

        {/* Main Content */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Chip icon={<ArrowBackIcon />} label="Back to Learning Hub" onClick={() => navigate("/learn")} sx={{ mb: 3, fontWeight: 600, cursor: "pointer" }} clickable />

          {/* Hero Section */}
          <Paper
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha("#dc2626", 0.15)} 0%, ${alpha("#7c3aed", 0.12)} 50%, ${alpha("#0ea5e9", 0.1)} 100%)`,
              border: `1px solid ${alpha("#dc2626", 0.2)}`,
              position: "relative",
              overflow: "hidden",
            }}
          >
            <Box sx={{ position: "absolute", top: -60, right: -40, width: 220, height: 220, borderRadius: "50%", background: `radial-gradient(circle, ${alpha("#dc2626", 0.15)} 0%, transparent 70%)` }} />
            <Box sx={{ position: "absolute", bottom: -40, left: "30%", width: 180, height: 180, borderRadius: "50%", background: `radial-gradient(circle, ${alpha("#7c3aed", 0.15)} 0%, transparent 70%)` }} />

            <Box sx={{ position: "relative", zIndex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
                <Box
                  sx={{
                    width: 80,
                    height: 80,
                    borderRadius: 3,
                    background: "linear-gradient(135deg, #dc2626, #7c3aed)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 8px 32px ${alpha("#dc2626", 0.35)}`,
                  }}
                >
                  <ShieldIcon sx={{ fontSize: 44, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                    Secure by Design
                  </Typography>
                  <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                    Build security into software from the ground up
                  </Typography>
                </Box>
              </Box>

              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip label="Security" sx={{ bgcolor: alpha("#dc2626", 0.15), color: "#dc2626", fontWeight: 600 }} />
                <Chip label="Threat Modeling" sx={{ bgcolor: alpha("#7c3aed", 0.15), color: "#7c3aed", fontWeight: 600 }} />
                <Chip label="Secure Coding" sx={{ bgcolor: alpha("#0ea5e9", 0.15), color: "#0ea5e9", fontWeight: 600 }} />
                <Chip label="OWASP" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
                <Chip label="Cryptography" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
              </Box>

              <Grid container spacing={2}>
                {quickStats.map((stat) => (
                  <Grid item xs={6} sm={3} key={stat.label}>
                    <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha(stat.color, 0.1), border: `1px solid ${alpha(stat.color, 0.2)}` }}>
                      <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>{stat.value}</Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>{stat.label}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </Paper>

          {/* Introduction */}
          <Paper id="introduction" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Avatar sx={{ bgcolor: alpha(accent, 0.15), color: accent }}><ShieldIcon /></Avatar>
              What is Secure by Design?
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              <strong>Secure by Design</strong> is a software development approach where security is considered and built into the system from the very beginning, rather than added as an afterthought. Instead of patching vulnerabilities after they're discovered, secure design anticipates threats and builds defenses into the architecture, code, and processes from day one.
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              This approach shifts security "left" in the development lifecycle, making it cheaper and more effective. Finding and fixing a vulnerability in design costs far less than fixing it in production. More importantly, some vulnerabilities simply cannot be patched—they require fundamental architectural changes that are prohibitively expensive after deployment.
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Secure by Design encompasses security principles, threat modeling, secure coding practices, security testing, and secure operations. It's not just about writing secure code—it's about creating systems that remain secure even as they evolve and face new threats.
            </Typography>
            <Alert severity="info" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Key Insight</AlertTitle>
              Security is not a feature you add—it's a property of how you build. Just like you can't make a building earthquake-resistant by adding supports afterward, you can't make software truly secure by patching it later.
            </Alert>
          </Paper>

          {/* Security Principles */}
          <Paper id="principles" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <LockIcon sx={{ color: accent }} />
              Core Security Principles
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              These foundational principles guide secure system design. Apply them consistently across all layers of your application.
            </Typography>
            <Grid container spacing={2}>
              {securityPrinciples.map((principle) => (
                <Grid item xs={12} sm={6} md={4} key={principle.name}>
                  <Paper sx={{ p: 3, borderRadius: 3, height: "100%", bgcolor: alpha(principle.color, 0.08), border: `1px solid ${alpha(principle.color, 0.2)}` }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1.5 }}>
                      <Avatar sx={{ bgcolor: alpha(principle.color, 0.15), color: principle.color }}>{principle.icon}</Avatar>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{principle.name}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary">{principle.description}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Threat Modeling */}
          <Paper id="threat-modeling" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <AccountTreeIcon sx={{ color: accent }} />
              Threat Modeling
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Threat modeling is a structured approach to identifying what can go wrong with your system's security, what you're going to do about it, and how to prioritize efforts. It helps you think like an attacker to find vulnerabilities before they do.
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Threat Modeling Process</Typography>
                <List>
                  {[
                    "Identify assets: What are you trying to protect?",
                    "Create architecture overview: Data flow diagrams, trust boundaries",
                    "Decompose the application: Entry points, exit points, trust levels",
                    "Identify threats: Use STRIDE or other frameworks",
                    "Rate and prioritize threats: DREAD or risk matrices",
                    "Plan mitigations: How will you address each threat?",
                    "Validate: Review and update as system evolves",
                  ].map((step, idx) => (
                    <ListItem key={step} sx={{ px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 36 }}>
                        <Avatar sx={{ width: 28, height: 28, bgcolor: alpha(accent, 0.15), color: accent, fontSize: 14, fontWeight: 700 }}>{idx + 1}</Avatar>
                      </ListItemIcon>
                      <ListItemText primary={step} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(accent, 0.05) }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Key Questions</Typography>
                  <List dense>
                    {[
                      "What are we building?",
                      "What can go wrong?",
                      "What are we going to do about it?",
                      "Did we do a good job?",
                    ].map((q) => (
                      <ListItem key={q} sx={{ px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}><TipsAndUpdatesIcon sx={{ color: accent, fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary={q} primaryTypographyProps={{ fontWeight: 600 }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Paper>

          {/* STRIDE Framework */}
          <Paper id="stride" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <WarningIcon sx={{ color: accent }} />
              STRIDE Threat Framework
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              STRIDE is a threat classification system developed by Microsoft. Each letter represents a category of security threat, helping you systematically identify potential vulnerabilities.
            </Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha(accent, 0.08) }}>
                    <TableCell sx={{ fontWeight: 700, width: 60 }}>Letter</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Threat</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Mitigation</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {strideThreats.map((threat) => (
                    <TableRow key={threat.letter}>
                      <TableCell>
                        <Avatar sx={{ bgcolor: accent, width: 32, height: 32, fontSize: 16, fontWeight: 800 }}>{threat.letter}</Avatar>
                      </TableCell>
                      <TableCell sx={{ fontWeight: 600 }}>{threat.name}</TableCell>
                      <TableCell>{threat.description}</TableCell>
                      <TableCell>{threat.mitigation}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Secure Coding */}
          <Paper id="secure-coding" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <CodeIcon sx={{ color: accent }} />
              Secure Coding Practices
            </Typography>
            <Grid container spacing={3}>
              {secureCodePractices.map((practice) => (
                <Grid item xs={12} md={6} key={practice.title}>
                  <Paper sx={{ p: 3, borderRadius: 3, height: "100%", bgcolor: alpha(accent, 0.03) }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>{practice.title}</Typography>
                    <List dense>
                      {practice.items.map((item) => (
                        <ListItem key={item} sx={{ px: 0 }}>
                          <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: accent, fontSize: 20 }} /></ListItemIcon>
                          <ListItemText primary={item} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Injection Attacks */}
          <Paper id="injection-attacks" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <GppBadIcon sx={{ color: accent }} />
              Preventing Injection Attacks
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accent }}>SQL Injection</Typography>
                <Typography variant="body2" sx={{ mb: 2 }}>
                  SQL Injection occurs when malicious SQL is inserted through user input. Always use parameterized queries.
                </Typography>
                <Paper sx={{ p: 2, mb: 2, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
                  <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                    <span style={{ color: "#6272a4" }}>// BAD - vulnerable to SQL injection</span>{"\n"}
                    <span style={{ color: "#ff79c6" }}>query</span> = <span style={{ color: "#f1fa8c" }}>"SELECT * FROM users WHERE id = "</span> + userId;{"\n"}
                    {"\n"}
                    <span style={{ color: "#6272a4" }}>// GOOD - parameterized query</span>{"\n"}
                    <span style={{ color: "#ff79c6" }}>query</span> = <span style={{ color: "#f1fa8c" }}>"SELECT * FROM users WHERE id = ?"</span>;{"\n"}
                    stmt.<span style={{ color: "#50fa7b" }}>setParameter</span>(<span style={{ color: "#bd93f9" }}>1</span>, userId);
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accent }}>Command Injection</Typography>
                <Typography variant="body2" sx={{ mb: 2 }}>
                  Command Injection occurs when OS commands are constructed from user input. Avoid shell execution with user data.
                </Typography>
                <Paper sx={{ p: 2, mb: 2, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
                  <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                    <span style={{ color: "#6272a4" }}>// BAD - command injection</span>{"\n"}
                    <span style={{ color: "#50fa7b" }}>exec</span>(<span style={{ color: "#f1fa8c" }}>"ping "</span> + userHost);{"\n"}
                    {"\n"}
                    <span style={{ color: "#6272a4" }}>// GOOD - validate input, use safe APIs</span>{"\n"}
                    <span style={{ color: "#ff79c6" }}>if</span> (isValidHostname(userHost)) {"{"}{"\n"}
                    {"  "}pingService.<span style={{ color: "#50fa7b" }}>ping</span>(userHost);{"\n"}
                    {"}"}
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Paper>

          {/* XSS & CSRF */}
          <Paper id="xss-csrf" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <HttpsIcon sx={{ color: accent }} />
              XSS and CSRF Prevention
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Cross-Site Scripting (XSS)</Typography>
                <List dense>
                  {[
                    "Encode all output for the correct context (HTML, JS, CSS)",
                    "Use Content Security Policy (CSP) headers",
                    "Validate and sanitize input",
                    "Use HttpOnly cookies for session tokens",
                    "Avoid dangerouslySetInnerHTML and similar APIs",
                  ].map((item) => (
                    <ListItem key={item} sx={{ px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: "#22c55e", fontSize: 20 }} /></ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Cross-Site Request Forgery (CSRF)</Typography>
                <List dense>
                  {[
                    "Use anti-CSRF tokens on state-changing requests",
                    "Set SameSite cookie attribute (Strict or Lax)",
                    "Verify Origin/Referer headers",
                    "Require re-authentication for sensitive actions",
                    "Use custom headers for API requests",
                  ].map((item) => (
                    <ListItem key={item} sx={{ px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: "#22c55e", fontSize: 20 }} /></ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
            </Grid>
          </Paper>

          {/* OWASP Top 10 */}
          <Paper id="owasp-top10" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <PolicyIcon sx={{ color: accent }} />
              OWASP Top 10 (2021)
            </Typography>
            <Typography variant="body1" sx={{ mb: 3 }}>
              The OWASP Top 10 is a standard awareness document representing the most critical web application security risks.
            </Typography>
            <Grid container spacing={2}>
              {owaspTop10.map((item) => (
                <Grid item xs={12} sm={6} key={item.rank}>
                  <Paper sx={{ p: 2, borderRadius: 2, display: "flex", gap: 2, alignItems: "flex-start", bgcolor: alpha(accent, 0.03) }}>
                    <Chip label={item.rank} size="small" sx={{ bgcolor: accent, color: "white", fontWeight: 700 }} />
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{item.description}</Typography>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Authentication */}
          <Paper id="authentication" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <KeyIcon sx={{ color: accent }} />
              Authentication Best Practices
            </Typography>
            <Grid container spacing={2}>
              {authBestPractices.map((item) => (
                <Grid item xs={12} md={6} key={item}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(accent, 0.03) }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <CheckCircleIcon sx={{ color: accent }} />
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>{item}</Typography>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Cryptography */}
          <Paper id="cryptography" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <VisibilityOffIcon sx={{ color: accent }} />
              Cryptography Essentials
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Do</Typography>
                <List dense>
                  {[
                    "Use established libraries (don't roll your own crypto)",
                    "Use TLS 1.2+ for data in transit",
                    "Use AES-256-GCM for symmetric encryption",
                    "Use bcrypt/Argon2/scrypt for password hashing",
                    "Generate cryptographic random values properly",
                    "Rotate keys periodically",
                  ].map((item) => (
                    <ListItem key={item} sx={{ px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}><GppGoodIcon sx={{ color: "#22c55e", fontSize: 20 }} /></ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Don't</Typography>
                <List dense>
                  {[
                    "Use MD5 or SHA1 for passwords",
                    "Store encryption keys in code",
                    "Use ECB mode for encryption",
                    "Implement custom cryptographic algorithms",
                    "Use predictable IVs or nonces",
                    "Ignore cryptographic library updates",
                  ].map((item) => (
                    <ListItem key={item} sx={{ px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}><GppBadIcon sx={{ color: "#ef4444", fontSize: 20 }} /></ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
            </Grid>
          </Paper>

          {/* Secrets Management */}
          <Paper id="secrets-management" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <StorageIcon sx={{ color: accent }} />
              Secrets Management
            </Typography>
            <List>
              {[
                "Never commit secrets to version control",
                "Use environment variables for configuration",
                "Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)",
                "Rotate secrets regularly and after incidents",
                "Audit secret access and usage",
                "Limit secret scope to what's needed",
                "Use different secrets per environment",
              ].map((item) => (
                <ListItem key={item} sx={{ px: 0 }}>
                  <ListItemIcon><CheckCircleIcon sx={{ color: accent }} /></ListItemIcon>
                  <ListItemText primary={item} />
                </ListItem>
              ))}
            </List>
          </Paper>

          {/* Security Testing */}
          <Paper id="security-testing" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <BugReportIcon sx={{ color: accent }} />
              Security Testing
            </Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha(accent, 0.08) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Full Name</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>When</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {securityTestingTypes.map((type) => (
                    <TableRow key={type.name}>
                      <TableCell sx={{ fontWeight: 600 }}>{type.name}</TableCell>
                      <TableCell>{type.full}</TableCell>
                      <TableCell>{type.description}</TableCell>
                      <TableCell>{type.when}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Secure SDLC */}
          <Paper id="secure-sdlc" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <CloudIcon sx={{ color: accent }} />
              Secure Software Development Lifecycle
            </Typography>
            <Grid container spacing={2}>
              {[
                { phase: "Requirements", security: "Define security requirements, abuse cases, compliance needs" },
                { phase: "Design", security: "Threat modeling, security architecture review, secure design patterns" },
                { phase: "Implementation", security: "Secure coding standards, code review, SAST" },
                { phase: "Testing", security: "Security testing, DAST, penetration testing" },
                { phase: "Deployment", security: "Secure configuration, hardening, infrastructure security" },
                { phase: "Operations", security: "Monitoring, incident response, vulnerability management" },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.phase}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: accent, mb: 0.5 }}>{item.phase}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.security}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Security Checklist */}
          <Paper id="checklist" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <CheckCircleIcon sx={{ color: accent }} />
              Security Checklist
            </Typography>
            <Grid container spacing={2}>
              {[
                "All user input is validated and sanitized",
                "Output is encoded for the appropriate context",
                "Authentication uses MFA where possible",
                "Passwords are hashed with bcrypt/Argon2",
                "Sessions are managed securely with proper timeout",
                "HTTPS is enforced everywhere",
                "API endpoints check authorization",
                "Secrets are not in code or version control",
                "Dependencies are scanned for vulnerabilities",
                "Security headers are configured (CSP, HSTS, etc.)",
                "Logging captures security events without sensitive data",
                "Error messages don't leak internal details",
              ].map((item) => (
                <Grid item xs={12} md={6} key={item}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05) }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <CheckCircleIcon sx={{ color: "#22c55e" }} />
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>{item}</Typography>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Quiz Section */}
          <Paper id="quiz-section" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <QuizIcon sx={{ color: accent }} />
              Knowledge Check
            </Typography>
            <QuizSection />
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Box sx={{ display: "flex", justifyContent: "center" }}>
            <Button
              variant="contained"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ bgcolor: accent, "&:hover": { bgcolor: "#b91c1c" }, px: 4, py: 1.5, fontWeight: 700 }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
