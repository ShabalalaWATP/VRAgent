import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  LinearProgress,
  Card,
  CardContent,
  Alert,
  Tabs,
  Tab,
  Divider,
  useMediaQuery,
  Drawer,
  Fab,
  Button,
} from "@mui/material";
import { Link } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import PhoneAndroidIcon from "@mui/icons-material/PhoneAndroid";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import InventoryIcon from "@mui/icons-material/Inventory";
import LockIcon from "@mui/icons-material/Lock";
import InputIcon from "@mui/icons-material/Input";
import WifiIcon from "@mui/icons-material/Wifi";
import PrivacyTipIcon from "@mui/icons-material/PrivacyTip";
import SecurityIcon from "@mui/icons-material/Security";
import ShieldIcon from "@mui/icons-material/Shield";
import SettingsIcon from "@mui/icons-material/Settings";
import StorageIcon from "@mui/icons-material/Storage";
import EnhancedEncryptionIcon from "@mui/icons-material/EnhancedEncryption";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import ErrorIcon from "@mui/icons-material/Error";
import AndroidIcon from "@mui/icons-material/Android";
import AppleIcon from "@mui/icons-material/Apple";
import BugReportIcon from "@mui/icons-material/BugReport";
import CodeIcon from "@mui/icons-material/Code";
import QuizIcon from "@mui/icons-material/Quiz";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import RefreshIcon from "@mui/icons-material/Refresh";
import MenuIcon from "@mui/icons-material/Menu";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import InfoIcon from "@mui/icons-material/Info";
import ListAltIcon from "@mui/icons-material/ListAlt";
import MenuBookIcon from "@mui/icons-material/MenuBook";

// Theme colors for consistent styling
const themeColors = {
  primary: "#f59e0b",
  primaryLight: "#fbbf24",
  secondary: "#8b5cf6",
  accent: "#3b82f6",
  bgCard: "#111424",
  bgNested: "#0c0f1c",
  border: "rgba(245, 158, 11, 0.2)",
  textMuted: "#94a3b8",
};

const attackSurfaceAreas = [
  {
    area: "App binary and resources",
    detail: "Reverse engineering reveals strings, endpoints, and hardcoded secrets.",
    examples: ["APK/IPA extraction", "embedded API keys", "feature flags"],
  },
  {
    area: "Local storage",
    detail: "Sensitive data stored on device can be extracted or tampered with.",
    examples: ["SQLite databases", "SharedPreferences/UserDefaults", "cache files"],
  },
  {
    area: "Network traffic",
    detail: "Weak TLS or missing validation allows interception or modification.",
    examples: ["HTTP endpoints", "weak pinning", "certificate bypass"],
  },
  {
    area: "OS integrations",
    detail: "Misused platform APIs expose data or privileged actions.",
    examples: ["intents and URL schemes", "clipboard", "notifications"],
  },
  {
    area: "Third-party SDKs",
    detail: "Libraries can add risk or leak data outside the app boundary.",
    examples: ["analytics SDKs", "ads", "crash reporting"],
  },
];

const trustBoundaries = [
  "Device to backend API: TLS configuration and certificate validation",
  "App to third-party SDKs: data sharing and permission scope",
  "App to OS services: secure storage, keychain/keystore, clipboard",
  "App to other apps: deep links, intents, and URL schemes",
  "Offline data to sync layer: replay, conflicts, and integrity checks",
];

const testingWorkflow = [
  {
    step: "Recon and setup",
    detail: "Gather app versions, permissions, endpoints, and run on test devices.",
    outputs: ["Device setup", "Proxy configured", "Baseline traffic captured"],
  },
  {
    step: "Static analysis",
    detail: "Inspect the binary for hardcoded secrets, insecure settings, and risky code.",
    outputs: ["Decompiled code", "secret scan", "manifest review"],
  },
  {
    step: "Dynamic analysis",
    detail: "Run the app through core flows while intercepting traffic.",
    outputs: ["MITM validation", "API fuzzing", "auth flow checks"],
  },
  {
    step: "Runtime instrumentation",
    detail: "Use tools like Frida to bypass checks and test deeper logic.",
    outputs: ["Bypass root detection", "modify auth responses"],
  },
  {
    step: "Backend/API validation",
    detail: "Verify server-side authorization and rate limiting controls.",
    outputs: ["IDOR checks", "privilege tests", "replay protection"],
  },
  {
    step: "Reporting and fixes",
    detail: "Document findings with reproduction steps and remediation guidance.",
    outputs: ["Risk summary", "fix recommendations", "test evidence"],
  },
];

const mobileTooling = [
  {
    category: "Static analysis",
    tools: ["MobSF", "JADX", "apktool", "Ghidra", "strings"],
  },
  {
    category: "Dynamic analysis",
    tools: ["Burp Suite", "mitmproxy", "Charles Proxy", "Proxyman"],
  },
  {
    category: "Runtime instrumentation",
    tools: ["Frida", "Objection", "Xposed", "Cycript"],
  },
  {
    category: "Android tooling",
    tools: ["adb", "drozer", "MobSF Android agent", "Android Studio profiler"],
  },
  {
    category: "iOS tooling",
    tools: ["Xcode", "Frida iOS", "class-dump", "lldb"],
  },
];

const storageLocations = [
  {
    platform: "Android",
    areas: ["SharedPreferences", "SQLite databases", "Files/Cache", "External storage", "Keystore"],
  },
  {
    platform: "iOS",
    areas: ["UserDefaults", "Core Data/SQLite", "Library/Caches", "Documents", "Keychain"],
  },
];

const hardeningChecklist = [
  "Remove debug builds and disable debuggable flags",
  "Enforce TLS with proper certificate validation or pinning",
  "Move secrets to backend services or secure storage",
  "Restrict exported components and deep link handlers",
  "Minimize permissions and request them at runtime",
  "Harden logging to avoid leaking tokens or PII",
  "Enable integrity checks, obfuscation, and anti-tamper controls",
  "Use SBOM and dependency scanning for third-party SDKs",
];

// Section navigation items
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <InfoIcon fontSize="small" /> },
  { id: "overview", label: "Overview", icon: <PhoneAndroidIcon fontSize="small" /> },
  { id: "threat-model", label: "Threat Model", icon: <SecurityIcon fontSize="small" /> },
  { id: "quick-reference", label: "Quick Reference", icon: <ListAltIcon fontSize="small" /> },
  { id: "testing-workflow", label: "Testing Workflow", icon: <BugReportIcon fontSize="small" /> },
  { id: "hardening", label: "Hardening", icon: <ShieldIcon fontSize="small" /> },
  { id: "detailed-analysis", label: "Detailed Analysis", icon: <SecurityIcon fontSize="small" /> },
  { id: "resources", label: "Resources", icon: <MenuBookIcon fontSize="small" /> },
  { id: "quiz-section", label: "Knowledge Check", icon: <QuizIcon fontSize="small" /> },
];

// Quiz Question Interface
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

// OWASP Mobile Top 10 Quiz Question Bank (75 questions)
const questionBank: QuizQuestion[] = [
  // M1: Improper Credential Usage (8 questions)
  { id: 1, question: "What is M1 in OWASP Mobile Top 10?", options: ["Improper Platform Usage", "Improper Credential Usage", "Insecure Data Storage", "Insecure Communication"], correctAnswer: 1, explanation: "M1 is Improper Credential Usage, covering hardcoded credentials and insecure key management.", topic: "M1: Credentials" },
  { id: 2, question: "What is a common M1 vulnerability?", options: ["SQL injection", "Hardcoded API keys in the app binary", "Buffer overflow", "XSS attack"], correctAnswer: 1, explanation: "Hardcoded secrets in app binaries can be extracted through reverse engineering.", topic: "M1: Credentials" },
  { id: 3, question: "How should API keys be protected in mobile apps?", options: ["Hardcode them", "Store in SharedPreferences", "Use backend proxy or secure key storage", "Put in comments"], correctAnswer: 2, explanation: "Sensitive keys should use backend proxies or secure storage like KeyStore/Keychain.", topic: "M1: Credentials" },
  { id: 4, question: "What is credential stuffing?", options: ["Adding more passwords", "Using stolen credentials from breaches to login", "Password encryption", "Key generation"], correctAnswer: 1, explanation: "Credential stuffing uses leaked username/password pairs to attempt unauthorized access.", topic: "M1: Credentials" },
  { id: 5, question: "Where should user passwords be validated?", options: ["Client-side only", "Server-side", "In the app binary", "In local storage"], correctAnswer: 1, explanation: "Authentication must be validated server-side; client-side checks can be bypassed.", topic: "M1: Credentials" },
  { id: 6, question: "What is the risk of storing OAuth tokens insecurely?", options: ["No risk", "Token theft enabling account takeover", "Slower performance", "UI issues"], correctAnswer: 1, explanation: "Stolen OAuth tokens allow attackers to impersonate users.", topic: "M1: Credentials" },
  { id: 7, question: "What is a secure way to store credentials on Android?", options: ["SharedPreferences plaintext", "Android KeyStore", "SQLite database", "Log files"], correctAnswer: 1, explanation: "Android KeyStore provides hardware-backed secure credential storage.", topic: "M1: Credentials" },
  { id: 8, question: "What is certificate/public key pinning for?", options: ["Physical security", "Preventing MITM by validating server certificate", "Performance", "Caching"], correctAnswer: 1, explanation: "Pinning prevents MITM attacks by ensuring only expected certificates are trusted.", topic: "M1: Credentials" },

  // M2: Inadequate Supply Chain Security (7 questions)
  { id: 9, question: "What is M2 in OWASP Mobile Top 10?", options: ["Insecure Storage", "Inadequate Supply Chain Security", "Broken Crypto", "Code Injection"], correctAnswer: 1, explanation: "M2 covers risks from third-party libraries, SDKs, and components.", topic: "M2: Supply Chain" },
  { id: 10, question: "What is a supply chain attack on mobile apps?", options: ["Shipping delays", "Compromised third-party SDK injecting malicious code", "App store issues", "Network problems"], correctAnswer: 1, explanation: "Supply chain attacks compromise dependencies to inject malicious code into apps.", topic: "M2: Supply Chain" },
  { id: 11, question: "How should third-party libraries be managed?", options: ["Use any version", "Pin versions, scan for vulnerabilities, review updates", "Never update", "Only use old libraries"], correctAnswer: 1, explanation: "Pin versions, scan for CVEs, and carefully review library updates.", topic: "M2: Supply Chain" },
  { id: 12, question: "What tool scans Android dependencies for vulnerabilities?", options: ["Photoshop", "OWASP Dependency-Check, Snyk", "Calculator", "Notepad"], correctAnswer: 1, explanation: "Tools like Dependency-Check and Snyk scan libraries for known vulnerabilities.", topic: "M2: Supply Chain" },
  { id: 13, question: "What is the risk of using unmaintained libraries?", options: ["No risk", "Unpatched vulnerabilities remain exploitable", "Better performance", "More features"], correctAnswer: 1, explanation: "Unmaintained libraries don't receive security patches for discovered vulnerabilities.", topic: "M2: Supply Chain" },
  { id: 14, question: "What is SBOM?", options: ["Security Buffer Overflow Monitor", "Software Bill of Materials", "System Boot Options Menu", "Secure Binary Object Model"], correctAnswer: 1, explanation: "SBOM lists all software components for supply chain visibility.", topic: "M2: Supply Chain" },
  { id: 15, question: "How can malicious SDKs affect your app?", options: ["Improve performance", "Exfiltrate data, inject ads, compromise security", "Add features", "Better UI"], correctAnswer: 1, explanation: "Malicious SDKs can steal data, inject unwanted content, or compromise app security.", topic: "M2: Supply Chain" },

  // M3: Insecure Authentication/Authorization (8 questions)
  { id: 16, question: "What is M3 in OWASP Mobile Top 10?", options: ["Insecure Storage", "Insecure Authentication/Authorization", "Code Tampering", "Reverse Engineering"], correctAnswer: 1, explanation: "M3 covers weak authentication mechanisms and broken authorization.", topic: "M3: Auth" },
  { id: 17, question: "What is the risk of client-side authentication only?", options: ["No risk", "Can be bypassed by modifying app or intercepting traffic", "Better security", "Faster login"], correctAnswer: 1, explanation: "Client-side auth can be bypassed through app modification or traffic interception.", topic: "M3: Auth" },
  { id: 18, question: "What is IDOR?", options: ["iOS Development Object Reference", "Insecure Direct Object Reference", "Internal Data Object Retrieval", "Interface Design Object Reference"], correctAnswer: 1, explanation: "IDOR allows accessing resources by manipulating identifiers without proper authorization.", topic: "M3: Auth" },
  { id: 19, question: "Why should session tokens be rotated?", options: ["Performance", "Limit impact of token theft", "UI refresh", "Database sync"], correctAnswer: 1, explanation: "Token rotation limits the window of opportunity for stolen tokens.", topic: "M3: Auth" },
  { id: 20, question: "What is privilege escalation?", options: ["Getting promoted", "Gaining higher access rights than authorized", "Installing updates", "Admin login"], correctAnswer: 1, explanation: "Privilege escalation exploits allow gaining admin or higher-level access.", topic: "M3: Auth" },
  { id: 21, question: "What should be checked for authorization bypass?", options: ["UI only", "Server-side checks for every sensitive action", "Client preferences", "Device model"], correctAnswer: 1, explanation: "Authorization must be enforced server-side for all sensitive operations.", topic: "M3: Auth" },
  { id: 22, question: "What is horizontal privilege escalation?", options: ["Vertical access", "Accessing other users' resources at same privilege level", "Admin access", "Root access"], correctAnswer: 1, explanation: "Horizontal escalation accesses other users' data without elevated privileges.", topic: "M3: Auth" },
  { id: 23, question: "How can biometric auth be bypassed?", options: ["Cannot bypass", "Hooking auth callbacks with Frida, exploiting fallback mechanisms", "Physical fingerprint", "Face photo"], correctAnswer: 1, explanation: "Biometric auth can be bypassed through runtime manipulation or fallback exploits.", topic: "M3: Auth" },

  // M4: Insufficient Input/Output Validation (8 questions)
  { id: 24, question: "What is M4 in OWASP Mobile Top 10?", options: ["Insecure Storage", "Insufficient Input/Output Validation", "Code Tampering", "Network Issues"], correctAnswer: 1, explanation: "M4 covers injection attacks from inadequate input/output validation.", topic: "M4: Validation" },
  { id: 25, question: "What is SQL injection?", options: ["SQL performance", "Injecting malicious SQL through user input", "Database backup", "Query optimization"], correctAnswer: 1, explanation: "SQL injection manipulates queries through unvalidated user input.", topic: "M4: Validation" },
  { id: 26, question: "What is path traversal?", options: ["Navigation UI", "Accessing files outside intended directory using ../ sequences", "File compression", "Path optimization"], correctAnswer: 1, explanation: "Path traversal exploits navigate outside intended directories to access sensitive files.", topic: "M4: Validation" },
  { id: 27, question: "What is XSS in WebView context?", options: ["Cross-site styling", "Injecting scripts through WebView that execute in app context", "Site loading", "Caching"], correctAnswer: 1, explanation: "WebView XSS can execute malicious JavaScript with app privileges.", topic: "M4: Validation" },
  { id: 28, question: "How to prevent SQL injection?", options: ["Use string concatenation", "Use parameterized queries/prepared statements", "Disable SQL", "Use plaintext"], correctAnswer: 1, explanation: "Parameterized queries prevent SQL injection by separating code from data.", topic: "M4: Validation" },
  { id: 29, question: "What is input sanitization?", options: ["Cleaning keyboards", "Filtering/encoding user input to prevent injection", "Input speed", "Input formatting"], correctAnswer: 1, explanation: "Sanitization removes or encodes potentially malicious characters from input.", topic: "M4: Validation" },
  { id: 30, question: "What is a deep link injection?", options: ["Link depth", "Manipulating deep link parameters to access unauthorized features", "URL shortening", "Link tracking"], correctAnswer: 1, explanation: "Deep link injection exploits parameter handling to bypass controls or access features.", topic: "M4: Validation" },
  { id: 31, question: "What is deserialization vulnerability?", options: ["Data formatting", "Executing malicious code through untrusted serialized data", "JSON parsing", "XML formatting"], correctAnswer: 1, explanation: "Unsafe deserialization can execute arbitrary code from malicious serialized objects.", topic: "M4: Validation" },

  // M5: Insecure Communication (8 questions)
  { id: 32, question: "What is M5 in OWASP Mobile Top 10?", options: ["Insecure Storage", "Insecure Communication", "Code Issues", "Platform Issues"], correctAnswer: 1, explanation: "M5 covers network security issues like missing encryption and certificate validation.", topic: "M5: Communication" },
  { id: 33, question: "What is the risk of cleartext HTTP?", options: ["No risk", "Traffic can be intercepted and modified by attackers", "Faster loading", "Better compatibility"], correctAnswer: 1, explanation: "Cleartext HTTP exposes data to eavesdropping and manipulation.", topic: "M5: Communication" },
  { id: 34, question: "What is a MITM attack?", options: ["Middle app", "Intercepting communications between app and server", "Media transfer", "Memory issue"], correctAnswer: 1, explanation: "MITM attacks intercept and potentially modify traffic between endpoints.", topic: "M5: Communication" },
  { id: 35, question: "What does SSL/TLS provide?", options: ["Speed boost", "Encryption, integrity, and authentication for network traffic", "Compression", "Caching"], correctAnswer: 1, explanation: "SSL/TLS encrypts data and verifies server identity to prevent interception.", topic: "M5: Communication" },
  { id: 36, question: "What is certificate validation bypass?", options: ["Speeding up connections", "Accepting any certificate without proper validation", "Certificate upgrade", "Key rotation"], correctAnswer: 1, explanation: "Bypassing cert validation allows MITM attacks with fraudulent certificates.", topic: "M5: Communication" },
  { id: 37, question: "What is ATS on iOS?", options: ["App Test Suite", "App Transport Security enforcing HTTPS", "Auto Test System", "Apple Test Standard"], correctAnswer: 1, explanation: "ATS enforces secure network connections, requiring HTTPS by default.", topic: "M5: Communication" },
  { id: 38, question: "What is android:usesCleartextTraffic?", options: ["Network speed setting", "Flag controlling whether app allows unencrypted HTTP", "Cache setting", "Debug setting"], correctAnswer: 1, explanation: "This manifest flag controls whether the app permits cleartext HTTP traffic.", topic: "M5: Communication" },
  { id: 39, question: "What should be logged about network traffic?", options: ["All data including credentials", "Non-sensitive metadata only, never credentials or tokens", "Nothing", "Only errors"], correctAnswer: 1, explanation: "Never log sensitive data; only log non-sensitive information for debugging.", topic: "M5: Communication" },

  // M6: Inadequate Privacy Controls (7 questions)
  { id: 40, question: "What is M6 in OWASP Mobile Top 10?", options: ["Code Tampering", "Inadequate Privacy Controls", "Reverse Engineering", "Binary Protection"], correctAnswer: 1, explanation: "M6 covers privacy issues like PII leakage and excessive data collection.", topic: "M6: Privacy" },
  { id: 41, question: "What is PII?", options: ["Program Interface Identifier", "Personally Identifiable Information", "Private Internet Index", "Protected Internal Instance"], correctAnswer: 1, explanation: "PII is data that can identify an individual, requiring protection.", topic: "M6: Privacy" },
  { id: 42, question: "What is data minimization?", options: ["Compressing data", "Collecting only necessary data for app function", "Deleting all data", "Data backup"], correctAnswer: 1, explanation: "Data minimization limits collection to what's strictly necessary.", topic: "M6: Privacy" },
  { id: 43, question: "What regulation requires privacy-by-design?", options: ["HTTP", "GDPR, CCPA", "TCP/IP", "DNS"], correctAnswer: 1, explanation: "GDPR and similar regulations require building privacy into app design.", topic: "M6: Privacy" },
  { id: 44, question: "What is the risk of analytics SDKs?", options: ["No risk", "May collect and transmit excessive user data", "Better performance", "Enhanced UI"], correctAnswer: 1, explanation: "Analytics SDKs can collect more data than necessary, creating privacy risks.", topic: "M6: Privacy" },
  { id: 45, question: "How should location data be handled?", options: ["Always collect", "Request minimum necessary precision, explain usage", "Never use", "Store forever"], correctAnswer: 1, explanation: "Use minimum necessary location precision and clearly explain why it's needed.", topic: "M6: Privacy" },
  { id: 46, question: "What is device fingerprinting?", options: ["Biometrics", "Identifying devices through unique characteristics", "Screen unlock", "Touch ID"], correctAnswer: 1, explanation: "Device fingerprinting identifies devices through hardware/software characteristics.", topic: "M6: Privacy" },

  // M7: Insufficient Binary Protections (8 questions)
  { id: 47, question: "What is M7 in OWASP Mobile Top 10?", options: ["Insecure Storage", "Insufficient Binary Protections", "Network Issues", "Auth Problems"], correctAnswer: 1, explanation: "M7 covers lack of protection against reverse engineering and tampering.", topic: "M7: Binary" },
  { id: 48, question: "What is code obfuscation?", options: ["Code deletion", "Making code difficult to understand and reverse engineer", "Code comments", "Code formatting"], correctAnswer: 1, explanation: "Obfuscation makes reverse engineering harder through code transformation.", topic: "M7: Binary" },
  { id: 49, question: "What is anti-tampering?", options: ["Weather protection", "Detecting modifications to app binary", "Crash prevention", "Performance tuning"], correctAnswer: 1, explanation: "Anti-tampering detects if the application has been modified.", topic: "M7: Binary" },
  { id: 50, question: "What is root/jailbreak detection?", options: ["Plant detection", "Identifying compromised device environments", "Hardware check", "Model detection"], correctAnswer: 1, explanation: "Root/jailbreak detection identifies devices where security controls are bypassed.", topic: "M7: Binary" },
  { id: 51, question: "What is debugger detection?", options: ["Finding bugs", "Detecting if debugger is attached to prevent analysis", "Error logging", "Performance monitoring"], correctAnswer: 1, explanation: "Debugger detection prevents runtime analysis and manipulation.", topic: "M7: Binary" },
  { id: 52, question: "What is ProGuard/R8 on Android?", options: ["Security guard", "Code shrinking and obfuscation tool", "Antivirus", "Firewall"], correctAnswer: 1, explanation: "ProGuard/R8 shrinks code and provides basic obfuscation.", topic: "M7: Binary" },
  { id: 53, question: "What is RASP?", options: ["Audio format", "Runtime Application Self-Protection", "Network protocol", "File type"], correctAnswer: 1, explanation: "RASP monitors and protects apps at runtime against attacks.", topic: "M7: Binary" },
  { id: 54, question: "Can binary protections be bypassed?", options: ["Never", "Yes, but they raise the bar for attackers", "Only on old devices", "Only with root"], correctAnswer: 1, explanation: "Binary protections can be bypassed but significantly increase attack difficulty.", topic: "M7: Binary" },

  // M8: Security Misconfiguration (7 questions)
  { id: 55, question: "What is M8 in OWASP Mobile Top 10?", options: ["Insecure Storage", "Security Misconfiguration", "Crypto Issues", "Platform Usage"], correctAnswer: 1, explanation: "M8 covers insecure default settings, exposed services, and configuration errors.", topic: "M8: Misconfig" },
  { id: 56, question: "What is android:debuggable='true' risk?", options: ["No risk", "Allows attaching debugger to production app", "Better logging", "Faster builds"], correctAnswer: 1, explanation: "debuggable=true in production allows debugging tools to attach.", topic: "M8: Misconfig" },
  { id: 57, question: "What is android:allowBackup='true' risk?", options: ["No risk", "App data can be extracted via adb backup", "Better backup", "Cloud sync"], correctAnswer: 1, explanation: "allowBackup allows extracting app data using adb without root.", topic: "M8: Misconfig" },
  { id: 58, question: "What are exported components risks?", options: ["No risk", "Unprotected components accessible by other apps", "Performance", "UI issues"], correctAnswer: 1, explanation: "Exported components without permission checks can be exploited by malicious apps.", topic: "M8: Misconfig" },
  { id: 59, question: "What should be disabled in production builds?", options: ["All features", "Debug logging, test endpoints, verbose errors", "Main functionality", "User accounts"], correctAnswer: 1, explanation: "Disable debug features, test code, and verbose logging in production.", topic: "M8: Misconfig" },
  { id: 60, question: "What is a WebView misconfiguration?", options: ["UI style", "Enabling JavaScript with file:// access or insecure settings", "Page layout", "Font size"], correctAnswer: 1, explanation: "Insecure WebView settings can enable code execution or data access.", topic: "M8: Misconfig" },
  { id: 61, question: "What is deep link scheme hijacking?", options: ["URL theft", "Malicious app registering same URL scheme to intercept", "Link shortening", "Redirect"], correctAnswer: 1, explanation: "Other apps can register the same scheme to hijack deep links.", topic: "M8: Misconfig" },

  // M9: Insecure Data Storage (7 questions)
  { id: 62, question: "What is M9 in OWASP Mobile Top 10?", options: ["Network Security", "Insecure Data Storage", "Binary Protection", "Auth Issues"], correctAnswer: 1, explanation: "M9 covers storing sensitive data insecurely on the device.", topic: "M9: Storage" },
  { id: 63, question: "What is the risk of storing credentials in SharedPreferences?", options: ["No risk", "Plaintext credentials accessible on rooted devices or via backup", "Better performance", "Easier access"], correctAnswer: 1, explanation: "SharedPreferences stores data in plaintext accessible through various means.", topic: "M9: Storage" },
  { id: 64, question: "What is the iOS Keychain for?", options: ["Physical keys", "Encrypted storage for sensitive credentials", "iCloud sync", "App settings"], correctAnswer: 1, explanation: "Keychain provides encrypted storage for passwords and sensitive data.", topic: "M9: Storage" },
  { id: 65, question: "What is the risk of logging sensitive data?", options: ["No risk", "Logs accessible via logcat, backup, or crash reports", "Better debugging", "Performance monitoring"], correctAnswer: 1, explanation: "Sensitive data in logs can be extracted through various channels.", topic: "M9: Storage" },
  { id: 66, question: "What is SQLCipher?", options: ["SQL editor", "Encryption extension for SQLite databases", "Database viewer", "Query tool"], correctAnswer: 1, explanation: "SQLCipher adds encryption to SQLite databases for secure storage.", topic: "M9: Storage" },
  { id: 67, question: "What are clipboard security concerns?", options: ["None", "Sensitive copied data accessible by other apps", "Performance", "Formatting"], correctAnswer: 1, explanation: "Clipboard content can be read by other apps, exposing copied secrets.", topic: "M9: Storage" },
  { id: 68, question: "What is screenshot protection?", options: ["Camera block", "Preventing sensitive screens from appearing in snapshots", "Photo filter", "Image compression"], correctAnswer: 1, explanation: "FLAG_SECURE and similar prevent capturing sensitive screen content.", topic: "M9: Storage" },

  // M10: Insufficient Cryptography (7 questions)
  { id: 69, question: "What is M10 in OWASP Mobile Top 10?", options: ["Network Security", "Insufficient Cryptography", "Storage Issues", "Platform Issues"], correctAnswer: 1, explanation: "M10 covers weak or improperly implemented cryptography.", topic: "M10: Crypto" },
  { id: 70, question: "What is a deprecated crypto algorithm?", options: ["AES-256", "MD5, SHA1 for security, DES", "ChaCha20", "Curve25519"], correctAnswer: 1, explanation: "MD5, SHA1 (for security), and DES are cryptographically broken.", topic: "M10: Crypto" },
  { id: 71, question: "What is the risk of hardcoded encryption keys?", options: ["Better performance", "Keys extractable through reverse engineering", "Easier implementation", "Stronger encryption"], correctAnswer: 1, explanation: "Hardcoded keys can be extracted, defeating the encryption purpose.", topic: "M10: Crypto" },
  { id: 72, question: "What is proper key storage?", options: ["In source code", "Hardware-backed KeyStore or Keychain", "In SharedPreferences", "In app resources"], correctAnswer: 1, explanation: "Keys should be stored in hardware-backed secure storage.", topic: "M10: Crypto" },
  { id: 73, question: "What is CBC mode vulnerability?", options: ["No vulnerability", "Padding oracle attacks possible without authentication", "Too slow", "Too complex"], correctAnswer: 1, explanation: "CBC without authentication is vulnerable to padding oracle attacks.", topic: "M10: Crypto" },
  { id: 74, question: "What is recommended symmetric encryption?", options: ["DES", "AES-GCM or ChaCha20-Poly1305", "Blowfish", "RC4"], correctAnswer: 1, explanation: "AES-GCM and ChaCha20-Poly1305 provide authenticated encryption.", topic: "M10: Crypto" },
  { id: 75, question: "What is key derivation function (KDF)?", options: ["Key deletion", "Deriving keys from passwords using PBKDF2, Argon2", "Key sharing", "Key display"], correctAnswer: 1, explanation: "KDFs derive cryptographic keys from passwords with stretching.", topic: "M10: Crypto" },
];

// Quiz Section Component
function QuizSection() {
  const theme = useTheme();
  const [quizStarted, setQuizStarted] = React.useState(false);
  const [currentQuestions, setCurrentQuestions] = React.useState<QuizQuestion[]>([]);
  const [userAnswers, setUserAnswers] = React.useState<{ [key: number]: number }>({});
  const [showResults, setShowResults] = React.useState(false);
  const [currentQuestionIndex, setCurrentQuestionIndex] = React.useState(0);

  const shuffleAndSelectQuestions = () => {
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, 10);
  };

  const startQuiz = () => {
    setCurrentQuestions(shuffleAndSelectQuestions());
    setUserAnswers({});
    setShowResults(false);
    setCurrentQuestionIndex(0);
    setQuizStarted(true);
  };

  const handleAnswerSelect = (questionId: number, answerIndex: number) => {
    setUserAnswers((prev) => ({ ...prev, [questionId]: answerIndex }));
  };

  const calculateScore = () => {
    let correct = 0;
    currentQuestions.forEach((q) => {
      if (userAnswers[q.id] === q.correctAnswer) correct++;
    });
    return correct;
  };

  const getScoreColor = (score: number) => {
    if (score >= 8) return "#f59e0b";
    if (score >= 6) return "#3b82f6";
    return "#ef4444";
  };

  const getScoreMessage = (score: number) => {
    if (score === 10) return "Perfect! You've mastered OWASP Mobile Top 10! 🏆";
    if (score >= 8) return "Excellent! Strong mobile security knowledge! 🛡️";
    if (score >= 6) return "Good job! Keep studying mobile vulnerabilities! 📚";
    if (score >= 4) return "Not bad, but review the OWASP categories again. 💪";
    return "Keep learning! Review all M1-M10 categories. 📖";
  };

  if (!quizStarted) {
    return (
      <Paper id="quiz-section" sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `2px solid ${alpha("#f59e0b", 0.2)}` }}>
        <Typography variant="h5" sx={{ fontWeight: 800, mb: 2, display: "flex", alignItems: "center", gap: 2 }}>
          <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #f59e0b, #d97706)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <QuizIcon sx={{ color: "white", fontSize: 28 }} />
          </Box>
          Test Your OWASP Mobile Knowledge
        </Typography>
        <Typography variant="body1" sx={{ mb: 3, color: "text.secondary" }}>
          Ready to test what you've learned? Take this <strong>10-question quiz</strong> covering all OWASP Mobile Top 10 categories. Questions are randomly selected from a pool of <strong>75 questions</strong>!
        </Typography>
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {[{ label: "Questions", value: "10", color: "#f59e0b" }, { label: "Question Pool", value: "75", color: "#d97706" }, { label: "Categories", value: "10", color: "#8b5cf6" }, { label: "Retakes", value: "∞", color: "#3b82f6" }].map((stat) => (
            <Grid item xs={6} sm={3} key={stat.label}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(stat.color, 0.1), borderRadius: 2 }}>
                <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>{stat.value}</Typography>
                <Typography variant="caption" color="text.secondary">{stat.label}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
        <Button variant="contained" size="large" onClick={startQuiz} startIcon={<QuizIcon />} sx={{ background: "linear-gradient(135deg, #f59e0b, #d97706)", fontWeight: 700, px: 4, py: 1.5, "&:hover": { background: "linear-gradient(135deg, #d97706, #b45309)" } }}>
          Start Quiz
        </Button>
      </Paper>
    );
  }

  if (showResults) {
    const score = calculateScore();
    return (
      <Paper id="quiz-section" sx={{ p: 4, mb: 4, borderRadius: 3, border: `2px solid ${alpha(getScoreColor(score), 0.3)}` }}>
        <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <EmojiEventsIcon sx={{ color: getScoreColor(score), fontSize: 36 }} /> Quiz Results
        </Typography>
        <Box sx={{ textAlign: "center", mb: 4 }}>
          <Typography variant="h1" sx={{ fontWeight: 900, color: getScoreColor(score) }}>{score}/10</Typography>
          <Typography variant="h6" color="text.secondary" sx={{ mb: 2 }}>{getScoreMessage(score)}</Typography>
          <Chip label={`${score * 10}%`} sx={{ bgcolor: alpha(getScoreColor(score), 0.15), color: getScoreColor(score), fontWeight: 700, fontSize: "1rem" }} />
        </Box>
        <Divider sx={{ my: 3 }} />
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Review Your Answers:</Typography>
        {currentQuestions.map((q, index) => {
          const isCorrect = userAnswers[q.id] === q.correctAnswer;
          return (
            <Paper key={q.id} sx={{ p: 2, mb: 2, borderRadius: 2, bgcolor: alpha(isCorrect ? "#f59e0b" : "#ef4444", 0.05), border: `1px solid ${alpha(isCorrect ? "#f59e0b" : "#ef4444", 0.2)}` }}>
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1 }}>
                <Chip label={`Q${index + 1}`} size="small" sx={{ bgcolor: isCorrect ? "#f59e0b" : "#ef4444", color: "white", fontWeight: 700 }} />
                <Typography variant="body2" sx={{ fontWeight: 600 }}>{q.question}</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ ml: 5 }}>
                <strong>Your answer:</strong> {q.options[userAnswers[q.id]] || "Not answered"}
                {!isCorrect && (<><br /><strong style={{ color: "#f59e0b" }}>Correct:</strong> {q.options[q.correctAnswer]}</>)}
              </Typography>
              {!isCorrect && <Alert severity="info" sx={{ mt: 1, ml: 5 }}><Typography variant="caption">{q.explanation}</Typography></Alert>}
            </Paper>
          );
        })}
        <Box sx={{ display: "flex", gap: 2, mt: 3 }}>
          <Button variant="contained" onClick={startQuiz} startIcon={<RefreshIcon />} sx={{ background: "linear-gradient(135deg, #f59e0b, #d97706)", fontWeight: 700 }}>Try Again</Button>
          <Button variant="outlined" onClick={() => setQuizStarted(false)}>Back to Overview</Button>
        </Box>
      </Paper>
    );
  }

  const currentQuestion = currentQuestions[currentQuestionIndex];
  const answeredCount = Object.keys(userAnswers).length;

  return (
    <Paper id="quiz-section" sx={{ p: 4, mb: 4, borderRadius: 3, border: `2px solid ${alpha("#f59e0b", 0.2)}` }}>
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Question {currentQuestionIndex + 1} of 10</Typography>
          <Chip label={currentQuestion.topic} size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
        </Box>
        <LinearProgress variant="determinate" value={((currentQuestionIndex + 1) / 10) * 100} sx={{ height: 8, borderRadius: 1, bgcolor: alpha("#f59e0b", 0.1), "& .MuiLinearProgress-bar": { bgcolor: "#f59e0b" } }} />
      </Box>
      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3, lineHeight: 1.5 }}>{currentQuestion.question}</Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {currentQuestion.options.map((option, index) => {
          const isSelected = userAnswers[currentQuestion.id] === index;
          return (
            <Grid item xs={12} key={index}>
              <Paper onClick={() => handleAnswerSelect(currentQuestion.id, index)} sx={{ p: 2, borderRadius: 2, cursor: "pointer", bgcolor: isSelected ? alpha("#f59e0b", 0.1) : "background.paper", border: `2px solid ${isSelected ? "#f59e0b" : alpha(theme.palette.divider, 0.2)}`, transition: "all 0.2s", "&:hover": { borderColor: "#f59e0b", bgcolor: alpha("#f59e0b", 0.05) } }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box sx={{ width: 32, height: 32, borderRadius: "50%", bgcolor: isSelected ? "#f59e0b" : alpha(theme.palette.divider, 0.3), color: isSelected ? "white" : "text.secondary", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700 }}>{String.fromCharCode(65 + index)}</Box>
                  <Typography variant="body1" sx={{ fontWeight: isSelected ? 600 : 400 }}>{option}</Typography>
                </Box>
              </Paper>
            </Grid>
          );
        })}
      </Grid>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Button variant="outlined" disabled={currentQuestionIndex === 0} onClick={() => setCurrentQuestionIndex((p) => p - 1)}>Previous</Button>
        <Typography variant="body2" color="text.secondary">{answeredCount}/10 answered</Typography>
        {currentQuestionIndex < 9 ? (
          <Button variant="contained" onClick={() => setCurrentQuestionIndex((p) => p + 1)} sx={{ background: "linear-gradient(135deg, #f59e0b, #d97706)" }}>Next</Button>
        ) : (
          <Button variant="contained" onClick={() => setShowResults(true)} disabled={answeredCount < 10} sx={{ background: answeredCount >= 10 ? "linear-gradient(135deg, #3b82f6, #2563eb)" : undefined, fontWeight: 700 }}>Submit Quiz</Button>
        )}
      </Box>
    </Paper>
  );
}

interface MobileRisk {
  id: string;
  rank: number;
  title: string;
  shortTitle: string;
  icon: React.ReactNode;
  color: string;
  description: string;
  prevalence: number;
  impact: "Critical" | "High" | "Medium";
  exploitability: "Easy" | "Medium" | "Difficult";
  keyPoints: string[];
  attackVectors: string[];
  vulnerableCode?: { platform: string; code: string; issue: string }[];
  secureCode?: { platform: string; code: string; fix: string }[];
  prevention: string[];
  testingTips: string[];
  realWorldExamples?: string[];
  tools?: string[];
  androidSpecific?: string[];
  iosSpecific?: string[];
}

const mobileRisks: MobileRisk[] = [
  {
    id: "m1",
    rank: 1,
    title: "Improper Credential Usage",
    shortTitle: "Credentials",
    icon: <VpnKeyIcon />,
    color: "#dc2626",
    description: "This category covers the misuse of credentials, including hardcoded credentials, insecure credential storage, and improper credential transmission. Mobile apps frequently mishandle credentials, leading to account takeovers and data breaches.",
    prevalence: 85,
    impact: "Critical",
    exploitability: "Easy",
    keyPoints: [
      "Hardcoded API keys, passwords, or secrets in source code",
      "Credentials stored in plain text or weakly encrypted",
      "Credentials transmitted over insecure channels",
      "Credentials logged in debug output or crash reports",
      "Shared credentials across multiple users or devices",
      "Insufficient credential rotation policies",
    ],
    attackVectors: [
      "Reverse engineering APK/IPA to extract hardcoded secrets",
      "Reading credentials from shared preferences or plist files",
      "Intercepting credentials via MITM attacks",
      "Extracting credentials from device backups",
      "Memory dumping to capture credentials in RAM",
    ],
    vulnerableCode: [
      {
        platform: "Android (Kotlin)",
        code: `// ❌ Hardcoded API key
const val API_KEY = "sk-1234567890abcdef"

// ❌ Plain text storage
sharedPrefs.edit()
    .putString("password", userPassword)
    .apply()`,
        issue: "Credentials easily extracted from APK or device storage",
      },
      {
        platform: "iOS (Swift)",
        code: `// ❌ Hardcoded secret
let apiSecret = "super_secret_key_123"

// ❌ UserDefaults for sensitive data
UserDefaults.standard.set(password, forKey: "userPassword")`,
        issue: "Secrets visible in binary, UserDefaults not encrypted",
      },
    ],
    secureCode: [
      {
        platform: "Android (Kotlin)",
        code: `// ✅ Use Android Keystore
val keyStore = KeyStore.getInstance("AndroidKeyStore")
keyStore.load(null)

// ✅ EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()
val encryptedPrefs = EncryptedSharedPreferences.create(...)`,
        fix: "Hardware-backed keystore and encrypted storage",
      },
      {
        platform: "iOS (Swift)",
        code: `// ✅ Use Keychain Services
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "userToken",
    kSecValueData as String: tokenData,
    kSecAttrAccessible as String: 
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)`,
        fix: "Keychain with appropriate accessibility level",
      },
    ],
    prevention: [
      "Never hardcode credentials in source code",
      "Use platform-specific secure storage (Keystore/Keychain)",
      "Implement proper key rotation mechanisms",
      "Use environment variables or secure vaults for CI/CD",
      "Encrypt credentials at rest and in transit",
      "Implement certificate pinning for credential transmission",
      "Use OAuth/OIDC instead of storing passwords",
    ],
    testingTips: [
      "Decompile APK with jadx/apktool and search for secrets",
      "Use strings command on iOS binaries",
      "Check SharedPreferences, databases, and plist files",
      "Monitor network traffic for credential exposure",
      "Analyze memory dumps for credential leakage",
    ],
    tools: ["jadx", "apktool", "Hopper", "Ghidra", "Frida", "objection", "MobSF"],
    realWorldExamples: [
      "Uber's 2016 breach: hardcoded AWS keys in GitHub repo",
      "Starbucks: API keys exposed in mobile app binary",
    ],
  },
  {
    id: "m2",
    rank: 2,
    title: "Inadequate Supply Chain Security",
    shortTitle: "Supply Chain",
    icon: <InventoryIcon />,
    color: "#ea580c",
    description: "Mobile apps rely on numerous third-party libraries, SDKs, and components. Vulnerabilities in these dependencies can compromise the entire application. This includes malicious libraries, outdated components, and compromised build pipelines.",
    prevalence: 78,
    impact: "Critical",
    exploitability: "Medium",
    keyPoints: [
      "Vulnerable third-party libraries and SDKs",
      "Malicious code injected through dependencies",
      "Outdated components with known CVEs",
      "Unverified or unsigned packages",
      "Compromised build or CI/CD pipelines",
      "Typosquatting attacks on package names",
    ],
    attackVectors: [
      "Exploiting known vulnerabilities in outdated libraries",
      "Dependency confusion attacks",
      "Malicious SDK updates with backdoors",
      "Compromised developer accounts pushing malicious updates",
      "Build system compromise injecting malware",
    ],
    prevention: [
      "Maintain Software Bill of Materials (SBOM)",
      "Regularly scan dependencies for vulnerabilities",
      "Use dependency lock files (package-lock.json, Podfile.lock)",
      "Verify package signatures and checksums",
      "Monitor for security advisories on dependencies",
      "Implement least-privilege for third-party SDKs",
      "Use private package registries with curation",
      "Secure CI/CD pipelines with MFA and audit logs",
    ],
    testingTips: [
      "Run OWASP Dependency-Check or Snyk on project",
      "Audit SDK permissions and data collection",
      "Review changes in dependency updates",
      "Check for known malicious packages",
      "Verify build reproducibility",
    ],
    tools: ["OWASP Dependency-Check", "Snyk", "npm audit", "Safety (Python)", "Dependabot", "Retire.js"],
    realWorldExamples: [
      "SolarWinds: Build system compromise affecting downstream",
      "event-stream npm: Malicious code targeting Bitcoin wallets",
      "ua-parser-js: Cryptominer injected via compromised maintainer",
    ],
  },
  {
    id: "m3",
    rank: 3,
    title: "Insecure Authentication/Authorization",
    shortTitle: "Auth/Authz",
    icon: <LockIcon />,
    color: "#f59e0b",
    description: "Weak or missing authentication and authorization controls allow attackers to bypass security mechanisms, impersonate users, or access unauthorized functionality. This is especially critical in mobile apps that interact with backend APIs.",
    prevalence: 82,
    impact: "Critical",
    exploitability: "Easy",
    keyPoints: [
      "Weak or missing authentication mechanisms",
      "Client-side authentication checks only",
      "Insecure session management",
      "Missing authorization checks on API endpoints",
      "Privilege escalation vulnerabilities",
      "Broken object-level authorization (BOLA)",
    ],
    attackVectors: [
      "Bypassing client-side authentication logic",
      "Session hijacking via token theft",
      "Accessing other users' data by modifying IDs",
      "Escalating privileges by tampering with role parameters",
      "Exploiting weak password policies",
    ],
    vulnerableCode: [
      {
        platform: "API Request",
        code: `// ❌ Client-side auth check only
if (isLoggedIn) {
    fetchUserData(userId)
}

// ❌ No server-side authorization
GET /api/users/123/profile
Authorization: Bearer <any_valid_token>`,
        issue: "Server doesn't verify if token owner can access user 123",
      },
    ],
    secureCode: [
      {
        platform: "Server-side (Node.js)",
        code: `// ✅ Server validates ownership
app.get('/api/users/:id/profile', auth, (req, res) => {
    if (req.user.id !== req.params.id && 
        !req.user.isAdmin) {
        return res.status(403).json({error: 'Forbidden'})
    }
    // Return profile data
})`,
        fix: "Server-side authorization check on every request",
      },
    ],
    prevention: [
      "Implement server-side authentication for all requests",
      "Use strong session management with secure tokens",
      "Enforce authorization checks on every API endpoint",
      "Implement proper access control (RBAC/ABAC)",
      "Use biometric authentication where appropriate",
      "Implement account lockout and rate limiting",
      "Never trust client-side authorization decisions",
    ],
    testingTips: [
      "Test API endpoints without authentication",
      "Try accessing other users' resources (IDOR)",
      "Modify role/privilege parameters in requests",
      "Test session timeout and invalidation",
      "Check if auth tokens are properly validated",
    ],
    tools: ["Burp Suite", "OWASP ZAP", "Postman", "Frida", "objection"],
  },
  {
    id: "m4",
    rank: 4,
    title: "Insufficient Input/Output Validation",
    shortTitle: "I/O Validation",
    icon: <InputIcon />,
    color: "#84cc16",
    description: "Failure to properly validate, sanitize, and encode data can lead to injection attacks, data corruption, and security bypasses. Mobile apps must validate all input from users, APIs, and external sources.",
    prevalence: 75,
    impact: "High",
    exploitability: "Medium",
    keyPoints: [
      "SQL injection in local SQLite databases",
      "JavaScript injection in WebViews",
      "Path traversal vulnerabilities",
      "XML/JSON injection attacks",
      "Format string vulnerabilities",
      "Buffer overflows in native code",
    ],
    attackVectors: [
      "Injecting malicious SQL into database queries",
      "XSS attacks via JavaScript bridges in WebViews",
      "Reading arbitrary files via path traversal",
      "Exploiting deep links with malicious parameters",
      "Manipulating intent extras on Android",
    ],
    vulnerableCode: [
      {
        platform: "Android (Java)",
        code: `// ❌ SQL Injection vulnerable
String query = "SELECT * FROM users WHERE name = '" 
    + userInput + "'";
db.rawQuery(query, null);

// ❌ WebView JavaScript injection
webView.loadUrl("javascript:handleData('" 
    + untrustedData + "')");`,
        issue: "User input directly concatenated into queries/scripts",
      },
    ],
    secureCode: [
      {
        platform: "Android (Java)",
        code: `// ✅ Parameterized query
String query = "SELECT * FROM users WHERE name = ?";
db.rawQuery(query, new String[]{userInput});

// ✅ Safe WebView communication
webView.evaluateJavascript(
    "handleData(" + JSONObject.quote(data) + ")",
    null
);`,
        fix: "Parameterized queries and proper encoding",
      },
    ],
    prevention: [
      "Use parameterized queries for all database operations",
      "Validate and sanitize all user inputs",
      "Encode output based on context (HTML, JS, URL)",
      "Implement allowlist validation where possible",
      "Disable JavaScript in WebViews if not needed",
      "Validate deep link parameters",
      "Use type-safe APIs and serialization",
    ],
    testingTips: [
      "Fuzz input fields with injection payloads",
      "Test deep links with malicious parameters",
      "Check WebView for JavaScript bridge vulnerabilities",
      "Test file path inputs for traversal",
      "Analyze intent handling for injection",
    ],
    tools: ["Drozer", "Frida", "Burp Suite", "sqlmap", "MobSF"],
  },
  {
    id: "m5",
    rank: 5,
    title: "Insecure Communication",
    shortTitle: "Communication",
    icon: <WifiIcon />,
    color: "#10b981",
    description: "Mobile apps often transmit sensitive data over networks. Without proper encryption and certificate validation, this data can be intercepted by attackers performing man-in-the-middle attacks.",
    prevalence: 70,
    impact: "High",
    exploitability: "Easy",
    keyPoints: [
      "Using HTTP instead of HTTPS",
      "Accepting invalid or self-signed certificates",
      "Missing or improper certificate pinning",
      "Leaking data through insecure WebSockets",
      "Exposing sensitive data in URL parameters",
      "Weak TLS configurations",
    ],
    attackVectors: [
      "Man-in-the-middle (MITM) attacks on public WiFi",
      "SSL stripping attacks",
      "Certificate spoofing without pinning",
      "Downgrade attacks to weaker protocols",
      "DNS spoofing to redirect traffic",
    ],
    vulnerableCode: [
      {
        platform: "Android (Java)",
        code: `// ❌ Trusting all certificates
TrustManager[] trustAll = new TrustManager[] {
    new X509TrustManager() {
        public void checkServerTrusted(...) { }
        public void checkClientTrusted(...) { }
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
};`,
        issue: "Accepts any certificate, enabling MITM attacks",
      },
    ],
    secureCode: [
      {
        platform: "Android (network_security_config.xml)",
        code: `<!-- ✅ Certificate pinning -->
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">
            api.example.com
        </domain>
        <pin-set>
            <pin digest="SHA-256">
                base64_encoded_pin_here
            </pin>
        </pin-set>
    </domain-config>
</network-security-config>`,
        fix: "Network security config with certificate pinning",
      },
    ],
    prevention: [
      "Always use HTTPS with TLS 1.2+",
      "Implement certificate pinning",
      "Use network security config (Android) or ATS (iOS)",
      "Never disable certificate validation in production",
      "Avoid sending sensitive data in URL parameters",
      "Implement proper error handling for SSL failures",
    ],
    testingTips: [
      "Use Burp/ZAP as proxy to intercept traffic",
      "Test with self-signed certificates",
      "Check if app works with proxy (cert pinning test)",
      "Verify TLS version and cipher suites",
      "Test on compromised network conditions",
    ],
    tools: ["Burp Suite", "OWASP ZAP", "Wireshark", "mitmproxy", "SSLscan"],
    androidSpecific: [
      "Use network_security_config.xml for pinning",
      "Set cleartextTrafficPermitted to false",
      "Use OkHttp CertificatePinner for dynamic pinning",
    ],
    iosSpecific: [
      "Enable App Transport Security (ATS)",
      "Use TrustKit for certificate pinning",
      "Avoid NSAllowsArbitraryLoads exception",
    ],
  },
  {
    id: "m6",
    rank: 6,
    title: "Inadequate Privacy Controls",
    shortTitle: "Privacy",
    icon: <PrivacyTipIcon />,
    color: "#06b6d4",
    description: "Mobile apps collect vast amounts of personal data. Inadequate privacy controls can lead to unauthorized data collection, exposure of PII, and violations of privacy regulations like GDPR and CCPA.",
    prevalence: 72,
    impact: "High",
    exploitability: "Medium",
    keyPoints: [
      "Excessive data collection beyond necessity",
      "Lack of user consent for data processing",
      "PII exposed in logs, backups, or analytics",
      "Inadequate data anonymization",
      "Missing data retention policies",
      "Third-party SDKs collecting user data",
    ],
    attackVectors: [
      "Extracting PII from application logs",
      "Accessing sensitive data in device backups",
      "Third-party SDK data exfiltration",
      "Screen capture of sensitive information",
      "Clipboard data leakage",
    ],
    prevention: [
      "Implement data minimization principles",
      "Obtain explicit user consent for data collection",
      "Anonymize or pseudonymize personal data",
      "Exclude sensitive data from logs and backups",
      "Audit third-party SDK data practices",
      "Implement proper data retention and deletion",
      "Mark sensitive fields to prevent screenshots",
      "Clear clipboard after sensitive operations",
    ],
    testingTips: [
      "Review what data is collected and why",
      "Check logs for PII exposure",
      "Analyze network traffic for unnecessary data",
      "Test backup extraction for sensitive data",
      "Audit third-party SDK permissions",
    ],
    tools: ["Charles Proxy", "Wireshark", "Android Backup Extractor", "iMazing"],
    androidSpecific: [
      "Set android:allowBackup=\"false\" for sensitive apps",
      "Use FLAG_SECURE to prevent screenshots",
      "Review and minimize app permissions",
    ],
    iosSpecific: [
      "Exclude sensitive files from iCloud backup",
      "Use Data Protection API with appropriate levels",
      "Implement App Privacy Report compliance",
    ],
  },
  {
    id: "m7",
    rank: 7,
    title: "Insufficient Binary Protections",
    shortTitle: "Binary Protection",
    icon: <SecurityIcon />,
    color: "#8b5cf6",
    description: "Mobile app binaries can be reverse engineered, modified, and redistributed. Without proper protections, attackers can extract secrets, bypass security controls, or create malicious versions of the app.",
    prevalence: 65,
    impact: "Medium",
    exploitability: "Medium",
    keyPoints: [
      "Easily reverse-engineered code",
      "Missing code obfuscation",
      "No runtime integrity checks",
      "Debugging enabled in production",
      "Missing anti-tampering controls",
      "Vulnerable to code injection",
    ],
    attackVectors: [
      "Decompiling APK/IPA to read source code",
      "Modifying app logic and repackaging",
      "Attaching debugger to running app",
      "Hooking functions with Frida/Xposed",
      "Bypassing license or payment checks",
    ],
    prevention: [
      "Apply code obfuscation (ProGuard/R8, SwiftShield)",
      "Implement root/jailbreak detection",
      "Add debugger detection and anti-debugging",
      "Use runtime application self-protection (RASP)",
      "Implement code integrity verification",
      "Detect emulators and analysis environments",
      "Use native code for sensitive operations",
    ],
    testingTips: [
      "Attempt to decompile and understand code flow",
      "Try to attach debugger to running app",
      "Use Frida to hook and modify functions",
      "Test on rooted/jailbroken device",
      "Attempt to repackage and install modified APK",
    ],
    tools: ["jadx", "apktool", "Hopper", "IDA Pro", "Frida", "Xposed", "Magisk"],
    androidSpecific: [
      "Enable ProGuard/R8 obfuscation",
      "Use SafetyNet/Play Integrity API",
      "Implement root detection checks",
      "Set debuggable=false in release builds",
    ],
    iosSpecific: [
      "Enable Bitcode and symbol stripping",
      "Implement jailbreak detection",
      "Use ptrace to prevent debugging",
      "Validate app signature at runtime",
    ],
  },
  {
    id: "m8",
    rank: 8,
    title: "Security Misconfiguration",
    shortTitle: "Misconfiguration",
    icon: <SettingsIcon />,
    color: "#6366f1",
    description: "Improper security configurations in mobile apps, backend services, and cloud infrastructure can expose sensitive functionality and data. Default settings are often insecure.",
    prevalence: 68,
    impact: "High",
    exploitability: "Easy",
    keyPoints: [
      "Debug features enabled in production",
      "Excessive app permissions",
      "Insecure default configurations",
      "Exposed sensitive components (Activities, Services)",
      "Improper WebView configurations",
      "Missing security headers on APIs",
    ],
    attackVectors: [
      "Accessing exported Activities/Services",
      "Exploiting debug endpoints or logs",
      "Abusing excessive permissions",
      "Attacking misconfigured WebViews",
      "Exploiting open Firebase/cloud databases",
    ],
    vulnerableCode: [
      {
        platform: "Android Manifest",
        code: `<!-- ❌ Exported component without protection -->
<activity 
    android:name=".AdminActivity"
    android:exported="true" />

<!-- ❌ Debug enabled -->
<application android:debuggable="true">`,
        issue: "Sensitive activity accessible to other apps",
      },
    ],
    secureCode: [
      {
        platform: "Android Manifest",
        code: `<!-- ✅ Protected component -->
<activity 
    android:name=".AdminActivity"
    android:exported="false" />
    
<!-- Or with permission -->
<activity 
    android:name=".AdminActivity"
    android:exported="true"
    android:permission="com.app.ADMIN_PERM" />`,
        fix: "Restrict component access or require permissions",
      },
    ],
    prevention: [
      "Disable debugging in production builds",
      "Request only necessary permissions",
      "Properly configure exported components",
      "Secure WebView settings (disable JS if not needed)",
      "Review and harden cloud/backend configurations",
      "Use security linters and scanners",
      "Implement proper Content Provider permissions",
    ],
    testingTips: [
      "Review AndroidManifest/Info.plist for misconfigs",
      "Test exported components with adb/Drozer",
      "Check for open Firebase databases",
      "Verify debug settings in production builds",
      "Scan for common misconfigurations with MobSF",
    ],
    tools: ["MobSF", "Drozer", "Firebase Scanner", "adb", "QARK"],
  },
  {
    id: "m9",
    rank: 9,
    title: "Insecure Data Storage",
    shortTitle: "Data Storage",
    icon: <StorageIcon />,
    color: "#ec4899",
    description: "Sensitive data stored insecurely on mobile devices can be accessed by attackers with physical access, malware, or through device backups. This includes data in files, databases, and caches.",
    prevalence: 80,
    impact: "High",
    exploitability: "Easy",
    keyPoints: [
      "Sensitive data in plain text files",
      "Unencrypted SQLite databases",
      "Data in shared/external storage",
      "Sensitive data in application logs",
      "Cached data containing PII",
      "Keyboard cache and autocomplete data",
    ],
    attackVectors: [
      "Reading files from rooted/jailbroken devices",
      "Extracting data from device backups",
      "Accessing shared/external storage",
      "Reading application logs",
      "Exploiting insecure file permissions",
    ],
    vulnerableCode: [
      {
        platform: "Android (Kotlin)",
        code: `// ❌ World-readable file
val file = File(getExternalFilesDir(null), "data.txt")
file.writeText(sensitiveData)

// ❌ Plain SQLite
val db = SQLiteDatabase.openDatabase(
    "users.db", null, SQLiteDatabase.CREATE_IF_NECESSARY
)
db.execSQL("INSERT INTO users VALUES ('$password')")`,
        issue: "Data accessible to other apps and in plain text",
      },
    ],
    secureCode: [
      {
        platform: "Android (Kotlin)",
        code: `// ✅ Internal encrypted storage
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()
    
val encryptedFile = EncryptedFile.Builder(
    context,
    File(context.filesDir, "secret.txt"),
    masterKey,
    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build()`,
        fix: "Use encrypted files with Jetpack Security",
      },
    ],
    prevention: [
      "Store sensitive data in internal storage only",
      "Encrypt all sensitive data at rest",
      "Use platform secure storage (Keychain/Keystore)",
      "Disable keyboard caching for sensitive fields",
      "Clear caches containing sensitive data",
      "Exclude sensitive data from backups",
      "Set appropriate file permissions",
    ],
    testingTips: [
      "Browse file system on rooted device",
      "Extract and analyze app sandbox",
      "Check SQLite databases for sensitive data",
      "Review log files for data leakage",
      "Test backup extraction procedures",
    ],
    tools: ["adb", "iFunbox", "SQLite Browser", "Frida", "objection"],
    androidSpecific: [
      "Use MODE_PRIVATE for file creation",
      "Implement EncryptedSharedPreferences",
      "Use SQLCipher for database encryption",
    ],
    iosSpecific: [
      "Use Data Protection API",
      "Set appropriate file protection attributes",
      "Exclude files from iCloud with NSURLIsExcludedFromBackupKey",
    ],
  },
  {
    id: "m10",
    rank: 10,
    title: "Insufficient Cryptography",
    shortTitle: "Cryptography",
    icon: <EnhancedEncryptionIcon />,
    color: "#f43f5e",
    description: "Weak or improperly implemented cryptography fails to protect sensitive data. This includes using deprecated algorithms, weak keys, improper key management, and flawed implementations.",
    prevalence: 60,
    impact: "High",
    exploitability: "Difficult",
    keyPoints: [
      "Using deprecated algorithms (MD5, SHA1, DES, RC4)",
      "Hardcoded encryption keys",
      "Insufficient key lengths",
      "Improper IV/nonce usage",
      "Missing or weak key derivation",
      "Predictable random number generation",
    ],
    attackVectors: [
      "Brute-forcing weak encryption keys",
      "Exploiting known algorithm weaknesses",
      "Extracting hardcoded keys from binary",
      "Attacking improper IV reuse",
      "Rainbow table attacks on weak hashes",
    ],
    vulnerableCode: [
      {
        platform: "Any",
        code: `// ❌ Weak hash
String hash = MD5(password);

// ❌ Hardcoded key
byte[] key = "MySecretKey12345".getBytes();
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));`,
        issue: "MD5 is broken, ECB mode is insecure, hardcoded key",
      },
    ],
    secureCode: [
      {
        platform: "Android (Kotlin)",
        code: `// ✅ Proper encryption
val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
)
keyGenerator.init(
    KeyGenParameterSpec.Builder("myKey",
        KeyProperties.PURPOSE_ENCRYPT or 
        KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(
            KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .build()
)

// ✅ Password hashing
val hash = Argon2(password, salt, iterations, memory)`,
        fix: "AES-256-GCM with hardware-backed keys, Argon2 for passwords",
      },
    ],
    prevention: [
      "Use modern algorithms (AES-256-GCM, ChaCha20-Poly1305)",
      "Never hardcode encryption keys",
      "Use proper key derivation (PBKDF2, Argon2)",
      "Generate keys in hardware security modules",
      "Use unique IVs/nonces for each encryption",
      "Implement proper random number generation",
      "Use platform crypto APIs (AndroidKeyStore, CommonCrypto)",
    ],
    testingTips: [
      "Review code for deprecated algorithms",
      "Search for hardcoded keys in binary",
      "Analyze encrypted data for patterns (ECB)",
      "Check key derivation implementation",
      "Verify random number generation",
    ],
    tools: ["MobSF", "jadx", "Hopper", "Ghidra", "CryptoAnalysis tools"],
  },
];

const impactColors = {
  Critical: "#dc2626",
  High: "#f59e0b",
  Medium: "#10b981",
};

const exploitabilityColors = {
  Easy: "#dc2626",
  Medium: "#f59e0b",
  Difficult: "#10b981",
};

export default function OwaspMobilePage() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [expandedRisk, setExpandedRisk] = useState<string | false>("m1");
  const [tabValue, setTabValue] = useState(0);
  const [activeSection, setActiveSection] = useState("intro");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const scrollToSection = (sectionId: string) => {
    setActiveSection(sectionId);
    const element = document.getElementById(sectionId);
    if (element) {
      const offset = 80;
      const elementPosition = element.getBoundingClientRect().top;
      const offsetPosition = elementPosition + window.pageYOffset - offset;
      window.scrollTo({ top: offsetPosition, behavior: "smooth" });
    }
    setMobileNavOpen(false);
  };

  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map((item) => item.id);
      for (const sectionId of sections) {
        const element = document.getElementById(sectionId);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 120 && rect.bottom >= 120) {
            setActiveSection(sectionId);
            break;
          }
        }
      }
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Sidebar navigation component
  const sidebarNav = (
    <Box sx={{ p: 2 }}>
      <Typography
        variant="overline"
        sx={{ color: themeColors.textMuted, fontWeight: 600, px: 1, mb: 1, display: "block" }}
      >
        Navigation
      </Typography>
      {sectionNavItems.map((item) => (
        <Box
          key={item.id}
          onClick={() => scrollToSection(item.id)}
          sx={{
            display: "flex",
            alignItems: "center",
            gap: 1.5,
            px: 2,
            py: 1,
            borderRadius: 2,
            cursor: "pointer",
            mb: 0.5,
            bgcolor: activeSection === item.id ? alpha(themeColors.primary, 0.15) : "transparent",
            borderLeft: activeSection === item.id ? `3px solid ${themeColors.primary}` : "3px solid transparent",
            color: activeSection === item.id ? themeColors.primary : themeColors.textMuted,
            transition: "all 0.2s ease",
            "&:hover": {
              bgcolor: alpha(themeColors.primary, 0.1),
              color: themeColors.primary,
            },
          }}
        >
          {item.icon}
          <Typography variant="body2" sx={{ fontWeight: activeSection === item.id ? 600 : 400 }}>
            {item.label}
          </Typography>
        </Box>
      ))}
    </Box>
  );

  const pageContext = `This page covers the OWASP Mobile Top 10 security risks for mobile applications. Topics include: improper credential usage, inadequate supply chain security, insecure authentication/authorization, insufficient input/output validation, insecure communication, inadequate privacy controls, insufficient binary protections, security misconfiguration, insecure data storage, and insufficient cryptography. Includes threat modeling, attack surface mapping, testing workflows, tooling, and hardening checklists. Current tab: ${['All Risks', 'Android', 'iOS'][tabValue] || 'Overview'}. ${expandedRisk ? `Currently viewing risk: ${expandedRisk.toUpperCase()}.` : ''}`;

  return (
    <LearnPageLayout pageTitle="OWASP Mobile Top 10" pageContext={pageContext}>
      <Box sx={{ minHeight: "100vh", bgcolor: "#0a0a0f" }}>
        <Container maxWidth="xl" sx={{ py: 4 }}>
          <Grid container spacing={4}>
            {/* Sidebar Navigation */}
            {!isMobile && (
              <Grid item md={2.5}>
                <Box sx={{ position: "sticky", top: 80 }}>
                  {sidebarNav}
                </Box>
              </Grid>
            )}

            {/* Main Content */}
            <Grid item xs={12} md={9.5}>
              {/* Intro Section */}
              <Paper
                id="intro"
                sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: themeColors.bgCard, border: `1px solid ${themeColors.border}` }}
              >
                <Chip
                  component={Link}
                  to="/learn"
                  icon={<ArrowBackIcon />}
                  label="Back to Learning Hub"
                  clickable
                  variant="outlined"
                  sx={{ borderRadius: 2, mb: 3, borderColor: themeColors.border, color: themeColors.textMuted }}
                />

                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <Box
                    sx={{
                      width: 72,
                      height: 72,
                      borderRadius: 3,
                      background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.secondary})`,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      boxShadow: `0 8px 32px ${alpha(themeColors.primary, 0.3)}`,
                    }}
                  >
                    <PhoneAndroidIcon sx={{ fontSize: 36, color: "white" }} />
                  </Box>
                  <Box>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                      <Typography
                        variant="h3"
                        sx={{
                          fontWeight: 800,
                          background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.secondary})`,
                          backgroundClip: "text",
                          WebkitBackgroundClip: "text",
                          WebkitTextFillColor: "transparent",
                        }}
                      >
                        OWASP Mobile Top 10
                      </Typography>
                      <Chip
                        label="2024"
                        sx={{
                          fontWeight: 700,
                          bgcolor: alpha(themeColors.primary, 0.1),
                          color: themeColors.primary,
                        }}
                      />
                    </Box>
                    <Typography variant="h6" sx={{ color: themeColors.textMuted }}>
                      Critical security risks for mobile applications
                    </Typography>
                  </Box>
                </Box>
              </Paper>

              {/* Overview Section */}
              <Paper
                id="overview"
                sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: themeColors.bgCard, border: `1px solid ${themeColors.border}` }}
              >
                {/* Platform Toggle */}
                <Paper sx={{ mb: 4, borderRadius: 3, overflow: "hidden", bgcolor: themeColors.bgNested }}>
                  <Tabs
                    value={tabValue}
                    onChange={(_, v) => setTabValue(v)}
                    centered
                    sx={{
                      "& .MuiTab-root": { minHeight: 56, fontWeight: 600, color: themeColors.textMuted },
                      "& .Mui-selected": { color: themeColors.primary },
                      "& .MuiTabs-indicator": { bgcolor: themeColors.primary },
                    }}
                  >
                    <Tab
                      label={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <PhoneAndroidIcon />
                          All Platforms
                        </Box>
                      }
                    />
                    <Tab
                      label={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <AndroidIcon sx={{ color: "#3DDC84" }} />
                          Android Focus
                        </Box>
                      }
                    />
                    <Tab
                      label={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <AppleIcon />
                          iOS Focus
                        </Box>
                      }
                    />
                  </Tabs>
                </Paper>

                {/* Stats */}
                <Grid container spacing={2} sx={{ mb: 4 }}>
                  {[
                    { value: "10", label: "Risk Categories", color: themeColors.accent },
                    { value: "4", label: "Critical Risks", color: "#dc2626" },
                    { value: "5", label: "High Impact", color: themeColors.primary },
                    { value: "50+", label: "Attack Vectors", color: themeColors.secondary },
                  ].map((stat) => (
                    <Grid item xs={6} md={3} key={stat.label}>
                      <Paper
                        sx={{
                          p: 2.5,
                          textAlign: "center",
                          borderRadius: 3,
                          bgcolor: themeColors.bgNested,
                          border: `1px solid ${alpha(stat.color, 0.2)}`,
                          background: `linear-gradient(135deg, ${alpha(stat.color, 0.05)}, transparent)`,
                        }}
                      >
                        <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                          {stat.value}
                        </Typography>
                        <Typography variant="body2" sx={{ color: themeColors.textMuted }}>
                          {stat.label}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>

                {/* Risk Overview Chart */}
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 3, color: "white" }}>
                  📊 Risk Prevalence Overview
                </Typography>
                <Grid container spacing={1}>
                  {mobileRisks.map((risk) => (
                    <Grid item xs={12} key={risk.id}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Typography
                          variant="body2"
                          sx={{ minWidth: 180, fontWeight: 500, fontSize: "0.8rem", color: themeColors.textMuted }}
                        >
                          M{risk.rank}: {risk.shortTitle}
                        </Typography>
                        <Box sx={{ flex: 1 }}>
                          <LinearProgress
                            variant="determinate"
                            value={risk.prevalence}
                            sx={{
                              height: 20,
                              borderRadius: 2,
                              bgcolor: alpha(risk.color, 0.1),
                              "& .MuiLinearProgress-bar": {
                                bgcolor: risk.color,
                                borderRadius: 2,
                              },
                            }}
                          />
                        </Box>
                        <Typography variant="body2" sx={{ minWidth: 40, fontWeight: 700, color: risk.color }}>
                          {risk.prevalence}%
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              {/* Threat Model Section */}
              <Paper
                id="threat-model"
                sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: themeColors.bgCard, border: `1px solid ${themeColors.border}` }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "white" }}>
                  🧭 Threat Model and Attack Surface
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, mb: 3 }}>
                  Mobile apps operate across multiple trust boundaries: device storage, OS services, network calls,
                  and third-party SDKs. A simple threat model helps you identify where data can leak, where attackers
                  can tamper with logic, and which controls should be enforced on the server instead of the client.
                </Typography>

                <Grid container spacing={2} sx={{ mb: 3 }}>
                  {attackSurfaceAreas.map((area) => (
                    <Grid item xs={12} md={6} key={area.area}>
                      <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: themeColors.primary, mb: 0.5 }}>
                          {area.area}
                        </Typography>
                        <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 1 }}>
                          {area.detail}
                        </Typography>
                        <Typography variant="caption" sx={{ color: themeColors.textMuted }}>
                          Examples: {area.examples.join(", ")}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>

                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "white" }}>
                  Trust Boundaries to Map
                </Typography>
                <List dense sx={{ mb: 2 }}>
                  {trustBoundaries.map((item) => (
                    <ListItem key={item} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <CheckCircleIcon sx={{ fontSize: 14, color: themeColors.primary }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={item}
                        primaryTypographyProps={{ variant: "body2", sx: { color: themeColors.textMuted } }}
                      />
                    </ListItem>
                  ))}
                </List>

                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "white" }}>
                  Common Data Storage Locations
                </Typography>
                <Grid container spacing={2}>
                  {storageLocations.map((location) => (
                    <Grid item xs={12} md={6} key={location.platform}>
                      <Paper sx={{ p: 2, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: themeColors.accent, mb: 0.5 }}>
                          {location.platform}
                        </Typography>
                        <Typography variant="caption" sx={{ color: themeColors.textMuted }}>
                          {location.areas.join(", ")}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              {/* Quick Reference Section */}
              <Paper
                id="quick-reference"
                sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: themeColors.bgCard, border: `1px solid ${themeColors.border}` }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "white" }}>
                  🔍 Quick Reference
                </Typography>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 3 }}>
                  Use this grid as a quick index. Click any risk to jump to the detailed analysis section with
                  example vulnerabilities, prevention guidance, and platform-specific tips.
                </Typography>
                <Grid container spacing={2}>
                  {mobileRisks.map((risk) => (
                    <Grid item xs={6} sm={4} md={2.4} key={risk.id}>
                      <Card
                        sx={{
                          height: "100%",
                          cursor: "pointer",
                          bgcolor: themeColors.bgNested,
                          border: `1px solid ${alpha(risk.color, 0.2)}`,
                          transition: "all 0.2s",
                          "&:hover": {
                            transform: "translateY(-4px)",
                            boxShadow: `0 8px 24px ${alpha(risk.color, 0.2)}`,
                            borderColor: risk.color,
                          },
                        }}
                        onClick={() => setExpandedRisk(risk.id)}
                      >
                        <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                          <Box
                            sx={{
                              width: 36,
                              height: 36,
                              borderRadius: 1.5,
                              bgcolor: alpha(risk.color, 0.1),
                              color: risk.color,
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              mb: 1.5,
                            }}
                          >
                            {risk.icon}
                          </Box>
                          <Chip
                            label={`M${risk.rank}`}
                            size="small"
                            sx={{
                              bgcolor: risk.color,
                              color: "white",
                              fontWeight: 700,
                              fontSize: "0.65rem",
                              height: 20,
                              mb: 0.5,
                            }}
                          />
                          <Typography variant="body2" sx={{ fontWeight: 600, fontSize: "0.75rem", color: "white" }}>
                            {risk.shortTitle}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              {/* Testing Workflow Section */}
              <Paper
                id="testing-workflow"
                sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: themeColors.bgCard, border: `1px solid ${themeColors.border}` }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "white" }}>
                  🧪 Mobile Security Testing Workflow
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, mb: 3 }}>
                  A repeatable workflow helps you cover both the client app and the backend APIs. The steps below
                  mirror how professional mobile security assessments are performed and map to OWASP MASVS and MASTG.
                </Typography>
                <Grid container spacing={2}>
                  {testingWorkflow.map((step, index) => (
                    <Grid item xs={12} md={6} key={step.step}>
                      <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: themeColors.primary, mb: 0.5 }}>
                          {index + 1}. {step.step}
                        </Typography>
                        <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 1 }}>
                          {step.detail}
                        </Typography>
                        <Typography variant="caption" sx={{ color: themeColors.textMuted }}>
                          Outputs: {step.outputs.join(", ")}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>

                <Divider sx={{ my: 3, borderColor: themeColors.border }} />

                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: "white" }}>
                  Tooling Cheat Sheet
                </Typography>
                <Grid container spacing={2}>
                  {mobileTooling.map((tool) => (
                    <Grid item xs={12} md={6} key={tool.category}>
                      <Paper sx={{ p: 2, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: themeColors.accent, mb: 0.5 }}>
                          {tool.category}
                        </Typography>
                        <Typography variant="caption" sx={{ color: themeColors.textMuted }}>
                          {tool.tools.join(", ")}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              {/* Hardening Section */}
              <Paper
                id="hardening"
                sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: themeColors.bgCard, border: `1px solid ${themeColors.border}` }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "white" }}>
                  🛡️ Secure Release and Hardening Checklist
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, mb: 3 }}>
                  These controls help reduce the most common OWASP Mobile Top 10 risks before release. Treat this
                  as a baseline: enforce server-side authorization, minimize data exposure, and lock down the app
                  so reverse engineering does not reveal secrets.
                </Typography>
                <List dense>
                  {hardeningChecklist.map((item) => (
                    <ListItem key={item} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <CheckCircleIcon sx={{ fontSize: 14, color: themeColors.primary }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={item}
                        primaryTypographyProps={{ variant: "body2", sx: { color: themeColors.textMuted } }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              {/* Detailed Analysis Section */}
              <Paper
                id="detailed-analysis"
                sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: themeColors.bgCard, border: `1px solid ${themeColors.border}` }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "white" }}>
                  📋 Detailed Analysis
                </Typography>

                {mobileRisks.map((risk) => (
                  <Accordion
                    key={risk.id}
                    expanded={expandedRisk === risk.id}
                    onChange={(_, isExpanded) => setExpandedRisk(isExpanded ? risk.id : false)}
                    sx={{
                      mb: 2,
                      bgcolor: themeColors.bgNested,
                      border: `1px solid ${alpha(risk.color, 0.2)}`,
                      borderRadius: "12px !important",
                      "&:before": { display: "none" },
                      overflow: "hidden",
                    }}
                  >
                    <AccordionSummary
                      expandIcon={<ExpandMoreIcon sx={{ color: themeColors.textMuted }} />}
                      sx={{
                        borderLeft: `4px solid ${risk.color}`,
                        "&:hover": { bgcolor: alpha(risk.color, 0.02) },
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%", flexWrap: "wrap" }}>
                        <Box
                          sx={{
                            width: 48,
                            height: 48,
                            borderRadius: 2,
                            bgcolor: alpha(risk.color, 0.1),
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            color: risk.color,
                          }}
                        >
                          {risk.icon}
                        </Box>
                        <Box sx={{ flex: 1, minWidth: 200 }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                            <Chip
                              label={`M${risk.rank}`}
                              size="small"
                              sx={{ bgcolor: risk.color, color: "white", fontWeight: 700 }}
                            />
                            <Typography variant="h6" sx={{ fontWeight: 700, color: "white" }}>
                              {risk.title}
                            </Typography>
                          </Box>
                          <Box sx={{ display: "flex", gap: 1, mt: 0.5, flexWrap: "wrap" }}>
                            <Chip
                              icon={<ErrorIcon sx={{ fontSize: 14 }} />}
                              label={`Impact: ${risk.impact}`}
                              size="small"
                              sx={{
                                bgcolor: alpha(impactColors[risk.impact], 0.1),
                                color: impactColors[risk.impact],
                                "& .MuiChip-icon": { color: impactColors[risk.impact] },
                              }}
                            />
                            <Chip
                              icon={<BugReportIcon sx={{ fontSize: 14 }} />}
                              label={`Exploit: ${risk.exploitability}`}
                              size="small"
                              sx={{
                                bgcolor: alpha(exploitabilityColors[risk.exploitability], 0.1),
                                color: exploitabilityColors[risk.exploitability],
                                "& .MuiChip-icon": { color: exploitabilityColors[risk.exploitability] },
                              }}
                            />
                          </Box>
                        </Box>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails sx={{ pt: 0 }}>
                      <Typography variant="body1" sx={{ mb: 3, color: themeColors.textMuted }}>
                        {risk.description}
                      </Typography>

                      <Grid container spacing={3}>
                        {/* Key Points */}
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: risk.color }}>
                            📋 Key Points
                          </Typography>
                          <List dense disablePadding>
                            {risk.keyPoints.map((point, i) => (
                              <ListItem key={i} disableGutters sx={{ py: 0.25 }}>
                                <ListItemIcon sx={{ minWidth: 24 }}>
                                  <CheckCircleIcon sx={{ fontSize: 14, color: risk.color }} />
                                </ListItemIcon>
                                <ListItemText
                                  primary={point}
                                  primaryTypographyProps={{ variant: "body2", sx: { color: themeColors.textMuted } }}
                                />
                              </ListItem>
                            ))}
                          </List>
                        </Grid>

                        {/* Attack Vectors */}
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#ef4444" }}>
                            ⚔️ Attack Vectors
                          </Typography>
                          <List dense disablePadding>
                            {risk.attackVectors.map((vector, i) => (
                              <ListItem key={i} disableGutters sx={{ py: 0.25 }}>
                                <ListItemIcon sx={{ minWidth: 24 }}>
                                  <WarningIcon sx={{ fontSize: 14, color: "#ef4444" }} />
                                </ListItemIcon>
                                <ListItemText
                                  primary={vector}
                                  primaryTypographyProps={{ variant: "body2", sx: { color: themeColors.textMuted } }}
                                />
                              </ListItem>
                            ))}
                          </List>
                        </Grid>

                        {/* Vulnerable Code */}
                        {risk.vulnerableCode && (tabValue === 0 || tabValue === 1) && (
                          <Grid item xs={12}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#ef4444" }}>
                              ❌ Vulnerable Code Example
                            </Typography>
                            {risk.vulnerableCode
                              .filter(vc => tabValue === 0 || vc.platform.toLowerCase().includes(tabValue === 1 ? "android" : "ios") || vc.platform === "Any" || vc.platform === "API Request")
                              .map((vc, i) => (
                              <Paper
                                key={i}
                                sx={{
                                  p: 2,
                                  mb: 2,
                                  bgcolor: alpha("#ef4444", 0.03),
                                  border: `1px solid ${alpha("#ef4444", 0.2)}`,
                                  borderRadius: 2,
                                }}
                              >
                                <Chip label={vc.platform} size="small" sx={{ mb: 1, bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
                                <Box
                                  component="pre"
                                  sx={{
                                    m: 0,
                                    p: 2,
                                    bgcolor: themeColors.bgNested,
                                    borderRadius: 1,
                                    overflow: "auto",
                                    fontSize: "0.75rem",
                                    fontFamily: "monospace",
                                    color: themeColors.textMuted,
                                  }}
                                >
                                  {vc.code}
                                </Box>
                                <Typography variant="caption" sx={{ mt: 1, display: "block", color: "#ef4444" }}>
                                  ⚠️ {vc.issue}
                                </Typography>
                              </Paper>
                            ))}
                          </Grid>
                        )}

                        {/* Secure Code */}
                        {risk.secureCode && (tabValue === 0 || tabValue === 1 || tabValue === 2) && (
                          <Grid item xs={12}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#10b981" }}>
                              ✅ Secure Code Example
                            </Typography>
                            {risk.secureCode
                              .filter(sc => tabValue === 0 || sc.platform.toLowerCase().includes(tabValue === 1 ? "android" : "ios") || sc.platform.toLowerCase().includes("server"))
                              .map((sc, i) => (
                              <Paper
                                key={i}
                                sx={{
                                  p: 2,
                                  mb: 2,
                                  bgcolor: alpha("#10b981", 0.03),
                                  border: `1px solid ${alpha("#10b981", 0.2)}`,
                                  borderRadius: 2,
                                }}
                              >
                                <Chip label={sc.platform} size="small" sx={{ mb: 1, bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
                                <Box
                                  component="pre"
                                  sx={{
                                    m: 0,
                                    p: 2,
                                    bgcolor: themeColors.bgNested,
                                    borderRadius: 1,
                                    overflow: "auto",
                                    fontSize: "0.75rem",
                                    fontFamily: "monospace",
                                    color: themeColors.textMuted,
                                  }}
                                >
                                  {sc.code}
                                </Box>
                                <Typography variant="caption" sx={{ mt: 1, display: "block", color: "#10b981" }}>
                                  ✓ {sc.fix}
                                </Typography>
                              </Paper>
                            ))}
                          </Grid>
                        )}

                        {/* Prevention */}
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#10b981" }}>
                            🛡️ Prevention
                          </Typography>
                          <Paper
                            sx={{
                              p: 2,
                              bgcolor: alpha("#10b981", 0.03),
                              border: `1px solid ${alpha("#10b981", 0.15)}`,
                              borderRadius: 2,
                            }}
                          >
                            {risk.prevention.map((item, i) => (
                              <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.5 }}>
                                <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981", mt: 0.3 }} />
                                <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{item}</Typography>
                              </Box>
                            ))}
                          </Paper>
                        </Grid>

                        {/* Testing Tips */}
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: themeColors.accent }}>
                            🔍 Testing Tips
                          </Typography>
                          <Paper
                            sx={{
                              p: 2,
                              bgcolor: alpha(themeColors.accent, 0.03),
                              border: `1px solid ${alpha(themeColors.accent, 0.15)}`,
                              borderRadius: 2,
                            }}
                          >
                            {risk.testingTips.map((tip, i) => (
                              <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.5 }}>
                                <CodeIcon sx={{ fontSize: 14, color: themeColors.accent, mt: 0.3 }} />
                                <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{tip}</Typography>
                              </Box>
                            ))}
                          </Paper>
                        </Grid>

                        {/* Platform Specific */}
                        {(tabValue === 1 && risk.androidSpecific) && (
                          <Grid item xs={12}>
                            <Alert
                              severity="info"
                              icon={<AndroidIcon sx={{ color: "#3DDC84" }} />}
                              sx={{ borderRadius: 2, bgcolor: alpha("#3DDC84", 0.05), border: `1px solid ${alpha("#3DDC84", 0.2)}` }}
                            >
                              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#3DDC84" }}>
                                Android-Specific Recommendations
                              </Typography>
                              {risk.androidSpecific.map((tip, i) => (
                                <Typography key={i} variant="body2" sx={{ color: themeColors.textMuted }}>• {tip}</Typography>
                              ))}
                            </Alert>
                          </Grid>
                        )}

                        {(tabValue === 2 && risk.iosSpecific) && (
                          <Grid item xs={12}>
                            <Alert
                              severity="info"
                              icon={<AppleIcon />}
                              sx={{ borderRadius: 2, bgcolor: alpha("#fff", 0.05), border: `1px solid ${alpha("#fff", 0.2)}` }}
                            >
                              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "white" }}>
                                iOS-Specific Recommendations
                              </Typography>
                              {risk.iosSpecific.map((tip, i) => (
                                <Typography key={i} variant="body2" sx={{ color: themeColors.textMuted }}>• {tip}</Typography>
                              ))}
                            </Alert>
                          </Grid>
                        )}

                        {/* Tools */}
                        {risk.tools && (
                          <Grid item xs={12}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "white" }}>
                              🛠️ Recommended Tools
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                              {risk.tools.map((tool) => (
                                <Chip
                                  key={tool}
                                  label={tool}
                                  size="small"
                                  sx={{ bgcolor: alpha(risk.color, 0.1), color: risk.color }}
                                />
                              ))}
                            </Box>
                          </Grid>
                        )}

                        {/* Real World Examples */}
                        {risk.realWorldExamples && (
                          <Grid item xs={12}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: themeColors.primary }}>
                              🌍 Real-World Examples
                            </Typography>
                            <Paper
                              sx={{
                                p: 2,
                                bgcolor: alpha(themeColors.primary, 0.03),
                                border: `1px solid ${alpha(themeColors.primary, 0.15)}`,
                                borderRadius: 2,
                              }}
                            >
                              {risk.realWorldExamples.map((example, i) => (
                                <Typography key={i} variant="body2" sx={{ mb: 0.5, color: themeColors.textMuted }}>
                                  • {example}
                                </Typography>
                              ))}
                            </Paper>
                          </Grid>
                        )}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                ))}
              </Paper>

              {/* Resources Section */}
              <Paper
                id="resources"
                sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: themeColors.bgCard, border: `1px solid ${themeColors.border}` }}
              >
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "white" }}>
                  📚 Essential Resources
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { name: "OWASP Mobile Security Project", url: "https://owasp.org/www-project-mobile-security/", desc: "Official OWASP mobile security resources" },
                    { name: "OWASP MASTG", url: "https://mas.owasp.org/MASTG/", desc: "Mobile Application Security Testing Guide" },
                    { name: "OWASP MASVS", url: "https://mas.owasp.org/MASVS/", desc: "Mobile Application Security Verification Standard" },
                    { name: "MobSF", url: "https://github.com/MobSF/Mobile-Security-Framework-MobSF", desc: "Automated mobile security testing framework" },
                    { name: "Frida", url: "https://frida.re/", desc: "Dynamic instrumentation toolkit for mobile apps" },
                    { name: "Android Security Docs", url: "https://developer.android.com/security", desc: "Official Android security best practices" },
                  ].map((resource) => (
                    <Grid item xs={12} sm={6} key={resource.name}>
                      <Paper
                        sx={{
                          p: 2,
                          borderRadius: 2,
                          bgcolor: themeColors.bgNested,
                          border: `1px solid ${themeColors.border}`,
                          cursor: "pointer",
                          transition: "all 0.2s",
                          "&:hover": {
                            borderColor: themeColors.primary,
                            transform: "translateY(-2px)",
                          },
                        }}
                        onClick={() => window.open(resource.url, "_blank")}
                      >
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: themeColors.primary }}>
                          {resource.name} ↗
                        </Typography>
                        <Typography variant="body2" sx={{ color: themeColors.textMuted }}>
                          {resource.desc}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              {/* Quiz Section */}
              <QuizSection />
            </Grid>
          </Grid>
        </Container>

        {/* Mobile Navigation Drawer */}
        <Drawer
          anchor="left"
          open={mobileNavOpen}
          onClose={() => setMobileNavOpen(false)}
          sx={{
            "& .MuiDrawer-paper": {
              bgcolor: themeColors.bgCard,
              borderRight: `1px solid ${themeColors.border}`,
              width: 280,
            },
          }}
        >
          {sidebarNav}
        </Drawer>

        {/* Floating Action Buttons */}
        {isMobile && (
          <Fab
            size="medium"
            onClick={() => setMobileNavOpen(true)}
            sx={{
              position: "fixed",
              bottom: 80,
              right: 16,
              bgcolor: themeColors.primary,
              color: "white",
              "&:hover": { bgcolor: themeColors.primaryLight },
            }}
          >
            <MenuIcon />
          </Fab>
        )}
        <Fab
          size="medium"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          sx={{
            position: "fixed",
            bottom: 16,
            right: 16,
            bgcolor: themeColors.bgCard,
            color: themeColors.primary,
            border: `1px solid ${themeColors.border}`,
            "&:hover": { bgcolor: alpha(themeColors.primary, 0.1) },
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      </Box>
    </LearnPageLayout>
  );
}
