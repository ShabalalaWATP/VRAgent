import React, { useState } from "react";
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
  IconButton,
  LinearProgress,
  Card,
  CardContent,
  Alert,
  Tabs,
  Tab,
  Tooltip,
} from "@mui/material";
import { useNavigate } from "react-router-dom";
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
  const navigate = useNavigate();
  const [expandedRisk, setExpandedRisk] = useState<string | false>("m1");
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `This page covers the OWASP Mobile Top 10 security risks for mobile applications. Topics include: improper credential usage, inadequate supply chain security, insecure authentication/authorization, insufficient input/output validation, insecure communication, inadequate privacy controls, insufficient binary protections, security misconfiguration, insecure data storage, and insufficient cryptography. Current tab: ${['All Risks', 'Android', 'iOS'][tabValue] || 'Overview'}. ${expandedRisk ? `Currently viewing risk: ${expandedRisk.toUpperCase()}.` : ''}`;

  return (
    <LearnPageLayout pageTitle="OWASP Mobile Top 10" pageContext={pageContext}>
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
              background: `linear-gradient(135deg, #3b82f6, #8b5cf6)`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: `0 8px 32px ${alpha("#3b82f6", 0.3)}`,
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
                  background: `linear-gradient(135deg, #3b82f6, #8b5cf6)`,
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
                  bgcolor: alpha("#3b82f6", 0.1),
                  color: "#3b82f6",
                }}
              />
            </Box>
            <Typography variant="h6" color="text.secondary">
              Critical security risks for mobile applications
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* Platform Toggle */}
      <Paper sx={{ mb: 4, borderRadius: 3, overflow: "hidden" }}>
        <Tabs
          value={tabValue}
          onChange={(_, v) => setTabValue(v)}
          centered
          sx={{
            bgcolor: alpha(theme.palette.background.paper, 0.5),
            "& .MuiTab-root": { minHeight: 56, fontWeight: 600 },
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
          { value: "10", label: "Risk Categories", color: "#3b82f6" },
          { value: "4", label: "Critical Risks", color: "#dc2626" },
          { value: "5", label: "High Impact", color: "#f59e0b" },
          { value: "50+", label: "Attack Vectors", color: "#8b5cf6" },
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

      {/* Risk Overview Chart */}
      <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
          📊 Risk Prevalence Overview
        </Typography>
        <Grid container spacing={1}>
          {mobileRisks.map((risk) => (
            <Grid item xs={12} key={risk.id}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <Typography
                  variant="body2"
                  sx={{ minWidth: 180, fontWeight: 500, fontSize: "0.8rem" }}
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

      {/* Quick Reference Cards */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
        🔍 Quick Reference
      </Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {mobileRisks.map((risk) => (
          <Grid item xs={6} sm={4} md={2.4} key={risk.id}>
            <Card
              sx={{
                height: "100%",
                cursor: "pointer",
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
                <Typography variant="body2" sx={{ fontWeight: 600, fontSize: "0.75rem" }}>
                  {risk.shortTitle}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Detailed Accordions */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
        📋 Detailed Analysis
      </Typography>

      {mobileRisks.map((risk) => (
        <Accordion
          key={risk.id}
          expanded={expandedRisk === risk.id}
          onChange={(_, isExpanded) => setExpandedRisk(isExpanded ? risk.id : false)}
          sx={{
            mb: 2,
            border: `1px solid ${alpha(risk.color, 0.2)}`,
            borderRadius: "12px !important",
            "&:before": { display: "none" },
            overflow: "hidden",
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
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
                  <Typography variant="h6" sx={{ fontWeight: 700 }}>
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
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
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
                        primaryTypographyProps={{ variant: "body2" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Grid>

              {/* Attack Vectors */}
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "error.main" }}>
                  ⚔️ Attack Vectors
                </Typography>
                <List dense disablePadding>
                  {risk.attackVectors.map((vector, i) => (
                    <ListItem key={i} disableGutters sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <WarningIcon sx={{ fontSize: 14, color: "error.main" }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={vector}
                        primaryTypographyProps={{ variant: "body2" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Grid>

              {/* Vulnerable Code */}
              {risk.vulnerableCode && (tabValue === 0 || tabValue === 1) && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "error.main" }}>
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
                        bgcolor: alpha(theme.palette.error.main, 0.03),
                        border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`,
                        borderRadius: 2,
                      }}
                    >
                      <Chip label={vc.platform} size="small" sx={{ mb: 1, bgcolor: alpha(theme.palette.error.main, 0.1) }} />
                      <Box
                        component="pre"
                        sx={{
                          m: 0,
                          p: 2,
                          bgcolor: alpha(theme.palette.background.default, 0.5),
                          borderRadius: 1,
                          overflow: "auto",
                          fontSize: "0.75rem",
                          fontFamily: "monospace",
                        }}
                      >
                        {vc.code}
                      </Box>
                      <Typography variant="caption" color="error.main" sx={{ mt: 1, display: "block" }}>
                        ⚠️ {vc.issue}
                      </Typography>
                    </Paper>
                  ))}
                </Grid>
              )}

              {/* Secure Code */}
              {risk.secureCode && (tabValue === 0 || tabValue === 1 || tabValue === 2) && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "success.main" }}>
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
                        bgcolor: alpha(theme.palette.success.main, 0.03),
                        border: `1px solid ${alpha(theme.palette.success.main, 0.2)}`,
                        borderRadius: 2,
                      }}
                    >
                      <Chip label={sc.platform} size="small" sx={{ mb: 1, bgcolor: alpha(theme.palette.success.main, 0.1) }} />
                      <Box
                        component="pre"
                        sx={{
                          m: 0,
                          p: 2,
                          bgcolor: alpha(theme.palette.background.default, 0.5),
                          borderRadius: 1,
                          overflow: "auto",
                          fontSize: "0.75rem",
                          fontFamily: "monospace",
                        }}
                      >
                        {sc.code}
                      </Box>
                      <Typography variant="caption" color="success.main" sx={{ mt: 1, display: "block" }}>
                        ✓ {sc.fix}
                      </Typography>
                    </Paper>
                  ))}
                </Grid>
              )}

              {/* Prevention */}
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "success.main" }}>
                  🛡️ Prevention
                </Typography>
                <Paper
                  sx={{
                    p: 2,
                    bgcolor: alpha(theme.palette.success.main, 0.03),
                    border: `1px solid ${alpha(theme.palette.success.main, 0.15)}`,
                    borderRadius: 2,
                  }}
                >
                  {risk.prevention.map((item, i) => (
                    <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.5 }}>
                      <CheckCircleIcon sx={{ fontSize: 14, color: "success.main", mt: 0.3 }} />
                      <Typography variant="body2">{item}</Typography>
                    </Box>
                  ))}
                </Paper>
              </Grid>

              {/* Testing Tips */}
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "info.main" }}>
                  🔍 Testing Tips
                </Typography>
                <Paper
                  sx={{
                    p: 2,
                    bgcolor: alpha(theme.palette.info.main, 0.03),
                    border: `1px solid ${alpha(theme.palette.info.main, 0.15)}`,
                    borderRadius: 2,
                  }}
                >
                  {risk.testingTips.map((tip, i) => (
                    <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 0.5 }}>
                      <CodeIcon sx={{ fontSize: 14, color: "info.main", mt: 0.3 }} />
                      <Typography variant="body2">{tip}</Typography>
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
                    sx={{ borderRadius: 2 }}
                  >
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                      Android-Specific Recommendations
                    </Typography>
                    {risk.androidSpecific.map((tip, i) => (
                      <Typography key={i} variant="body2">• {tip}</Typography>
                    ))}
                  </Alert>
                </Grid>
              )}

              {(tabValue === 2 && risk.iosSpecific) && (
                <Grid item xs={12}>
                  <Alert
                    severity="info"
                    icon={<AppleIcon />}
                    sx={{ borderRadius: 2 }}
                  >
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                      iOS-Specific Recommendations
                    </Typography>
                    {risk.iosSpecific.map((tip, i) => (
                      <Typography key={i} variant="body2">• {tip}</Typography>
                    ))}
                  </Alert>
                </Grid>
              )}

              {/* Tools */}
              {risk.tools && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
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
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                    🌍 Real-World Examples
                  </Typography>
                  <Paper
                    sx={{
                      p: 2,
                      bgcolor: alpha(theme.palette.warning.main, 0.03),
                      border: `1px solid ${alpha(theme.palette.warning.main, 0.15)}`,
                      borderRadius: 2,
                    }}
                  >
                    {risk.realWorldExamples.map((example, i) => (
                      <Typography key={i} variant="body2" sx={{ mb: 0.5 }}>
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

      {/* Resources */}
      <Paper sx={{ mt: 4, p: 4, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.02) }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
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
    </LearnPageLayout>
  );
}
