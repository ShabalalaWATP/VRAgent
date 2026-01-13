import React, { useEffect, useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import { Link } from "react-router-dom";
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
  Alert,
  AlertTitle,
  alpha,
  useTheme,
  useMediaQuery,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  IconButton,
  Tooltip,
  Drawer,
  Fab,
  LinearProgress,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import PhoneIphoneIcon from "@mui/icons-material/PhoneIphone";
import MemoryIcon from "@mui/icons-material/Memory";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import SecurityIcon from "@mui/icons-material/Security";
import TerminalIcon from "@mui/icons-material/Terminal";
import BugReportIcon from "@mui/icons-material/BugReport";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SearchIcon from "@mui/icons-material/Search";
import SchoolIcon from "@mui/icons-material/School";
import LayersIcon from "@mui/icons-material/Layers";
import StorageIcon from "@mui/icons-material/Storage";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import WarningIcon from "@mui/icons-material/Warning";
import HttpsIcon from "@mui/icons-material/Https";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import GavelIcon from "@mui/icons-material/Gavel";
import { useNavigate } from "react-router-dom";

// ==================== CODE BLOCK COMPONENT ====================
const CodeBlock: React.FC<{ code: string; language?: string; title?: string }> = ({ code, language = "bash", title }) => {
  const [copied, setCopied] = React.useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <Paper sx={{ my: 2, borderRadius: 2, overflow: "hidden", border: "1px solid rgba(59, 130, 246, 0.3)" }}>
      {title && (
        <Box sx={{ px: 2, py: 1, bgcolor: "rgba(59, 130, 246, 0.1)", borderBottom: "1px solid rgba(59, 130, 246, 0.2)" }}>
          <Typography variant="caption" sx={{ fontWeight: 600, color: "#3b82f6" }}>{title}</Typography>
        </Box>
      )}
      <Box sx={{ position: "relative", bgcolor: "#0d1117" }}>
        <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
          <Chip label={language} size="small" sx={{ bgcolor: "#3b82f6", color: "white", fontSize: "0.7rem" }} />
          <Tooltip title={copied ? "Copied!" : "Copy"}>
            <IconButton size="small" onClick={handleCopy} sx={{ color: "#e2e8f0" }}>
              <ContentCopyIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
        <Box component="pre" sx={{ m: 0, p: 2, pt: 4, overflow: "auto", fontFamily: "monospace", fontSize: "0.85rem", color: "#e2e8f0", lineHeight: 1.6 }}>
          {code}
        </Box>
      </Box>
    </Paper>
  );
};

const outlineSections = [
  {
    id: "ios-architecture",
    title: "1. iOS Architecture and Security Model",
    icon: <SecurityIcon />,
    color: "#3b82f6",
    description: "Darwin, kernel layers, sandboxing, and how apps are isolated from each other.",
  },
  {
    id: "app-packaging",
    title: "2. App Packaging and IPA Structure",
    icon: <LayersIcon />,
    color: "#60a5fa",
    description: "IPA files, app bundles, Info.plist, frameworks, and compiled assets.",
  },
  {
    id: "macho-format",
    title: "3. Mach-O Format and Universal Binaries",
    icon: <MemoryIcon />,
    color: "#22c55e",
    description: "Mach-O headers, load commands, segments, and fat binaries.",
  },
  {
    id: "code-signing",
    title: "4. Code Signing and Entitlements",
    icon: <BuildIcon />,
    color: "#f97316",
    description: "Why signatures matter, provisioning profiles, and entitlements that enable features.",
  },
  {
    id: "objc-swift",
    title: "5. Objective-C Runtime and Swift Metadata",
    icon: <CodeIcon />,
    color: "#a855f7",
    description: "Selectors, classes, Swift name mangling, and runtime introspection.",
  },
  {
    id: "static-analysis",
    title: "6. Static Analysis Workflow",
    icon: <SearchIcon />,
    color: "#14b8a6",
    description: "Strings, otool, class-dump, disassemblers, and first-pass mapping.",
  },
  {
    id: "dynamic-analysis",
    title: "7. Dynamic Analysis Workflow",
    icon: <TerminalIcon />,
    color: "#0ea5e9",
    description: "LLDB, Frida, runtime hooks, and behavior validation.",
  },
  {
    id: "device-setup",
    title: "8. Device Setup and Jailbreak Basics",
    icon: <PhoneIphoneIcon />,
    color: "#ef4444",
    description: "Test devices, backups, SSH access, and safe lab setup.",
  },
  {
    id: "data-storage",
    title: "9. Data Storage and Secrets",
    icon: <StorageIcon />,
    color: "#10b981",
    description: "Keychain, plist files, SQLite, caches, and common mistakes.",
  },
  {
    id: "network-security",
    title: "10. Network Behavior and ATS",
    icon: <BugReportIcon />,
    color: "#f59e0b",
    description: "TLS requirements, proxying traffic, and SSL pinning basics.",
  },
  {
    id: "bypass-techniques",
    title: "11. Bypass and Validation Techniques",
    icon: <BuildIcon />,
    color: "#ec4899",
    description: "Bypassing jailbreak detection, pinning, and root checks safely.",
  },
  {
    id: "reporting-ethics",
    title: "12. Reporting and Ethics",
    icon: <SchoolIcon />,
    color: "#8b5cf6",
    description: "Documenting findings, reproducibility, and responsible disclosure.",
  },
];

const quickStats = [
  { value: "12", label: "Core Sections", color: "#3b82f6" },
  { value: "Mach-O", label: "Binary Format", color: "#22c55e" },
  { value: "LLDB", label: "Primary Debugger", color: "#f97316" },
  { value: "Frida", label: "Runtime Hooks", color: "#0ea5e9" },
];

const toolHighlights = [
  "Hopper, Ghidra, or IDA for disassembly and decompilation.",
  "otool, lipo, and strings for fast static inspection.",
  "class-dump or class-dump-swift for Objective-C metadata.",
  "LLDB and debugserver for stepping through code.",
  "Frida and Objection for dynamic instrumentation and bypasses.",
  "mitmproxy or Burp Suite for network analysis.",
];

const gettingStartedChecklist = [
  "Use a spare iOS device or simulator for safe testing.",
  "Back up the device before installing any tooling.",
  "Extract the IPA and inspect Info.plist first.",
  "Identify the main binary and confirm architecture.",
  "Search strings for URLs, keys, and feature flags.",
  "Map key classes and functions before diving deep.",
];

const commonPitfalls = [
  "Assuming the decompiler output is always correct.",
  "Skipping entitlements and code signing checks.",
  "Forgetting to verify runtime behavior after static findings.",
  "Overlooking Swift name mangling and metadata.",
];

// ==================== DETAILED SECTION CONTENT ====================
const iosArchitectureLayers = [
  { layer: "Hardware", description: "Apple Silicon (A-series/M-series), Secure Enclave, coprocessors", color: "#ef4444" },
  { layer: "Firmware/Bootloader", description: "SecureROM, iBoot, boot chain verification", color: "#f97316" },
  { layer: "Darwin/XNU Kernel", description: "Mach microkernel + BSD layer + IOKit drivers", color: "#f59e0b" },
  { layer: "Core Services", description: "Foundation, CoreFoundation, Security framework", color: "#22c55e" },
  { layer: "Cocoa Touch", description: "UIKit, SwiftUI, app frameworks", color: "#3b82f6" },
  { layer: "Applications", description: "System apps and third-party apps in sandboxes", color: "#8b5cf6" },
];

const sandboxRestrictions = [
  { restriction: "File System", effect: "Apps can only access their own container directories", bypass: "Jailbreak or container escape" },
  { restriction: "Inter-Process Comm", effect: "Limited IPC via XPC, URL schemes, app groups", bypass: "Analyze allowed channels" },
  { restriction: "Network", effect: "ATS enforces HTTPS, no raw sockets without entitlement", bypass: "Proxy with trusted cert" },
  { restriction: "Hardware Access", effect: "Camera, mic, location require permission prompts", bypass: "Permission prompt analysis" },
  { restriction: "Code Execution", effect: "No JIT compilation without entitlement, no dlopen of arbitrary code", bypass: "Frida injection on jailbreak" },
];

const ipaStructure = [
  { path: "Payload/", description: "Contains the .app bundle", type: "Directory" },
  { path: "Payload/App.app/", description: "Main application bundle", type: "Directory" },
  { path: "Payload/App.app/Info.plist", description: "App metadata, permissions, URL schemes", type: "Plist" },
  { path: "Payload/App.app/AppName", description: "Main Mach-O executable binary", type: "Binary" },
  { path: "Payload/App.app/_CodeSignature/", description: "Code signature and manifest", type: "Directory" },
  { path: "Payload/App.app/embedded.mobileprovision", description: "Provisioning profile", type: "Profile" },
  { path: "Payload/App.app/Frameworks/", description: "Embedded frameworks and dylibs", type: "Directory" },
  { path: "Payload/App.app/Assets.car", description: "Compiled asset catalog (images)", type: "Archive" },
  { path: "Payload/App.app/*.storyboardc", description: "Compiled storyboards", type: "NIB" },
  { path: "Payload/App.app/*.lproj/", description: "Localization bundles", type: "Directory" },
];

const infoPlistKeys = [
  { key: "CFBundleIdentifier", purpose: "Unique app identifier (com.company.app)", importance: "Critical" },
  { key: "CFBundleExecutable", purpose: "Name of main binary", importance: "Critical" },
  { key: "CFBundleURLTypes", purpose: "Custom URL schemes the app handles", importance: "High" },
  { key: "NSAppTransportSecurity", purpose: "ATS exceptions and network config", importance: "High" },
  { key: "UIBackgroundModes", purpose: "Background execution capabilities", importance: "Medium" },
  { key: "LSApplicationQueriesSchemes", purpose: "URL schemes the app can open", importance: "Medium" },
  { key: "NSCameraUsageDescription", purpose: "Camera permission prompt text", importance: "Low" },
  { key: "UIRequiredDeviceCapabilities", purpose: "Required hardware features", importance: "Low" },
];

const machoSegments = [
  { segment: "__PAGEZERO", description: "Unmapped zero page to catch null derefs", permissions: "---" },
  { segment: "__TEXT", description: "Executable code and read-only data", permissions: "r-x" },
  { segment: "__DATA", description: "Writable initialized data", permissions: "rw-" },
  { segment: "__DATA_CONST", description: "Writable data marked const after load", permissions: "rw-" },
  { segment: "__OBJC", description: "Objective-C runtime metadata (legacy)", permissions: "rw-" },
  { segment: "__LINKEDIT", description: "Symbol tables, string tables, code signature", permissions: "r--" },
];

const machoLoadCommands = [
  { command: "LC_SEGMENT_64", purpose: "Defines a 64-bit segment and its sections" },
  { command: "LC_DYLD_INFO_ONLY", purpose: "Compressed dyld info (binds, rebases)" },
  { command: "LC_SYMTAB", purpose: "Symbol table location" },
  { command: "LC_DYSYMTAB", purpose: "Dynamic symbol table info" },
  { command: "LC_LOAD_DYLIB", purpose: "Specifies a linked dynamic library" },
  { command: "LC_ID_DYLIB", purpose: "Identifies this as a dylib" },
  { command: "LC_UUID", purpose: "Unique identifier for the binary" },
  { command: "LC_CODE_SIGNATURE", purpose: "Location of code signature" },
  { command: "LC_ENCRYPTION_INFO_64", purpose: "FairPlay encryption info" },
  { command: "LC_MAIN", purpose: "Entry point for main executables" },
];

const objcRuntimeConcepts = [
  { concept: "Classes", description: "Objective-C classes stored in __objc_classlist", tool: "class-dump" },
  { concept: "Selectors", description: "Method names stored in __objc_methname", tool: "strings, nm" },
  { concept: "Categories", description: "Extensions to existing classes", tool: "class-dump" },
  { concept: "Protocols", description: "Interfaces that classes conform to", tool: "class-dump" },
  { concept: "objc_msgSend", description: "Central message dispatch function", tool: "Frida hook" },
  { concept: "Method Swizzling", description: "Runtime method implementation exchange", tool: "Frida, Cycript" },
];

const staticAnalysisTools = [
  { tool: "file", purpose: "Identify file type and architecture", command: "file AppBinary" },
  { tool: "otool -L", purpose: "List linked libraries", command: "otool -L AppBinary" },
  { tool: "otool -l", purpose: "Show load commands", command: "otool -l AppBinary" },
  { tool: "strings", purpose: "Extract readable strings", command: "strings AppBinary | grep -i api" },
  { tool: "nm", purpose: "List symbols", command: "nm -m AppBinary" },
  { tool: "lipo", purpose: "Extract/list architectures", command: "lipo -info AppBinary" },
  { tool: "class-dump", purpose: "Extract Obj-C headers", command: "class-dump -H -o headers/ AppBinary" },
  { tool: "plutil", purpose: "Convert/read plist files", command: "plutil -p Info.plist" },
  { tool: "codesign", purpose: "Verify/show signatures", command: "codesign -dvv AppBinary" },
  { tool: "jtool2", purpose: "Advanced Mach-O analysis", command: "jtool2 --sig AppBinary" },
];

const dynamicAnalysisTools = [
  { tool: "LLDB", purpose: "Apple's debugger", use: "Breakpoints, stepping, memory inspection" },
  { tool: "Frida", purpose: "Dynamic instrumentation", use: "Hook functions, trace calls, bypass checks" },
  { tool: "Objection", purpose: "Frida wrapper", use: "Automated tasks, SSL bypass, jailbreak bypass" },
  { tool: "Cycript", purpose: "Runtime scripting", use: "Explore Obj-C objects interactively" },
  { tool: "debugserver", purpose: "Remote debug daemon", use: "Allow LLDB to attach on device" },
  { tool: "dtrace", purpose: "System tracing", use: "Trace syscalls and function calls" },
];

const jailbreakTools = [
  { tool: "checkra1n", type: "Semi-tethered", devices: "A5-A11 (iPhone 5s - iPhone X)", notes: "Hardware exploit, survives updates" },
  { tool: "unc0ver", type: "Semi-untethered", devices: "iOS 11-14.8", notes: "Software exploit, needs re-jailbreak on reboot" },
  { tool: "palera1n", type: "Semi-tethered", devices: "A8-A11 on iOS 15-17", notes: "Based on checkm8, rootless option" },
  { tool: "Dopamine", type: "Semi-untethered", devices: "iOS 15+", notes: "Rootless jailbreak, app-based" },
  { tool: "Taurine", type: "Semi-untethered", devices: "iOS 14-14.3", notes: "Rootless option available" },
];

const dataStorageLocations = [
  { location: "Keychain", path: "Secure enclave / keychain-2.db", security: "Encrypted, access-controlled", check: "keychain-dumper, Objection" },
  { location: "NSUserDefaults", path: "Library/Preferences/*.plist", security: "Unencrypted plist", check: "plutil, Objection" },
  { location: "SQLite DBs", path: "Documents/, Library/", security: "Usually unencrypted", check: "sqlite3, DB Browser" },
  { location: "Core Data", path: "Library/Application Support/", security: "SQLite-based", check: "sqlite3" },
  { location: "Cache", path: "Library/Caches/", security: "Unencrypted", check: "File browser" },
  { location: "Cookies", path: "Library/Cookies/", security: "Binarycookies format", check: "BinaryCookieReader" },
  { location: "Snapshots", path: "Library/SplashBoard/", security: "UI screenshots", check: "File browser" },
];

const sslPinningTypes = [
  { type: "Certificate Pinning", description: "Pin to specific certificate", bypass: "Replace cert in bundle or hook validation" },
  { type: "Public Key Pinning", description: "Pin to public key (survives cert rotation)", bypass: "Hook key comparison" },
  { type: "HPKP Headers", description: "HTTP header-based pinning", bypass: "Less common on mobile" },
  { type: "TrustKit", description: "iOS pinning framework", bypass: "Hook TrustKit validation methods" },
  { type: "AFNetworking", description: "Popular networking lib with pinning", bypass: "Hook AFSecurityPolicy" },
  { type: "Alamofire", description: "Swift networking with pinning", bypass: "Hook ServerTrustManager" },
];

const jailbreakDetectionMethods = [
  { method: "File checks", description: "Check for /Applications/Cydia.app, /bin/bash, etc.", bypass: "Hook file APIs" },
  { method: "URL scheme", description: "canOpenURL for cydia://", bypass: "Hook canOpenURL" },
  { method: "Sandbox escape", description: "Try writing outside sandbox", bypass: "Hook file write APIs" },
  { method: "Fork check", description: "fork() succeeds on jailbreak", bypass: "Hook fork()" },
  { method: "Dylib injection", description: "Check DYLD_INSERT_LIBRARIES", bypass: "Hook getenv" },
  { method: "Symbol resolution", description: "dlsym for jailbreak functions", bypass: "Hook dlsym" },
  { method: "Integrity checks", description: "Verify code signature at runtime", bypass: "Hook signature validation" },
];

const fridaScripts = {
  sslBypass: `// SSL Pinning Bypass (iOS)
// Bypass common certificate validation

if (ObjC.available) {
    // Bypass NSURLSession delegate
    var resolver = new ApiResolver('objc');
    resolver.enumerateMatches('-[* URLSession:didReceiveChallenge:completionHandler:]', {
        onMatch: function(match) {
            Interceptor.attach(match.address, {
                onEnter: function(args) {
                    var dominated = new ObjC.Object(args[4]);
                    var handler = new ObjC.Block(args[5]);
                    handler.implementation(0, dominated); // Trust the certificate
                },
                onLeave: function(retval) {}
            });
        },
        onComplete: function() {}
    });
    
    // Bypass AFNetworking (if present)
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        Interceptor.attach(AFSecurityPolicy['- evaluateServerTrust:forDomain:'].implementation, {
            onLeave: function(retval) {
                retval.replace(1); // Always return YES
            }
        });
        console.log("[*] AFNetworking bypass installed");
    } catch(e) {}
    
    console.log("[*] SSL pinning bypass active");
}`,

  jailbreakBypass: `// Jailbreak Detection Bypass
// Hook common detection methods

if (ObjC.available) {
    // Hook NSFileManager fileExistsAtPath
    var NSFileManager = ObjC.classes.NSFileManager;
    var fileExistsAtPath = NSFileManager['- fileExistsAtPath:'];
    
    var jbPaths = [
        '/Applications/Cydia.app',
        '/Library/MobileSubstrate',
        '/bin/bash',
        '/usr/sbin/sshd',
        '/etc/apt',
        '/private/var/lib/apt',
        '/usr/bin/ssh'
    ];
    
    Interceptor.attach(fileExistsAtPath.implementation, {
        onEnter: function(args) {
            this.path = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            for (var i = 0; i < jbPaths.length; i++) {
                if (this.path.indexOf(jbPaths[i]) !== -1) {
                    retval.replace(0); // Return NO
                    console.log('[*] Blocked jailbreak check: ' + this.path);
                }
            }
        }
    });
    
    // Hook canOpenURL for cydia://
    var UIApplication = ObjC.classes.UIApplication;
    Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
        onEnter: function(args) {
            this.url = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            if (this.url.indexOf('cydia') !== -1) {
                retval.replace(0);
                console.log('[*] Blocked canOpenURL: ' + this.url);
            }
        }
    });
    
    console.log('[*] Jailbreak detection bypass active');
}`,

  methodTrace: `// Trace Objective-C Method Calls
// Use: frida -U -l trace.js -f com.app.bundle

var className = "TargetClass";  // Change this
var methods = ObjC.classes[className].$ownMethods;

methods.forEach(function(method) {
    var impl = ObjC.classes[className][method].implementation;
    
    Interceptor.attach(impl, {
        onEnter: function(args) {
            console.log("\\n[ENTER] " + className + " " + method);
            
            // Log first 5 arguments
            for (var i = 2; i < Math.min(args.length, 7); i++) {
                try {
                    var arg = new ObjC.Object(args[i]);
                    console.log("  arg[" + (i-2) + "]: " + arg.toString().substring(0, 100));
                } catch(e) {
                    console.log("  arg[" + (i-2) + "]: " + args[i]);
                }
            }
        },
        onLeave: function(retval) {
            try {
                var ret = new ObjC.Object(retval);
                console.log("[LEAVE] Return: " + ret.toString().substring(0, 100));
            } catch(e) {
                console.log("[LEAVE] Return: " + retval);
            }
        }
    });
});

console.log("[*] Tracing " + methods.length + " methods on " + className);`,

  keychainDump: `// Keychain Dumper
// Extract keychain items accessible to the app

if (ObjC.available) {
    var SecItemCopyMatching = new NativeFunction(
        Module.findExportByName('Security', 'SecItemCopyMatching'),
        'int', ['pointer', 'pointer']
    );
    
    function dumpKeychain() {
        var query = ObjC.classes.NSMutableDictionary.alloc().init();
        query.setObject_forKey_(ObjC.classes.kSecClassGenericPassword, 'kSecClass');
        query.setObject_forKey_(ObjC.classes.kSecMatchLimitAll, 'kSecMatchLimit');
        query.setObject_forKey_(true, 'kSecReturnAttributes');
        query.setObject_forKey_(true, 'kSecReturnData');
        
        var resultPtr = Memory.alloc(Process.pointerSize);
        var status = SecItemCopyMatching(query.handle, resultPtr);
        
        if (status === 0) {
            var results = new ObjC.Object(resultPtr.readPointer());
            console.log("\\n=== Keychain Items ===");
            for (var i = 0; i < results.count(); i++) {
                var item = results.objectAtIndex_(i);
                console.log("\\nItem " + i + ":");
                console.log("  Account: " + item.objectForKey_('acct'));
                console.log("  Service: " + item.objectForKey_('svce'));
                var data = item.objectForKey_('v_Data');
                if (data) {
                    console.log("  Data: " + ObjC.classes.NSString.alloc()
                        .initWithData_encoding_(data, 4).toString());
                }
            }
        }
    }
    
    dumpKeychain();
}`
};

const lldbCommands = [
  { command: "process attach --name AppName", purpose: "Attach to running process" },
  { command: "breakpoint set --name objc_msgSend", purpose: "Break on Obj-C message sends" },
  { command: "breakpoint set -r ClassName", purpose: "Break on all methods of a class" },
  { command: "register read", purpose: "Show CPU registers" },
  { command: "memory read 0xaddress", purpose: "Read memory at address" },
  { command: "expression (void)NSLog(@\"test\")", purpose: "Execute Obj-C expression" },
  { command: "image list", purpose: "List loaded modules" },
  { command: "thread backtrace", purpose: "Show call stack" },
  { command: "disassemble --frame", purpose: "Disassemble current function" },
  { command: "watchpoint set variable varName", purpose: "Break on variable change" },
];

interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

const questionBank: QuizQuestion[] = [
  // iOS Basics (1-10)
  {
    id: 1,
    question: "What is iOS?",
    options: ["A Windows driver", "Apple's mobile operating system", "A browser plugin", "A file system"],
    correctAnswer: 1,
    explanation: "iOS is the operating system that powers iPhones and iPads.",
    topic: "iOS Basics",
  },
  {
    id: 2,
    question: "What is Darwin in the context of iOS?",
    options: ["A programming language", "The Unix-based core of iOS", "A UI framework", "An encryption library"],
    correctAnswer: 1,
    explanation: "Darwin is the Unix-based core that provides the kernel and low-level services.",
    topic: "iOS Basics",
  },
  {
    id: 3,
    question: "What does the iOS sandbox do?",
    options: ["Encrypts the screen", "Isolates apps from each other and the system", "Compiles Swift code", "Creates backups"],
    correctAnswer: 1,
    explanation: "The sandbox limits what each app can access on the device.",
    topic: "iOS Basics",
  },
  {
    id: 4,
    question: "What is an IPA file?",
    options: ["A firmware image", "An iOS app package", "A log file", "A kernel extension"],
    correctAnswer: 1,
    explanation: "IPA is the packaged format used to distribute iOS applications.",
    topic: "iOS Basics",
  },
  {
    id: 5,
    question: "What does a bundle identifier represent?",
    options: ["The device serial number", "A unique app identifier", "A debug symbol", "A network port"],
    correctAnswer: 1,
    explanation: "The bundle identifier uniquely identifies an app in the Apple ecosystem.",
    topic: "iOS Basics",
  },
  {
    id: 6,
    question: "What is an entitlement in iOS?",
    options: ["A binary patch", "A permission embedded in the code signature", "A malware signature", "A log entry"],
    correctAnswer: 1,
    explanation: "Entitlements are permissions granted via the code signature.",
    topic: "iOS Basics",
  },
  {
    id: 7,
    question: "What is the iOS Keychain used for?",
    options: ["Graphics rendering", "Secure storage of credentials and secrets", "Packaging apps", "Network routing"],
    correctAnswer: 1,
    explanation: "Keychain securely stores passwords, tokens, and certificates.",
    topic: "iOS Basics",
  },
  {
    id: 8,
    question: "What does ASLR do?",
    options: ["Disables encryption", "Randomizes memory addresses", "Adds new entitlements", "Compresses binaries"],
    correctAnswer: 1,
    explanation: "ASLR makes memory layouts unpredictable to reduce exploitation.",
    topic: "iOS Basics",
  },
  {
    id: 9,
    question: "What does a universal (fat) binary contain?",
    options: ["Only ARM64", "Multiple architectures in one file", "Only debug symbols", "Only assets"],
    correctAnswer: 1,
    explanation: "Universal binaries include multiple architectures such as arm64 and arm64e.",
    topic: "iOS Basics",
  },
  {
    id: 10,
    question: "Which devices run iOS?",
    options: ["MacBook only", "iPhone and iPad", "Windows PCs", "Android devices"],
    correctAnswer: 1,
    explanation: "iOS powers iPhones and iPads (iPadOS shares the same core).",
    topic: "iOS Basics",
  },

  // App Packaging (11-20)
  {
    id: 11,
    question: "Which file contains app metadata like permissions and version?",
    options: ["Info.plist", "README.txt", "boot.ini", "config.sys"],
    correctAnswer: 0,
    explanation: "Info.plist stores app metadata and configuration settings.",
    topic: "App Packaging",
  },
  {
    id: 12,
    question: "Where is the main executable usually located in an app bundle?",
    options: ["Inside Documents", "At the root of the .app directory", "Inside Library/Caches", "Inside Assets.car"],
    correctAnswer: 1,
    explanation: "The executable is typically at the root of the app bundle.",
    topic: "App Packaging",
  },
  {
    id: 13,
    question: "What is embedded.mobileprovision?",
    options: ["A log file", "A provisioning profile embedded in the app", "A malware signature", "A database file"],
    correctAnswer: 1,
    explanation: "The provisioning profile ties the app to certificates and devices.",
    topic: "App Packaging",
  },
  {
    id: 14,
    question: "What is the _CodeSignature folder?",
    options: ["A cache folder", "The app code signature and manifest", "A crash log", "A network config"],
    correctAnswer: 1,
    explanation: "_CodeSignature holds signature data that verifies integrity.",
    topic: "App Packaging",
  },
  {
    id: 15,
    question: "What does Assets.car contain?",
    options: ["Compiled asset catalogs", "Executable code", "SQL tables", "Network traces"],
    correctAnswer: 0,
    explanation: "Assets.car stores compiled images and assets.",
    topic: "App Packaging",
  },
  {
    id: 16,
    question: "What are .dylib files?",
    options: ["Dynamic libraries", "Disk images", "Logs", "Kernel drivers"],
    correctAnswer: 0,
    explanation: ".dylib files are dynamic libraries loaded at runtime.",
    topic: "App Packaging",
  },
  {
    id: 17,
    question: "What is the Frameworks directory used for?",
    options: ["Temporary files", "Embedded frameworks and libraries", "User data", "Crash dumps"],
    correctAnswer: 1,
    explanation: "The Frameworks directory contains embedded frameworks.",
    topic: "App Packaging",
  },
  {
    id: 18,
    question: "Which tool can extract an IPA file?",
    options: ["zip or unzip", "grep", "ping", "sudo"],
    correctAnswer: 0,
    explanation: "IPAs are ZIP files, so zip tools can extract them.",
    topic: "App Packaging",
  },
  {
    id: 19,
    question: "Why inspect Info.plist during triage?",
    options: ["To change the UI theme", "To find URL schemes and permissions", "To compile the app", "To run tests"],
    correctAnswer: 1,
    explanation: "Info.plist reveals configuration, URL schemes, and capabilities.",
    topic: "App Packaging",
  },
  {
    id: 20,
    question: "What does storyboardc represent?",
    options: ["Compiled storyboard resources", "A command-line tool", "A debug log", "A keychain entry"],
    correctAnswer: 0,
    explanation: "storyboardc is the compiled storyboard format.",
    topic: "App Packaging",
  },

  // Mach-O and Binaries (21-30)
  {
    id: 21,
    question: "What is Mach-O?",
    options: ["A database engine", "The executable file format for iOS and macOS", "A compression algorithm", "A network protocol"],
    correctAnswer: 1,
    explanation: "Mach-O is the executable format used on Apple platforms.",
    topic: "Mach-O",
  },
  {
    id: 22,
    question: "What does the lipo tool do?",
    options: ["Encrypts binaries", "Lists or extracts architectures from a fat binary", "Edits plist files", "Shows network connections"],
    correctAnswer: 1,
    explanation: "lipo can list, thin, or combine architectures in universal binaries.",
    topic: "Mach-O",
  },
  {
    id: 23,
    question: "What does `otool -L` display?",
    options: ["Symbol tables", "Linked shared libraries", "Network sockets", "CPU temperature"],
    correctAnswer: 1,
    explanation: "`otool -L` shows which libraries the binary links against.",
    topic: "Mach-O",
  },
  {
    id: 24,
    question: "What is a Mach-O load command?",
    options: ["A runtime log", "A header entry that describes binary layout", "A network request", "A code signature"],
    correctAnswer: 1,
    explanation: "Load commands describe segments, libraries, and other metadata.",
    topic: "Mach-O",
  },
  {
    id: 25,
    question: "Which segment typically contains executable code?",
    options: ["__TEXT", "__DATA", "__LINKEDIT", "__PAGEZERO"],
    correctAnswer: 0,
    explanation: "__TEXT usually contains executable code and read-only data.",
    topic: "Mach-O",
  },

  {
    id: 26,
    question: "What is the __DATA segment used for?",
    options: ["Executable code only", "Writable data and globals", "Encryption keys only", "Debug symbols only"],
    correctAnswer: 1,
    explanation: "__DATA holds writable data such as globals and buffers.",
    topic: "Mach-O",
  },
  {
    id: 27,
    question: "What does `nm` help you find?",
    options: ["Symbols in the binary", "Network routes", "Binary size only", "Certificates"],
    correctAnswer: 0,
    explanation: "nm lists symbols, which can reveal function names if not stripped.",
    topic: "Mach-O",
  },
  {
    id: 28,
    question: "What does symbol stripping do?",
    options: ["Adds new symbols", "Removes symbol names from binaries", "Encrypts data", "Improves performance only"],
    correctAnswer: 1,
    explanation: "Stripping removes symbol names, making analysis harder.",
    topic: "Mach-O",
  },
  {
    id: 29,
    question: "Why run strings on a Mach-O binary?",
    options: ["To change permissions", "To find readable hints like URLs and keys", "To re-sign the app", "To build the app"],
    correctAnswer: 1,
    explanation: "Strings can reveal endpoints, error messages, or feature flags.",
    topic: "Mach-O",
  },
  {
    id: 30,
    question: "What is a fat binary?",
    options: ["A binary with large file size only", "A binary containing multiple architectures", "A binary with debug symbols", "A compressed binary"],
    correctAnswer: 1,
    explanation: "Fat binaries contain multiple architectures in a single file.",
    topic: "Mach-O",
  },

  // Objective-C and Swift (31-40)
  {
    id: 31,
    question: "What is message passing in Objective-C?",
    options: ["A network protocol", "Sending messages to objects via objc_msgSend", "A logging system", "A compression method"],
    correctAnswer: 1,
    explanation: "Objective-C uses objc_msgSend to dispatch method calls.",
    topic: "Obj-C and Swift",
  },
  {
    id: 32,
    question: "What does class-dump help with?",
    options: ["Extracting Objective-C headers", "Encrypting binaries", "Finding network connections", "Building apps"],
    correctAnswer: 0,
    explanation: "class-dump extracts Objective-C class and method definitions.",
    topic: "Obj-C and Swift",
  },
  {
    id: 33,
    question: "What is a selector?",
    options: ["A UI element", "An Objective-C method name", "A network port", "A code signature"],
    correctAnswer: 1,
    explanation: "Selectors represent method names in Objective-C.",
    topic: "Obj-C and Swift",
  },
  {
    id: 34,
    question: "What is method swizzling?",
    options: ["Replacing a method implementation at runtime", "Encrypting methods", "Deleting a class", "Compiling Swift"],
    correctAnswer: 0,
    explanation: "Swizzling replaces implementations to alter behavior.",
    topic: "Obj-C and Swift",
  },
  {
    id: 35,
    question: "What is Swift name mangling?",
    options: ["A UI theme", "Encoding type information into symbol names", "A network filter", "A file format"],
    correctAnswer: 1,
    explanation: "Swift mangles names to encode types and namespaces.",
    topic: "Obj-C and Swift",
  },
  {
    id: 36,
    question: "What is an Objective-C category?",
    options: ["A malware category", "A way to add methods to an existing class", "A debugger feature", "A storage format"],
    correctAnswer: 1,
    explanation: "Categories add methods without subclassing.",
    topic: "Obj-C and Swift",
  },
  {
    id: 37,
    question: "Where are Objective-C method names stored?",
    options: ["__objc_methname", "__DATA_CONST", "__PAGEZERO", "__BSS"],
    correctAnswer: 0,
    explanation: "Method name strings are stored in __objc_methname.",
    topic: "Obj-C and Swift",
  },
  {
    id: 38,
    question: "What does @objc do in Swift?",
    options: ["Disables ARC", "Exposes Swift symbols to the Objective-C runtime", "Encrypts classes", "Removes symbols"],
    correctAnswer: 1,
    explanation: "@objc allows Swift symbols to be visible to Obj-C runtime.",
    topic: "Obj-C and Swift",
  },
  {
    id: 39,
    question: "Why is objc_msgSend important in RE?",
    options: ["It encrypts traffic", "It dispatches method calls in Obj-C", "It strips symbols", "It signs binaries"],
    correctAnswer: 1,
    explanation: "objc_msgSend is central to Objective-C method calls.",
    topic: "Obj-C and Swift",
  },
  {
    id: 40,
    question: "What does dynamic mean in Swift?",
    options: ["Compiled to JavaScript", "Uses runtime dispatch like Obj-C", "Runs only on simulator", "Requires root"],
    correctAnswer: 1,
    explanation: "dynamic enables Obj-C style dispatch instead of static calls.",
    topic: "Obj-C and Swift",
  },

  // Code Signing and Entitlements (41-50)
  {
    id: 41,
    question: "Why does iOS require code signing?",
    options: ["To speed up apps", "To ensure integrity and trust", "To compress binaries", "To enable Wi-Fi"],
    correctAnswer: 1,
    explanation: "Code signing ensures apps are from a trusted source and not modified.",
    topic: "Code Signing",
  },
  {
    id: 42,
    question: "What happens if an app signature is invalid?",
    options: ["It runs normally", "It will not launch on a device", "It only affects icons", "It disables sandbox"],
    correctAnswer: 1,
    explanation: "iOS enforces code signing and will block unsigned apps.",
    topic: "Code Signing",
  },
  {
    id: 43,
    question: "What is a provisioning profile?",
    options: ["A UI layout", "A file linking app, cert, and devices", "A crash log", "A runtime hook"],
    correctAnswer: 1,
    explanation: "Provisioning profiles tie the app to signing certificates and devices.",
    topic: "Code Signing",
  },
  {
    id: 44,
    question: "Which tool verifies code signatures on macOS?",
    options: ["codesign", "grep", "ping", "tail"],
    correctAnswer: 0,
    explanation: "codesign verifies and applies signatures on Apple platforms.",
    topic: "Code Signing",
  },
  {
    id: 45,
    question: "What does the get-task-allow entitlement enable?",
    options: ["UI themes", "Debugging with a debugger", "Network encryption", "Bluetooth only"],
    correctAnswer: 1,
    explanation: "get-task-allow allows attaching a debugger to the app.",
    topic: "Code Signing",
  },
  {
    id: 46,
    question: "What is an entitlement plist?",
    options: ["A log of crashes", "A list of app permissions in the signature", "A UI stylesheet", "A database file"],
    correctAnswer: 1,
    explanation: "Entitlements define special permissions in the signature.",
    topic: "Code Signing",
  },
  {
    id: 47,
    question: "Why re-sign an app after modification?",
    options: ["To update UI icons", "To make it launch on a device", "To remove symbols", "To enable ASLR"],
    correctAnswer: 1,
    explanation: "Modified binaries need a valid signature to run.",
    topic: "Code Signing",
  },
  {
    id: 48,
    question: "What is the Team ID used for?",
    options: ["Screen resolution", "Developer identity in code signing", "Network routing", "Database sharding"],
    correctAnswer: 1,
    explanation: "Team ID identifies the developer or organization.",
    topic: "Code Signing",
  },
  {
    id: 49,
    question: "What does the App Sandbox restrict?",
    options: ["Only UI elements", "Access to files, network, and system resources", "Only Bluetooth", "Only logs"],
    correctAnswer: 1,
    explanation: "The sandbox restricts what the app can access.",
    topic: "Code Signing",
  },
  {
    id: 50,
    question: "Which file often lists entitlements in an app?",
    options: ["Entitlements.plist", "README.md", "Package.json", "hosts"],
    correctAnswer: 0,
    explanation: "Entitlements are stored in a plist when extracted.",
    topic: "Code Signing",
  },

  // Tools and Workflow (51-60)
  {
    id: 51,
    question: "What is Hopper commonly used for?",
    options: ["Packet capture", "Disassembly and decompilation", "Building IPA files", "Flashing firmware"],
    correctAnswer: 1,
    explanation: "Hopper is a disassembler and decompiler.",
    topic: "Tools",
  },
  {
    id: 52,
    question: "What is Ghidra?",
    options: ["A malware family", "An open-source reverse engineering suite", "A jailbreak tweak", "A network scanner"],
    correctAnswer: 1,
    explanation: "Ghidra is a free reverse engineering platform.",
    topic: "Tools",
  },
  {
    id: 53,
    question: "What is IDA Pro?",
    options: ["A browser", "A commercial disassembler and debugger", "A build system", "A proxy"],
    correctAnswer: 1,
    explanation: "IDA Pro is a commercial reverse engineering tool.",
    topic: "Tools",
  },
  {
    id: 54,
    question: "What is LLDB used for?",
    options: ["Disk encryption", "Debugging iOS binaries", "Database queries", "Compiling Swift"],
    correctAnswer: 1,
    explanation: "LLDB is Apple's debugger for macOS and iOS.",
    topic: "Tools",
  },
  {
    id: 55,
    question: "What is Frida?",
    options: ["A compiler", "A dynamic instrumentation framework", "A package manager", "A kernel module"],
    correctAnswer: 1,
    explanation: "Frida injects scripts into running processes for hooking.",
    topic: "Tools",
  },
  {
    id: 56,
    question: "What is Objection?",
    options: ["A legal term", "A Frida-based mobile exploration toolkit", "A database engine", "A firmware flasher"],
    correctAnswer: 1,
    explanation: "Objection automates common mobile RE tasks using Frida.",
    topic: "Tools",
  },
  {
    id: 57,
    question: "What is class-dump used for?",
    options: ["Capturing network traffic", "Extracting Obj-C class interfaces", "Signing apps", "Encrypting bundles"],
    correctAnswer: 1,
    explanation: "class-dump extracts Objective-C headers from binaries.",
    topic: "Tools",
  },
  {
    id: 58,
    question: "What does `file` help you confirm?",
    options: ["Binary type and architecture", "Network routes", "Installed apps", "Keychain access"],
    correctAnswer: 0,
    explanation: "file identifies the type and architecture of a binary.",
    topic: "Tools",
  },
  {
    id: 59,
    question: "What does `otool -l` show?",
    options: ["Load commands and segments", "Wi-Fi networks", "Keychain entries", "UIKit classes"],
    correctAnswer: 0,
    explanation: "otool -l lists Mach-O load commands and segments.",
    topic: "Tools",
  },
  {
    id: 60,
    question: "Why start with strings during triage?",
    options: ["It removes encryption", "It reveals URLs, keys, and hints", "It patches the binary", "It signs the app"],
    correctAnswer: 1,
    explanation: "Strings provide quick clues about behavior.",
    topic: "Tools",
  },

  // Dynamic Analysis and Jailbreak (61-70)
  {
    id: 61,
    question: "What is a jailbreak?",
    options: ["A backup format", "Removing iOS restrictions to gain root access", "A network proxy", "A file system"],
    correctAnswer: 1,
    explanation: "Jailbreaking removes restrictions and allows deeper analysis.",
    topic: "Dynamic Analysis",
  },
  {
    id: 62,
    question: "Why use a jailbroken device for RE?",
    options: ["To increase battery life", "To allow runtime hooks and filesystem access", "To remove Bluetooth", "To hide apps"],
    correctAnswer: 1,
    explanation: "Jailbreak access enables runtime tooling and file access.",
    topic: "Dynamic Analysis",
  },
  {
    id: 63,
    question: "What does frida-server do?",
    options: ["Compiles code", "Listens on the device for Frida connections", "Encrypts storage", "Manages keys"],
    correctAnswer: 1,
    explanation: "frida-server runs on the device and accepts Frida connections.",
    topic: "Dynamic Analysis",
  },
  {
    id: 64,
    question: "What is the default Frida port?",
    options: ["22", "27042", "443", "8080"],
    correctAnswer: 1,
    explanation: "Frida server listens on port 27042 by default.",
    topic: "Dynamic Analysis",
  },
  {
    id: 65,
    question: "What is SSL pinning?",
    options: ["Saving certificates for speed", "Verifying specific certificates in code", "Compressing SSL", "Disabling TLS"],
    correctAnswer: 1,
    explanation: "Pinning checks for a specific certificate to prevent interception.",
    topic: "Dynamic Analysis",
  },
  {
    id: 66,
    question: "How can SSL pinning be bypassed in tests?",
    options: ["Disable Wi-Fi", "Hook trust APIs at runtime", "Delete the binary", "Remove Info.plist"],
    correctAnswer: 1,
    explanation: "Runtime hooks can override trust checks for testing.",
    topic: "Dynamic Analysis",
  },
  {
    id: 67,
    question: "What is debugserver?",
    options: ["A logging tool", "A service that allows LLDB attachment", "A compression tool", "A package manager"],
    correctAnswer: 1,
    explanation: "debugserver enables LLDB debugging on a device.",
    topic: "Dynamic Analysis",
  },
  {
    id: 68,
    question: "What is cycript used for?",
    options: ["UI design", "Runtime inspection and scripting on iOS", "Networking", "Signing apps"],
    correctAnswer: 1,
    explanation: "cycript enables runtime inspection of Obj-C objects.",
    topic: "Dynamic Analysis",
  },
  {
    id: 69,
    question: "Why use SSH during iOS analysis?",
    options: ["To mount assets", "To access the device shell remotely", "To sign binaries", "To convert IPA files"],
    correctAnswer: 1,
    explanation: "SSH provides remote shell access to a jailbroken device.",
    topic: "Dynamic Analysis",
  },
  {
    id: 70,
    question: "What does jailbreak detection try to do?",
    options: ["Enable Bluetooth", "Identify if the device is modified", "Encrypt files", "Increase performance"],
    correctAnswer: 1,
    explanation: "Apps check for jailbreak signs to block analysis or tampering.",
    topic: "Dynamic Analysis",
  },

  // Security and Data Storage (71-75)
  {
    id: 71,
    question: "Where are user defaults typically stored?",
    options: ["Library/Preferences plist files", "Kernel memory", "Assets.car", "Frameworks directory"],
    correctAnswer: 0,
    explanation: "NSUserDefaults are stored in plist files under Library/Preferences.",
    topic: "Security and Data",
  },
  {
    id: 72,
    question: "What is App Transport Security (ATS)?",
    options: ["A UI framework", "A policy enforcing secure network connections", "A build tool", "A backup format"],
    correctAnswer: 1,
    explanation: "ATS enforces HTTPS and secure TLS settings by default.",
    topic: "Security and Data",
  },
  {
    id: 73,
    question: "What is FairPlay?",
    options: ["A game API", "Apple's DRM encryption for App Store apps", "A debugger", "A database engine"],
    correctAnswer: 1,
    explanation: "FairPlay is Apple's DRM used to encrypt App Store binaries.",
    topic: "Security and Data",
  },
  {
    id: 74,
    question: "Why is Keychain safer than plain plist storage?",
    options: ["It is faster", "It is encrypted and access-controlled", "It is smaller", "It is public"],
    correctAnswer: 1,
    explanation: "Keychain items are encrypted and controlled by access policies.",
    topic: "Security and Data",
  },
  {
    id: 75,
    question: "What is a data protection class?",
    options: ["A UI class", "A file encryption policy tied to device state", "A network protocol", "A compiler flag"],
    correctAnswer: 1,
    explanation: "Data protection classes control encryption based on device lock state.",
    topic: "Security and Data",
  },
];

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
    if (score >= 8) return "#22c55e";
    if (score >= 6) return "#f97316";
    return "#ef4444";
  };

  const getScoreMessage = (score: number) => {
    if (score === 10) return "Perfect. Strong iOS reverse engineering fundamentals.";
    if (score >= 8) return "Excellent work. Your fundamentals are solid.";
    if (score >= 6) return "Good progress. Review the core concepts and try again.";
    if (score >= 4) return "Keep going. Revisit the overview and workflow sections.";
    return "Start with the basics and take the quiz again.";
  };

  if (!quizStarted) {
    return (
      <Paper
        id="quiz-section"
        sx={{
          p: 4,
          mb: 5,
          borderRadius: 4,
          bgcolor: alpha(theme.palette.background.paper, 0.6),
          border: `2px solid ${alpha("#3b82f6", 0.3)}`,
          background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.06)} 0%, ${alpha("#60a5fa", 0.06)} 100%)`,
        }}
      >
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              background: "linear-gradient(135deg, #3b82f6, #60a5fa)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <QuizIcon sx={{ color: "white", fontSize: 32 }} />
          </Box>
          Test Your Knowledge
        </Typography>

        <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8, fontSize: "1.05rem" }}>
          Ready to test what you learned? Take this <strong>10-question quiz</strong> covering iOS reverse engineering
          fundamentals. Questions are randomly selected from a pool of <strong>75 questions</strong>, so every attempt
          is different.
        </Typography>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#3b82f6", 0.12), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#3b82f6" }}>10</Typography>
              <Typography variant="caption" color="text.secondary">Questions</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#22c55e", 0.12), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#22c55e" }}>75</Typography>
              <Typography variant="caption" color="text.secondary">Question Pool</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#60a5fa", 0.12), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#60a5fa" }}>8</Typography>
              <Typography variant="caption" color="text.secondary">Topics Covered</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#f97316", 0.12), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#f97316" }}>Unlimited</Typography>
              <Typography variant="caption" color="text.secondary">Retakes</Typography>
            </Paper>
          </Grid>
        </Grid>

        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          startIcon={<QuizIcon />}
          sx={{
            background: "linear-gradient(135deg, #3b82f6, #60a5fa)",
            fontWeight: 700,
            px: 4,
            py: 1.5,
            fontSize: "1.1rem",
            "&:hover": {
              background: "linear-gradient(135deg, #2563eb, #3b82f6)",
            },
          }}
        >
          Start Quiz
        </Button>
      </Paper>
    );
  }

  if (showResults) {
    const score = calculateScore();
    return (
      <Paper
        id="quiz-section"
        sx={{
          p: 4,
          mb: 5,
          borderRadius: 4,
          bgcolor: alpha(theme.palette.background.paper, 0.6),
          border: `2px solid ${alpha(getScoreColor(score), 0.3)}`,
        }}
      >
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <EmojiEventsIcon sx={{ color: getScoreColor(score), fontSize: 40 }} />
          Quiz Results
        </Typography>

        <Box sx={{ textAlign: "center", mb: 4 }}>
          <Typography variant="h1" sx={{ fontWeight: 900, color: getScoreColor(score), mb: 1 }}>
            {score}/10
          </Typography>
          <Typography variant="h6" sx={{ color: "text.secondary", mb: 2 }}>
            {getScoreMessage(score)}
          </Typography>
          <Chip
            label={`${score * 10}%`}
            sx={{
              bgcolor: alpha(getScoreColor(score), 0.15),
              color: getScoreColor(score),
              fontWeight: 700,
              fontSize: "1rem",
              px: 2,
            }}
          />
        </Box>

        <Divider sx={{ my: 3 }} />

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Review Your Answers:</Typography>

        {currentQuestions.map((q, index) => {
          const isCorrect = userAnswers[q.id] === q.correctAnswer;
          return (
            <Paper
              key={q.id}
              sx={{
                p: 2,
                mb: 2,
                borderRadius: 2,
                bgcolor: alpha(isCorrect ? "#22c55e" : "#ef4444", 0.05),
                border: `1px solid ${alpha(isCorrect ? "#22c55e" : "#ef4444", 0.2)}`,
              }}
            >
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1 }}>
                <Chip
                  label={`Q${index + 1}`}
                  size="small"
                  sx={{
                    bgcolor: isCorrect ? "#22c55e" : "#ef4444",
                    color: "white",
                    fontWeight: 700,
                  }}
                />
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  {q.question}
                </Typography>
              </Box>
              <Typography variant="body2" sx={{ color: "text.secondary", ml: 4.5 }}>
                <strong>Your answer:</strong> {q.options[userAnswers[q.id]] || "Not answered"}
                {!isCorrect && (
                  <>
                    <br />
                    <strong style={{ color: "#22c55e" }}>Correct:</strong> {q.options[q.correctAnswer]}
                  </>
                )}
              </Typography>
              {!isCorrect && (
                <Alert severity="info" sx={{ mt: 1, ml: 4.5 }}>
                  <Typography variant="caption">{q.explanation}</Typography>
                </Alert>
              )}
            </Paper>
          );
        })}

        <Box sx={{ display: "flex", gap: 2, mt: 3 }}>
          <Button
            variant="contained"
            onClick={startQuiz}
            startIcon={<RefreshIcon />}
            sx={{
              background: "linear-gradient(135deg, #3b82f6, #60a5fa)",
              fontWeight: 700,
            }}
          >
            Try Again (New Questions)
          </Button>
          <Button
            variant="outlined"
            onClick={() => setQuizStarted(false)}
            sx={{ fontWeight: 600 }}
          >
            Back to Overview
          </Button>
        </Box>
      </Paper>
    );
  }

  const currentQuestion = currentQuestions[currentQuestionIndex];
  const answeredCount = Object.keys(userAnswers).length;

  return (
    <Paper
      id="quiz-section"
      sx={{
        p: 4,
        mb: 5,
        borderRadius: 4,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        border: `2px solid ${alpha("#3b82f6", 0.3)}`,
      }}
    >
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
            Question {currentQuestionIndex + 1} of 10
          </Typography>
          <Chip
            label={currentQuestion.topic}
            size="small"
            sx={{ bgcolor: alpha("#60a5fa", 0.15), color: "#60a5fa", fontWeight: 600 }}
          />
        </Box>
        <Box sx={{ width: "100%", bgcolor: alpha("#3b82f6", 0.1), borderRadius: 1, height: 8 }}>
          <Box
            sx={{
              width: `${((currentQuestionIndex + 1) / 10) * 100}%`,
              bgcolor: "#3b82f6",
              borderRadius: 1,
              height: "100%",
              transition: "width 0.3s ease",
            }}
          />
        </Box>
      </Box>

      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3, lineHeight: 1.6 }}>
        {currentQuestion.question}
      </Typography>

      <Grid container spacing={2} sx={{ mb: 4 }}>
        {currentQuestion.options.map((option, index) => {
          const isSelected = userAnswers[currentQuestion.id] === index;
          return (
            <Grid item xs={12} key={index}>
              <Paper
                onClick={() => handleAnswerSelect(currentQuestion.id, index)}
                sx={{
                  p: 2,
                  borderRadius: 2,
                  cursor: "pointer",
                  bgcolor: isSelected ? alpha("#3b82f6", 0.15) : alpha(theme.palette.background.paper, 0.5),
                  border: `2px solid ${isSelected ? "#3b82f6" : alpha(theme.palette.divider, 0.2)}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    borderColor: "#3b82f6",
                    bgcolor: alpha("#3b82f6", 0.08),
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box
                    sx={{
                      width: 32,
                      height: 32,
                      borderRadius: "50%",
                      bgcolor: isSelected ? "#3b82f6" : alpha(theme.palette.divider, 0.3),
                      color: isSelected ? "white" : "text.secondary",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontWeight: 700,
                      fontSize: "0.9rem",
                    }}
                  >
                    {String.fromCharCode(65 + index)}
                  </Box>
                  <Typography variant="body1" sx={{ fontWeight: isSelected ? 600 : 400 }}>
                    {option}
                  </Typography>
                </Box>
              </Paper>
            </Grid>
          );
        })}
      </Grid>

      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Button
          variant="outlined"
          disabled={currentQuestionIndex === 0}
          onClick={() => setCurrentQuestionIndex((prev) => prev - 1)}
        >
          Previous
        </Button>

        <Typography variant="body2" color="text.secondary">
          {answeredCount}/10 answered
        </Typography>

        {currentQuestionIndex < 9 ? (
          <Button
            variant="contained"
            onClick={() => setCurrentQuestionIndex((prev) => prev + 1)}
            sx={{
              background: "linear-gradient(135deg, #3b82f6, #60a5fa)",
            }}
          >
            Next
          </Button>
        ) : (
          <Button
            variant="contained"
            onClick={() => setShowResults(true)}
            disabled={answeredCount < 10}
            sx={{
              background: answeredCount >= 10
                ? "linear-gradient(135deg, #22c55e, #16a34a)"
                : undefined,
              fontWeight: 700,
            }}
          >
            Submit Quiz
          </Button>
        )}
      </Box>

      <Box sx={{ mt: 3, pt: 3, borderTop: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
        <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: "block" }}>
          Quick Navigation:
        </Typography>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          {currentQuestions.map((_, index) => {
            const isAnswered = userAnswers[currentQuestions[index].id] !== undefined;
            const isCurrent = index === currentQuestionIndex;
            return (
              <Box
                key={index}
                onClick={() => setCurrentQuestionIndex(index)}
                sx={{
                  width: 32,
                  height: 32,
                  borderRadius: 1,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  cursor: "pointer",
                  fontWeight: 700,
                  fontSize: "0.85rem",
                  bgcolor: isCurrent
                    ? "#3b82f6"
                    : isAnswered
                    ? alpha("#22c55e", 0.2)
                    : alpha(theme.palette.divider, 0.1),
                  color: isCurrent ? "white" : isAnswered ? "#22c55e" : "text.secondary",
                  border: `1px solid ${isCurrent ? "#3b82f6" : isAnswered ? "#22c55e" : "transparent"}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    bgcolor: isCurrent ? "#3b82f6" : alpha("#3b82f6", 0.2),
                  },
                }}
              >
                {index + 1}
              </Box>
            );
          })}
        </Box>
      </Box>
    </Paper>
  );
}

export default function IOSReverseEngineeringFundamentalsPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const accent = "#3b82f6";

  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const sectionNavItems = [
    { id: "intro", label: "Overview", icon: <SchoolIcon /> },
    { id: "outline", label: "Outline", icon: <SearchIcon /> },
    { id: "tools", label: "Tooling", icon: <BuildIcon /> },
    { id: "pitfalls", label: "Pitfalls", icon: <WarningIcon /> },
    { id: "ios-architecture", label: "Architecture", icon: <SecurityIcon /> },
    { id: "app-packaging", label: "Packaging", icon: <LayersIcon /> },
    { id: "macho-format", label: "Mach-O", icon: <MemoryIcon /> },
    { id: "code-signing", label: "Code Signing", icon: <VpnKeyIcon /> },
    { id: "objc-swift", label: "ObjC/Swift", icon: <CodeIcon /> },
    { id: "static-analysis", label: "Static Analysis", icon: <SearchIcon /> },
    { id: "dynamic-analysis", label: "Dynamic Analysis", icon: <TerminalIcon /> },
    { id: "device-setup", label: "Device Setup", icon: <PhoneIphoneIcon /> },
    { id: "data-storage", label: "Data Storage", icon: <StorageIcon /> },
    { id: "network-security", label: "Network", icon: <NetworkCheckIcon /> },
    { id: "bypass-techniques", label: "Bypasses", icon: <HttpsIcon /> },
    { id: "reporting-ethics", label: "Reporting", icon: <GavelIcon /> },
    { id: "key-takeaways", label: "Takeaways", icon: <TipsAndUpdatesIcon /> },
    { id: "quiz", label: "Quiz", icon: <QuizIcon /> },
  ];

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setNavDrawerOpen(false);
    }
  };

  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map((item) => item.id);
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

  const currentIndex = sectionNavItems.findIndex((item) => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / sectionNavItems.length) * 100 : 0;

  const pageContext = `iOS Reverse Engineering Fundamentals - A beginner friendly guide covering iOS architecture, app packaging, Mach-O binaries, code signing, Objective-C and Swift metadata, static and dynamic analysis workflows, and safe lab practices. Includes practical tooling, pitfalls, and a structured learning outline.`;

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
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha(accent, 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography
          variant="subtitle2"
          sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}
        >
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              Progress
            </Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
              {Math.round(progressPercent)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: accent,
                borderRadius: 3,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {sectionNavItems.map((item) => (
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
                "&:hover": {
                  bgcolor: alpha(accent, 0.08),
                },
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
    <LearnPageLayout pageTitle="iOS Reverse Engineering Fundamentals" pageContext={pageContext}>
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
            "&:hover": { bgcolor: "#2563eb" },
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
          sx: {
            width: isMobile ? "85%" : 320,
            bgcolor: theme.palette.background.paper,
            backgroundImage: "none",
          },
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

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                Progress
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
                {Math.round(progressPercent)}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(accent, 0.1),
                "& .MuiLinearProgress-bar": {
                  bgcolor: accent,
                  borderRadius: 3,
                },
              }}
            />
          </Box>

          {/* Navigation List */}
          <List dense sx={{ mx: -1 }}>
            {sectionNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                  "&:hover": {
                    bgcolor: alpha(accent, 0.1),
                  },
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
                  <Chip
                    label="Current"
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: "0.65rem",
                      bgcolor: alpha(accent, 0.2),
                      color: accent,
                    }}
                  />
                )}
              </ListItem>
            ))}
          </List>

          <Divider sx={{ my: 2 }} />

          {/* Quick Actions */}
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={scrollToTop}
              startIcon={<KeyboardArrowUpIcon />}
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Box sx={{ maxWidth: 1200, mx: "auto" }}>
            <Chip
              component={Link}
              to="/learn"
              icon={<ArrowBackIcon />}
              label="Back to Learning Hub"
              clickable
              variant="outlined"
              sx={{ borderRadius: 2, mb: 3, borderColor: alpha(accent, 0.4), color: accent }}
            />

        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.15)} 0%, ${alpha("#60a5fa", 0.15)} 60%, ${alpha("#22c55e", 0.12)} 100%)`,
            border: `1px solid ${alpha("#3b82f6", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 2 }}>
            <Box
              sx={{
                width: 72,
                height: 72,
                borderRadius: 3,
                background: "linear-gradient(135deg, #3b82f6, #60a5fa)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: `0 8px 32px ${alpha("#3b82f6", 0.3)}`,
              }}
            >
              <PhoneIphoneIcon sx={{ fontSize: 40, color: "white" }} />
            </Box>
            <Box>
              <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                iOS Reverse Engineering Fundamentals
              </Typography>
              <Typography variant="h6" color="text.secondary">
                Understand how iOS apps work under the hood and how to analyze them safely.
              </Typography>
            </Box>
          </Box>

          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
            <Chip label="Beginner Friendly" color="primary" />
            <Chip label="Mach-O" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            <Chip label="Static Analysis" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 600 }} />
            <Chip label="Dynamic Analysis" sx={{ bgcolor: alpha("#0ea5e9", 0.15), color: "#0ea5e9", fontWeight: 600 }} />
          </Box>

          <Grid container spacing={2}>
            {quickStats.map((stat) => (
              <Grid item xs={6} sm={3} key={stat.label}>
                <Paper
                  sx={{
                    p: 2,
                    textAlign: "center",
                    borderRadius: 2,
                    bgcolor: alpha(stat.color, 0.1),
                    border: `1px solid ${alpha(stat.color, 0.2)}`,
                  }}
                >
                  <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                    {stat.value}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
                    {stat.label}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Quick Navigation */}
        <Paper
          sx={{
            p: 2,
            mb: 4,
            borderRadius: 3,
            position: "sticky",
            top: 70,
            zIndex: 100,
            backdropFilter: "blur(10px)",
            bgcolor: alpha(theme.palette.background.paper, 0.9),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            boxShadow: `0 4px 20px ${alpha("#000", 0.1)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1.5 }}>
            <Chip
              label="Learning Hub"
              size="small"
              clickable
              onClick={() => navigate("/learn")}
              sx={{
                fontWeight: 700,
                fontSize: "0.75rem",
                bgcolor: alpha(accent, 0.1),
                color: accent,
                "&:hover": {
                  bgcolor: alpha(accent, 0.2),
                },
              }}
            />
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.secondary" }}>
              Quick Navigation
            </Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {sectionNavItems.map((nav) => (
              <Chip
                key={nav.id}
                label={nav.label}
                size="small"
                clickable
                onClick={() => scrollToSection(nav.id)}
                sx={{
                  fontWeight: 600,
                  fontSize: "0.75rem",
                  "&:hover": {
                    bgcolor: alpha(accent, 0.15),
                    color: accent,
                  },
                }}
              />
            ))}
          </Box>
        </Paper>

        <Box id="intro" sx={{ scrollMarginTop: 180, mb: 4 }}>
        <Paper
          sx={{
            p: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.7),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: "linear-gradient(135deg, #3b82f6, #60a5fa)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <SchoolIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Beginner Overview
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            iOS reverse engineering is the practice of understanding how an iPhone or iPad app works when you do not
            have the original source code. iOS apps are distributed as compiled binaries. That binary is designed for
            the CPU to execute, not for humans to read. Reverse engineering helps you translate that machine code into
            concepts you can understand, such as data flows, network behavior, and security checks.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Unlike many desktop programs, iOS apps live inside a tightly controlled environment. Every app is packaged
            as an IPA file that contains the executable, resources, and metadata like Info.plist. Apple enforces strict
            code signing and sandboxing, which means you cannot freely run modified apps without re-signing them or
            working in a controlled testing environment. This makes iOS reverse engineering a blend of static analysis
            (reading the binary) and dynamic analysis (observing the app while it runs).
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            A good beginner workflow starts with static analysis: unpack the IPA, review Info.plist, inspect strings,
            and map classes and functions. Once you have a mental map, you move to dynamic analysis using tools like
            LLDB and Frida to confirm behavior, capture runtime data, or bypass checks. The goal is not just to read
            code but to build an accurate model of how the app behaves in real conditions.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            This fundamentals page is structured as an outline: each section shows the core topics you need to study
            and practice. You can use it as a learning roadmap, a checklist for assessments, or a reference when you
            are stuck. Focus on understanding app packaging, Mach-O binaries, and code signing first. Those topics
            unlock nearly everything else.
          </Typography>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Beginner Tip</AlertTitle>
            Start with your own apps or sample binaries and keep a simple notes file. Small, consistent notes make
            later analysis faster and more accurate.
          </Alert>
        </Paper>
        </Box>

        <Box id="outline" sx={{ scrollMarginTop: 180, mb: 4 }}>
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1.5 }}>
            <SearchIcon sx={{ color: "#3b82f6" }} />
            Learning Outline
          </Typography>
          <Grid container spacing={2}>
            {outlineSections.map((section) => (
              <Grid item xs={12} sm={6} md={4} key={section.id}>
                <Paper
                  sx={{
                    p: 2.5,
                    height: "100%",
                    borderRadius: 3,
                    bgcolor: alpha(section.color, 0.06),
                    border: `1px solid ${alpha(section.color, 0.2)}`,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                    <Box sx={{ color: section.color }}>{section.icon}</Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: section.color }}>
                      {section.title}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>
                    {section.description}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>
        </Box>

        <Box id="tools" sx={{ scrollMarginTop: 180, mb: 4 }}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                Core Tooling
              </Typography>
              <List dense>
                {toolHighlights.map((tool) => (
                  <ListItem key={tool} sx={{ py: 0.4 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ color: "#3b82f6", fontSize: 18 }} />
                    </ListItemIcon>
                    <ListItemText primary={tool} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                Getting Started Checklist
              </Typography>
              <List dense>
                {gettingStartedChecklist.map((item) => (
                  <ListItem key={item} sx={{ py: 0.4 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 18 }} />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>
        </Box>

        <Box id="pitfalls" sx={{ scrollMarginTop: 180, mb: 4 }}>
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Common Pitfalls to Avoid
          </Typography>
          <List dense>
            {commonPitfalls.map((item) => (
              <ListItem key={item} sx={{ py: 0.4 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <BugReportIcon sx={{ color: "#f97316", fontSize: 18 }} />
                </ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>
        </Box>

        {/* ==================== SECTION DIVIDER ==================== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, my: 5 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            DETAILED SECTIONS
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* ==================== SECTION 1: iOS Architecture ==================== */}
        <Paper id="ios-architecture" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}`, scrollMarginTop: 180 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #3b82f6, #60a5fa)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <SecurityIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            1. iOS Architecture and Security Model
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            iOS is built on Darwin, Apple's Unix-based operating system that combines the Mach microkernel with BSD components.
            Understanding the layered architecture helps you know where security controls exist and what you're analyzing at each level.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>System Layers</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#3b82f6", 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Layer</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Components</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {iosArchitectureLayers.map((layer) => (
                  <TableRow key={layer.layer}>
                    <TableCell sx={{ color: layer.color, fontWeight: 600 }}>{layer.layer}</TableCell>
                    <TableCell>{layer.description}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>Sandbox Restrictions</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Every app runs in its own sandbox container. This isolation is enforced by the kernel and limits what each app can access.
          </Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#3b82f6", 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Restriction</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Effect</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Analysis Approach</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {sandboxRestrictions.map((item) => (
                  <TableRow key={item.restriction}>
                    <TableCell sx={{ fontWeight: 600 }}>{item.restriction}</TableCell>
                    <TableCell>{item.effect}</TableCell>
                    <TableCell sx={{ color: "#22c55e" }}>{item.bypass}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Key Takeaway</AlertTitle>
            The sandbox is your primary obstacle for dynamic analysis. On a jailbroken device, you can escape the sandbox.
            On a stock device, you must work within its constraints or use a debugger with proper entitlements.
          </Alert>
        </Paper>

        {/* ==================== SECTION 2: App Packaging ==================== */}
        <Paper id="app-packaging" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#60a5fa", 0.2)}`, scrollMarginTop: 180 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #60a5fa, #3b82f6)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <LayersIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            2. App Packaging and IPA Structure
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            iOS apps are distributed as IPA files, which are simply ZIP archives containing an app bundle. Understanding this structure
            is essential for static analysis—you'll extract the IPA and examine each component.
          </Typography>

          <CodeBlock
            title="Extract and Examine IPA"
            language="bash"
            code={`# Rename and extract
mv app.ipa app.zip
unzip app.zip -d extracted/

# Navigate to app bundle
cd extracted/Payload/AppName.app/

# List contents
ls -la

# Check binary architecture
file AppName
lipo -info AppName

# Read Info.plist
plutil -p Info.plist`}
          />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#60a5fa" }}>IPA Structure</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#60a5fa", 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Path</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {ipaStructure.map((item) => (
                  <TableRow key={item.path}>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>{item.path}</TableCell>
                    <TableCell><Chip label={item.type} size="small" /></TableCell>
                    <TableCell>{item.description}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#60a5fa" }}>Important Info.plist Keys</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#60a5fa", 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Key</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Priority</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {infoPlistKeys.map((item) => (
                  <TableRow key={item.key}>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>{item.key}</TableCell>
                    <TableCell>{item.purpose}</TableCell>
                    <TableCell>
                      <Chip 
                        label={item.importance} 
                        size="small" 
                        color={item.importance === "Critical" ? "error" : item.importance === "High" ? "warning" : "default"}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* ==================== SECTION 3: Mach-O Format ==================== */}
        <Paper id="macho-format" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}`, scrollMarginTop: 180 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #22c55e, #16a34a)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <MemoryIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            3. Mach-O Format and Universal Binaries
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Mach-O (Mach Object) is the executable format for iOS and macOS. Every iOS binary—apps, dylibs, frameworks—uses this format.
            Understanding Mach-O structure helps you navigate binaries in disassemblers and understand how code is organized.
          </Typography>

          <CodeBlock
            title="Mach-O Inspection Commands"
            language="bash"
            code={`# Check file type and architecture
file AppBinary
# Output: Mach-O 64-bit executable arm64

# List architectures in fat binary
lipo -info AppBinary
# Output: Architectures in the fat file: arm64 arm64e

# Extract single architecture
lipo AppBinary -thin arm64 -output AppBinary_arm64

# Show Mach-O header
otool -h AppBinary

# List all load commands
otool -l AppBinary

# Show linked libraries
otool -L AppBinary

# Display symbol table
nm -m AppBinary | head -50

# Show segment info
size -m AppBinary`}
          />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>Mach-O Segments</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#22c55e", 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Segment</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Permissions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {machoSegments.map((seg) => (
                  <TableRow key={seg.segment}>
                    <TableCell sx={{ fontFamily: "monospace", fontWeight: 600 }}>{seg.segment}</TableCell>
                    <TableCell>{seg.description}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace" }}>{seg.permissions}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>Load Commands</Typography>
          <Grid container spacing={2}>
            {machoLoadCommands.map((cmd) => (
              <Grid item xs={12} sm={6} key={cmd.command}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontFamily: "monospace", color: "#22c55e", fontWeight: 700 }}>{cmd.command}</Typography>
                  <Typography variant="body2" color="text.secondary">{cmd.purpose}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== SECTION 4: Code Signing ==================== */}
        <Paper id="code-signing" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#f97316", 0.2)}`, scrollMarginTop: 180 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #f97316, #ea580c)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <VpnKeyIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            4. Code Signing and Entitlements
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            iOS enforces code signing to ensure apps come from trusted sources and haven't been tampered with.
            Entitlements are embedded permissions that grant apps special capabilities. Understanding both is critical
            for RE because you'll need to re-sign modified apps to run them.
          </Typography>

          <CodeBlock
            title="Code Signing Commands"
            language="bash"
            code={`# Verify code signature
codesign -dvv AppName.app

# Show entitlements
codesign -d --entitlements - AppName.app

# Extract entitlements to file
codesign -d --entitlements :entitlements.plist AppName.app

# Check signature validity
codesign --verify --deep --strict AppName.app

# View provisioning profile
security cms -D -i embedded.mobileprovision

# Re-sign app (requires valid certificate)
codesign -f -s "iPhone Developer: Name" --entitlements entitlements.plist AppName.app

# Use ldid for ad-hoc signing (jailbreak)
ldid -S AppBinary
ldid -Sentitlements.xml AppBinary`}
          />

          <Alert severity="warning" sx={{ mb: 3, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Important</AlertTitle>
            If you modify a binary without re-signing, iOS will refuse to run it. On jailbroken devices, you can use
            <code style={{ margin: "0 4px" }}>ldid</code> for ad-hoc signing. On stock devices, you need a valid Apple developer certificate.
          </Alert>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>Common Entitlements</Typography>
          <Grid container spacing={2}>
            {[
              { key: "get-task-allow", desc: "Allows debugger attachment", impact: "Required for debugging" },
              { key: "com.apple.developer.team-identifier", desc: "Developer team ID", impact: "Identifies developer" },
              { key: "application-identifier", desc: "Full app identifier", impact: "Unique app identity" },
              { key: "keychain-access-groups", desc: "Keychain sharing groups", impact: "Data sharing between apps" },
              { key: "com.apple.security.application-groups", desc: "App group containers", impact: "Shared storage" },
              { key: "aps-environment", desc: "Push notification environment", impact: "dev or production" },
            ].map((ent) => (
              <Grid item xs={12} sm={6} key={ent.key}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f97316", 0.05), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontFamily: "monospace", color: "#f97316", fontWeight: 700 }}>{ent.key}</Typography>
                  <Typography variant="body2" color="text.secondary">{ent.desc}</Typography>
                  <Typography variant="caption" color="text.secondary">{ent.impact}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== SECTION 5: Objective-C and Swift ==================== */}
        <Paper id="objc-swift" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#a855f7", 0.2)}`, scrollMarginTop: 180 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #a855f7, #9333ea)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <CodeIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            5. Objective-C Runtime and Swift Metadata
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Objective-C's dynamic runtime is a goldmine for reverse engineers. Method names, class structures, and selectors
            are preserved in the binary. Swift is more challenging due to name mangling and static dispatch, but mixed
            Obj-C/Swift apps still expose useful metadata.
          </Typography>

          <CodeBlock
            title="Extracting Objective-C Headers"
            language="bash"
            code={`# Extract Objective-C class definitions
class-dump -H -o headers/ AppBinary

# For Swift apps, try class-dump-swift
class-dump-swift AppBinary > headers.txt

# Search for specific classes
class-dump AppBinary | grep -A 20 "LoginViewController"

# Find selectors (method names)
strings AppBinary | grep -E "^[+-]\\[.*\\]"

# Search for interesting methods
strings AppBinary | grep -i "password\\|token\\|secret\\|api"`}
          />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>Runtime Concepts</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#a855f7", 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Concept</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Analysis Tool</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {objcRuntimeConcepts.map((item) => (
                  <TableRow key={item.concept}>
                    <TableCell sx={{ fontWeight: 600, color: "#a855f7" }}>{item.concept}</TableCell>
                    <TableCell>{item.description}</TableCell>
                    <TableCell><Chip label={item.tool} size="small" /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>Swift Name Mangling</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Swift encodes type information into symbol names. You can demangle them with <code>swift-demangle</code>.
          </Typography>
          <CodeBlock
            title="Swift Demangling"
            language="bash"
            code={`# Demangle Swift symbols
xcrun swift-demangle _$s7MyClass10doSomethingyyF
# Output: MyClass.doSomething() -> ()

# Find and demangle all Swift symbols
nm AppBinary | grep " _\\$s" | cut -d' ' -f3 | xcrun swift-demangle

# Common Swift symbol prefixes:
# _$s - Swift symbol
# _$S - Swift 4.0 symbol  
# _T  - Swift 3.x symbol`}
          />
        </Paper>

        {/* ==================== SECTION 6: Static Analysis ==================== */}
        <Paper id="static-analysis" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#14b8a6", 0.2)}`, scrollMarginTop: 180 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #14b8a6, #0d9488)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <SearchIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            6. Static Analysis Workflow
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Static analysis examines the binary without running it. This is your first pass: extract the IPA, identify key
            components, search for strings, and map out classes and functions before diving into a disassembler.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>Command-Line Tools</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#14b8a6", 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Tool</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {staticAnalysisTools.map((tool) => (
                  <TableRow key={tool.tool}>
                    <TableCell sx={{ fontWeight: 600, color: "#14b8a6" }}>{tool.tool}</TableCell>
                    <TableCell>{tool.purpose}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{tool.command}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <CodeBlock
            title="Complete Static Analysis Workflow"
            language="bash"
            code={`#!/bin/bash
# iOS Static Analysis Script

APP_NAME="Target"
IPA_PATH="app.ipa"

# 1. Extract IPA
unzip -o "$IPA_PATH" -d extracted/
cd extracted/Payload/*.app/

# 2. Identify binary
BINARY=$(plutil -extract CFBundleExecutable raw Info.plist)
echo "[*] Binary: $BINARY"

# 3. Check architecture
file "$BINARY"
lipo -info "$BINARY"

# 4. Extract strings
echo "[*] Extracting strings..."
strings "$BINARY" > ../strings.txt
grep -iE "http|api|key|token|password|secret" ../strings.txt > ../interesting_strings.txt

# 5. List linked libraries
otool -L "$BINARY" > ../libraries.txt

# 6. Check for encryption (FairPlay)
otool -l "$BINARY" | grep -A4 LC_ENCRYPTION

# 7. Extract Objective-C headers
class-dump -H -o ../headers/ "$BINARY"

# 8. Check entitlements
codesign -d --entitlements :../entitlements.plist "$BINARY" 2>/dev/null

# 9. Analyze Info.plist
echo "[*] URL Schemes:"
plutil -extract CFBundleURLTypes json Info.plist 2>/dev/null

echo "[*] ATS Configuration:"
plutil -extract NSAppTransportSecurity json Info.plist 2>/dev/null

echo "[*] Static analysis complete!"`}
          />

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Disassemblers for Deeper Analysis</AlertTitle>
            For in-depth code analysis, load the binary into Ghidra (free), Hopper (macOS, paid), or IDA Pro (paid).
            These tools provide decompilation, cross-references, and control flow graphs.
          </Alert>
        </Paper>

        {/* ==================== SECTION 7: Dynamic Analysis ==================== */}
        <Paper id="dynamic-analysis" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}`, scrollMarginTop: 180 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #0ea5e9, #0284c7)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <TerminalIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            7. Dynamic Analysis Workflow
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Dynamic analysis observes the app while it runs. You can trace function calls, inspect memory, hook methods,
            and bypass security checks. This requires either a jailbroken device or a debuggable build of the app.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>Dynamic Analysis Tools</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#0ea5e9", 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Tool</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Use Cases</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {dynamicAnalysisTools.map((tool) => (
                  <TableRow key={tool.tool}>
                    <TableCell sx={{ fontWeight: 600, color: "#0ea5e9" }}>{tool.tool}</TableCell>
                    <TableCell>{tool.purpose}</TableCell>
                    <TableCell>{tool.use}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>LLDB Commands</Typography>
          <Grid container spacing={1} sx={{ mb: 3 }}>
            {lldbCommands.map((cmd) => (
              <Grid item xs={12} sm={6} key={cmd.command}>
                <Paper sx={{ p: 1.5, bgcolor: alpha("#0ea5e9", 0.05), borderRadius: 2 }}>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#0ea5e9", fontWeight: 600, display: "block" }}>{cmd.command}</Typography>
                  <Typography variant="caption" color="text.secondary">{cmd.purpose}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Accordion sx={{ mb: 2, bgcolor: alpha("#0ea5e9", 0.03), borderRadius: 2 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0ea5e9" }}>Frida: Method Tracing Script</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Trace Objective-C Methods" language="javascript" code={fridaScripts.methodTrace} />
            </AccordionDetails>
          </Accordion>

          <Accordion sx={{ mb: 2, bgcolor: alpha("#0ea5e9", 0.03), borderRadius: 2 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0ea5e9" }}>Frida: Keychain Dumper</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Dump Keychain Items" language="javascript" code={fridaScripts.keychainDump} />
            </AccordionDetails>
          </Accordion>
        </Paper>

        {/* ==================== SECTION 8: Device Setup ==================== */}
        <Paper id="device-setup" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}`, scrollMarginTop: 180 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #ef4444, #dc2626)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <PhoneIphoneIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            8. Device Setup and Jailbreak Basics
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            For serious iOS reverse engineering, you'll need a jailbroken test device. Jailbreaking removes iOS restrictions,
            giving you root access, SSH, and the ability to run unsigned code and dynamic instrumentation tools.
          </Typography>

          <Alert severity="warning" sx={{ mb: 3, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>⚠️ Use a Dedicated Test Device</AlertTitle>
            Never jailbreak your personal device. Use a spare device dedicated to testing. Always backup before jailbreaking.
          </Alert>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>Popular Jailbreak Tools</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#ef4444", 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Tool</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Compatible Devices</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {jailbreakTools.map((tool) => (
                  <TableRow key={tool.tool}>
                    <TableCell sx={{ fontWeight: 600, color: "#ef4444" }}>{tool.tool}</TableCell>
                    <TableCell>{tool.type}</TableCell>
                    <TableCell>{tool.devices}</TableCell>
                    <TableCell>{tool.notes}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <CodeBlock
            title="Post-Jailbreak Setup"
            language="bash"
            code={`# SSH to device (default password: alpine)
ssh root@<device-ip>
# CHANGE THE PASSWORD IMMEDIATELY
passwd

# Install essential packages via Sileo/Cydia
# - OpenSSH (if not already installed)
# - Frida from https://build.frida.re
# - AppSync Unified (sideloading)
# - Filza File Manager
# - NewTerm (terminal on device)

# Verify Frida server is running
frida-ps -U

# Test SSH file transfer
scp local_file root@<device-ip>:/var/root/

# Find installed apps
find /var/containers/Bundle/Application -name "*.app" -maxdepth 2

# Locate app data
find /var/mobile/Containers/Data/Application -type d -maxdepth 1`}
          />
        </Paper>

        {/* ==================== SECTION 9: Data Storage ==================== */}
        <Paper id="data-storage" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#10b981", 0.2)}`, scrollMarginTop: 180 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #10b981, #059669)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <StorageIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            9. Data Storage and Secrets
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            iOS apps store data in various locations with different security levels. During RE, you'll check for sensitive
            data stored insecurely—credentials in plists, tokens in SQLite, API keys hardcoded in the binary.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>Storage Locations</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#10b981", 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Location</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Path</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Security</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Analysis Tool</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {dataStorageLocations.map((loc) => (
                  <TableRow key={loc.location}>
                    <TableCell sx={{ fontWeight: 600, color: "#10b981" }}>{loc.location}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{loc.path}</TableCell>
                    <TableCell>{loc.security}</TableCell>
                    <TableCell>{loc.check}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <CodeBlock
            title="Analyzing App Data (Jailbroken Device)"
            language="bash"
            code={`# Find app's data container
BUNDLE_ID="com.target.app"
APP_DATA=$(find /var/mobile/Containers/Data/Application -name ".com.apple.mobile_container_manager.metadata.plist" -exec grep -l "$BUNDLE_ID" {} \\; | head -1 | xargs dirname)

cd "$APP_DATA"

# Check NSUserDefaults (plist files)
find Library/Preferences -name "*.plist" -exec plutil -p {} \\;

# Search for SQLite databases
find . -name "*.db" -o -name "*.sqlite"

# Examine SQLite contents
sqlite3 Documents/data.db ".tables"
sqlite3 Documents/data.db "SELECT * FROM users;"

# Check for sensitive data in caches
strings Library/Caches/* | grep -iE "token|key|pass|auth"

# Dump keychain items (requires keychain-dumper or Objection)
# objection --gadget com.target.app explore
# ios keychain dump`}
          />
        </Paper>

        {/* ==================== SECTION 10: Network Security ==================== */}
        <Paper id="network-security" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}`, scrollMarginTop: 180 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #f59e0b, #d97706)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <NetworkCheckIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            10. Network Behavior and ATS
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            App Transport Security (ATS) enforces HTTPS by default. Apps using SSL pinning add another layer that must
            be bypassed for traffic interception. Understanding network behavior reveals API endpoints, authentication
            flows, and potential vulnerabilities.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>SSL Pinning Types</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#f59e0b", 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Bypass Approach</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {sslPinningTypes.map((type) => (
                  <TableRow key={type.type}>
                    <TableCell sx={{ fontWeight: 600, color: "#f59e0b" }}>{type.type}</TableCell>
                    <TableCell>{type.description}</TableCell>
                    <TableCell>{type.bypass}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion sx={{ mb: 2, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b" }}>Frida: SSL Pinning Bypass Script</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Universal SSL Pinning Bypass" language="javascript" code={fridaScripts.sslBypass} />
            </AccordionDetails>
          </Accordion>

          <CodeBlock
            title="Network Interception Setup"
            language="bash"
            code={`# 1. Generate CA certificate (Burp Suite / mitmproxy)
mitmproxy --mode regular

# 2. Install CA on device
# Export cert, email to device, install via Settings > General > Profile

# 3. On jailbroken device, install cert to system trust store
# /Library/PreferenceBundles/TrustStore.sqlite3

# 4. Configure proxy on device
# Settings > Wi-Fi > (i) > Configure Proxy > Manual
# Server: your-computer-ip, Port: 8080

# 5. Run pinning bypass
frida -U -f com.target.app -l ssl_bypass.js --no-pause

# 6. Use Objection for automated bypass
objection --gadget com.target.app explore
# ios sslpinning disable`}
          />
        </Paper>

        {/* ==================== SECTION 11: Bypass Techniques ==================== */}
        <Paper id="bypass-techniques" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#ec4899", 0.2)}`, scrollMarginTop: 180 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #ec4899, #db2777)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <BuildIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            11. Bypass and Validation Techniques
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Apps implement various security checks to prevent analysis: jailbreak detection, debugger detection, integrity
            checks. Understanding and bypassing these is essential for dynamic analysis on protected apps.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>Jailbreak Detection Methods</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#ec4899", 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Method</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Bypass</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {jailbreakDetectionMethods.map((method) => (
                  <TableRow key={method.method}>
                    <TableCell sx={{ fontWeight: 600, color: "#ec4899" }}>{method.method}</TableCell>
                    <TableCell>{method.description}</TableCell>
                    <TableCell>{method.bypass}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Accordion sx={{ mb: 2, bgcolor: alpha("#ec4899", 0.03), borderRadius: 2 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ec4899" }}>Frida: Jailbreak Detection Bypass</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <CodeBlock title="Comprehensive Jailbreak Bypass" language="javascript" code={fridaScripts.jailbreakBypass} />
            </AccordionDetails>
          </Accordion>

          <CodeBlock
            title="Quick Bypass with Objection"
            language="bash"
            code={`# Launch app with Objection
objection --gadget com.target.app explore

# Disable jailbreak detection
ios jailbreak disable

# Disable SSL pinning
ios sslpinning disable

# Simulate non-jailbroken environment
ios jailbreak simulate

# Dump classes
ios hooking list classes

# Hook specific method
ios hooking watch class_method "-[JailbreakChecker isJailbroken]" --dump-return`}
          />
        </Paper>

        {/* ==================== SECTION 12: Reporting ==================== */}
        <Paper id="reporting-ethics" sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}`, scrollMarginTop: 180 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #8b5cf6, #7c3aed)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <GavelIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            12. Reporting and Ethics
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Reverse engineering comes with legal and ethical responsibilities. Document your findings clearly, report
            vulnerabilities responsibly, and always operate within authorized scope.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}>
                  <CheckCircleIcon /> Ethical Guidelines
                </Typography>
                <List dense>
                  {[
                    "Only analyze apps you own or have explicit permission to test",
                    "Follow responsible disclosure timelines (typically 90 days)",
                    "Never exploit vulnerabilities beyond proof-of-concept",
                    "Protect any user data discovered during analysis",
                    "Document methodology for reproducibility",
                    "Credit prior research and tools used",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.3 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 16 }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
                  <WarningIcon /> Legal Considerations
                </Typography>
                <List dense>
                  {[
                    "DMCA may apply to circumventing protection measures",
                    "Terms of Service may prohibit reverse engineering",
                    "Some jurisdictions have specific RE exemptions",
                    "Bug bounty programs provide legal safe harbor",
                    "Written authorization is your best protection",
                    "Consult legal counsel for commercial RE work",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.3 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <WarningIcon sx={{ color: "#ef4444", fontSize: 16 }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mt: 3, mb: 2, color: "#8b5cf6" }}>Report Template</Typography>
          <CodeBlock
            title="Vulnerability Report Structure"
            language="markdown"
            code={`# iOS Security Assessment Report

## Executive Summary
Brief overview of findings and risk level.

## Scope
- Application: [Name] v[Version]
- Bundle ID: com.company.app
- Test Device: [Model] iOS [Version]
- Test Period: [Dates]
- Authorization: [Reference]

## Methodology
Tools and techniques used.

## Findings

### [VULN-001] Insecure Data Storage
**Severity**: High
**Location**: Library/Preferences/com.app.plist
**Description**: Authentication token stored in plaintext.
**Impact**: Attacker with device access can steal credentials.
**Reproduction**:
1. Install app and authenticate
2. Extract plist: \`plutil -p Library/Preferences/com.app.plist\`
3. Observe plaintext token

**Recommendation**: Store sensitive data in Keychain with appropriate access control.

## Conclusion
Summary and prioritized remediation plan.`}
          />
        </Paper>

        {/* ==================== KEY TAKEAWAYS ==================== */}
        <Box id="key-takeaways" sx={{ scrollMarginTop: 180, mb: 5 }}>
          <Paper sx={{ p: 4, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
              <TipsAndUpdatesIcon sx={{ color: "#3b82f6" }} />
              Key Takeaways
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Start Static, Go Dynamic</Typography>
                <Typography variant="body2" color="text.secondary">
                  Always begin with static analysis to understand the app structure before running dynamic analysis.
                  Map classes, find interesting strings, understand the architecture first.
                </Typography>
              </Grid>
              <Grid item xs={12} md={4}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Tools Are Secondary</Typography>
                <Typography variant="body2" color="text.secondary">
                  Understanding iOS internals matters more than mastering any specific tool. Mach-O, Obj-C runtime,
                  sandboxing-these concepts transfer across all tools.
                </Typography>
              </Grid>
              <Grid item xs={12} md={4}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Document Everything</Typography>
                <Typography variant="body2" color="text.secondary">
                  Take notes as you analyze. Capture screenshots, save scripts, record your methodology.
                  Good notes make reporting easier and help you learn faster.
                </Typography>
              </Grid>
            </Grid>
          </Paper>
        </Box>

        <Box id="quiz" sx={{ scrollMarginTop: 180, mb: 4 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            Knowledge Quiz
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Test your understanding of iOS reverse engineering fundamentals.
          </Typography>
          <QuizSection />
        </Box>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            size="large"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{
              borderRadius: 2,
              px: 4,
              py: 1.5,
              fontWeight: 600,
              borderColor: alpha(accent, 0.3),
              color: accent,
              "&:hover": {
                borderColor: accent,
                bgcolor: alpha(accent, 0.05),
              },
            }}
          >
            Return to Learning Hub
          </Button>
        </Box>
      </Box>
    </Box>
  </Box>
    </LearnPageLayout>
  );
}
