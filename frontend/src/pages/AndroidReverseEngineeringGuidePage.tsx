import React, { useEffect, useState } from "react";
import {
  Box,
  Typography,
  Paper,
  Chip,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Grid,
  Card,
  CardContent,
  Drawer,
  Fab,
  alpha,
  Divider,
  Alert,
  AlertTitle,
  LinearProgress,
  useTheme,
  useMediaQuery,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import AndroidIcon from "@mui/icons-material/Android";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import LockIcon from "@mui/icons-material/Lock";
import BugReportIcon from "@mui/icons-material/BugReport";
import StorageIcon from "@mui/icons-material/Storage";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import SchoolIcon from "@mui/icons-material/School";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import TerminalIcon from "@mui/icons-material/Terminal";
import PhoneAndroidIcon from "@mui/icons-material/PhoneAndroid";
import QuizIcon from "@mui/icons-material/Quiz";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import RefreshIcon from "@mui/icons-material/Refresh";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import { useNavigate, Link } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";

// Quiz question type
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

// Question bank for Android Reverse Engineering quiz (75 questions)
const questionBank: QuizQuestion[] = [
  // Section 1: APK Structure & Basics (10 questions)
  {
    id: 1,
    question: "What file format is an APK file?",
    options: ["TAR archive", "ZIP archive", "RAR archive", "7z archive"],
    correctAnswer: 1,
    explanation: "An APK (Android Package) file is essentially a ZIP archive containing all resources and code for an Android app.",
    topic: "APK Structure"
  },
  {
    id: 2,
    question: "What does DEX stand for in Android?",
    options: ["Data Exchange", "Dalvik Executable", "Device Executable", "Debug Extension"],
    correctAnswer: 1,
    explanation: "DEX stands for Dalvik Executable, the bytecode format executed by the Android runtime.",
    topic: "APK Structure"
  },
  {
    id: 3,
    question: "Where is the AndroidManifest.xml located in an APK?",
    options: ["In the res folder", "In the root of the APK", "In the META-INF folder", "In the lib folder"],
    correctAnswer: 1,
    explanation: "AndroidManifest.xml is located at the root of the APK and contains essential app metadata.",
    topic: "APK Structure"
  },
  {
    id: 4,
    question: "What does the classes.dex file contain?",
    options: ["Native code", "Compiled Java/Kotlin bytecode", "Resources only", "Signatures"],
    correctAnswer: 1,
    explanation: "classes.dex contains the Dalvik bytecode compiled from Java/Kotlin source code.",
    topic: "APK Structure"
  },
  {
    id: 5,
    question: "What is the purpose of the resources.arsc file?",
    options: ["Store native libraries", "Compiled binary resources table", "Application signatures", "Debug symbols"],
    correctAnswer: 1,
    explanation: "resources.arsc is the compiled binary resources table containing strings, styles, and resource references.",
    topic: "APK Structure"
  },
  {
    id: 6,
    question: "What folder contains native libraries in an APK?",
    options: ["native/", "lib/", "jni/", "so/"],
    correctAnswer: 1,
    explanation: "The lib/ folder contains native libraries (.so files) organized by architecture (arm64-v8a, armeabi-v7a, x86, etc.).",
    topic: "APK Structure"
  },
  {
    id: 7,
    question: "What is the META-INF folder used for?",
    options: ["Metadata and APK signatures", "Native libraries", "User data", "Cache files"],
    correctAnswer: 0,
    explanation: "META-INF contains the APK signature files (CERT.SF, CERT.RSA/DSA, MANIFEST.MF).",
    topic: "APK Structure"
  },
  {
    id: 8,
    question: "What is an AXML file?",
    options: ["Audio XML", "Android compiled binary XML", "Archive XML", "Application XML"],
    correctAnswer: 1,
    explanation: "AXML is Android's compiled binary XML format, a compressed version of XML resource files.",
    topic: "APK Structure"
  },
  {
    id: 9,
    question: "Which signature scheme uses the APK Signing Block?",
    options: ["v1 (JAR signing)", "v2 and v3 (APK Signature Scheme)", "v0 (no signing)", "PGP signing"],
    correctAnswer: 1,
    explanation: "APK Signature Scheme v2 and v3 use the APK Signing Block for whole-file signing.",
    topic: "APK Structure"
  },
  {
    id: 10,
    question: "What happens when you rename an APK to .zip and extract it?",
    options: ["Nothing, it won't work", "You can view all contents including decompiled code", "You see the raw structure but XML is binary encoded", "The APK gets corrupted"],
    correctAnswer: 2,
    explanation: "Renaming to .zip lets you extract and see the structure, but XML files are in binary AXML format requiring tools like apktool to decode.",
    topic: "APK Structure"
  },

  // Section 2: Decompilation Tools (10 questions)
  {
    id: 11,
    question: "What is the primary purpose of apktool?",
    options: ["Sign APKs", "Decode/rebuild APKs with resources", "Only extract DEX files", "Obfuscate code"],
    correctAnswer: 1,
    explanation: "apktool decodes APKs to near-original form (including resources) and can rebuild them.",
    topic: "Decompilation Tools"
  },
  {
    id: 12,
    question: "What does jadx produce from an APK?",
    options: ["Smali code only", "Decompiled Java source code", "Native code", "Bytecode"],
    correctAnswer: 1,
    explanation: "jadx decompiles DEX/APK files directly to readable Java source code.",
    topic: "Decompilation Tools"
  },
  {
    id: 13,
    question: "What is Smali?",
    options: ["A programming language", "Human-readable DEX assembly language", "A compression format", "An encryption algorithm"],
    correctAnswer: 1,
    explanation: "Smali is the human-readable assembly language representation of Dalvik bytecode.",
    topic: "Decompilation Tools"
  },
  {
    id: 14,
    question: "What tool converts DEX to JAR files?",
    options: ["jadx", "dex2jar", "apktool", "smali"],
    correctAnswer: 1,
    explanation: "dex2jar converts DEX files to JAR format, which can then be decompiled with Java decompilers.",
    topic: "Decompilation Tools"
  },
  {
    id: 15,
    question: "Which tool provides a GUI for APK analysis with decompilation?",
    options: ["dex2jar", "JADX-GUI", "baksmali", "aapt"],
    correctAnswer: 1,
    explanation: "JADX-GUI provides a graphical interface for browsing decompiled Java code from APKs.",
    topic: "Decompilation Tools"
  },
  {
    id: 16,
    question: "What command decodes an APK using apktool?",
    options: ["apktool extract app.apk", "apktool d app.apk", "apktool decode app.apk", "apktool unzip app.apk"],
    correctAnswer: 1,
    explanation: "apktool d (decode) is the command to decode an APK to its decompiled form.",
    topic: "Decompilation Tools"
  },
  {
    id: 17,
    question: "What is baksmali?",
    options: ["An APK builder", "A disassembler for DEX to Smali", "A signing tool", "A resource extractor"],
    correctAnswer: 1,
    explanation: "baksmali is a disassembler that converts DEX bytecode to Smali assembly code.",
    topic: "Decompilation Tools"
  },
  {
    id: 18,
    question: "What command rebuilds an APK with apktool?",
    options: ["apktool rebuild folder/", "apktool b folder/", "apktool r folder/", "apktool build folder/"],
    correctAnswer: 1,
    explanation: "apktool b (build) rebuilds an APK from the decoded folder.",
    topic: "Decompilation Tools"
  },
  {
    id: 19,
    question: "Why might jadx show some methods as /* compiled code */?",
    options: ["The code is encrypted", "Decompilation failed for complex/obfuscated code", "It's native code", "Missing dependencies"],
    correctAnswer: 1,
    explanation: "jadx shows this when it cannot reliably decompile complex, unusual, or obfuscated bytecode patterns.",
    topic: "Decompilation Tools"
  },
  {
    id: 20,
    question: "What is JEB Decompiler known for?",
    options: ["Free and open source", "Professional-grade Android/native decompiler with advanced features", "Only for iOS", "Command-line only"],
    correctAnswer: 1,
    explanation: "JEB is a professional decompiler with advanced features like interactive analysis, scripting, and better obfuscation handling.",
    topic: "Decompilation Tools"
  },

  // Section 3: Dynamic Analysis & Frida (10 questions)
  {
    id: 21,
    question: "What is Frida?",
    options: ["A static analyzer", "A dynamic instrumentation toolkit", "An emulator", "A compiler"],
    correctAnswer: 1,
    explanation: "Frida is a dynamic instrumentation toolkit allowing runtime code injection and hooking.",
    topic: "Dynamic Analysis"
  },
  {
    id: 22,
    question: "What command lists running processes with Frida?",
    options: ["frida-ls", "frida-ps -U", "frida-list", "frida-processes"],
    correctAnswer: 1,
    explanation: "frida-ps -U lists processes on a USB-connected device.",
    topic: "Dynamic Analysis"
  },
  {
    id: 23,
    question: "What does the Java.perform() function do in Frida?",
    options: ["Executes Java code on PC", "Ensures code runs in the Java runtime context on Android", "Compiles Java code", "Starts the app"],
    correctAnswer: 1,
    explanation: "Java.perform() ensures your JavaScript code executes within the app's Java runtime context.",
    topic: "Dynamic Analysis"
  },
  {
    id: 24,
    question: "How do you hook a method's implementation in Frida?",
    options: ["Java.hook()", "ClassName.methodName.implementation = function(){}", "Java.replace()", "Method.intercept()"],
    correctAnswer: 1,
    explanation: "You set the implementation property of the method to a new function to hook it.",
    topic: "Dynamic Analysis"
  },
  {
    id: 25,
    question: "What is objection in Android security testing?",
    options: ["A legal term", "Runtime mobile exploration toolkit built on Frida", "An emulator", "A static analyzer"],
    correctAnswer: 1,
    explanation: "objection is a runtime exploration toolkit powered by Frida, simplifying common tasks.",
    topic: "Dynamic Analysis"
  },
  {
    id: 26,
    question: "What does frida-server do?",
    options: ["Hosts a web server", "Runs on the device to enable Frida instrumentation", "Compiles scripts", "Signs APKs"],
    correctAnswer: 1,
    explanation: "frida-server runs on the target device and communicates with the Frida client on your PC.",
    topic: "Dynamic Analysis"
  },
  {
    id: 27,
    question: "How can you spawn and attach to an app with Frida?",
    options: ["frida -U -f com.app.package", "frida -U -spawn com.app", "frida --start com.app", "frida -run com.app"],
    correctAnswer: 0,
    explanation: "frida -U -f <package> spawns the app and attaches Frida before execution continues.",
    topic: "Dynamic Analysis"
  },
  {
    id: 28,
    question: "What is the purpose of Java.choose() in Frida?",
    options: ["Select a Java version", "Find existing instances of a class in memory", "Choose a method to hook", "Pick a thread"],
    correctAnswer: 1,
    explanation: "Java.choose() searches the heap for existing instances of a specified class.",
    topic: "Dynamic Analysis"
  },
  {
    id: 29,
    question: "What tool provides a MITM proxy for intercepting app traffic?",
    options: ["Wireshark only", "Burp Suite or mitmproxy", "frida-trace", "jadx"],
    correctAnswer: 1,
    explanation: "Burp Suite and mitmproxy are commonly used to intercept and modify HTTP/HTTPS traffic.",
    topic: "Dynamic Analysis"
  },
  {
    id: 30,
    question: "What does frida-trace do?",
    options: ["Traces network packets", "Automatically generates hooks for specified functions/methods", "Traces file system", "Traces memory"],
    correctAnswer: 1,
    explanation: "frida-trace auto-generates hooks to trace function calls matching a pattern.",
    topic: "Dynamic Analysis"
  },

  // Section 4: Root Detection & Bypass (8 questions)
  {
    id: 31,
    question: "What is a common root detection method?",
    options: ["Checking screen size", "Checking for su binary or root management apps", "Checking battery level", "Checking app version"],
    correctAnswer: 1,
    explanation: "Apps commonly check for su binary, Magisk/SuperSU apps, or dangerous properties to detect root.",
    topic: "Root Detection"
  },
  {
    id: 32,
    question: "What is Magisk Hide / DenyList?",
    options: ["Hides the device", "Hides root from specific apps", "Hides user data", "Hides network traffic"],
    correctAnswer: 1,
    explanation: "Magisk Hide (now DenyList) conceals root status from selected apps.",
    topic: "Root Detection"
  },
  {
    id: 33,
    question: "Which property is commonly checked for root detection?",
    options: ["ro.build.version", "ro.debuggable or ro.secure", "ro.product.model", "ro.hardware"],
    correctAnswer: 1,
    explanation: "ro.debuggable and ro.secure properties indicate if the device is in a debuggable/insecure state.",
    topic: "Root Detection"
  },
  {
    id: 34,
    question: "How can Frida bypass root detection?",
    options: ["By uninstalling root", "By hooking detection methods to return false", "By encrypting the app", "By changing device ID"],
    correctAnswer: 1,
    explanation: "Frida can hook root detection methods and modify return values to indicate non-rooted device.",
    topic: "Root Detection"
  },
  {
    id: 35,
    question: "What does SafetyNet/Play Integrity check?",
    options: ["Network security only", "Device integrity, root, and tampering", "App performance", "Battery health"],
    correctAnswer: 1,
    explanation: "SafetyNet/Play Integrity checks device integrity, bootloader status, root, and system tampering.",
    topic: "Root Detection"
  },
  {
    id: 36,
    question: "What is a common location apps check for su binary?",
    options: ["/sdcard/su", "/system/bin/su or /system/xbin/su", "/data/local/su", "/cache/su"],
    correctAnswer: 1,
    explanation: "Common su binary locations include /system/bin/su, /system/xbin/su, and /sbin/su.",
    topic: "Root Detection"
  },
  {
    id: 37,
    question: "What is the purpose of checking for test-keys in build.prop?",
    options: ["Check app signature", "Detect custom/rooted ROM (not release-keys)", "Check encryption", "Verify developer"],
    correctAnswer: 1,
    explanation: "Official builds use release-keys; test-keys indicate a custom or potentially rooted ROM.",
    topic: "Root Detection"
  },
  {
    id: 38,
    question: "What library is commonly used by apps for root detection?",
    options: ["OpenSSL", "RootBeer", "OkHttp", "Retrofit"],
    correctAnswer: 1,
    explanation: "RootBeer is a popular open-source library for root detection in Android apps.",
    topic: "Root Detection"
  },

  // Section 5: SSL Pinning & Network (8 questions)
  {
    id: 39,
    question: "What is SSL/Certificate Pinning?",
    options: ["Encrypting the APK", "Hardcoding expected server certificate/public key in the app", "Hiding SSL traffic", "Compressing data"],
    correctAnswer: 1,
    explanation: "SSL pinning hardcodes the expected server certificate or public key to prevent MITM attacks.",
    topic: "SSL Pinning"
  },
  {
    id: 40,
    question: "Why does SSL pinning prevent proxy interception?",
    options: ["It encrypts traffic", "The app rejects proxy's certificate not matching the pinned cert", "It blocks all network", "It uses different protocol"],
    correctAnswer: 1,
    explanation: "Pinned apps reject the proxy's certificate because it doesn't match the expected pinned certificate.",
    topic: "SSL Pinning"
  },
  {
    id: 41,
    question: "What does the network_security_config.xml file define?",
    options: ["App permissions", "Network security settings including trusted CAs and pins", "API endpoints", "Database config"],
    correctAnswer: 1,
    explanation: "network_security_config.xml defines trusted CAs, certificate pins, and cleartext traffic policy.",
    topic: "SSL Pinning"
  },
  {
    id: 42,
    question: "What is a common way to bypass SSL pinning with Frida?",
    options: ["Delete the certificate", "Hook TrustManager and certificate validation to always succeed", "Change DNS", "Use a VPN"],
    correctAnswer: 1,
    explanation: "Frida scripts can hook TrustManager.checkServerTrusted() and similar methods to bypass validation.",
    topic: "SSL Pinning"
  },
  {
    id: 43,
    question: "What does objection's 'android sslpinning disable' do?",
    options: ["Enables pinning", "Hooks common pinning implementations to bypass them", "Deletes certificates", "Blocks network"],
    correctAnswer: 1,
    explanation: "This objection command hooks various SSL pinning implementations to bypass certificate validation.",
    topic: "SSL Pinning"
  },
  {
    id: 44,
    question: "What is OkHttp's CertificatePinner?",
    options: ["A certificate generator", "A pinning implementation that apps use with OkHttp", "An encryption tool", "A logging library"],
    correctAnswer: 1,
    explanation: "CertificatePinner is OkHttp's built-in SSL pinning mechanism that many apps use.",
    topic: "SSL Pinning"
  },
  {
    id: 45,
    question: "On Android 7+, what changed regarding user-installed CA certificates?",
    options: ["They're always trusted", "Apps don't trust them by default unless configured", "They're blocked completely", "No change"],
    correctAnswer: 1,
    explanation: "Android 7+ apps don't trust user-installed CAs by default; the app must explicitly allow them.",
    topic: "SSL Pinning"
  },
  {
    id: 46,
    question: "How can you make an app trust user certificates on Android 7+?",
    options: ["Root only", "Modify network_security_config.xml or use Magisk module", "Change system settings", "Use older Android"],
    correctAnswer: 1,
    explanation: "You can modify the app's network_security_config.xml or use Magisk modules to inject user CAs into system store.",
    topic: "SSL Pinning"
  },

  // Section 6: Smali & Patching (8 questions)
  {
    id: 47,
    question: "What does the Smali opcode 'invoke-virtual' do?",
    options: ["Calls a static method", "Calls a virtual (instance) method", "Creates an object", "Returns a value"],
    correctAnswer: 1,
    explanation: "invoke-virtual calls an instance method through virtual method dispatch.",
    topic: "Smali & Patching"
  },
  {
    id: 48,
    question: "In Smali, what does 'const/4 v0, 0x0' do?",
    options: ["Creates a string", "Loads the integer 0 into register v0", "Calls a method", "Returns null"],
    correctAnswer: 1,
    explanation: "const/4 loads a 4-bit constant (0 in this case) into the specified register.",
    topic: "Smali & Patching"
  },
  {
    id: 49,
    question: "How would you patch a method to always return true in Smali?",
    options: ["Delete the method", "Replace body with 'const/4 v0, 0x1' and 'return v0'", "Add a comment", "Change the method name"],
    correctAnswer: 1,
    explanation: "Setting v0 to 1 (true) and returning it makes the method always return true.",
    topic: "Smali & Patching"
  },
  {
    id: 50,
    question: "What is the Smali register naming convention?",
    options: ["r0, r1, r2", "v0, v1, v2 for locals and p0, p1 for parameters", "a, b, c", "reg1, reg2"],
    correctAnswer: 1,
    explanation: "Smali uses v-registers for locals and p-registers (parameter aliases) for method parameters.",
    topic: "Smali & Patching"
  },
  {
    id: 51,
    question: "After patching Smali code, what must you do before installing?",
    options: ["Nothing", "Rebuild with apktool and re-sign the APK", "Just rename the file", "Clear app data"],
    correctAnswer: 1,
    explanation: "After patching, you must rebuild with 'apktool b' and sign the APK with a valid keystore.",
    topic: "Smali & Patching"
  },
  {
    id: 52,
    question: "What tool is used to sign a rebuilt APK?",
    options: ["apktool sign", "jarsigner or apksigner", "signapk", "keytool sign"],
    correctAnswer: 1,
    explanation: "jarsigner or apksigner (Android SDK) are used to sign APKs after rebuilding.",
    topic: "Smali & Patching"
  },
  {
    id: 53,
    question: "What does 'zipalign' do to an APK?",
    options: ["Signs it", "Optimizes alignment of uncompressed data for better performance", "Compresses it", "Encrypts it"],
    correctAnswer: 1,
    explanation: "zipalign aligns uncompressed data on 4-byte boundaries for optimized memory-mapped access.",
    topic: "Smali & Patching"
  },
  {
    id: 54,
    question: "What Smali instruction is used for conditional branching?",
    options: ["goto", "if-eqz, if-nez, if-eq, etc.", "jump", "branch"],
    correctAnswer: 1,
    explanation: "Conditional branches use if-* instructions (if-eqz, if-nez, if-eq, if-ne, etc.).",
    topic: "Smali & Patching"
  },

  // Section 7: Native Code & Libraries (8 questions)
  {
    id: 55,
    question: "What is JNI in Android?",
    options: ["Java Network Interface", "Java Native Interface - bridge between Java and native code", "Java New Instance", "Java Numeric Interface"],
    correctAnswer: 1,
    explanation: "JNI (Java Native Interface) allows Java code to call and be called by native code (C/C++).",
    topic: "Native Code"
  },
  {
    id: 56,
    question: "What are .so files in an APK?",
    options: ["Sound files", "Shared object (native library) files", "Source files", "Settings files"],
    correctAnswer: 1,
    explanation: ".so files are shared object files containing compiled native code (like Linux .so libraries).",
    topic: "Native Code"
  },
  {
    id: 57,
    question: "What tool is commonly used to disassemble native libraries?",
    options: ["jadx", "IDA Pro or Ghidra", "apktool", "dex2jar"],
    correctAnswer: 1,
    explanation: "IDA Pro and Ghidra are powerful disassemblers/decompilers for analyzing native code.",
    topic: "Native Code"
  },
  {
    id: 58,
    question: "What is the common naming convention for JNI functions?",
    options: ["jni_methodName", "Java_packageName_ClassName_methodName", "native_methodName", "call_methodName"],
    correctAnswer: 1,
    explanation: "JNI functions follow Java_fully_qualified_ClassName_methodName convention.",
    topic: "Native Code"
  },
  {
    id: 59,
    question: "How can you hook native functions with Frida?",
    options: ["Java.use()", "Interceptor.attach() with the function address", "NativeFunction.hook()", "System.loadLibrary()"],
    correctAnswer: 1,
    explanation: "Frida's Interceptor.attach() hooks native functions at their memory addresses.",
    topic: "Native Code"
  },
  {
    id: 60,
    question: "What is System.loadLibrary() used for?",
    options: ["Load Java classes", "Load native .so libraries at runtime", "Load resources", "Load configuration"],
    correctAnswer: 1,
    explanation: "System.loadLibrary() loads native shared libraries (.so files) into the app's process.",
    topic: "Native Code"
  },
  {
    id: 61,
    question: "What architectures are common for Android native libraries?",
    options: ["x86 only", "arm64-v8a, armeabi-v7a, x86, x86_64", "PowerPC", "MIPS only"],
    correctAnswer: 1,
    explanation: "Common Android architectures are arm64-v8a (64-bit ARM), armeabi-v7a (32-bit ARM), x86, and x86_64.",
    topic: "Native Code"
  },
  {
    id: 62,
    question: "What makes native code harder to analyze than DEX?",
    options: ["It's smaller", "It's compiled machine code without high-level abstractions", "It's encrypted by default", "It requires root"],
    correctAnswer: 1,
    explanation: "Native code is compiled machine code, lacking the metadata and high-level structure of DEX bytecode.",
    topic: "Native Code"
  },

  // Section 8: Obfuscation & Protection (7 questions)
  {
    id: 63,
    question: "What is ProGuard/R8?",
    options: ["An emulator", "Code obfuscation and optimization tool for Android", "A testing framework", "A database"],
    correctAnswer: 1,
    explanation: "ProGuard/R8 obfuscates, optimizes, and shrinks Android apps by renaming and removing unused code.",
    topic: "Obfuscation"
  },
  {
    id: 64,
    question: "What does string encryption obfuscation do?",
    options: ["Makes strings longer", "Encrypts strings and decrypts at runtime to hide from static analysis", "Compresses strings", "Removes strings"],
    correctAnswer: 1,
    explanation: "String encryption hides sensitive strings from static analysis; they're decrypted only at runtime.",
    topic: "Obfuscation"
  },
  {
    id: 65,
    question: "What is control flow obfuscation?",
    options: ["Network protection", "Restructuring code logic to make it harder to understand", "Encrypting methods", "Hiding the APK"],
    correctAnswer: 1,
    explanation: "Control flow obfuscation adds fake branches, opaque predicates, and restructures code logic.",
    topic: "Obfuscation"
  },
  {
    id: 66,
    question: "What is a packer in Android protection?",
    options: ["A compression tool", "Tool that encrypts/hides the real DEX and unpacks at runtime", "A signing tool", "A manifest editor"],
    correctAnswer: 1,
    explanation: "Packers encrypt or hide the original DEX; a loader unpacks it into memory at runtime.",
    topic: "Obfuscation"
  },
  {
    id: 67,
    question: "How does reflection-based obfuscation work?",
    options: ["Uses mirrors", "Calls methods dynamically via reflection to hide direct references", "Encrypts reflection", "Blocks reflection"],
    correctAnswer: 1,
    explanation: "Methods are called via reflection APIs using encrypted strings, hiding direct method references.",
    topic: "Obfuscation"
  },
  {
    id: 68,
    question: "What is DexGuard?",
    options: ["A free tool", "Commercial app protection with advanced obfuscation and protection", "An open-source decompiler", "A testing tool"],
    correctAnswer: 1,
    explanation: "DexGuard is a commercial protection tool offering stronger obfuscation than ProGuard.",
    topic: "Obfuscation"
  },
  {
    id: 69,
    question: "What is anti-tampering protection?",
    options: ["Prevents app updates", "Detects modifications to the APK and prevents execution", "Encrypts the APK", "Compresses code"],
    correctAnswer: 1,
    explanation: "Anti-tampering checks APK integrity (signature, checksums) and blocks if modifications are detected.",
    topic: "Obfuscation"
  },

  // Section 9: Android Security Features (6 questions)
  {
    id: 70,
    question: "What is the Android Keystore system?",
    options: ["File storage", "Secure hardware-backed storage for cryptographic keys", "Password manager", "App store"],
    correctAnswer: 1,
    explanation: "Android Keystore provides hardware-backed secure storage for cryptographic keys.",
    topic: "Security Features"
  },
  {
    id: 71,
    question: "What is SELinux on Android?",
    options: ["A file system", "Mandatory access control system enforcing security policies", "A web browser", "A root tool"],
    correctAnswer: 1,
    explanation: "SELinux enforces mandatory access controls, limiting what processes can access regardless of permissions.",
    topic: "Security Features"
  },
  {
    id: 72,
    question: "What does 'android:exported=false' in a component mean?",
    options: ["Component is public", "Component cannot be accessed by other apps", "Component is disabled", "Component is hidden from user"],
    correctAnswer: 1,
    explanation: "exported=false means the component can only be accessed by the same app or apps with the same user ID.",
    topic: "Security Features"
  },
  {
    id: 73,
    question: "What is the purpose of Android's sandbox model?",
    options: ["Gaming feature", "Isolates apps from each other with unique UID/file permissions", "Cloud storage", "Development testing"],
    correctAnswer: 1,
    explanation: "Each app runs with a unique Linux UID, isolating its data and processes from other apps.",
    topic: "Security Features"
  },
  {
    id: 74,
    question: "What is Scoped Storage introduced in Android 10+?",
    options: ["Cloud storage", "Restricted file access limiting apps to their own directories", "Encrypted storage", "External storage only"],
    correctAnswer: 1,
    explanation: "Scoped Storage restricts apps to accessing only their own files without broad storage permissions.",
    topic: "Security Features"
  },
  {
    id: 75,
    question: "What is the purpose of runtime permissions (Android 6+)?",
    options: ["Install-time only", "Users grant sensitive permissions at runtime when needed", "Automatic permissions", "No permissions needed"],
    correctAnswer: 1,
    explanation: "Dangerous permissions must be requested at runtime, giving users control over when to grant access.",
    topic: "Security Features"
  }
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
    if (score >= 8) return "#22c55e";
    if (score >= 6) return "#f97316";
    return "#ef4444";
  };

  const getScoreMessage = (score: number) => {
    if (score === 10) return "Perfect! You're an Android RE master! 🏆";
    if (score >= 8) return "Excellent work! Strong Android security knowledge! 🌟";
    if (score >= 6) return "Good job! Keep studying Android internals! 📚";
    if (score >= 4) return "Not bad, but review the material again. 💪";
    return "Keep learning! Review the sections above. 📖";
  };

  if (!quizStarted) {
    return (
      <Paper
        id="quiz-section"
        sx={{
          p: 4,
          mb: 5,
          borderRadius: 4,
          bgcolor: alpha("#0f0f14", 0.8),
          border: `2px solid ${alpha("#22c55e", 0.3)}`,
          background: `linear-gradient(135deg, ${alpha("#22c55e", 0.05)} 0%, ${alpha("#16a34a", 0.05)} 100%)`,
        }}
      >
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2, color: "white" }}>
          <Box sx={{ width: 56, height: 56, borderRadius: 2, background: "linear-gradient(135deg, #22c55e, #16a34a)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <QuizIcon sx={{ color: "white", fontSize: 32 }} />
          </Box>
          Test Your Android RE Knowledge
        </Typography>

        <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8, fontSize: "1.05rem", color: "grey.300" }}>
          Ready to test what you've learned? Take this <strong>10-question quiz</strong> covering Android reverse engineering. 
          Questions are randomly selected from a pool of <strong>75 questions</strong>!
        </Typography>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#22c55e", 0.1), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#22c55e" }}>10</Typography>
              <Typography variant="caption" color="grey.400">Questions</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#3b82f6" }}>75</Typography>
              <Typography variant="caption" color="grey.400">Question Pool</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#a855f7", 0.1), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#a855f7" }}>9</Typography>
              <Typography variant="caption" color="grey.400">Topics Covered</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#f97316", 0.1), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#f97316" }}>∞</Typography>
              <Typography variant="caption" color="grey.400">Retakes Allowed</Typography>
            </Paper>
          </Grid>
        </Grid>

        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          startIcon={<QuizIcon />}
          sx={{ background: "linear-gradient(135deg, #22c55e, #16a34a)", fontWeight: 700, px: 4, py: 1.5, fontSize: "1.1rem", "&:hover": { background: "linear-gradient(135deg, #16a34a, #15803d)" } }}
        >
          Start Quiz
        </Button>
      </Paper>
    );
  }

  if (showResults) {
    const score = calculateScore();
    return (
      <Paper id="quiz-section" sx={{ p: 4, mb: 5, borderRadius: 4, bgcolor: alpha("#0f0f14", 0.8), border: `2px solid ${alpha(getScoreColor(score), 0.3)}` }}>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2, color: "white" }}>
          <EmojiEventsIcon sx={{ color: getScoreColor(score), fontSize: 40 }} />
          Quiz Results
        </Typography>

        <Box sx={{ textAlign: "center", mb: 4 }}>
          <Typography variant="h1" sx={{ fontWeight: 900, color: getScoreColor(score), mb: 1 }}>{score}/10</Typography>
          <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>{getScoreMessage(score)}</Typography>
          <Chip label={`${score * 10}%`} sx={{ bgcolor: alpha(getScoreColor(score), 0.15), color: getScoreColor(score), fontWeight: 700, fontSize: "1rem", px: 2 }} />
        </Box>

        <Divider sx={{ my: 3, borderColor: "grey.700" }} />
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "white" }}>Review Your Answers:</Typography>

        {currentQuestions.map((q, index) => {
          const isCorrect = userAnswers[q.id] === q.correctAnswer;
          return (
            <Paper key={q.id} sx={{ p: 2, mb: 2, borderRadius: 2, bgcolor: alpha(isCorrect ? "#22c55e" : "#ef4444", 0.05), border: `1px solid ${alpha(isCorrect ? "#22c55e" : "#ef4444", 0.2)}` }}>
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1 }}>
                <Chip label={`Q${index + 1}`} size="small" sx={{ bgcolor: isCorrect ? "#22c55e" : "#ef4444", color: "white", fontWeight: 700 }} />
                <Typography variant="body2" sx={{ fontWeight: 600, color: "white" }}>{q.question}</Typography>
              </Box>
              <Typography variant="body2" sx={{ color: "grey.400", ml: 4.5 }}>
                <strong>Your answer:</strong> {q.options[userAnswers[q.id]] || "Not answered"}
                {!isCorrect && (<><br /><strong style={{ color: "#22c55e" }}>Correct:</strong> {q.options[q.correctAnswer]}</>)}
              </Typography>
              {!isCorrect && (<Alert severity="info" sx={{ mt: 1, ml: 4.5, bgcolor: alpha("#3b82f6", 0.1) }}><Typography variant="caption">{q.explanation}</Typography></Alert>)}
            </Paper>
          );
        })}

        <Box sx={{ display: "flex", gap: 2, mt: 3 }}>
          <Button variant="contained" onClick={startQuiz} startIcon={<RefreshIcon />} sx={{ background: "linear-gradient(135deg, #22c55e, #16a34a)", fontWeight: 700 }}>Try Again</Button>
          <Button variant="outlined" onClick={() => setQuizStarted(false)} sx={{ fontWeight: 600, borderColor: "grey.600", color: "grey.300" }}>Back to Overview</Button>
        </Box>
      </Paper>
    );
  }

  const currentQuestion = currentQuestions[currentQuestionIndex];
  const answeredCount = Object.keys(userAnswers).length;

  return (
    <Paper id="quiz-section" sx={{ p: 4, mb: 5, borderRadius: 4, bgcolor: alpha("#0f0f14", 0.8), border: `2px solid ${alpha("#22c55e", 0.3)}` }}>
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "white" }}>Question {currentQuestionIndex + 1} of 10</Typography>
          <Chip label={currentQuestion.topic} size="small" sx={{ bgcolor: alpha("#a855f7", 0.15), color: "#a855f7", fontWeight: 600 }} />
        </Box>
        <Box sx={{ width: "100%", bgcolor: alpha("#22c55e", 0.1), borderRadius: 1, height: 8 }}>
          <Box sx={{ width: `${((currentQuestionIndex + 1) / 10) * 100}%`, bgcolor: "#22c55e", borderRadius: 1, height: "100%", transition: "width 0.3s ease" }} />
        </Box>
      </Box>

      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3, lineHeight: 1.6, color: "white" }}>{currentQuestion.question}</Typography>

      <Grid container spacing={2} sx={{ mb: 4 }}>
        {currentQuestion.options.map((option, index) => {
          const isSelected = userAnswers[currentQuestion.id] === index;
          return (
            <Grid item xs={12} key={index}>
              <Paper
                onClick={() => handleAnswerSelect(currentQuestion.id, index)}
                sx={{ p: 2, borderRadius: 2, cursor: "pointer", bgcolor: isSelected ? alpha("#22c55e", 0.15) : alpha("#1a1a24", 0.5), border: `2px solid ${isSelected ? "#22c55e" : alpha("#444", 0.3)}`, transition: "all 0.2s ease", "&:hover": { borderColor: "#22c55e", bgcolor: alpha("#22c55e", 0.08) } }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box sx={{ width: 32, height: 32, borderRadius: "50%", bgcolor: isSelected ? "#22c55e" : alpha("#666", 0.3), color: isSelected ? "white" : "grey.400", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: "0.9rem" }}>
                    {String.fromCharCode(65 + index)}
                  </Box>
                  <Typography variant="body1" sx={{ fontWeight: isSelected ? 600 : 400, color: "white" }}>{option}</Typography>
                </Box>
              </Paper>
            </Grid>
          );
        })}
      </Grid>

      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Button variant="outlined" disabled={currentQuestionIndex === 0} onClick={() => setCurrentQuestionIndex((prev) => prev - 1)} sx={{ borderColor: "grey.600", color: "grey.300" }}>Previous</Button>
        <Typography variant="body2" color="grey.400">{answeredCount}/10 answered</Typography>
        {currentQuestionIndex < 9 ? (
          <Button variant="contained" onClick={() => setCurrentQuestionIndex((prev) => prev + 1)} sx={{ background: "linear-gradient(135deg, #22c55e, #16a34a)" }}>Next</Button>
        ) : (
          <Button variant="contained" onClick={() => setShowResults(true)} disabled={answeredCount < 10} sx={{ background: answeredCount >= 10 ? "linear-gradient(135deg, #3b82f6, #2563eb)" : undefined, fontWeight: 700 }}>Submit Quiz</Button>
        )}
      </Box>
    </Paper>
  );
}

const CodeBlock: React.FC<{ code: string; language?: string; title?: string }> = ({
  code,
  language = "bash",
  title,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper
      sx={{
        bgcolor: "#0d1117",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(34, 197, 94, 0.2)",
        overflow: "hidden",
      }}
    >
      {title && (
        <Box sx={{ px: 2, py: 1, bgcolor: "rgba(34, 197, 94, 0.1)", borderBottom: "1px solid rgba(34, 197, 94, 0.2)" }}>
          <Typography variant="subtitle2" sx={{ color: "#22c55e", fontWeight: 600 }}>{title}</Typography>
        </Box>
      )}
      <Box sx={{ position: "absolute", top: title ? 40 : 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: alpha("#22c55e", 0.2), color: "#22c55e", fontSize: "0.7rem" }} />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: copied ? "#22c55e" : "#888" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          p: 2,
          pt: 3,
          overflow: "auto",
          fontFamily: "'Fira Code', 'Consolas', monospace",
          fontSize: "0.8rem",
          color: "#e6edf3",
          lineHeight: 1.6,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const AndroidReverseEngineeringGuidePage: React.FC = () => {
  const navigate = useNavigate();
  const theme = useTheme();
  const accent = "#22c55e";

  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const sectionNavItems = [
    { id: "intro", label: "Overview", icon: <AndroidIcon /> },
    { id: "fundamentals", label: "Fundamentals", icon: <SchoolIcon /> },
    { id: "architecture", label: "Architecture", icon: <PhoneAndroidIcon /> },
    { id: "tools-setup", label: "Tools & Setup", icon: <BuildIcon /> },
    { id: "static-analysis", label: "Static Analysis", icon: <CodeIcon /> },
    { id: "dynamic-analysis", label: "Dynamic Analysis", icon: <TerminalIcon /> },
    { id: "vulnerabilities", label: "Vulnerabilities", icon: <BugReportIcon /> },
    { id: "resources", label: "Resources", icon: <TipsAndUpdatesIcon /> },
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

  // Essential tools for Android RE
  const essentialTools = [
    { tool: "JADX", description: "DEX to Java decompiler with GUI - the go-to tool for reading Android app source code", category: "Static Analysis", url: "https://github.com/skylot/jadx" },
    { tool: "apktool", description: "APK disassembly/reassembly - essential for modifying and repackaging apps", category: "Static Analysis", url: "https://ibotpeaches.github.io/Apktool/" },
    { tool: "Frida", description: "Dynamic instrumentation toolkit - hook any function at runtime", category: "Dynamic Analysis", url: "https://frida.re/" },
    { tool: "objection", description: "Frida-powered runtime exploration with pre-built scripts", category: "Dynamic Analysis", url: "https://github.com/sensepost/objection" },
    { tool: "Ghidra", description: "NSA's reverse engineering suite - essential for native library analysis", category: "Native Code", url: "https://ghidra-sre.org/" },
    { tool: "Android Studio", description: "Official IDE with profiler, debugger, and layout inspector", category: "Development", url: "https://developer.android.com/studio" },
    { tool: "Burp Suite", description: "HTTP/HTTPS proxy for intercepting app traffic", category: "Network", url: "https://portswigger.net/burp" },
    { tool: "MobSF", description: "Mobile Security Framework - automated static/dynamic analysis", category: "Automation", url: "https://github.com/MobSF/Mobile-Security-Framework-MobSF" },
    { tool: "Drozer", description: "Android security assessment framework for IPC testing", category: "Dynamic Analysis", url: "https://github.com/WithSecureLabs/drozer" },
  ];

  // Additional tools by category
  const additionalTools = {
    "Static Analysis": [
      { name: "Bytecode Viewer", desc: "Java/Android decompiler with multiple backends" },
      { name: "APKiD", desc: "Identify packers, protectors, and obfuscators" },
      { name: "ClassyShark", desc: "Android executable browser" },
      { name: "dex2jar", desc: "Convert DEX to JAR for analysis" },
    ],
    "Dynamic Analysis": [
      { name: "Xposed Framework", desc: "System-wide hooks without app modification" },
      { name: "LSPosed", desc: "Modern Xposed implementation for newer Android" },
      { name: "RMS", desc: "Runtime Mobile Security - Frida web UI" },
      { name: "House", desc: "Runtime mobile analysis toolkit" },
    ],
    "Network Analysis": [
      { name: "mitmproxy", desc: "Interactive HTTPS proxy" },
      { name: "Charles Proxy", desc: "HTTP debugging proxy with SSL support" },
      { name: "PCAPdroid", desc: "No-root network capture on device" },
      { name: "HTTP Toolkit", desc: "Beautiful HTTP debugging tool" },
    ],
  };

  // Android architecture layers
  const androidLayers = [
    { layer: "Applications", description: "User apps, system apps (Java/Kotlin)", examples: "Gmail, Settings, Your APK" },
    { layer: "Framework", description: "Android APIs, Activity Manager, Content Providers", examples: "android.*, javax.*" },
    { layer: "Native Libraries", description: "C/C++ libraries, JNI", examples: "libc, libssl, libcrypto" },
    { layer: "Android Runtime (ART)", description: "DEX bytecode execution, JIT/AOT compilation", examples: "dalvikvm, dex2oat" },
    { layer: "HAL", description: "Hardware Abstraction Layer", examples: "Camera, Sensors, Audio" },
    { layer: "Linux Kernel", description: "Process management, memory, drivers", examples: "Binder IPC, SELinux" },
  ];

  // Android components
  const androidComponents = [
    { component: "Activity", description: "Single screen with UI, entry point for user interaction", security: "Can be exported and launched by other apps" },
    { component: "Service", description: "Background operations without UI", security: "Bound services can leak data, started services can be hijacked" },
    { component: "Broadcast Receiver", description: "Responds to system-wide broadcasts", security: "Can intercept sensitive broadcasts or be triggered maliciously" },
    { component: "Content Provider", description: "Manages shared app data", security: "SQL injection, path traversal, data leakage" },
  ];

  // Important Android directories
  const androidDirectories = [
    { path: "/data/data/<package>/", desc: "App private data directory", content: "SharedPrefs, databases, files" },
    { path: "/data/data/<package>/shared_prefs/", desc: "SharedPreferences XML files", content: "Often contains tokens, settings" },
    { path: "/data/data/<package>/databases/", desc: "SQLite databases", content: "User data, cached content" },
    { path: "/data/data/<package>/files/", desc: "Internal storage files", content: "App-created files" },
    { path: "/sdcard/Android/data/<package>/", desc: "External storage (less secure)", content: "Downloaded files, caches" },
    { path: "/data/app/<package>/", desc: "Installed APK location", content: "APK, native libs, ODEX" },
  ];

  // Common vulnerability categories
  const vulnCategories = [
    { category: "Insecure Data Storage", description: "Sensitive data in SharedPrefs, SQLite, files, logs", severity: "High", examples: "Plaintext passwords, tokens in SharedPreferences" },
    { category: "Insecure Communication", description: "Missing SSL pinning, cleartext traffic, weak TLS", severity: "High", examples: "HTTP traffic, accepting all certificates" },
    { category: "Insufficient Cryptography", description: "Weak algorithms, hardcoded keys, improper IV usage", severity: "Critical", examples: "DES, ECB mode, static keys in code" },
    { category: "Client-Side Injection", description: "WebView JavaScript injection, SQL injection, path traversal", severity: "High", examples: "addJavascriptInterface, raw SQL queries" },
    { category: "Improper Platform Usage", description: "Exported components, intent vulnerabilities, broadcast issues", severity: "Medium", examples: "Exported activities without permissions" },
    { category: "Code Tampering", description: "Lack of integrity checks, no root detection, debuggable", severity: "Medium", examples: "android:debuggable=true, no signature verification" },
    { category: "Reverse Engineering", description: "No obfuscation, debug builds, readable strings", severity: "Low", examples: "ProGuard disabled, hardcoded API keys" },
    { category: "Extraneous Functionality", description: "Hidden backdoors, debug endpoints, test code in production", severity: "High", examples: "Debug menus, bypass flags" },
  ];

  // Specific vulnerability patterns to search for
  const vulnPatterns = [
    { pattern: "MODE_WORLD_READABLE", desc: "Files readable by all apps", severity: "High" },
    { pattern: "setJavaScriptEnabled(true)", desc: "WebView with JS enabled - check for XSS", severity: "Medium" },
    { pattern: "addJavascriptInterface", desc: "Exposes Java objects to JavaScript", severity: "High" },
    { pattern: "android:exported=\"true\"", desc: "Component accessible to other apps", severity: "Medium" },
    { pattern: "android:debuggable=\"true\"", desc: "App can be debugged", severity: "Medium" },
    { pattern: "android:allowBackup=\"true\"", desc: "App data can be backed up via ADB", severity: "Low" },
    { pattern: "checkServerTrusted", desc: "Custom SSL - look for empty implementations", severity: "Critical" },
    { pattern: "ALLOW_ALL_HOSTNAME_VERIFIER", desc: "Accepts any hostname in SSL", severity: "Critical" },
    { pattern: "Log.d|Log.v|Log.i", desc: "Debug logging - may leak sensitive data", severity: "Low" },
    { pattern: "getExternalStorage", desc: "External storage usage - world-readable", severity: "Medium" },
  ];

  const pageContext = `This page covers Android Reverse Engineering fundamentals including Android OS architecture, APK structure, Dalvik/ART runtime, smali code, static analysis with JADX and APKTool, dynamic analysis with Frida, common vulnerability patterns, root detection bypass, certificate pinning bypass, and VRAgent AI-assisted analysis tools.`;

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
    <LearnPageLayout pageTitle="Android Reverse Engineering" pageContext={pageContext}>
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
            "&:hover": { bgcolor: "#16a34a" },
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
          <Box sx={{ minHeight: "100vh", bgcolor: "#0a0a0f", py: 4 }}>
            <Box sx={{ maxWidth: 1200, mx: "auto" }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Chip
            component={Link}
            to="/learn"
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            clickable
            variant="outlined"
            sx={{ borderRadius: 2, mb: 2, color: "#22c55e", borderColor: "#22c55e" }}
          />
          
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.1) }}>
              <AndroidIcon sx={{ fontSize: 48, color: "#22c55e" }} />
            </Box>
            <Box>
              <Typography variant="h3" sx={{ fontWeight: 800, color: "white" }}>
                Android Reverse Engineering
              </Typography>
              <Typography variant="h6" sx={{ color: "grey.400" }}>
                Comprehensive Guide to Android Security Research & App Analysis
              </Typography>
            </Box>
          </Box>
        </Box>

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

        <Box id="intro" sx={{ scrollMarginTop: 180, mb: 5 }}>
          {/* Comprehensive Introduction Section */}
          <Paper sx={{ p: 4, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            🔬 What is Android Reverse Engineering?
          </Typography>

          <Typography variant="body1" sx={{ fontSize: "1.1rem", lineHeight: 1.9, mb: 2, color: "grey.200" }}>
            <strong>Android reverse engineering</strong> is the process of analyzing Android applications (APK files) to 
            understand how they work without access to the original source code. With over 3 billion active Android devices 
            worldwide, Android apps handle everything from banking and healthcare to social media and gaming — making them 
            prime targets for security researchers, penetration testers, and unfortunately, attackers. Understanding how to 
            dissect and analyze Android apps is an essential skill for mobile security professionals.
          </Typography>

          <Typography variant="body1" sx={{ fontSize: "1.1rem", lineHeight: 1.9, mb: 2, color: "grey.200" }}>
            <strong>What makes Android unique for reverse engineering?</strong> Unlike traditional compiled programs (like 
            Windows .exe files), Android apps are distributed as APK (Android Package) files — essentially ZIP archives 
            containing compiled bytecode, resources, and metadata. The app's Java or Kotlin code is compiled into DEX 
            (Dalvik Executable) format, which runs on the Android Runtime (ART). This bytecode is easier to decompile 
            back to readable Java code than native x86/ARM binaries, making Android a relatively accessible platform 
            for learning reverse engineering. However, many apps include native code (C/C++ libraries in .so files) 
            that requires traditional binary analysis techniques.
          </Typography>

          <Typography variant="body1" sx={{ fontSize: "1.1rem", lineHeight: 1.9, mb: 2, color: "grey.200" }}>
            <strong>Why would you reverse engineer Android apps?</strong> Security researchers analyze apps to find 
            vulnerabilities: insecure data storage (passwords saved in plaintext), weak cryptography (hardcoded keys), 
            improper certificate validation (allowing MITM attacks), or exported components that can be exploited by 
            malicious apps. Bug bounty hunters examine popular apps for security flaws that qualify for rewards. 
            Malware analysts dissect suspicious apps to understand their behavior, identify command-and-control servers, 
            and develop detection signatures. Developers audit third-party SDKs and libraries their apps depend on. 
            And sometimes, researchers simply want to understand how a clever feature was implemented.
          </Typography>

          <Typography variant="body1" sx={{ fontSize: "1.1rem", lineHeight: 1.9, mb: 2, color: "grey.200" }}>
            <strong>The APK structure</strong> is your starting point. An APK contains: <code>classes.dex</code> (or 
            multiple DEX files) with the compiled application code; <code>AndroidManifest.xml</code> describing the 
            app's components, permissions, and requirements; the <code>res/</code> folder with layouts, strings, and 
            other resources; the <code>lib/</code> folder containing native libraries for different CPU architectures; 
            and <code>assets/</code> for raw files the app uses. Tools like <strong>JADX</strong> can decompile the DEX 
            bytecode back to Java, while <strong>apktool</strong> decodes the binary XML resources and allows you to 
            repackage modified APKs.
          </Typography>

          <Typography variant="body1" sx={{ fontSize: "1.1rem", lineHeight: 1.9, mb: 3, color: "grey.200" }}>
            <strong>Dynamic analysis</strong> is equally important. While static analysis shows you the code, dynamic 
            analysis shows you the app in action. Tools like <strong>Frida</strong> let you hook into running apps, 
            intercept function calls, modify return values, and bypass security checks in real-time. You can disable 
            root detection, bypass certificate pinning to intercept HTTPS traffic, and trace exactly what happens when 
            a user taps a button. This combination of static analysis (reading the code) and dynamic analysis (watching 
            it run) gives you a complete picture of how an app behaves.
          </Typography>

          <Divider sx={{ my: 3, borderColor: "rgba(34, 197, 94, 0.2)" }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            📱 Android Architecture Overview
          </Typography>

          <Typography variant="body1" sx={{ fontSize: "1rem", lineHeight: 1.8, mb: 2, color: "grey.300" }}>
            Android is built in layers. Understanding this architecture helps you know where to look for different 
            types of vulnerabilities and what tools to use:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { layer: "Applications", desc: "User apps and system apps written in Java/Kotlin. This is where most RE focuses.", color: "#22c55e" },
              { layer: "Android Framework", desc: "APIs for activities, content providers, services. Security boundaries live here.", color: "#10b981" },
              { layer: "Native Libraries", desc: "C/C++ libs (OpenGL, SQLite, SSL). Requires binary RE skills like Ghidra/IDA.", color: "#059669" },
              { layer: "ART Runtime", desc: "Executes DEX bytecode. JIT/AOT compilation, garbage collection.", color: "#047857" },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.layer}>
                <Paper sx={{ p: 2, bgcolor: alpha(item.color, 0.1), borderRadius: 2, border: `1px solid ${alpha(item.color, 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.layer}</Typography>
                  <Typography variant="body2" sx={{ color: "grey.300" }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            🎯 Common Security Issues in Android Apps
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { title: "Insecure Data Storage", desc: "Sensitive data in SharedPreferences, SQLite databases, or log files without encryption", icon: <StorageIcon />, color: "#ef4444" },
              { title: "Weak SSL/TLS", desc: "Missing certificate pinning, accepting all certificates, or allowing cleartext HTTP", icon: <LockIcon />, color: "#f59e0b" },
              { title: "Exported Components", desc: "Activities, services, or content providers accessible to other apps without proper permissions", icon: <WarningIcon />, color: "#8b5cf6" },
              { title: "Hardcoded Secrets", desc: "API keys, credentials, or encryption keys embedded directly in the code", icon: <SecurityIcon />, color: "#3b82f6" },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.title}>
                <Paper sx={{ p: 2, bgcolor: alpha(item.color, 0.08), borderRadius: 2, border: `1px solid ${alpha(item.color, 0.2)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Box sx={{ color: item.color }}>{item.icon}</Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>{item.title}</Typography>
                  </Box>
                  <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="success" sx={{ bgcolor: "rgba(34, 197, 94, 0.1)" }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Getting Started</AlertTitle>
            Begin with static analysis: download an APK, decompile it with JADX, and explore the code. Look for the 
            <code>AndroidManifest.xml</code> to understand app structure, search for "password" or "api_key" in strings, 
            and examine how data flows through the app. Once comfortable, move to dynamic analysis with Frida.
          </Alert>
        </Paper>
        </Box>

        <Box id="fundamentals" sx={{ scrollMarginTop: 180, mb: 5 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, color: "white" }}>
            Fundamentals
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Core concepts to understand APK structure, bytecode, and Android RE goals.
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  What is Android Reverse Engineering?
                </Typography>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 2 }}>
                  Android reverse engineering is the process of analyzing Android applications to understand how they work,
                  find security vulnerabilities, or extract information without access to the original source code. Unlike
                  compiled native binaries, Android apps are relatively easier to reverse engineer because they compile to
                  Dalvik bytecode (DEX) which can be decompiled back to readable Java/Kotlin code.
                </Typography>
                <Grid container spacing={2} sx={{ mt: 2 }}>
                  {[
                    { title: "Security Research", desc: "Find vulnerabilities before attackers do - authentication bypasses, data leaks, injection flaws", icon: <SecurityIcon /> },
                    { title: "Malware Analysis", desc: "Understand malicious app behavior - C2 servers, exfiltration methods, persistence mechanisms", icon: <BugReportIcon /> },
                    { title: "Penetration Testing", desc: "Test mobile apps for clients - API security, local storage, network traffic analysis", icon: <TerminalIcon /> },
                    { title: "Bug Bounty", desc: "Find vulnerabilities in popular apps for rewards - many companies have mobile programs", icon: <StorageIcon /> },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} md={3} key={item.title}>
                      <Card sx={{ bgcolor: alpha("#22c55e", 0.05), height: "100%" }}>
                        <CardContent>
                          <Box sx={{ color: "#22c55e", mb: 1 }}>{item.icon}</Box>
                          <Typography sx={{ color: "white", fontWeight: 600 }}>{item.title}</Typography>
                          <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  APK File Structure
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  An APK (Android Package) is essentially a ZIP file containing everything needed to run an Android app.
                  You can unzip any APK to explore its contents:
                </Typography>
                <CodeBlock
                  title="Extract APK Contents"
                  language="bash"
                  code={`# Simply unzip the APK
unzip app.apk -d extracted/

# Or use apktool for decoded resources
apktool d app.apk -o decoded/`}
                />
                <Grid container spacing={2}>
                  {[
                    { file: "AndroidManifest.xml", desc: "App metadata, permissions, components - START HERE! Binary XML that needs decoding" },
                    { file: "classes.dex", desc: "Compiled Dalvik bytecode - your Java/Kotlin code lives here. May have classes2.dex, classes3.dex for multidex" },
                    { file: "resources.arsc", desc: "Compiled resources table - maps resource IDs to values (strings, colors, dimensions)" },
                    { file: "res/", desc: "Resource files - layouts (XML), images (PNG/WebP), raw assets. Partially compiled" },
                    { file: "lib/", desc: "Native libraries (.so) - ARM, ARM64, x86 subdirectories. Analyze with Ghidra/IDA" },
                    { file: "assets/", desc: "Raw bundled files - configs, databases, HTML, JavaScript. Often contains secrets!" },
                    { file: "META-INF/", desc: "Signature and certificate - CERT.RSA, CERT.SF, MANIFEST.MF. Verifies app integrity" },
                    { file: "kotlin/", desc: "Kotlin metadata files - present in Kotlin apps, can reveal original structure" },
                  ].map((item) => (
                    <Grid item xs={12} sm={6} key={item.file}>
                      <Box sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                        <Typography sx={{ color: "#22c55e", fontFamily: "monospace", fontWeight: 600 }}>{item.file}</Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>{item.desc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  DEX vs Native Code
                </Typography>
                <Grid container spacing={3}>
                  <Grid item xs={12} md={6}>
                    <Box sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2, border: "1px solid rgba(59, 130, 246, 0.3)" }}>
                      <Typography sx={{ color: "#3b82f6", fontWeight: 700, mb: 1 }}>DEX (Dalvik Executable)</Typography>
                      <List dense>
                        {[
                          "Java/Kotlin source → DEX bytecode",
                          "Easily decompiled with JADX",
                          "Runs on ART (Android Runtime)",
                          "Most app logic lives here",
                          "Obfuscation makes it harder but not impossible",
                        ].map((item, i) => (
                          <ListItem key={i} sx={{ py: 0.5 }}>
                            <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: "#3b82f6", fontSize: 16 }} /></ListItemIcon>
                            <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{item}</Typography>} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Box sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 2, border: "1px solid rgba(245, 158, 11, 0.3)" }}>
                      <Typography sx={{ color: "#f59e0b", fontWeight: 700, mb: 1 }}>Native Code (.so files)</Typography>
                      <List dense>
                        {[
                          "C/C++ source → ARM/x86 assembly",
                          "Requires disassemblers (Ghidra, IDA)",
                          "Used for performance, security, games",
                          "JNI bridge connects Java ↔ Native",
                          "Harder to reverse but not impossible",
                        ].map((item, i) => (
                          <ListItem key={i} sx={{ py: 0.5 }}>
                            <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: "#f59e0b", fontSize: 16 }} /></ListItemIcon>
                            <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{item}</Typography>} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </Box>

        <Box id="architecture" sx={{ scrollMarginTop: 180, mb: 5 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, color: "white" }}>
            Android Architecture
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            A layered view of Android internals and the core app components.
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 3, fontWeight: 700 }}>
                  Android System Architecture
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Layer</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Description</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Examples</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {androidLayers.map((row) => (
                        <TableRow key={row.layer}>
                          <TableCell sx={{ color: "white", fontWeight: 600 }}>{row.layer}</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>{row.description}</TableCell>
                          <TableCell sx={{ color: "grey.400", fontFamily: "monospace", fontSize: "0.85rem" }}>{row.examples}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Android App Components
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Android apps are built from four main component types. Each can be an entry point for attacks:
                </Typography>
                <Grid container spacing={2}>
                  {androidComponents.map((comp) => (
                    <Grid item xs={12} sm={6} key={comp.component}>
                      <Card sx={{ bgcolor: alpha("#22c55e", 0.05), height: "100%" }}>
                        <CardContent>
                          <Typography sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>{comp.component}</Typography>
                          <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>{comp.description}</Typography>
                          <Alert severity="warning" sx={{ py: 0.5, bgcolor: "transparent", color: "#f59e0b" }}>
                            <Typography variant="caption">{comp.security}</Typography>
                          </Alert>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Important File System Locations
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Path</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Description</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>What to Look For</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {androidDirectories.map((dir) => (
                        <TableRow key={dir.path}>
                          <TableCell sx={{ color: "#3b82f6", fontFamily: "monospace", fontSize: "0.8rem" }}>{dir.path}</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>{dir.desc}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{dir.content}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
                <CodeBlock
                  title="Explore App Data (requires root or ADB backup)"
                  language="bash"
                  code={`# With root access
adb shell
su
cd /data/data/com.example.app/
ls -la
cat shared_prefs/preferences.xml

# Without root - use run-as (only for debuggable apps)
adb shell run-as com.example.app ls -la

# Backup method (if allowBackup=true)
adb backup -f backup.ab com.example.app
java -jar abe.jar unpack backup.ab backup.tar`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Intent System
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Intents are the messaging system that allows components to communicate. They're a prime attack surface:
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { type: "Explicit Intent", desc: "Targets a specific component by name", example: "new Intent(this, TargetActivity.class)", risk: "Low - internal communication" },
                    { type: "Implicit Intent", desc: "Declares an action, system finds handler", example: "new Intent(Intent.ACTION_VIEW, uri)", risk: "Medium - can be intercepted" },
                    { type: "Broadcast Intent", desc: "Sent to all registered receivers", example: "sendBroadcast(intent)", risk: "High - can leak data" },
                    { type: "Pending Intent", desc: "Token given to external apps", example: "PendingIntent.getActivity(...)", risk: "Critical - if mutable, can be hijacked" },
                  ].map((intent) => (
                    <Grid item xs={12} sm={6} key={intent.type}>
                      <Box sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                        <Typography sx={{ color: "#22c55e", fontWeight: 600 }}>{intent.type}</Typography>
                        <Typography variant="body2" sx={{ color: "grey.300" }}>{intent.desc}</Typography>
                        <Typography variant="caption" sx={{ color: "#3b82f6", fontFamily: "monospace", display: "block", mt: 1 }}>{intent.example}</Typography>
                        <Chip label={intent.risk} size="small" sx={{ mt: 1, bgcolor: alpha(intent.risk.includes("Critical") ? "#ef4444" : intent.risk.includes("High") ? "#f59e0b" : "#22c55e", 0.2), color: intent.risk.includes("Critical") ? "#ef4444" : intent.risk.includes("High") ? "#f59e0b" : "#22c55e" }} />
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </Box>

        <Box id="tools-setup" sx={{ scrollMarginTop: 180, mb: 5 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, color: "white" }}>
            Tools & Setup
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            The core toolkit for Android RE, from decompilers to dynamic instrumentation.
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 3, fontWeight: 700 }}>
                  Essential Tools
                </Typography>
                <Grid container spacing={2}>
                  {essentialTools.map((tool) => (
                    <Grid item xs={12} sm={6} md={4} key={tool.tool}>
                      <Card sx={{ bgcolor: alpha("#22c55e", 0.05), height: "100%" }}>
                        <CardContent>
                          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "start", mb: 1 }}>
                            <Typography sx={{ color: "white", fontWeight: 700 }}>{tool.tool}</Typography>
                            <Chip label={tool.category} size="small" sx={{ bgcolor: alpha("#22c55e", 0.2), color: "#22c55e" }} />
                          </Box>
                          <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>{tool.description}</Typography>
                          <Button size="small" href={tool.url} target="_blank" sx={{ color: "#22c55e" }}>
                            Learn More →
                          </Button>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Additional Tools by Category
                </Typography>
                <Grid container spacing={2}>
                  {Object.entries(additionalTools).map(([category, tools]) => (
                    <Grid item xs={12} md={4} key={category}>
                      <Box sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                        <Typography sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>{category}</Typography>
                        <List dense>
                          {tools.map((tool) => (
                            <ListItem key={tool.name} sx={{ px: 0, py: 0.5 }}>
                              <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: "#22c55e", fontSize: 16 }} /></ListItemIcon>
                              <ListItemText 
                                primary={<Typography variant="body2" sx={{ color: "white" }}>{tool.name}</Typography>}
                                secondary={<Typography variant="caption" sx={{ color: "grey.500" }}>{tool.desc}</Typography>}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Quick Setup Commands
                </Typography>
                <CodeBlock
                  title="Install Essential Tools (Ubuntu/Debian)"
                  language="bash"
                  code={`# Install Java (required for most tools)
sudo apt install openjdk-17-jdk

# Install apktool
sudo apt install apktool
# Or latest version:
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar
sudo mv apktool_2.9.3.jar /usr/local/bin/apktool.jar

# Install JADX
wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d ~/tools/jadx
echo 'export PATH=$PATH:~/tools/jadx/bin' >> ~/.bashrc

# Install Frida
pip install frida-tools
# For device: push frida-server (match your arch)
adb push frida-server-16.1.4-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# Install ADB (Android Debug Bridge)
sudo apt install adb

# Install objection
pip install objection`}
                />

                <CodeBlock
                  title="Device Setup"
                  language="bash"
                  code={`# Enable USB debugging on device:
# Settings > Developer Options > USB Debugging

# Verify device connection
adb devices

# Get device shell
adb shell

# Install APK
adb install app.apk

# Pull APK from device
adb shell pm path com.example.app
adb pull /data/app/com.example.app-1/base.apk

# Logcat (view app logs)
adb logcat | grep -i "com.example.app"

# Port forwarding for Burp
adb reverse tcp:8080 tcp:8080`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 2, border: "1px solid rgba(245, 158, 11, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", mb: 2, fontWeight: 700 }}>
                  ⚠️ Emulator vs Physical Device
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography sx={{ color: "white", fontWeight: 600, mb: 1 }}>Emulator (Genymotion/AVD)</Typography>
                    <List dense>
                      {[
                        "Easy to root and configure",
                        "Can install Xposed/Frida easily",
                        "Some apps detect emulators",
                        "Performance can be slow",
                        "Missing some hardware features",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>• {item}</Typography>} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography sx={{ color: "white", fontWeight: 600, mb: 1 }}>Physical Device</Typography>
                    <List dense>
                      {[
                        "Real-world behavior",
                        "Better for network testing",
                        "Root may void warranty",
                        "Some devices hard to root",
                        "Recommended: Pixel or OnePlus",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>• {item}</Typography>} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </Box>

        <Box id="static-analysis" sx={{ scrollMarginTop: 180, mb: 5 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, color: "white" }}>
            Static Analysis
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Decompile and inspect APKs without executing them.
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Static Analysis Techniques
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                  Static analysis examines the app without executing it. This includes decompiling, disassembling, 
                  and reviewing code. It's safer than dynamic analysis and reveals the complete codebase.
                </Typography>
                
                <Alert severity="info" sx={{ mb: 3, bgcolor: alpha("#3b82f6", 0.1) }}>
                  <Typography variant="body2">
                    <strong>Analysis Flow:</strong> Start with AndroidManifest.xml → identify entry points (Activities, 
                    Services, Receivers, Providers) → trace data flow → look for hardcoded secrets → analyze network calls
                  </Typography>
                </Alert>

                <CodeBlock
                  title="Decompile APK with JADX"
                  language="bash"
                  code={`# GUI mode - best for exploration
jadx-gui app.apk

# Command line - output to directory
jadx -d output_dir app.apk

# Export as Gradle project (can import to Android Studio)
jadx -e -d output_dir app.apk

# Decompile with all options
jadx -d output --deobf --show-bad-code --escape-unicode app.apk`}
                />

                <CodeBlock
                  title="Disassemble with apktool (for Smali)"
                  language="bash"
                  code={`# Decode APK to Smali and resources
apktool d app.apk -o output_dir

# Decode without resources (faster)
apktool d -r app.apk -o output_dir

# Rebuild after modifications
apktool b output_dir -o modified.apk

# Sign the modified APK (required to install)
keytool -genkey -v -keystore debug.keystore -alias debug -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks debug.keystore --ks-key-alias debug modified.apk
# Or with jarsigner:
jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore debug.keystore modified.apk debug`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  What to Look For
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <CodeBlock
                      title="Search for Secrets (grep)"
                      language="bash"
                      code={`# API Keys
grep -rn "api_key\\|apikey\\|api-key" output_dir/
grep -rn "AIza[0-9A-Za-z_-]{35}" output_dir/  # Google API

# Passwords and tokens
grep -rn "password\\|passwd\\|secret\\|token" output_dir/

# URLs and endpoints
grep -rn "https://\\|http://" output_dir/
grep -rn "api\\." output_dir/

# Firebase
grep -rn "firebase\\|firebaseio.com" output_dir/

# AWS
grep -rn "AKIA[0-9A-Z]{16}" output_dir/  # AWS Access Key`}
                    />
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <CodeBlock
                      title="Search for Vulnerabilities"
                      language="bash"
                      code={`# Insecure WebView
grep -rn "setJavaScriptEnabled\\|addJavascriptInterface" output_dir/

# SQL Injection
grep -rn "rawQuery\\|execSQL" output_dir/

# Logging sensitive data
grep -rn "Log\\.d\\|Log\\.v\\|Log\\.i" output_dir/

# Insecure storage
grep -rn "MODE_WORLD_READABLE\\|MODE_WORLD_WRITEABLE" output_dir/

# Weak crypto
grep -rn "DES\\|MD5\\|SHA1" output_dir/

# Certificate pinning bypass opportunities
grep -rn "checkServerTrusted\\|X509TrustManager" output_dir/`}
                    />
                  </Grid>
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Manifest Analysis
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  The AndroidManifest.xml is your roadmap. Always start here:
                </Typography>
                <CodeBlock
                  title="Key Manifest Elements"
                  language="xml"
                  code={`<!-- Dangerous: App can be debugged -->
<application android:debuggable="true" ...>

<!-- Dangerous: Backup enabled (data extraction) -->
<application android:allowBackup="true" ...>

<!-- Check: What permissions does it request? -->
<uses-permission android:name="android.permission.READ_SMS" />
<uses-permission android:name="android.permission.CAMERA" />

<!-- Attack Surface: Exported components -->
<activity android:name=".AdminActivity" android:exported="true" />
<service android:name=".BackgroundService" android:exported="true" />
<receiver android:name=".BootReceiver" android:exported="true" />
<provider android:name=".DataProvider" 
          android:exported="true" 
          android:authorities="com.app.provider" />

<!-- Deep Links: URL entry points -->
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <data android:scheme="myapp" android:host="*" />
</intent-filter>

<!-- Network Security Config -->
<application android:networkSecurityConfig="@xml/network_security_config" ...>`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Native Library Analysis
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  If the app uses native code (.so files), you'll need Ghidra or IDA Pro:
                </Typography>
                <CodeBlock
                  title="Analyze Native Libraries"
                  language="bash"
                  code={`# List native libraries
ls -la lib/arm64-v8a/  # or armeabi-v7a, x86, x86_64

# Check library info
file lib/arm64-v8a/libnative.so
readelf -d lib/arm64-v8a/libnative.so

# Find JNI functions (entry points from Java)
nm -D lib/arm64-v8a/libnative.so | grep Java_

# Open in Ghidra
ghidraRun  # Then File > Import > select .so file

# Strings in native code
strings lib/arm64-v8a/libnative.so | grep -i "password\\|key\\|secret\\|http"`}
                />
              </Paper>
            </Grid>
          </Grid>
        </Box>

        <Box id="dynamic-analysis" sx={{ scrollMarginTop: 180, mb: 5 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, color: "white" }}>
            Dynamic Analysis
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Hook, trace, and intercept behavior while the app runs.
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Dynamic Analysis & Runtime Instrumentation
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                  Dynamic analysis runs the app and observes its behavior in real-time. Use Frida to hook functions, 
                  bypass security checks, and extract runtime data. Objection provides a user-friendly wrapper around Frida.
                </Typography>
                
                <Alert severity="warning" sx={{ mb: 3, bgcolor: alpha("#f59e0b", 0.1) }}>
                  <Typography variant="body2">
                    <strong>Prerequisites:</strong> Device must be rooted or use a rooted emulator. Install frida-server 
                    on device matching your Frida version.
                  </Typography>
                </Alert>

                <CodeBlock
                  title="Frida Setup & Basic Commands"
                  language="bash"
                  code={`# List running apps
frida-ps -U

# Spawn app and attach
frida -U -f com.target.app --no-pause

# Attach to running app
frida -U com.target.app

# Load script from file
frida -U -f com.target.app -l script.js --no-pause

# Trace all methods in a class
frida-trace -U -j "com.target.app.*!*" com.target.app`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Root Detection Bypass
                </Typography>
                <CodeBlock
                  title="Frida Root Bypass Script"
                  language="javascript"
                  code={`Java.perform(function() {
  // Hook common root check
  var RootCheck = Java.use("com.app.security.RootChecker");
  RootCheck.isRooted.implementation = function() {
    console.log("[*] Root check bypassed");
    return false;
  };
  
  // Block su binary checks
  var File = Java.use("java.io.File");
  File.exists.implementation = function() {
    var path = this.getAbsolutePath();
    if (path.indexOf("/su") !== -1) {
      return false;
    }
    return this.exists();
  };
});`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  SSL Pinning Bypass
                </Typography>
                <CodeBlock
                  title="Universal SSL Bypass"
                  language="javascript"
                  code={`Java.perform(function() {
  // OkHttp3 CertificatePinner
  try {
    var CertPinner = Java.use("okhttp3.CertificatePinner");
    CertPinner.check.overload("java.lang.String", "java.util.List")
      .implementation = function(hostname, certs) {
      console.log("[*] Bypassed: " + hostname);
      return;
    };
  } catch(e) {}

  // TrustManagerImpl
  try {
    var TrustManager = Java.use(
      "com.android.org.conscrypt.TrustManagerImpl");
    TrustManager.verifyChain.implementation = function() {
      return arguments[0];
    };
  } catch(e) {}
});`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Intercept Crypto Operations
                </Typography>
                <CodeBlock
                  title="Hook Encryption"
                  language="javascript"
                  code={`Java.perform(function() {
  var Cipher = Java.use("javax.crypto.Cipher");
  
  Cipher.doFinal.overload("[B").implementation = 
    function(input) {
    var result = this.doFinal(input);
    console.log("[*] Cipher.doFinal()");
    console.log("    Input:  " + bytesToHex(input));
    console.log("    Output: " + bytesToHex(result));
    return result;
  };
  
  // Capture encryption keys
  var SecretKeySpec = Java.use(
    "javax.crypto.spec.SecretKeySpec");
  SecretKeySpec.$init.overload("[B", "java.lang.String")
    .implementation = function(key, alg) {
    console.log("[*] Key: " + bytesToHex(key));
    return this.$init(key, alg);
  };
});`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Objection Quick Reference
                </Typography>
                <CodeBlock
                  title="Objection Commands"
                  language="bash"
                  code={`# Start objection
objection -g com.target.app explore

# Common commands:
android sslpinning disable
android root disable
android hooking list classes
android hooking watch class ClassName

# File system
ls /data/data/com.target.app/
file download prefs.xml

# Memory
memory search "password"
memory dump all dump.bin

# Keystore
android keystore list
android keystore dump`}
                />
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  Network Traffic Interception
                </Typography>
                <CodeBlock
                  title="Setup Traffic Interception"
                  language="bash"
                  code={`# 1. Configure proxy on device (Settings > Wi-Fi > Proxy)
#    Host: your-pc-ip, Port: 8080

# 2. Install Burp CA certificate as system cert
openssl x509 -inform DER -in burp.der -out burp.pem
hash=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)
adb root && adb remount
adb push $hash.0 /system/etc/security/cacerts/

# 3. Run app with SSL bypass script
frida -U -f com.target.app -l ssl_bypass.js --no-pause

# 4. Traffic now visible in Burp Suite!`}
                />
              </Paper>
            </Grid>
          </Grid>
        </Box>

        <Box id="vulnerabilities" sx={{ scrollMarginTop: 180, mb: 5 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, color: "white" }}>
            Vulnerabilities
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Common Android security issues and the patterns to search for.
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h5" sx={{ color: "#22c55e", mb: 3, fontWeight: 700 }}>
                  Common Android Vulnerabilities (OWASP Mobile Top 10)
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Category</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Description</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Example</TableCell>
                        <TableCell sx={{ color: "#22c55e", fontWeight: 700 }}>Severity</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {vulnCategories.map((row) => (
                        <TableRow key={row.category}>
                          <TableCell sx={{ color: "white", fontWeight: 600 }}>{row.category}</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>{row.description}</TableCell>
                          <TableCell sx={{ color: "grey.400", fontFamily: "monospace", fontSize: "0.75rem" }}>{row.examples}</TableCell>
                          <TableCell>
                            <Chip 
                              label={row.severity} 
                              size="small" 
                              sx={{ 
                                bgcolor: alpha(
                                  row.severity === "Critical" ? "#ef4444" : 
                                  row.severity === "High" ? "#f59e0b" : 
                                  row.severity === "Medium" ? "#3b82f6" : "#22c55e", 
                                  0.2
                                ),
                                color: row.severity === "Critical" ? "#ef4444" : 
                                       row.severity === "High" ? "#f59e0b" : 
                                       row.severity === "Medium" ? "#3b82f6" : "#22c55e",
                              }} 
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  🔍 Code Patterns to Search For
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Use grep or JADX search to find these vulnerability indicators:
                </Typography>
                <Grid container spacing={2}>
                  {vulnPatterns.map((pattern, index) => (
                    <Grid item xs={12} md={6} key={index}>
                      <Box sx={{ 
                        p: 2, 
                        bgcolor: alpha("#ef4444", 0.05), 
                        borderRadius: 1, 
                        border: "1px solid rgba(239, 68, 68, 0.2)" 
                      }}>
                        <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 0.5 }}>
                          {pattern.desc}
                        </Typography>
                        <Typography 
                          variant="body2" 
                          sx={{ 
                            color: "grey.300", 
                            fontFamily: "monospace", 
                            fontSize: "0.75rem",
                            wordBreak: "break-all"
                          }}
                        >
                          {pattern.pattern}
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2, border: "1px solid rgba(59, 130, 246, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2, fontWeight: 700 }}>
                  💡 Testing Checklist
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Typography sx={{ color: "white", fontWeight: 600, mb: 1 }}>Data Storage</Typography>
                    <List dense>
                      {[
                        "Check SharedPreferences encryption",
                        "Review SQLite for sensitive data",
                        "Check for data in logs (adb logcat)",
                        "Examine backup files",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>☐ {item}</Typography>} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography sx={{ color: "white", fontWeight: 600, mb: 1 }}>Network Security</Typography>
                    <List dense>
                      {[
                        "Test SSL pinning",
                        "Check for cleartext traffic",
                        "Inspect API endpoints",
                        "Review certificate validation",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>☐ {item}</Typography>} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Typography sx={{ color: "white", fontWeight: 600, mb: 1 }}>Authentication</Typography>
                    <List dense>
                      {[
                        "Review biometric implementation",
                        "Check session management",
                        "Test for weak passwords",
                        "Verify token storage",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>☐ {item}</Typography>} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </Box>

        <Box id="resources" sx={{ scrollMarginTop: 180, mb: 5 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, color: "white" }}>
            Resources
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Documentation, practice apps, and curated references for Android RE.
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  📚 Essential Documentation
                </Typography>
                <List>
                  {[
                    { name: "OWASP MASTG", url: "https://mas.owasp.org/MASTG/", desc: "Mobile Application Security Testing Guide - the bible of mobile security" },
                    { name: "OWASP MASVS", url: "https://mas.owasp.org/MASVS/", desc: "Mobile Application Security Verification Standard" },
                    { name: "Android Security Docs", url: "https://source.android.com/security", desc: "Official Android security architecture documentation" },
                    { name: "Frida Documentation", url: "https://frida.re/docs/home/", desc: "Complete Frida reference and JavaScript API" },
                    { name: "JADX GitHub", url: "https://github.com/skylot/jadx", desc: "DEX to Java decompiler - documentation and releases" },
                  ].map((resource) => (
                    <ListItem key={resource.name} sx={{ px: 0 }}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: "#22c55e" }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Button href={resource.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, justifyContent: "flex-start" }}>{resource.name}</Button>}
                        secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>{resource.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  🎯 Vulnerable Practice Apps
                </Typography>
                <List>
                  {[
                    { name: "DIVA (Damn Insecure Vulnerable App)", url: "https://github.com/payatu/diva-android", desc: "13 challenges covering common vulnerabilities" },
                    { name: "InsecureBankv2", url: "https://github.com/dineshshetty/Android-InsecureBankv2", desc: "Vulnerable banking app with comprehensive backend" },
                    { name: "OWASP UnCrackable Apps", url: "https://mas.owasp.org/crackmes/", desc: "Official OWASP mobile crackmes - L1 to L4 difficulty" },
                    { name: "AndroGoat", url: "https://github.com/AnirudhHack/AndroGoat", desc: "Open source vulnerable app with CTF challenges" },
                    { name: "MSTG Apps", url: "https://github.com/OWASP/owasp-mastg/tree/master/Crackmes", desc: "Test cases for OWASP MASTG methodology" },
                  ].map((target) => (
                    <ListItem key={target.name} sx={{ px: 0 }}>
                      <ListItemIcon>
                        <BugReportIcon sx={{ color: "#f59e0b" }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Button href={target.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, justifyContent: "flex-start" }}>{target.name}</Button>}
                        secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>{target.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  🛠️ Tool Repositories
                </Typography>
                <List>
                  {[
                    { name: "Frida CodeShare", url: "https://codeshare.frida.re/", desc: "Community scripts for Frida - ready to use hooks" },
                    { name: "awesome-mobile-security", url: "https://github.com/vaib25vicky/awesome-mobile-security", desc: "Curated list of mobile security resources" },
                    { name: "Android Security Awesome", url: "https://github.com/ashishb/android-security-awesome", desc: "Collection of Android security tools" },
                    { name: "MobSF", url: "https://github.com/MobSF/Mobile-Security-Framework-MobSF", desc: "Automated mobile security framework" },
                  ].map((tool) => (
                    <ListItem key={tool.name} sx={{ px: 0 }}>
                      <ListItemIcon>
                        <BuildIcon sx={{ color: "#3b82f6" }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Button href={tool.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, justifyContent: "flex-start" }}>{tool.name}</Button>}
                        secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>{tool.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  🎓 Learning Platforms & Courses
                </Typography>
                <List>
                  {[
                    { name: "HackTricks - Android", url: "https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting", desc: "Comprehensive Android pentesting methodology" },
                    { name: "TCM Security - Mobile", url: "https://tcm-sec.com/", desc: "Practical mobile app hacking courses" },
                    { name: "Corellium", url: "https://www.corellium.com/", desc: "Virtual iOS/Android devices for security research" },
                    { name: "NowSecure Academy", url: "https://www.nowsecure.com/", desc: "Mobile app security training and certification" },
                  ].map((course) => (
                    <ListItem key={course.name} sx={{ px: 0 }}>
                      <ListItemIcon>
                        <SchoolIcon sx={{ color: "#a855f7" }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Button href={course.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, justifyContent: "flex-start" }}>{course.name}</Button>}
                        secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>{course.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3, bgcolor: alpha("#22c55e", 0.1), borderRadius: 2, border: "1px solid rgba(34, 197, 94, 0.3)" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                  📖 Recommended Books
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { title: "Android Hacker's Handbook", author: "Joshua Drake et al.", desc: "Deep dive into Android internals and exploitation" },
                    { title: "Learning Frida", author: "Debasish Mandal", desc: "Practical guide to dynamic instrumentation" },
                    { title: "The Mobile Application Hacker's Handbook", author: "Dominic Chell et al.", desc: "Comprehensive mobile security testing" },
                    { title: "Android Security Internals", author: "Nikolay Elenkov", desc: "In-depth look at Android security architecture" },
                  ].map((book, index) => (
                    <Grid item xs={12} sm={6} md={3} key={index}>
                      <Box sx={{ p: 2, bgcolor: "rgba(0,0,0,0.2)", borderRadius: 1 }}>
                        <Typography variant="subtitle2" sx={{ color: "white", fontWeight: 600 }}>{book.title}</Typography>
                        <Typography variant="caption" sx={{ color: "#22c55e" }}>{book.author}</Typography>
                        <Typography variant="body2" sx={{ color: "grey.400", mt: 1, fontSize: "0.75rem" }}>{book.desc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </Box>

        <Box id="quiz" sx={{ scrollMarginTop: 180, mb: 4 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, color: "white" }}>
            Knowledge Quiz
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Test your understanding of Android reverse engineering fundamentals.
          </Typography>
          <QuizSection />
        </Box>

        <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
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
  </Box>
    </LearnPageLayout>
  );
};

export default AndroidReverseEngineeringGuidePage;
