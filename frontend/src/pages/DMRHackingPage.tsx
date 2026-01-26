import React, { useState } from "react";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  Button,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Grid,
  IconButton,
  Tooltip,
  Divider,
  alpha,
  useTheme,
  useMediaQuery,
  Drawer,
  Fab,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import RadioIcon from "@mui/icons-material/Radio";
import SettingsInputAntennaIcon from "@mui/icons-material/SettingsInputAntenna";
import SecurityIcon from "@mui/icons-material/Security";
import BuildIcon from "@mui/icons-material/Build";
import SearchIcon from "@mui/icons-material/Search";
import BugReportIcon from "@mui/icons-material/BugReport";
import ShieldIcon from "@mui/icons-material/Shield";
import GavelIcon from "@mui/icons-material/Gavel";
import QuizIcon from "@mui/icons-material/Quiz";
import SchoolIcon from "@mui/icons-material/School";
import ScienceIcon from "@mui/icons-material/Science";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import RouterIcon from "@mui/icons-material/Router";
import LockIcon from "@mui/icons-material/Lock";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import MemoryIcon from "@mui/icons-material/Memory";
import CellTowerIcon from "@mui/icons-material/CellTower";
import HeadsetMicIcon from "@mui/icons-material/HeadsetMic";
import BusinessIcon from "@mui/icons-material/Business";
import LocalPoliceIcon from "@mui/icons-material/LocalPolice";
import HistoryEduIcon from "@mui/icons-material/HistoryEdu";
import { useNavigate, Link } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

// Section Navigation Items
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
  { id: "protocol", label: "DMR Protocol", icon: <RadioIcon /> },
  { id: "architecture", label: "Network Architecture", icon: <CellTowerIcon /> },
  { id: "encryption", label: "Encryption & Security", icon: <LockIcon /> },
  { id: "hardware", label: "Hardware & Tools", icon: <BuildIcon /> },
  { id: "sdr-processing", label: "SDR Signal Processing", icon: <SettingsInputAntennaIcon /> },
  { id: "reconnaissance", label: "Reconnaissance", icon: <SearchIcon /> },
  { id: "exploitation", label: "Exploitation", icon: <BugReportIcon /> },
  { id: "firmware", label: "Firmware Security", icon: <MemoryIcon /> },
  { id: "detection", label: "Detection & Monitoring", icon: <RouterIcon /> },
  { id: "case-studies", label: "Case Studies", icon: <HistoryEduIcon /> },
  { id: "defense", label: "Defense", icon: <ShieldIcon /> },
  { id: "labs", label: "Hands-On Labs", icon: <ScienceIcon /> },
  { id: "glossary", label: "Glossary", icon: <MenuBookIcon /> },
  { id: "resources", label: "Resources", icon: <MenuBookIcon /> },
  { id: "legal", label: "Legal & Ethics", icon: <GavelIcon /> },
  { id: "quiz-section", label: "Knowledge Check", icon: <QuizIcon /> },
];

// Theme colors
const theme = {
  primary: "#8b5cf6",
  primaryLight: "#a78bfa",
  secondary: "#06b6d4",
  accent: "#f59e0b",
  success: "#10b981",
  warning: "#f59e0b",
  info: "#3b82f6",
  error: "#ef4444",
  bgDark: "#0a0a0f",
  bgCard: "#12121a",
  bgNested: "#0f1024",
  bgCode: "#1a1a2e",
  border: "rgba(139, 92, 246, 0.2)",
  text: "#e2e8f0",
  textMuted: "#94a3b8",
};

const QUIZ_QUESTION_COUNT = 10;

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "What does DMR stand for?",
    options: [
      "Dynamic Modulation Receiver",
      "Digital Mobile Radio",
      "Direct Mode Relay",
      "Distributed Mobile Routing",
    ],
    correctAnswer: 1,
    explanation: "DMR stands for Digital Mobile Radio, an ETSI standard for digital two-way radio communications.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "What modulation technique does DMR use?",
    options: [
      "QPSK",
      "8PSK",
      "4FSK (4-level Frequency Shift Keying)",
      "OFDM",
    ],
    correctAnswer: 2,
    explanation: "DMR uses 4FSK modulation, transmitting 2 bits per symbol at 4800 symbols/second for 9600 bps data rate.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "How many time slots does a standard DMR channel have?",
    options: [
      "1 (FDMA)",
      "4",
      "8",
      "2 (TDMA)",
    ],
    correctAnswer: 3,
    explanation: "DMR uses 2-slot TDMA (Time Division Multiple Access), allowing two simultaneous conversations on one 12.5 kHz channel.",
  },
  {
    id: 4,
    topic: "Protocol",
    question: "What is the purpose of a DMR Color Code?",
    options: [
      "A display setting for radios",
      "An identifier to separate systems on the same frequency",
      "An encryption key",
      "A priority level",
    ],
    correctAnswer: 1,
    explanation: "Color Codes (0-15) act like CTCSS/DCS in analog, allowing multiple DMR systems to share a frequency without interference.",
  },
  {
    id: 5,
    topic: "Protocol",
    question: "What is a DMR Talk Group?",
    options: [
      "A hardware radio model",
      "An encryption algorithm",
      "A virtual channel for group communications",
      "A time slot configuration",
    ],
    correctAnswer: 2,
    explanation: "Talk Groups are virtual channels that allow users to communicate with specific groups without affecting others on the same repeater.",
  },
  {
    id: 6,
    topic: "Security",
    question: "What is the basic encryption in DMR called?",
    options: [
      "AES-256",
      "DES",
      "RSA",
      "Basic Privacy (BP) / DMR Scrambling",
    ],
    correctAnswer: 3,
    explanation: "Basic Privacy uses simple XOR scrambling with a 16-bit key - easily broken and provides minimal security.",
  },
  {
    id: 7,
    topic: "Security",
    question: "What encryption does DMR Tier III support?",
    options: [
      "Only Basic Privacy",
      "WEP",
      "AES-256",
      "No encryption",
    ],
    correctAnswer: 2,
    explanation: "DMR Tier III (trunked systems) supports AES-256 encryption for high-security applications like public safety.",
  },
  {
    id: 8,
    topic: "Architecture",
    question: "What is DMR Tier I used for?",
    options: [
      "Licensed conventional repeater systems",
      "Trunked infrastructure systems",
      "Unlicensed, low-power, peer-to-peer operation",
      "Military-grade encrypted systems",
    ],
    correctAnswer: 2,
    explanation: "DMR Tier I operates in the 446 MHz band (Europe) for unlicensed, low-power communications - similar to FRS radios.",
  },
  {
    id: 9,
    topic: "Architecture",
    question: "What is DMR Tier II designed for?",
    options: [
      "Unlicensed operation only",
      "Licensed conventional and repeater systems",
      "Trunked systems with central control",
      "Amateur radio only",
    ],
    correctAnswer: 1,
    explanation: "DMR Tier II covers licensed conventional systems with repeaters, used by businesses and amateur radio operators.",
  },
  {
    id: 10,
    topic: "Architecture",
    question: "What is DMR Tier III?",
    options: [
      "Trunked systems with central controller",
      "Simplex-only operation",
      "Consumer handheld radios",
      "Satellite-based DMR",
    ],
    correctAnswer: 0,
    explanation: "DMR Tier III provides trunked operation with central site controller, used by public safety and large enterprises.",
  },
  {
    id: 11,
    topic: "Tools",
    question: "What is DSD+ primarily used for?",
    options: [
      "Programming DMR radios",
      "Encrypting DMR traffic",
      "Decoding digital radio signals including DMR",
      "Managing repeater systems",
    ],
    correctAnswer: 2,
    explanation: "DSD+ (Digital Speech Decoder) can decode various digital voice modes including DMR, P25, NXDN, and D-STAR.",
  },
  {
    id: 12,
    topic: "Tools",
    question: "What type of SDR is commonly used for DMR reception?",
    options: [
      "WiFi adapter",
      "Bluetooth dongle",
      "GPS receiver",
      "RTL-SDR dongle",
    ],
    correctAnswer: 3,
    explanation: "RTL-SDR dongles (based on RTL2832U chip) are inexpensive receivers commonly used for monitoring DMR and other radio signals.",
  },
  {
    id: 13,
    topic: "Exploitation",
    question: "What is a replay attack in DMR context?",
    options: [
      "Restarting a radio remotely",
      "Recording and retransmitting captured DMR traffic",
      "Resetting encryption keys",
      "Replaying audio recordings",
    ],
    correctAnswer: 1,
    explanation: "Replay attacks capture legitimate DMR transmissions and retransmit them, potentially causing confusion or unauthorized access.",
  },
  {
    id: 14,
    topic: "Exploitation",
    question: "What major vulnerability affects Basic Privacy encryption?",
    options: [
      "Buffer overflow in radio firmware",
      "SQL injection in trunking controller",
      "Weak XOR scrambling with small key space (16-bit)",
      "Man-in-the-middle on IP backhaul",
    ],
    correctAnswer: 2,
    explanation: "Basic Privacy uses 16-bit XOR scrambling - trivially broken with known-plaintext attacks or brute force.",
  },
  {
    id: 15,
    topic: "Reconnaissance",
    question: "What information can be extracted from DMR headers?",
    options: [
      "GPS coordinates only",
      "Encryption keys",
      "User passwords",
      "Source/destination IDs, talk group, color code",
    ],
    correctAnswer: 3,
    explanation: "DMR headers contain metadata like radio IDs, talk groups, color codes - useful for mapping network structure.",
  },
  {
    id: 16,
    topic: "Reconnaissance",
    question: "What is Brandmeister in DMR?",
    options: [
      "A radio manufacturer",
      "An encryption standard",
      "A worldwide DMR network linking repeaters via internet",
      "A military DMR protocol",
    ],
    correctAnswer: 2,
    explanation: "Brandmeister is a global amateur DMR network connecting thousands of repeaters worldwide via internet linking.",
  },
  {
    id: 17,
    topic: "Defense",
    question: "How can DMR systems defend against replay attacks?",
    options: [
      "Using analog instead of digital",
      "Timestamps, sequence numbers, and AES encryption",
      "Increasing transmit power",
      "Changing color codes frequently",
    ],
    correctAnswer: 1,
    explanation: "Proper AES encryption with timestamps and sequence numbers prevents replay attacks by invalidating old/duplicate packets.",
  },
  {
    id: 18,
    topic: "Defense",
    question: "What is radio ID validation?",
    options: [
      "Verifying the radio's serial number",
      "Testing radio hardware",
      "Checking if a radio ID is authorized on the network",
      "Calibrating the radio",
    ],
    correctAnswer: 2,
    explanation: "Radio ID validation ensures only authorized radio IDs can access the system, blocking unknown or cloned radios.",
  },
  {
    id: 19,
    topic: "Protocol",
    question: "What is the standard channel bandwidth for DMR?",
    options: [
      "25 kHz",
      "12.5 kHz",
      "6.25 kHz",
      "50 kHz",
    ],
    correctAnswer: 1,
    explanation: "DMR uses 12.5 kHz channel spacing, meeting global narrowbanding requirements while supporting 2 time slots.",
  },
  {
    id: 20,
    topic: "Protocol",
    question: "What vocoder does DMR use for voice compression?",
    options: [
      "Codec2",
      "AMBE+2 (Advanced Multi-Band Excitation)",
      "G.711",
      "Opus",
    ],
    correctAnswer: 1,
    explanation: "DMR uses the proprietary AMBE+2 vocoder, compressing voice to approximately 2.4 kbps for digital transmission.",
  },
  {
    id: 21,
    topic: "Exploitation",
    question: "What is radio ID spoofing?",
    options: [
      "Changing display name on radio",
      "Updating radio firmware",
      "Transmitting with a falsified radio ID",
      "Registering a new radio",
    ],
    correctAnswer: 2,
    explanation: "Radio ID spoofing involves programming a radio with someone else's ID to impersonate them or bypass access controls.",
  },
  {
    id: 22,
    topic: "Architecture",
    question: "What is IP Site Connect in DMR?",
    options: [
      "Connecting radios to the internet",
      "A VoIP phone system",
      "Web-based radio programming",
      "Linking DMR repeaters over IP networks",
    ],
    correctAnswer: 3,
    explanation: "IP Site Connect links geographically separated DMR repeaters over IP networks for wide-area coverage.",
  },
  {
    id: 23,
    topic: "Security",
    question: "What is OTAR in DMR?",
    options: [
      "Online Transmission And Reception",
      "Optimized Trunking And Routing",
      "Over-The-Air Rekeying - changing encryption keys wirelessly",
      "Open Talkgroup Access Request",
    ],
    correctAnswer: 2,
    explanation: "OTAR allows encryption keys to be updated remotely over the air, reducing the risk of key compromise.",
  },
  {
    id: 24,
    topic: "Tools",
    question: "What is a codeplug in DMR?",
    options: [
      "Hardware encryption module",
      "Configuration file containing channels, contacts, and settings",
      "Antenna connector type",
      "Audio codec plugin",
    ],
    correctAnswer: 1,
    explanation: "A codeplug is the configuration file programmed into DMR radios containing frequencies, talk groups, contacts, and settings.",
  },
  {
    id: 25,
    topic: "Fundamentals",
    question: "What benefit does TDMA provide in DMR?",
    options: [
      "Better audio quality",
      "Longer range",
      "Two voice paths on one frequency channel",
      "Stronger encryption",
    ],
    correctAnswer: 2,
    explanation: "TDMA (Time Division Multiple Access) divides the channel into time slots, allowing 2 simultaneous calls on 12.5 kHz.",
  },
  {
    id: 26,
    topic: "Reconnaissance",
    question: "What database tracks DMR user IDs?",
    options: [
      "FCC ULS",
      "ICANN",
      "RadioID.net (DMR-MARC database)",
      "IEEE OUI database",
    ],
    correctAnswer: 2,
    explanation: "RadioID.net (formerly DMR-MARC) maintains the database of registered amateur DMR user IDs worldwide.",
  },
  {
    id: 27,
    topic: "Exploitation",
    question: "What is a DMR jamming attack?",
    options: [
      "Stealing encryption keys",
      "Cloning radios",
      "Transmitting noise or invalid frames to disrupt communications",
      "Intercepting GPS data",
    ],
    correctAnswer: 2,
    explanation: "Jamming attacks transmit interfering signals on DMR frequencies to deny service to legitimate users.",
  },
  {
    id: 28,
    topic: "Security",
    question: "Enhanced Privacy in DMR uses what key length options?",
    options: [
      "8-bit",
      "40-bit or AES-256",
      "16-bit only",
      "No encryption",
    ],
    correctAnswer: 1,
    explanation: "Enhanced Privacy offers 40-bit RC4 or full AES-256 encryption, significantly stronger than Basic Privacy.",
  },
  {
    id: 29,
    topic: "Protocol",
    question: "What is the total data rate of DMR?",
    options: [
      "56 kbps",
      "1 Mbps",
      "9.6 kbps total (4.8 kbps per time slot)",
      "100 kbps",
    ],
    correctAnswer: 2,
    explanation: "DMR provides 9.6 kbps total data rate using 4FSK modulation, split between two TDMA time slots.",
  },
  {
    id: 30,
    topic: "Defense",
    question: "What is the best defense against DMR eavesdropping?",
    options: [
      "Using higher power",
      "AES-256 encryption with proper key management",
      "Changing frequencies often",
      "Using directional antennas",
    ],
    correctAnswer: 1,
    explanation: "AES-256 encryption properly implemented with secure key management provides strong protection against eavesdropping.",
  },
  {
    id: 31,
    topic: "Tools",
    question: "What is GNU Radio used for in DMR research?",
    options: [
      "Programming DMR radios only",
      "Encrypting DMR traffic",
      "Building custom SDR signal processing flowgraphs",
      "Managing repeater networks",
    ],
    correctAnswer: 2,
    explanation: "GNU Radio is a software development toolkit for creating SDR signal processing flowgraphs, useful for DMR signal analysis and decoding.",
  },
  {
    id: 32,
    topic: "Protocol",
    question: "What is the CACH in DMR frames?",
    options: [
      "Cipher Authentication Channel Hash",
      "Call Allocation Control Header",
      "Common Announcement Channel for slot timing",
      "Channel Access Control Handshake",
    ],
    correctAnswer: 2,
    explanation: "CACH (Common Announcement Channel) provides timing information and allows radios to synchronize to the correct time slot.",
  },
  {
    id: 33,
    topic: "Exploitation",
    question: "What is a 'man-in-the-middle' attack on DMR?",
    options: [
      "Standing between two radio antennas",
      "Intercepting and potentially modifying traffic between radios",
      "Using a handheld radio in the middle of a call",
      "Programming radios from the middle of a network",
    ],
    correctAnswer: 1,
    explanation: "MitM attacks on DMR intercept traffic between radios or between radios and repeaters, potentially modifying or injecting messages.",
  },
  {
    id: 34,
    topic: "Firmware",
    question: "What is md380tools?",
    options: [
      "A commercial radio programming suite",
      "Encryption key management software",
      "Open-source firmware tools for TYT MD-380 radios",
      "DMR network monitoring tool",
    ],
    correctAnswer: 2,
    explanation: "md380tools is an open-source project providing alternative firmware and tools for TYT MD-380/390 radios, enabling security research.",
  },
  {
    id: 35,
    topic: "Protocol",
    question: "What is the PI (Privacy Indicator) flag in DMR?",
    options: [
      "Personal Identification number",
      "Priority Indicator for emergency calls",
      "Indicates whether the transmission is encrypted",
      "Protocol Interface version",
    ],
    correctAnswer: 2,
    explanation: "The Privacy Indicator (PI) flag in DMR headers indicates whether the voice or data payload is encrypted.",
  },
  {
    id: 36,
    topic: "Reconnaissance",
    question: "What tool can capture raw IQ samples from DMR signals?",
    options: [
      "Standard FM radio",
      "RTL-SDR with rtl_sdr command",
      "Analog scanner",
      "DMR radio in monitor mode",
    ],
    correctAnswer: 1,
    explanation: "RTL-SDR can capture raw IQ (In-phase/Quadrature) samples using rtl_sdr, enabling offline analysis and signal processing.",
  },
  {
    id: 37,
    topic: "Architecture",
    question: "What is Capacity Max in DMR?",
    options: [
      "Maximum number of users on a channel",
      "Signal strength limitation",
      "Motorola's multi-site trunked DMR system",
      "Battery capacity indicator",
    ],
    correctAnswer: 2,
    explanation: "Capacity Max is Motorola's enterprise-grade multi-site trunked DMR system, supporting thousands of users across many sites.",
  },
  {
    id: 38,
    topic: "Security",
    question: "Why is static key management a security risk in DMR?",
    options: [
      "Static keys have lower entropy",
      "Compromised keys remain valid until manual rotation",
      "Static keys are easier to guess",
      "Static keys don't work with DMR",
    ],
    correctAnswer: 1,
    explanation: "Static keys that never change mean a compromised key provides persistent access. OTAR (Over-The-Air Rekeying) mitigates this.",
  },
  {
    id: 39,
    topic: "Tools",
    question: "What is SDR# (SDRSharp) primarily used for?",
    options: [
      "Programming DMR radios",
      "Windows-based SDR receiver software with visualization",
      "Transmitting DMR signals",
      "Managing encryption keys",
    ],
    correctAnswer: 1,
    explanation: "SDR# is a popular Windows SDR application for receiving and visualizing radio signals, often used with RTL-SDR for DMR monitoring.",
  },
  {
    id: 40,
    topic: "Protocol",
    question: "What is the embedded LC (Link Control) in DMR used for?",
    options: [
      "Linking repeaters together",
      "Controlling transmit power",
      "Carrying source/destination IDs and talk group info mid-call",
      "Managing time slot allocation",
    ],
    correctAnswer: 2,
    explanation: "Embedded LC carries Link Control information within voice frames, allowing late-entry radios to identify the call participants.",
  },
  {
    id: 41,
    topic: "Defense",
    question: "What is radio inhibit/stun in DMR?",
    options: [
      "Physical damage to radio circuits",
      "Signal jamming technique",
      "Remote command to disable a radio over-the-air",
      "Encryption key deletion",
    ],
    correctAnswer: 2,
    explanation: "Radio inhibit/stun is a management feature allowing administrators to remotely disable stolen or compromised radios.",
  },
  {
    id: 42,
    topic: "Exploitation",
    question: "What vulnerability allows GPS tracking of DMR users?",
    options: [
      "GPS satellites are insecure",
      "Unencrypted location data in transmissions",
      "Radio antennas leak position",
      "DMR signals can be triangulated",
    ],
    correctAnswer: 1,
    explanation: "Many DMR systems transmit GPS location data unencrypted, allowing anyone monitoring the frequency to track user locations.",
  },
  {
    id: 43,
    topic: "Firmware",
    question: "What is OpenGD77?",
    options: [
      "A DMR network protocol",
      "Commercial radio software",
      "Open-source firmware for Radioddity GD-77 and similar radios",
      "Encryption standard",
    ],
    correctAnswer: 2,
    explanation: "OpenGD77 is open-source firmware for GD-77/DM-1801 radios, providing enhanced features and enabling security research.",
  },
  {
    id: 44,
    topic: "Protocol",
    question: "What is the SYNC pattern used for in DMR?",
    options: [
      "Synchronizing encryption keys",
      "Timing repeater handoffs",
      "Identifying burst type and enabling frame synchronization",
      "Calibrating audio levels",
    ],
    correctAnswer: 2,
    explanation: "The 48-bit SYNC pattern identifies the burst type (voice, data, idle) and allows receivers to synchronize to the frame structure.",
  },
  {
    id: 45,
    topic: "Reconnaissance",
    question: "What is the Talker Alias feature in DMR?",
    options: [
      "Disguising your voice",
      "Creating fake identities",
      "Transmitting callsign/name along with Radio ID",
      "Aliasing IP addresses",
    ],
    correctAnswer: 2,
    explanation: "Talker Alias transmits a user's callsign or name in the embedded signaling, allowing receiving radios to display identification.",
  },
  {
    id: 46,
    topic: "Fundamentals",
    question: "What is the symbol rate used in DMR?",
    options: [
      "4800 symbols per second",
      "9600 symbols per second",
      "2400 symbols per second",
      "1200 symbols per second",
    ],
    correctAnswer: 0,
    explanation: "DMR uses 4800 symbols per second with 4FSK modulation, where each symbol carries 2 bits, resulting in 9600 bps.",
  },
  {
    id: 47,
    topic: "Protocol",
    question: "How many bits does each DMR symbol represent?",
    options: [
      "1 bit",
      "2 bits (dibit)",
      "3 bits (tribit)",
      "4 bits (nibble)",
    ],
    correctAnswer: 1,
    explanation: "Each 4FSK symbol in DMR represents 2 bits (a dibit), with four possible frequency deviations mapping to 00, 01, 10, and 11.",
  },
  {
    id: 48,
    topic: "Security",
    question: "How many possible keys exist in Basic Privacy encryption?",
    options: [
      "256 (8-bit)",
      "65,536 (16-bit)",
      "16,777,216 (24-bit)",
      "4,294,967,296 (32-bit)",
    ],
    correctAnswer: 1,
    explanation: "Basic Privacy uses a 16-bit key, resulting in only 65,536 possible keys - easily brute-forced in milliseconds.",
  },
  {
    id: 49,
    topic: "Architecture",
    question: "What frequency band is used for DMR Tier I in Europe?",
    options: [
      "VHF 136-174 MHz",
      "UHF 446 MHz (dPMR446)",
      "UHF 400-430 MHz",
      "UHF 450-470 MHz",
    ],
    correctAnswer: 1,
    explanation: "DMR Tier I in Europe operates on 446 MHz for license-free, low-power digital PMR similar to analog PMR446.",
  },
  {
    id: 50,
    topic: "Tools",
    question: "What is the purpose of a MMDVM in DMR?",
    options: [
      "Modulating and demodulating digital voice for hotspots",
      "Managing multiple DMR repeaters",
      "Encrypting DMR traffic",
      "Monitoring network performance",
    ],
    correctAnswer: 0,
    explanation: "MMDVM (Multi-Mode Digital Voice Modem) is hardware/firmware that modulates and demodulates digital voice for hotspots and repeaters.",
  },
  {
    id: 51,
    topic: "Exploitation",
    question: "What makes radio ID spoofing possible in DMR?",
    options: [
      "Radios can be remotely reprogrammed",
      "Radio IDs are self-reported and not cryptographically authenticated",
      "All radios use the same ID by default",
      "DMR systems don't track radio IDs",
    ],
    correctAnswer: 1,
    explanation: "Radio IDs in DMR are simply transmitted values with no cryptographic proof of identity, allowing any radio to claim any ID.",
  },
  {
    id: 52,
    topic: "Protocol",
    question: "What is the duration of a complete DMR TDMA frame?",
    options: [
      "30 ms",
      "60 ms",
      "120 ms",
      "15 ms",
    ],
    correctAnswer: 1,
    explanation: "A complete DMR TDMA frame is 60 ms, divided into two 30 ms time slots for Time Slot 1 and Time Slot 2.",
  },
  {
    id: 53,
    topic: "Reconnaissance",
    question: "What can be learned from passive DMR monitoring?",
    options: [
      "Only encrypted voice content",
      "Network structure, active users, talk groups, and traffic patterns",
      "Nothing useful without encryption keys",
      "Only radio serial numbers",
    ],
    correctAnswer: 1,
    explanation: "Passive monitoring reveals radio IDs, talk groups, timing patterns, GPS data, and network topology even without decrypting voice.",
  },
  {
    id: 54,
    topic: "Defense",
    question: "What is the purpose of sequence numbers in DMR?",
    options: [
      "Ordering radios in a queue",
      "Detecting replay attacks and duplicate transmissions",
      "Numbering talk groups",
      "Tracking radio battery life",
    ],
    correctAnswer: 1,
    explanation: "Sequence numbers in encrypted DMR help detect replay attacks by identifying duplicate or out-of-order transmissions.",
  },
  {
    id: 55,
    topic: "Firmware",
    question: "What processor does the TYT MD-380 use?",
    options: [
      "Intel x86",
      "STM32F405 ARM Cortex-M4",
      "PIC microcontroller",
      "AVR ATmega",
    ],
    correctAnswer: 1,
    explanation: "The TYT MD-380 uses an STM32F405 ARM Cortex-M4 microcontroller at 168 MHz, making it a target for firmware research.",
  },
  {
    id: 56,
    topic: "Security",
    question: "Why is AMBE+2 vocoder relevant to Basic Privacy attacks?",
    options: [
      "It provides the encryption",
      "Known AMBE+2 patterns serve as cribs for cryptanalysis",
      "It prevents brute force attacks",
      "AMBE+2 is unrelated to encryption",
    ],
    correctAnswer: 1,
    explanation: "AMBE+2 encoded silence and common voice patterns provide known plaintext for attacking the weak XOR-based Basic Privacy encryption.",
  },
  {
    id: 57,
    topic: "Architecture",
    question: "What is the TGIF network?",
    options: [
      "A commercial DMR service provider",
      "The Group of International Friends - an amateur DMR network",
      "A government emergency network",
      "A military communication standard",
    ],
    correctAnswer: 1,
    explanation: "TGIF (The Group of International Friends) is a worldwide amateur DMR network alternative to Brandmeister.",
  },
  {
    id: 58,
    topic: "Tools",
    question: "What is Pi-Star used for?",
    options: [
      "Commercial DMR infrastructure",
      "Raspberry Pi-based digital voice hotspot software",
      "SDR signal analysis only",
      "Radio firmware updates",
    ],
    correctAnswer: 1,
    explanation: "Pi-Star is a Raspberry Pi-based hotspot software supporting DMR and other digital modes, connecting radios to internet networks.",
  },
  {
    id: 59,
    topic: "Protocol",
    question: "What are the frequency deviation levels in DMR 4FSK?",
    options: [
      "±1.944 kHz and ±648 Hz",
      "±2.5 kHz and ±1 kHz",
      "±5 kHz and ±2.5 kHz",
      "±3 kHz only",
    ],
    correctAnswer: 0,
    explanation: "DMR 4FSK uses four deviation levels: ±1.944 kHz (outer) and ±648 Hz (inner), representing 2-bit symbols.",
  },
  {
    id: 60,
    topic: "Exploitation",
    question: "What is a selective jamming attack on DMR?",
    options: [
      "Jamming all frequencies simultaneously",
      "Targeting specific time slots, headers, or users while allowing others",
      "Only jamming encrypted traffic",
      "Jamming the control channel only",
    ],
    correctAnswer: 1,
    explanation: "Selective jamming targets specific time slots, users, or frame components, making detection more difficult than broadband jamming.",
  },
  {
    id: 61,
    topic: "Reconnaissance",
    question: "What tool is commonly used for DMR protocol analysis via IP?",
    options: [
      "Nmap",
      "Wireshark with DMR dissector",
      "Burp Suite",
      "Metasploit",
    ],
    correctAnswer: 1,
    explanation: "Wireshark with DMR protocol dissectors can analyze DMR-over-IP traffic from Homebrew, DMR+, and MMDVM networks.",
  },
  {
    id: 62,
    topic: "Defense",
    question: "What is the benefit of using AES-256 in DMR over Basic Privacy?",
    options: [
      "AES-256 is faster to process",
      "AES-256 uses less bandwidth",
      "AES-256 provides cryptographically secure encryption immune to brute force",
      "AES-256 is free while Basic Privacy requires licensing",
    ],
    correctAnswer: 2,
    explanation: "AES-256 with its 256-bit key space is computationally infeasible to brute force, unlike the 16-bit Basic Privacy.",
  },
  {
    id: 63,
    topic: "Firmware",
    question: "What debug interface is often found on DMR radios for firmware access?",
    options: [
      "USB debugging only",
      "JTAG/SWD (Serial Wire Debug)",
      "Bluetooth debugging",
      "WiFi debugging",
    ],
    correctAnswer: 1,
    explanation: "Many DMR radios have JTAG or SWD debug interfaces that allow firmware extraction and debugging when physical access is possible.",
  },
  {
    id: 64,
    topic: "Protocol",
    question: "What is a Private Call in DMR?",
    options: [
      "An encrypted group call",
      "A one-to-one call between specific radio IDs",
      "A call to emergency services",
      "A call on a private repeater",
    ],
    correctAnswer: 1,
    explanation: "A Private Call (or Individual Call) is a direct call between two specific radio IDs, as opposed to a Group Call to a Talk Group.",
  },
  {
    id: 65,
    topic: "Security",
    question: "What is the risk of transmitting GPS data over unencrypted DMR?",
    options: [
      "GPS data is always encrypted separately",
      "Real-time tracking of all radio users by anyone with a receiver",
      "GPS accuracy is reduced",
      "GPS transmission uses too much bandwidth",
    ],
    correctAnswer: 1,
    explanation: "Unencrypted GPS data allows passive observers to track the real-time locations of all transmitting radios on the network.",
  },
  {
    id: 66,
    topic: "Architecture",
    question: "What is a DMR hotspot?",
    options: [
      "A high-power repeater",
      "A low-power personal gateway connecting a radio to internet DMR networks",
      "An encrypted access point",
      "A mobile command center",
    ],
    correctAnswer: 1,
    explanation: "A hotspot is a low-power personal device that bridges a DMR radio to internet-connected networks like Brandmeister.",
  },
  {
    id: 67,
    topic: "Tools",
    question: "What is the HackRF One capable of that RTL-SDR is not?",
    options: [
      "Receiving signals",
      "Transmitting signals (TX capability)",
      "Higher sensitivity",
      "Lower cost",
    ],
    correctAnswer: 1,
    explanation: "HackRF One is a transceiver capable of both receiving and transmitting, unlike receive-only RTL-SDR dongles.",
  },
  {
    id: 68,
    topic: "Exploitation",
    question: "What happens if a DMR system doesn't validate radio IDs?",
    options: [
      "The system works normally with no issues",
      "Any radio can impersonate any user or access restricted talk groups",
      "Only encrypted calls are affected",
      "GPS tracking becomes more accurate",
    ],
    correctAnswer: 1,
    explanation: "Without radio ID validation, any radio can claim any ID, enabling impersonation and unauthorized access to restricted resources.",
  },
  {
    id: 69,
    topic: "Protocol",
    question: "What is an All Call in DMR?",
    options: [
      "A call to a specific talk group",
      "A broadcast to all radios on a channel regardless of talk group",
      "An emergency-only transmission",
      "A call requiring all time slots",
    ],
    correctAnswer: 1,
    explanation: "An All Call is a broadcast transmission received by all radios on the channel, regardless of their programmed talk group.",
  },
  {
    id: 70,
    topic: "Defense",
    question: "How can organizations detect rogue DMR radios?",
    options: [
      "By using stronger antennas",
      "By monitoring for unknown radio IDs and anomalous RSSI patterns",
      "Rogue radios cannot be detected",
      "By increasing transmit power",
    ],
    correctAnswer: 1,
    explanation: "Network monitoring can detect unknown radio IDs attempting access and suspicious signal strength patterns indicating spoofing.",
  },
  {
    id: 71,
    topic: "Reconnaissance",
    question: "What is RepeaterBook used for?",
    options: [
      "Programming DMR radios",
      "A database of repeater frequencies and configurations",
      "Encrypting DMR traffic",
      "Managing talk groups",
    ],
    correctAnswer: 1,
    explanation: "RepeaterBook is a worldwide database of amateur and commercial repeaters, including DMR repeater information.",
  },
  {
    id: 72,
    topic: "Security",
    question: "What is the weakness of RC4 encryption used in some Enhanced Privacy implementations?",
    options: [
      "RC4 is too slow",
      "Known statistical biases in keystream, especially with weak IVs",
      "RC4 keys are too long",
      "RC4 is not supported by DMR",
    ],
    correctAnswer: 1,
    explanation: "RC4 has known cryptographic weaknesses including keystream biases, especially when initialization vectors are predictable.",
  },
  {
    id: 73,
    topic: "Firmware",
    question: "What is Read Protection (RDP) on STM32 microcontrollers?",
    options: [
      "A feature to improve read speed",
      "A security feature preventing firmware extraction via debug interfaces",
      "A method to reduce power consumption",
      "A communication protocol",
    ],
    correctAnswer: 1,
    explanation: "RDP (Read Protection) prevents unauthorized reading of flash memory via debug interfaces like JTAG/SWD, protecting firmware.",
  },
  {
    id: 74,
    topic: "Protocol",
    question: "What information is contained in the EMB (Embedded) field?",
    options: [
      "Only audio data",
      "Color code, privacy indicator, and link control fragment data",
      "GPS coordinates only",
      "Encryption keys",
    ],
    correctAnswer: 1,
    explanation: "The EMB field carries the color code, PI flag, LCSS bits, and other control information embedded within voice bursts.",
  },
  {
    id: 75,
    topic: "Defense",
    question: "What is the advantage of OTAR over manual key distribution?",
    options: [
      "OTAR is faster to initially set up",
      "OTAR allows immediate revocation and update of compromised keys",
      "OTAR uses weaker but faster encryption",
      "OTAR requires less bandwidth",
    ],
    correctAnswer: 1,
    explanation: "OTAR enables rapid key changes across a network without physical access to radios, critical when keys are compromised.",
  },
  {
    id: 76,
    topic: "Exploitation",
    question: "What is the danger of using default color codes on DMR systems?",
    options: [
      "Default color codes use more bandwidth",
      "Adjacent systems may interfere if they also use defaults",
      "Default color codes cannot be encrypted",
      "Default color codes are always Color Code 0",
    ],
    correctAnswer: 1,
    explanation: "Default color codes (often 1) may match nearby systems, causing unintended interference or access to other networks.",
  },
  {
    id: 77,
    topic: "Architecture",
    question: "What protocol does the Homebrew network use for DMR over IP?",
    options: [
      "TCP with TLS encryption",
      "UDP with custom DMR encapsulation",
      "HTTP REST API",
      "WebSocket protocol",
    ],
    correctAnswer: 1,
    explanation: "Homebrew/MMDVM uses UDP (typically port 62031) for low-latency transport of encapsulated DMR frames over IP networks.",
  },
  {
    id: 78,
    topic: "Tools",
    question: "What is OP25 used for?",
    options: [
      "Programming Motorola radios only",
      "Decoding P25 and other digital voice modes including DMR",
      "Encrypting radio traffic",
      "Managing DMR repeaters",
    ],
    correctAnswer: 1,
    explanation: "OP25 is an open-source project for GNU Radio that decodes P25 and other digital voice modes, with some DMR support.",
  },
  {
    id: 79,
    topic: "Protocol",
    question: "What is the purpose of the CSBK (Control Signaling Block)?",
    options: [
      "Carrying voice data only",
      "Transmitting control signaling like registration and channel grants",
      "Encrypting all traffic",
      "Synchronizing time slots only",
    ],
    correctAnswer: 1,
    explanation: "CSBK carries control signaling including registration, channel grants, announcements, and other network management functions.",
  },
  {
    id: 80,
    topic: "Security",
    question: "Why is forward secrecy important for DMR encryption?",
    options: [
      "It makes encryption faster",
      "Compromising current keys doesn't expose past communications",
      "It reduces bandwidth usage",
      "It's required by FCC regulations",
    ],
    correctAnswer: 1,
    explanation: "Forward secrecy ensures that past communications remain secure even if current encryption keys are later compromised.",
  },
];

// Code block component
const CodeBlock: React.FC<{ code: string; language?: string }> = ({
  code,
  language = "bash",
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
        p: 2,
        bgcolor: theme.bgCode,
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: `1px solid ${theme.border}`,
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8 }}>
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: theme.textMuted }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Typography
        component="pre"
        sx={{
          fontFamily: "monospace",
          fontSize: "0.85rem",
          color: theme.text,
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
          m: 0,
          pr: 4,
        }}
      >
        {code}
      </Typography>
    </Paper>
  );
};

const DMRHackingPage: React.FC = () => {
  const navigate = useNavigate();
  const muiTheme = useTheme();
  const isMobile = useMediaQuery(muiTheme.breakpoints.down("md"));
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    setNavDrawerOpen(false);
  };

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  // Sidebar navigation
  const sidebarNav = (
    <Box sx={{ position: "sticky", top: 24 }}>
      <Paper
        sx={{
          bgcolor: theme.bgCard,
          border: `1px solid ${theme.border}`,
          borderRadius: 2,
          p: 2,
        }}
      >
        <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 2, fontWeight: 600 }}>
          NAVIGATION
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
                bgcolor: "transparent",
                width: "100%",
                textAlign: "left",
                "&:hover": {
                  bgcolor: alpha(theme.primary, 0.1),
                },
              }}
            >
              <ListItemIcon sx={{ minWidth: 32, color: theme.primary }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  variant: "body2",
                  sx: { color: theme.text },
                }}
              />
            </ListItem>
          ))}
        </List>
      </Paper>
    </Box>
  );

  return (
    <LearnPageLayout
      pageTitle="DMR Hacking & Security"
      pageContext="This page covers Digital Mobile Radio (DMR) security, including protocol fundamentals, encryption weaknesses, reconnaissance techniques, exploitation methods, and defensive measures. Focus on educational content about two-way radio security research."
    >
      <Box sx={{ bgcolor: theme.bgDark, minHeight: "100vh", py: 4 }}>
        <Container maxWidth="xl">
          <Grid container spacing={3}>
            {/* Sidebar - Desktop */}
            <Grid item md={3} sx={{ display: { xs: "none", md: "block" } }}>
              {sidebarNav}
            </Grid>

            {/* Main Content */}
            <Grid item xs={12} md={9}>
              {/* Back to Learning Hub */}
              <Chip
                component={Link}
                to="/learn"
                icon={<ArrowBackIcon />}
                label="Back to Learning Hub"
                clickable
                variant="outlined"
                sx={{
                  mb: 3,
                  borderColor: theme.primary,
                  color: theme.primary,
                  "&:hover": {
                    bgcolor: alpha(theme.primary, 0.1),
                    borderColor: theme.primaryLight,
                  },
                }}
              />

              {/* Header */}
              <Paper
                sx={{
                  p: 4,
                  mb: 4,
                  bgcolor: theme.bgCard,
                  border: `1px solid ${theme.border}`,
                  borderRadius: 2,
                  background: `linear-gradient(135deg, ${theme.bgCard} 0%, ${alpha(theme.primary, 0.1)} 100%)`,
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <RadioIcon sx={{ fontSize: 48, color: theme.primary }} />
                  <Box>
                    <Typography variant="h4" sx={{ color: theme.text, fontWeight: 700 }}>
                      DMR Hacking & Security
                    </Typography>
                    <Typography variant="subtitle1" sx={{ color: theme.textMuted }}>
                      Digital Mobile Radio Protocol Analysis & Exploitation
                    </Typography>
                  </Box>
                </Box>
                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 2 }}>
                  <Chip label="ETSI TS 102 361" size="small" sx={{ bgcolor: alpha(theme.primary, 0.2), color: theme.primary }} />
                  <Chip label="TDMA" size="small" sx={{ bgcolor: alpha(theme.secondary, 0.2), color: theme.secondary }} />
                  <Chip label="4FSK" size="small" sx={{ bgcolor: alpha(theme.accent, 0.2), color: theme.accent }} />
                  <Chip label="AMBE+2" size="small" sx={{ bgcolor: alpha(theme.info, 0.2), color: theme.info }} />
                </Box>
              </Paper>

              {/* Introduction Section */}
              <Box id="intro" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <SchoolIcon /> Introduction to DMR Security
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Digital Mobile Radio (DMR) is an ETSI standard for professional mobile radio communications used by
                    businesses, public safety agencies, utilities, and amateur radio operators worldwide. Understanding
                    DMR security is essential for protecting critical communications infrastructure.
                  </Typography>

                  {/* Deep Theory: History and Evolution */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Historical Context and Evolution of Digital Mobile Radio
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The evolution of professional mobile radio (PMR) communications represents a fascinating journey from simple
                      analog amplitude modulation systems of the early 20th century to the sophisticated digital protocols we use today.
                      DMR emerged in the late 2000s as a response to the growing need for spectrum-efficient digital communications
                      that could replace aging analog infrastructure while providing enhanced features such as text messaging, GPS
                      location services, and improved audio quality in challenging RF environments.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The European Telecommunications Standards Institute (ETSI) published the DMR standard (TS 102 361) in 2005,
                      establishing a framework for interoperable digital two-way radio communications. Unlike proprietary systems
                      such as Motorola's MotoTRBO or Kenwood's NEXEDGE, DMR was designed from the ground up as an open standard,
                      enabling multiple manufacturers to produce compatible equipment. This openness has been both a blessing—promoting
                      competition and lowering costs—and a challenge for security, as the protocol's specifications are publicly
                      available for analysis by both defenders and potential attackers.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The migration from analog to digital radio communications follows a global trend driven by regulatory requirements
                      for narrowbanding—the mandated reduction in channel bandwidth to increase spectrum efficiency. In the United States,
                      the FCC required all Part 90 licensees to migrate to 12.5 kHz narrowband channels by January 2013. DMR's 2-slot
                      TDMA architecture elegantly addresses this requirement by providing two simultaneous voice paths on a single
                      12.5 kHz channel, effectively doubling spectrum efficiency compared to analog FM while maintaining backward
                      compatibility with existing repeater infrastructure through careful frequency planning.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      From a security research perspective, DMR occupies a unique position in the radio communications landscape.
                      Its widespread adoption across critical infrastructure—including utilities, transportation, manufacturing,
                      and public safety—makes it a high-value target for adversaries seeking to disrupt operations or gather
                      intelligence. Simultaneously, the amateur radio community's embrace of DMR provides researchers with a legal
                      platform for protocol analysis and security experimentation, as amateur DMR transmissions are required by
                      regulation to remain unencrypted in most jurisdictions. This dual nature of DMR—critical infrastructure
                      technology and amateur experimentation platform—creates a rich environment for security research that
                      benefits both communities.
                    </Typography>
                  </Box>

                  {/* Deep Theory: Why DMR Security Matters */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      The Strategic Importance of Radio Communications Security
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Radio communications occupy a fundamentally different threat landscape compared to wired network protocols.
                      Unlike TCP/IP traffic that traverses defined network paths and can be segmented with firewalls and access
                      controls, radio frequency transmissions propagate through free space and can be received by any appropriately
                      equipped receiver within range. This inherent broadcast nature of RF communications means that confidentiality
                      must be achieved through cryptographic means rather than physical isolation—a principle that many DMR deployments
                      fail to adequately address.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The consequences of compromised radio communications extend far beyond simple eavesdropping. Consider a
                      scenario where an adversary gains the ability to transmit on a DMR network used by emergency services:
                      false dispatch calls could divert resources from genuine emergencies, impersonation of supervisors could
                      authorize inappropriate actions, and coordinated jamming during critical incidents could render the entire
                      communication system useless precisely when it's needed most. Historical incidents have demonstrated that
                      even passive monitoring of unencrypted public safety communications provides tactical advantages to criminals
                      seeking to evade law enforcement.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The attack surface of a DMR system encompasses multiple layers: the RF physical layer where signals can
                      be captured, analyzed, jammed, or spoofed; the protocol layer where framing, addressing, and signaling
                      vulnerabilities exist; the cryptographic layer where weak or improperly implemented encryption can be
                      broken; the infrastructure layer where repeaters, controllers, and IP backhaul networks may have
                      traditional IT vulnerabilities; and the human layer where social engineering and operational security
                      failures can compromise even well-designed technical controls. Effective DMR security requires addressing
                      threats at all these levels through a defense-in-depth approach.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Understanding DMR security is not merely an academic exercise—it has direct implications for the protection
                      of critical national infrastructure. Electric utilities use DMR for SCADA communications with remote
                      substations, transportation agencies coordinate rail movements and traffic management, and water treatment
                      facilities monitor distributed assets across vast geographic areas. A sophisticated adversary targeting
                      these systems could leverage DMR vulnerabilities as an initial access vector or as a means of maintaining
                      persistent command-and-control channels that operate outside traditional network monitoring. Security
                      researchers who understand these systems are essential to identifying and remediating vulnerabilities
                      before they can be exploited at scale.
                    </Typography>
                  </Box>
                  <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha(theme.warning, 0.1), color: theme.text }}>
                    <Typography variant="body2">
                      <strong>Educational Purpose:</strong> This content is for authorized security research, amateur radio
                      experimentation, and defensive security only. Intercepting or interfering with radio communications
                      without authorization is illegal in most jurisdictions.
                    </Typography>
                  </Alert>

                  <Grid container spacing={2} sx={{ mb: 2 }}>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%" }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <BusinessIcon sx={{ color: theme.secondary }} />
                          <Typography variant="subtitle2" sx={{ color: theme.secondary, fontWeight: 600 }}>Commercial</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: theme.textMuted }}>
                          Retail, hospitality, manufacturing, transportation, security companies
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%" }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <LocalPoliceIcon sx={{ color: theme.error }} />
                          <Typography variant="subtitle2" sx={{ color: theme.error, fontWeight: 600 }}>Public Safety</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: theme.textMuted }}>
                          Police, fire, EMS, emergency management (often encrypted)
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%" }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <HeadsetMicIcon sx={{ color: theme.success }} />
                          <Typography variant="subtitle2" sx={{ color: theme.success, fontWeight: 600 }}>Amateur Radio</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: theme.textMuted }}>
                          Ham radio operators using Brandmeister, TGIF, and other networks
                        </Typography>
                      </Paper>
                    </Grid>
                  </Grid>

                  <Box sx={{ bgcolor: theme.bgNested, p: 2, borderRadius: 1 }}>
                    <Typography variant="subtitle2" sx={{ color: theme.secondary, mb: 1 }}>
                      Why Study DMR Security?
                    </Typography>
                    <List dense>
                      {[
                        "Critical infrastructure often relies on DMR for coordination",
                        "Many systems use weak or no encryption",
                        "Radio ID spoofing and replay attacks are practical threats",
                        "Growing adoption means increasing attack surface",
                        "Amateur radio provides legal experimentation platform",
                      ].map((item, idx) => (
                        <ListItem key={idx} sx={{ py: 0.5 }}>
                          <ListItemIcon sx={{ minWidth: 32 }}>
                            <KeyboardArrowRightIcon sx={{ color: theme.secondary }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.text } }} />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                </Paper>
              </Box>

              {/* DMR Protocol Section */}
              <Box id="protocol" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <RadioIcon /> DMR Protocol Fundamentals
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    DMR is defined in ETSI TS 102 361 and uses TDMA technology to provide two voice/data paths
                    on a single 12.5 kHz channel.
                  </Typography>

                  {/* Deep Theory: TDMA Architecture */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Understanding Time Division Multiple Access (TDMA) in DMR
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Time Division Multiple Access represents one of the fundamental multiplexing strategies in digital communications,
                      and its implementation in DMR provides an elegant solution to the challenge of spectrum efficiency. Unlike
                      Frequency Division Multiple Access (FDMA) systems where each user occupies a distinct frequency channel
                      simultaneously, TDMA systems allow multiple users to share a single frequency by allocating each user exclusive
                      access during specific time intervals called "slots." In DMR, each 12.5 kHz channel is divided into two
                      alternating time slots, enabling two independent voice or data streams to coexist on what would otherwise
                      be a single analog channel.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The DMR TDMA frame has a total duration of 60 milliseconds, divided evenly between Time Slot 1 (TS1) and
                      Time Slot 2 (TS2), each lasting 30 milliseconds. Within each slot, the radio transmits a burst containing
                      voice frames, data packets, or control signaling. The precision required for TDMA operation is remarkable—
                      radios must synchronize their transmissions to within microseconds to avoid overlapping into adjacent time
                      slots, a phenomenon known as "slot collision" that would corrupt both channels. This synchronization is
                      achieved through the CACH (Common Announcement Channel) embedded in each burst, which provides timing
                      references that receiving radios use to maintain slot alignment.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      From an RF efficiency perspective, TDMA offers significant advantages over continuous-wave analog transmission.
                      Because each radio only transmits during its assigned slot (approximately 50% duty cycle for a single-slot
                      transmission), the average power consumption and heat dissipation are reduced, extending battery life in
                      portable radios. The transmitter effectively operates in a burst mode, keying up for 30 ms and then
                      going silent while the other slot transmits. This pulsed nature of TDMA also has implications for signal
                      reception—the receiver must precisely gate its processing to capture only the relevant slot, rejecting
                      energy from the alternate slot that may contain traffic for a different talk group or user.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      The security implications of TDMA extend beyond simple eavesdropping concerns. An attacker with precise
                      timing capabilities could theoretically perform selective jamming—disrupting only one time slot while
                      leaving the other operational, or targeting specific portions of a burst such as the header or SYNC
                      patterns to cause maximum disruption with minimal transmitted energy. Additionally, the shared nature
                      of the frequency channel means that traffic analysis can reveal patterns even when encryption is employed:
                      an observer can determine how many simultaneous conversations are occurring, the duration and timing
                      of calls, and potentially correlate activity patterns with external events. Understanding these
                      TDMA-specific attack vectors is essential for both offensive security assessment and defensive
                      system hardening.
                    </Typography>
                  </Box>

                  {/* Deep Theory: 4FSK Modulation */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      4FSK Modulation: The Physical Layer Foundation
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      At the physical layer, DMR employs 4-level Frequency Shift Keying (4FSK), a modulation scheme that encodes
                      digital data by shifting the transmitted carrier frequency between four discrete states. Each frequency
                      deviation represents a "symbol" that carries two bits of information (a "dibit"), enabling a data rate
                      of 9,600 bits per second while maintaining the 4,800 symbol-per-second rate compatible with the 12.5 kHz
                      channel bandwidth. The four frequency deviations used in DMR are +1,944 Hz, +648 Hz, -648 Hz, and -1,944 Hz
                      relative to the carrier center frequency, corresponding to the symbol values +3, +1, -1, and -3 in a
                      normalized representation.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The choice of 4FSK over simpler 2FSK (as used in some earlier digital systems) or more complex modulation
                      schemes (such as QPSK or OFDM found in LTE) reflects a careful balance between spectral efficiency, robustness,
                      and implementation complexity. 4FSK provides twice the bit rate of 2FSK within the same bandwidth while
                      maintaining the constant-envelope characteristic that allows efficient class-C amplification—critical for
                      battery-powered portable radios. The frequency deviations are carefully chosen to maintain adequate separation
                      between adjacent symbols while staying within the channel bandwidth limits, with the outer deviation
                      (±1,944 Hz) providing good noise immunity and the inner deviation (±648 Hz) ensuring distinguishability
                      even in the presence of frequency drift or Doppler shift from mobile operation.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Demodulation of 4FSK signals requires careful consideration of both frequency discrimination and symbol
                      timing recovery. The classic approach uses a frequency discriminator—either analog (Foster-Seeley or ratio
                      detector) or digital (arctangent of IQ samples with phase unwrapping)—to convert the frequency-modulated
                      signal into a baseband waveform whose amplitude corresponds to the instantaneous frequency deviation.
                      This baseband signal is then sampled at the symbol rate (4,800 samples per second) and quantized to one
                      of four levels using decision thresholds. The mapping from frequency deviation to dibit value uses Gray
                      coding, where adjacent symbols differ by only one bit, minimizing the bit error rate when noise causes
                      a symbol to be mistaken for its neighbor.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      For security researchers working with Software Defined Radio, understanding the 4FSK demodulation chain
                      is essential for both passive signal analysis and active transmission experiments. The entire demodulation
                      process can be implemented in software using tools like GNU Radio, enabling capture and processing of raw
                      IQ samples into decoded DMR frames. Key challenges include automatic frequency control (AFC) to track
                      transmitter drift, symbol timing recovery to sample at the optimal instant within each symbol period,
                      and frame synchronization to align the decoded symbols with the DMR burst structure. Each of these
                      processing stages represents a potential point of vulnerability—an adversary could potentially inject
                      carefully crafted signals designed to confuse AFC loops, corrupt timing recovery, or exploit edge cases
                      in frame parsing logic.
                    </Typography>
                  </Box>

                  {/* Deep Theory: AMBE+2 Voice Codec */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      AMBE+2 Voice Codec: Compression and Security Implications
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The Advanced Multi-Band Excitation (AMBE+2) vocoder, developed by Digital Voice Systems Inc. (DVSI),
                      serves as the voice compression engine for DMR and several other digital radio standards including D-STAR
                      and System Fusion. AMBE+2 achieves remarkable compression ratios by modeling the human vocal tract rather
                      than directly digitizing the acoustic waveform. At its core, the codec analyzes speech frames (typically
                      20 ms segments) and extracts parameters describing the fundamental frequency (pitch), spectral envelope
                      (formants), and voiced/unvoiced characteristics. These parameters are quantized and encoded into a compact
                      bitstream of approximately 2,450 bits per second, representing a compression ratio of over 25:1 compared
                      to telephone-quality PCM audio.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The security implications of vocoder-based compression are subtle but significant. Because AMBE+2 processes
                      speech using a parametric model, certain non-speech sounds—background noise, musical tones, DTMF signaling—
                      may be poorly reproduced or completely suppressed, as these signals don't conform to the speech model
                      assumptions. This characteristic can actually aid eavesdropping in some scenarios: encoded silence frames
                      have predictable, known bit patterns that can serve as "cribs" for cryptanalysis when weak encryption
                      (such as Basic Privacy) is employed. Similarly, common speech patterns and phrases produce recognizable
                      vocoder outputs, potentially enabling known-plaintext attacks against improperly protected communications.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The proprietary nature of AMBE+2 presents both challenges and opportunities for security research. DVSI
                      maintains tight control over the codec specifications, requiring licensing for implementation and restricting
                      access to detailed algorithmic documentation. This "security through obscurity" approach has historically
                      provided some barrier to casual eavesdropping, as decoding DMR audio required either licensed hardware or
                      reverse-engineered implementations. However, open-source projects such as mbelib have successfully recreated
                      AMBE decoding functionality through careful analysis, enabling software-defined radio receivers to produce
                      intelligible audio from captured DMR transmissions. The existence of these implementations means that
                      the vocoder itself provides no meaningful security—protection of voice communications must rely entirely
                      on the cryptographic layer.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      For researchers analyzing DMR traffic, understanding the AMBE+2 frame structure is essential for both
                      decoding voice and identifying metadata. Each voice superframe in DMR contains six AMBE+2 voice frames
                      distributed across the burst, interleaved with embedded signaling (EMB) and link control (LC) information.
                      The forward error correction applied to voice frames (rate 3/4 convolutional coding) provides resilience
                      against channel errors but also creates patterns that can aid in frame synchronization and protocol
                      analysis. Tools like DSD+ leverage this structure to decode audio even from weak or partially corrupted
                      signals, demonstrating both the robustness of the DMR design and the accessibility of transmitted voice
                      content to anyone with appropriate receiving equipment.
                    </Typography>
                  </Box>

                  <Box sx={{ bgcolor: theme.bgNested, p: 2, borderRadius: 1, mb: 3 }}>
                    <Typography variant="subtitle2" sx={{ color: theme.secondary, mb: 1 }}>
                      Key Technical Specifications
                    </Typography>
                    <TableContainer>
                      <Table size="small">
                        <TableBody>
                          {[
                            { param: "Channel Bandwidth", value: "12.5 kHz" },
                            { param: "Modulation", value: "4FSK (4-level FSK)" },
                            { param: "Symbol Rate", value: "4800 symbols/second" },
                            { param: "Data Rate", value: "9.6 kbps (4.8 kbps per slot)" },
                            { param: "Access Method", value: "2-slot TDMA" },
                            { param: "Voice Codec", value: "AMBE+2 (~2.4 kbps)" },
                            { param: "Frame Duration", value: "60 ms (30 ms per slot)" },
                            { param: "Frequency Range", value: "VHF (136-174 MHz), UHF (400-527 MHz)" },
                          ].map((row, idx) => (
                            <TableRow key={idx}>
                              <TableCell sx={{ color: theme.secondary, fontWeight: 600, border: "none", py: 0.5 }}>{row.param}</TableCell>
                              <TableCell sx={{ color: theme.text, fontFamily: "monospace", border: "none", py: 0.5 }}>{row.value}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Box>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        TDMA Frame Structure
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`DMR TDMA Frame Structure (60 ms total)
═══════════════════════════════════════════════════════════════

│←───────────── 30 ms ──────────────→│←───────────── 30 ms ──────────────→│
┌─────────────────────────────────────┬─────────────────────────────────────┐
│           TIME SLOT 1               │           TIME SLOT 2               │
│  (Voice/Data Burst 1)               │  (Voice/Data Burst 2)               │
└─────────────────────────────────────┴─────────────────────────────────────┘

Single Burst Structure (27.5 ms payload):
┌──────┬────────┬──────┬──────────┬──────┬────────┬──────┐
│ CACH │ Voice  │ SYNC │  EMB/LC  │Voice │  SYNC  │ CACH │
│ 12   │  54    │  48  │   32     │  54  │   48   │  12  │ symbols
└──────┴────────┴──────┴──────────┴──────┴────────┴──────┘

CACH: Common Announcement Channel (slot timing)
SYNC: Synchronization pattern (identifies burst type)
EMB:  Embedded signaling (color code, PI, LCSS)
LC:   Link Control (source/dest IDs, talk group)`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Color Codes & Talk Groups
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        DMR uses Color Codes (0-15) to separate co-channel systems, similar to CTCSS/DCS in analog.
                        Talk Groups provide virtual channels for organizing communications.
                      </Typography>
                      <CodeBlock
                        code={`Color Code: 4-bit value (0-15)
- Embedded in every burst
- Must match for communication
- Prevents cross-talk between adjacent systems

Talk Group Types:
┌─────────────────┬──────────────────────────────────────────┐
│ Group Call      │ One-to-many within talk group            │
│ Private Call    │ One-to-one between specific radio IDs    │
│ All Call        │ Broadcast to all radios on the channel   │
└─────────────────┴──────────────────────────────────────────┘

Common Talk Group Ranges:
- 1-999:        Local/regional groups
- 1000-9999:    National groups
- 10000+:       Special purpose (parrot, testing)
- 91-99:        Worldwide groups (Brandmeister)`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        DMR Data Types
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        {[
                          { type: "Voice", desc: "AMBE+2 encoded audio, ~2.4 kbps" },
                          { type: "SMS", desc: "Short text messages between radios" },
                          { type: "GPS/Location", desc: "Position data embedded in transmissions" },
                          { type: "Telemetry", desc: "Status, emergency, remote monitoring" },
                          { type: "IP Data", desc: "Packet data for connected systems" },
                        ].map((item, idx) => (
                          <Grid item xs={12} sm={6} key={idx}>
                            <Box sx={{ p: 1.5, bgcolor: theme.bgCode, borderRadius: 1 }}>
                              <Typography variant="subtitle2" sx={{ color: theme.primary }}>{item.type}</Typography>
                              <Typography variant="caption" sx={{ color: theme.textMuted }}>{item.desc}</Typography>
                            </Box>
                          </Grid>
                        ))}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Network Architecture Section */}
              <Box id="architecture" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <CellTowerIcon /> DMR Network Architecture
                  </Typography>

                  {/* Deep Theory: Network Topology */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Understanding DMR Network Topologies and Their Security Implications
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      DMR network architecture encompasses a spectrum of complexity from simple peer-to-peer simplex operation
                      to sophisticated multi-site trunked systems spanning geographic regions. Each architectural pattern presents
                      distinct security considerations, attack surfaces, and protective capabilities. Understanding these topologies
                      is essential for both assessing the security posture of specific deployments and designing new systems with
                      security requirements in mind.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      At the simplest level, DMR Tier I systems operate in direct mode (simplex) where radios communicate
                      peer-to-peer without infrastructure support. This topology, common in consumer and light-commercial
                      applications, offers minimal attack surface—there's no repeater to compromise, no IP backhaul to intercept,
                      and no central controller to target. However, Tier I systems also lack any infrastructure-based security
                      controls: there's no authentication server to validate radio IDs, no logging system to record traffic,
                      and no management interface to push configuration changes. Security relies entirely on the radios themselves
                      and whatever encryption they implement locally.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Tier II conventional systems introduce repeater infrastructure that extends range and enables centralized
                      monitoring but also creates new attack surfaces. The repeater itself becomes a high-value target—an adversary
                      who compromises the repeater gains the ability to intercept all traffic passing through it, potentially
                      inject malicious transmissions, or deny service by taking the repeater offline. IP Site Connect extends
                      Tier II systems across multiple locations by linking repeaters over IP networks, introducing traditional
                      IT security concerns: the IP backhaul must be secured against interception and injection, authentication
                      between sites prevents rogue repeaters from joining the network, and the internet connectivity creates
                      potential for remote attacks from anywhere in the world.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Tier III trunked systems provide the most sophisticated architecture but also the most complex security
                      landscape. A central controller manages channel allocation, tracks radio registration, enforces access
                      control policies, and may provide encryption key management through OTAR. This centralization enables
                      comprehensive security controls impossible in simpler architectures—but it also concentrates risk. The
                      control channel becomes a critical chokepoint whose disruption affects the entire system. The controller
                      database containing radio registrations, talk group memberships, and potentially encryption keys represents
                      a high-value target. The management interfaces used for system administration must be secured against
                      unauthorized access that could modify security policies or extract sensitive configuration data.
                    </Typography>
                  </Box>

                  {/* Deep Theory: IP Interconnection */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      IP Interconnection: Where Radio Meets Network Security
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Modern DMR deployments increasingly rely on IP networks to interconnect sites, link to amateur networks
                      like Brandmeister, and provide remote management capabilities. This convergence of radio and IP networking
                      creates an intersection where traditional network security practices become essential components of DMR
                      protection. The protocols used for DMR-over-IP—including Homebrew/MMDVM, IPSC, DMR+, and proprietary
                      manufacturer protocols—were designed primarily for functionality rather than security, creating
                      opportunities for network-based attacks that complement RF-based threats.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The Homebrew protocol, widely used by amateur DMR hotspots and open-source repeater projects, transports
                      DMR frames over UDP without encryption or strong authentication. Anyone who can access the network path
                      between a hotspot and a master server can intercept DMR traffic, inject frames, or impersonate either
                      endpoint. The authentication mechanism—typically a simple password hash exchanged during connection—is
                      vulnerable to replay attacks and provides no protection for the subsequent traffic stream. For amateur
                      applications where encryption is prohibited anyway, this may be acceptable; for commercial or critical
                      infrastructure deployments, wrapping the DMR-over-IP traffic in a VPN tunnel provides essential protection.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Network segmentation principles apply to DMR infrastructure just as they do to traditional IT systems.
                      DMR controllers, repeaters, and management stations should reside on isolated network segments with
                      firewall controls limiting access to only necessary traffic flows. Management interfaces should be
                      accessible only from designated administrative workstations, ideally through jump servers that provide
                      additional logging and access control. The principle of least privilege dictates that each network
                      component should have only the connectivity required for its function—a repeater doesn't need outbound
                      internet access, and the management console doesn't need direct access to the radio network.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Amateur DMR networks like Brandmeister and TGIF provide fascinating case studies in large-scale DMR security.
                      These networks connect thousands of repeaters and hotspots worldwide, creating a massive distributed
                      system with limited central control over endpoint security. The networks implement various abuse prevention
                      mechanisms—rate limiting, IP blacklists, ID validation against the RadioID.net database—but fundamental
                      authentication weaknesses remain. Security researchers have demonstrated injection of false traffic,
                      impersonation of repeaters, and traffic interception on these networks, highlighting vulnerabilities
                      that could have more serious consequences if similar weaknesses exist in critical infrastructure DMR
                      deployments sharing architectural patterns with amateur systems.
                    </Typography>
                  </Box>

                  <TableContainer component={Paper} sx={{ bgcolor: theme.bgNested, mb: 3 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Tier</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Name</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Use Case</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Encryption</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          { tier: "I", name: "dPMR446", use: "Unlicensed, consumer (Europe 446 MHz)", enc: "None/Basic" },
                          { tier: "II", name: "Conventional", use: "Licensed, business/amateur, repeaters", enc: "Basic/Enhanced" },
                          { tier: "III", name: "Trunked", use: "Public safety, large enterprise", enc: "AES-256" },
                        ].map((row, idx) => (
                          <TableRow key={idx} sx={{ "&:hover": { bgcolor: alpha(theme.primary, 0.05) } }}>
                            <TableCell sx={{ color: theme.secondary, fontWeight: 600 }}>Tier {row.tier}</TableCell>
                            <TableCell sx={{ color: theme.text }}>{row.name}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{row.use}</TableCell>
                            <TableCell sx={{ color: theme.accent }}>{row.enc}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Tier II - Conventional Systems
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Tier II Network Topology
════════════════════════════════════════════════════════════

Simple Repeater:
                    ┌─────────────┐
    Radio A ───────►│   REPEATER  │◄─────── Radio B
    (TX: 445.500)   │  (Duplex)   │   (TX: 445.500)
                    │ RX: 445.500 │
                    │ TX: 440.500 │
                    └─────────────┘

IP Site Connect (Multi-Site):
┌─────────┐     ┌─────────────┐     ┌─────────┐
│ Site A  │────►│  IP Network │◄────│ Site B  │
│Repeater │     │  (Internet) │     │Repeater │
└─────────┘     └─────────────┘     └─────────┘
                       │
                       ▼
                ┌─────────────┐
                │   Site C    │
                │  Repeater   │
                └─────────────┘

Capacity Plus (Single-Site Trunking):
- Up to 12 repeaters at one site
- Dynamic channel allocation
- Still Tier II licensing`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Amateur DMR Networks
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        {[
                          { name: "Brandmeister", desc: "Largest worldwide network, 5000+ repeaters", region: "Global" },
                          { name: "TGIF", desc: "The Group of International Friends network", region: "Global" },
                          { name: "DMR+", desc: "European-focused network", region: "Europe" },
                          { name: "FreeDMR", desc: "Open-source DMR network", region: "Global" },
                        ].map((net, idx) => (
                          <Grid item xs={12} sm={6} key={idx}>
                            <Paper sx={{ p: 2, bgcolor: theme.bgCode }}>
                              <Typography variant="subtitle2" sx={{ color: theme.primary }}>{net.name}</Typography>
                              <Typography variant="caption" sx={{ color: theme.textMuted, display: "block" }}>{net.desc}</Typography>
                              <Chip label={net.region} size="small" sx={{ mt: 1, bgcolor: alpha(theme.success, 0.2), color: theme.success }} />
                            </Paper>
                          </Grid>
                        ))}
                      </Grid>
                      <Alert severity="info" sx={{ mt: 2, bgcolor: alpha(theme.info, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          Amateur networks are <strong>unencrypted by law</strong> in most countries, making them
                          ideal for learning DMR protocol analysis legally.
                        </Typography>
                      </Alert>
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Encryption Section */}
              <Box id="encryption" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <LockIcon /> DMR Encryption & Security
                  </Typography>

                  <Alert severity="error" sx={{ mb: 3, bgcolor: alpha(theme.error, 0.1), color: theme.text }}>
                    <Typography variant="body2">
                      <strong>Critical:</strong> Basic Privacy (BP) encryption is trivially broken. Many commercial
                      DMR systems rely on this weak protection, leaving communications exposed.
                    </Typography>
                  </Alert>

                  {/* Deep Theory: Cryptographic Foundations */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Cryptographic Architecture and Fundamental Weaknesses
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The encryption landscape in DMR reflects an uncomfortable tension between cost-conscious commercial deployments
                      and the cryptographic requirements of secure communications. At the protocol level, DMR defines several
                      privacy options ranging from Basic Privacy—a woefully inadequate 16-bit XOR scrambling mechanism—through
                      Enhanced Privacy with 40-bit RC4, to full AES-256 encryption typically reserved for Tier III trunked systems
                      and high-security applications. Understanding the cryptographic weaknesses at each level is essential for
                      both security assessors evaluating DMR deployments and defenders seeking to protect their communications.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Basic Privacy, despite its name suggesting some level of protection, provides virtually no cryptographic
                      security by modern standards. The mechanism operates as a simple XOR cipher with a 16-bit key, meaning
                      the entire keyspace consists of only 65,536 possible values. A brute-force attack testing all possible
                      keys takes mere milliseconds on commodity hardware, making Basic Privacy trivially breakable in real-time.
                      The situation is actually worse than pure brute force suggests: the AMBE+2 vocoder produces highly structured
                      output with known patterns (particularly for silence frames and common phonemes), providing abundant
                      known plaintext for cryptanalysis. An attacker can XOR captured ciphertext with suspected plaintext patterns
                      to directly recover the key without any brute-force search whatsoever.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Enhanced Privacy represents an improvement but still falls short of modern security requirements in its
                      weaker configurations. The 40-bit RC4 option, while computationally more demanding to brute-force than
                      Basic Privacy's 16-bit key, remains within reach of determined attackers with moderate resources. More
                      concerning are the well-documented cryptographic weaknesses in RC4 itself: statistical biases in the
                      keystream output, particularly in the first bytes, have enabled practical attacks against protocols
                      ranging from WEP wireless encryption to TLS. When RC4 is used with predictable or reused initialization
                      vectors—a common implementation flaw in embedded radio firmware—these weaknesses become dramatically
                      more exploitable.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Only AES-256 encryption, properly implemented with secure key management, provides cryptographic protection
                      that meets contemporary security standards. The 256-bit key space renders brute-force attacks computationally
                      infeasible, and the AES algorithm itself has withstood over two decades of intense cryptanalytic scrutiny
                      without significant practical breaks. However, the strength of AES encryption is only realized when combined
                      with proper key management practices: keys must be generated from high-quality random sources, distributed
                      securely, rotated regularly, and protected from extraction through physical or electronic means. Many
                      ostensibly AES-encrypted DMR systems fail at one or more of these requirements, creating vulnerabilities
                      that bypass the cryptographic strength entirely—a compromised key provides complete access regardless of
                      the cipher's theoretical security.
                    </Typography>
                  </Box>

                  {/* Deep Theory: Key Management Challenges */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Key Management: The Achilles Heel of Radio Encryption
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The practical security of any encryption system depends critically on key management—how cryptographic keys
                      are generated, distributed, stored, used, and eventually retired. In the context of DMR radio networks,
                      key management presents unique challenges that often lead to security compromises even when strong encryption
                      algorithms are employed. Unlike IP networks where automated key exchange protocols like IKE/IPsec can
                      negotiate fresh session keys for each connection, radio networks traditionally relied on static pre-shared
                      keys programmed into devices during initial deployment, creating a brittle security model vulnerable to
                      key compromise.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Consider the operational reality of a DMR deployment with 500 portable radios distributed across a large
                      organization. Each radio must be programmed with encryption keys using a Customer Programming Software
                      (CPS) application—typically requiring physical connection via USB or serial cable. If a single radio is
                      lost or stolen, the encryption key it contains is potentially compromised, necessitating rekeying of all
                      500 units to maintain confidentiality. The logistical burden of such an operation—recalling radios,
                      connecting them individually, uploading new codeplugs—often leads organizations to defer rekeying far
                      longer than security best practices would dictate, or to simply accept the risk of compromised keys
                      rather than bear the operational cost of rotation.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Over-The-Air Rekeying (OTAR) addresses these challenges by enabling encryption keys to be updated remotely
                      via encrypted radio transmissions, eliminating the need for physical access to devices. When properly
                      implemented, OTAR dramatically improves operational security posture: keys can be rotated on regular
                      schedules, compromised radios can have their keys immediately revoked, and emergency rekeying in response
                      to suspected breaches becomes operationally feasible. However, OTAR itself introduces new attack surfaces—
                      the key encryption key (KEK) used to protect OTAR transmissions must be pre-shared and maintained, and
                      the OTAR protocol itself may have implementation vulnerabilities that could enable key injection or extraction.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      The human element in key management deserves particular attention. Encryption keys are often generated
                      using predictable patterns (sequential numbers, dates, callsigns) rather than cryptographically random
                      sources, drastically reducing the effective keyspace. Keys may be written on labels affixed to radios
                      for "convenience," transmitted via unencrypted email or text message, or stored in unprotected spreadsheets
                      accessible to unauthorized personnel. Even sophisticated OTAR systems can be undermined by poor operational
                      security—the KEK itself must have been securely generated and distributed, creating a bootstrap problem
                      that ultimately requires some secure out-of-band channel for initial key establishment. Security researchers
                      assessing DMR deployments frequently find that the weakest link is not the cryptography itself but the
                      human processes surrounding key generation, distribution, and protection.
                    </Typography>
                  </Box>

                  {/* Deep Theory: Cryptanalytic Techniques */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Cryptanalytic Techniques Against DMR Encryption
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Cryptanalysis of DMR encryption systems employs a hierarchy of techniques ranging from brute-force
                      exhaustive search through sophisticated statistical and algebraic attacks. The choice of attack method
                      depends on the specific encryption implementation, available computational resources, amount of captured
                      ciphertext, and any available side-channel information. Understanding these techniques enables security
                      professionals to assess the practical vulnerability of specific DMR deployments and prioritize remediation
                      efforts accordingly.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      For Basic Privacy's 16-bit XOR cipher, brute-force attack represents the most straightforward approach.
                      The algorithm iterates through all 65,536 possible key values, decrypting captured ciphertext with each
                      candidate key and checking whether the result matches expected patterns for valid AMBE+2 voice frames.
                      The structure of AMBE+2 output provides abundant validation criteria: silence frames have known values,
                      voiced frames have constrained bit patterns in the pitch and gain parameters, and forward error correction
                      parity checks must be consistent. A modern CPU can test millions of keys per second, completing an
                      exhaustive search in under a millisecond. Real-time decryption of Basic Privacy traffic is therefore
                      trivially achievable with commodity hardware.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Known-plaintext attacks exploit the predictable structure of DMR transmissions to accelerate key recovery
                      without exhaustive search. Every DMR voice burst contains known elements: the SYNC pattern is constant
                      for each burst type, embedded signaling fields have constrained values, and AMBE+2 silence frames are
                      entirely predictable. When encryption is applied as a simple XOR operation (as in Basic Privacy), the
                      key can be directly recovered by XORing ciphertext with known plaintext: Key = Ciphertext ⊕ Plaintext.
                      Even partial known plaintext—such as a single silence frame within a transmission—provides sufficient
                      information to recover the key. This attack completes in microseconds, requiring only the capture of a
                      single encrypted transmission that includes any predictable content.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Against stronger encryption like RC4 or AES, direct cryptanalytic breaks are computationally infeasible
                      with current technology when properly implemented. However, implementation flaws frequently provide
                      alternative attack vectors. Weak random number generators used for key or IV generation may produce
                      predictable values reducible to brute-force search. Side-channel attacks can extract key material through
                      power analysis, electromagnetic emissions, or timing variations during cryptographic operations. Protocol-level
                      vulnerabilities may enable replay attacks where previously recorded encrypted transmissions are retransmitted
                      to cause unauthorized actions, or oracle attacks where the system's response to malformed ciphertext
                      leaks information about the key. Comprehensive security assessment of DMR encryption must consider not
                      only the theoretical strength of the cipher but also the complete implementation and deployment context.
                    </Typography>
                  </Box>

                  <Grid container spacing={3} sx={{ mb: 3 }}>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%", borderLeft: `4px solid ${theme.error}` }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <LockOpenIcon sx={{ color: theme.error }} />
                          <Typography variant="subtitle2" sx={{ color: theme.error, fontWeight: 600 }}>Basic Privacy</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: theme.textMuted, mb: 1 }}>
                          16-bit XOR scrambling
                        </Typography>
                        <List dense>
                          {[
                            "Only 65,536 possible keys",
                            "Trivial brute force",
                            "Known-plaintext attack",
                            "NOT real encryption",
                          ].map((item, idx) => (
                            <ListItem key={idx} sx={{ py: 0, pl: 0 }}>
                              <ListItemIcon sx={{ minWidth: 20 }}>
                                <WarningIcon sx={{ fontSize: 14, color: theme.error }} />
                              </ListItemIcon>
                              <ListItemText primary={item} primaryTypographyProps={{ variant: "caption", sx: { color: theme.textMuted } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%", borderLeft: `4px solid ${theme.warning}` }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <LockIcon sx={{ color: theme.warning }} />
                          <Typography variant="subtitle2" sx={{ color: theme.warning, fontWeight: 600 }}>Enhanced Privacy</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: theme.textMuted, mb: 1 }}>
                          40-bit RC4 or AES
                        </Typography>
                        <List dense>
                          {[
                            "40-bit still weak by modern standards",
                            "AES-128 option available",
                            "Proprietary implementation",
                            "Better but not ideal",
                          ].map((item, idx) => (
                            <ListItem key={idx} sx={{ py: 0, pl: 0 }}>
                              <ListItemIcon sx={{ minWidth: 20 }}>
                                <WarningIcon sx={{ fontSize: 14, color: theme.warning }} />
                              </ListItemIcon>
                              <ListItemText primary={item} primaryTypographyProps={{ variant: "caption", sx: { color: theme.textMuted } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%", borderLeft: `4px solid ${theme.success}` }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <SecurityIcon sx={{ color: theme.success }} />
                          <Typography variant="subtitle2" sx={{ color: theme.success, fontWeight: 600 }}>AES-256</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: theme.textMuted, mb: 1 }}>
                          Full AES encryption
                        </Typography>
                        <List dense>
                          {[
                            "Industry standard",
                            "256-bit keys",
                            "OTAR support",
                            "Required for public safety",
                          ].map((item, idx) => (
                            <ListItem key={idx} sx={{ py: 0, pl: 0 }}>
                              <ListItemIcon sx={{ minWidth: 20 }}>
                                <CheckCircleIcon sx={{ fontSize: 14, color: theme.success }} />
                              </ListItemIcon>
                              <ListItemText primary={item} primaryTypographyProps={{ variant: "caption", sx: { color: theme.textMuted } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                  </Grid>

                  <CodeBlock
                    code={`Basic Privacy Weakness Demonstration
════════════════════════════════════════════════════════════

Basic Privacy uses XOR with 16-bit key:
  Ciphertext = Plaintext XOR Key

Attack 1: Brute Force (trivial)
  - 2^16 = 65,536 possible keys
  - Test all keys in milliseconds
  - AMBE+2 codec provides known patterns

Attack 2: Known Plaintext
  - SYNC patterns are known (constant)
  - XOR ciphertext with known plaintext = key
  - Key = Ciphertext XOR Known_Plaintext

Attack 3: Crib Dragging
  - Voice has predictable patterns
  - Silence = specific AMBE+2 frames
  - "Break" and "Over" provide cribs

# Python pseudocode for BP attack:
for key in range(0, 65536):
    decrypted = xor_decrypt(ciphertext, key)
    if is_valid_ambe(decrypted):
        print(f"Key found: {key}")`}
                  />
                </Paper>
              </Box>

              {/* Hardware & Tools Section */}
              <Box id="hardware" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <BuildIcon /> Hardware & Tools
                  </Typography>

                  <Typography variant="subtitle1" sx={{ color: theme.text, mb: 2 }}>
                    Receive & Analysis Tools
                  </Typography>
                  <TableContainer component={Paper} sx={{ bgcolor: theme.bgNested, mb: 3 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Tool</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Type</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Cost</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Use Case</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          { tool: "RTL-SDR v3", type: "SDR Receiver", cost: "$30", use: "Basic DMR monitoring" },
                          { tool: "SDRPlay RSPdx", type: "SDR Receiver", cost: "$250", use: "Wideband monitoring" },
                          { tool: "HackRF One", type: "SDR Transceiver", cost: "$350", use: "TX/RX research" },
                          { tool: "DSD+", type: "Software Decoder", cost: "Free/Paid", use: "Decode DMR audio" },
                          { tool: "SDR#", type: "SDR Software", cost: "Free", use: "Signal visualization" },
                          { tool: "GQRX", type: "SDR Software", cost: "Free", use: "Linux SDR receiver" },
                          { tool: "OP25", type: "Decoder", cost: "Free", use: "P25/DMR decoding" },
                          { tool: "Wireshark", type: "Analyzer", cost: "Free", use: "DMR protocol analysis" },
                        ].map((row, idx) => (
                          <TableRow key={idx} sx={{ "&:hover": { bgcolor: alpha(theme.primary, 0.05) } }}>
                            <TableCell sx={{ color: theme.secondary, fontWeight: 500 }}>{row.tool}</TableCell>
                            <TableCell sx={{ color: theme.text }}>{row.type}</TableCell>
                            <TableCell sx={{ color: theme.accent }}>{row.cost}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{row.use}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  <Typography variant="subtitle1" sx={{ color: theme.text, mb: 2 }}>
                    DMR Radios for Research
                  </Typography>
                  <Grid container spacing={2}>
                    {[
                      { name: "TYT MD-380/390", price: "$80-150", notes: "Hackable firmware, well documented" },
                      { name: "Anytone AT-D878UV", price: "$200", notes: "Popular, APRS, Bluetooth" },
                      { name: "Ailunce HD1", price: "$150", notes: "GPS, dual band" },
                      { name: "Radioddity GD-77", price: "$80", notes: "OpenGD77 firmware available" },
                    ].map((radio, idx) => (
                      <Grid item xs={12} sm={6} key={idx}>
                        <Paper sx={{ p: 2, bgcolor: theme.bgNested }}>
                          <Typography variant="subtitle2" sx={{ color: theme.primary }}>{radio.name}</Typography>
                          <Typography variant="caption" sx={{ color: theme.accent, display: "block" }}>{radio.price}</Typography>
                          <Typography variant="caption" sx={{ color: theme.textMuted }}>{radio.notes}</Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>
              </Box>

              {/* SDR Signal Processing Section */}
              <Box id="sdr-processing" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <SettingsInputAntennaIcon /> SDR Signal Processing
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    Advanced Software Defined Radio techniques for DMR signal analysis, capture, and processing.
                  </Typography>

                  {/* Deep Theory: SDR Fundamentals */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Software Defined Radio: Principles and Architecture
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Software Defined Radio represents a paradigm shift in radio receiver design, replacing fixed analog circuitry
                      with flexible digital signal processing that can be reconfigured through software alone. Traditional radio
                      receivers implement filtering, demodulation, and decoding using discrete analog components—mixers, filters,
                      amplifiers, and discriminators—each designed for a specific modulation scheme and frequency band. SDR moves
                      these functions into the digital domain, where a general-purpose analog-to-digital converter captures raw
                      radio frequency energy, and software algorithms perform all subsequent processing. This flexibility enables
                      a single SDR device to receive DMR, FM broadcast, aircraft transponders, and countless other signals simply
                      by loading different software configurations.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The heart of any SDR system is the analog-to-digital conversion process, which must satisfy the Nyquist
                      criterion: the sampling rate must exceed twice the highest frequency component of the signal being digitized.
                      For practical RF reception, direct sampling at radio frequencies would require ADCs operating at billions
                      of samples per second—achievable with high-end equipment but impractical for consumer devices. Instead,
                      most affordable SDRs (including the popular RTL-SDR) use a technique called quadrature sampling or IQ
                      demodulation, where the RF signal is first mixed down to baseband (or a low intermediate frequency) and
                      then split into two components: the In-phase (I) and Quadrature (Q) channels, representing the real and
                      imaginary parts of the complex baseband signal. This representation preserves both the amplitude and phase
                      of the original RF signal, enabling complete reconstruction of the transmitted waveform in software.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The IQ representation of signals is fundamental to understanding SDR-based DMR reception. A complex IQ
                      sample can be thought of as a vector in the complex plane, where the length of the vector represents
                      instantaneous signal amplitude and the angle represents instantaneous phase. For frequency-modulated signals
                      like DMR's 4FSK, the frequency information is encoded in the rate of change of this phase angle over time.
                      Differentiating the unwrapped phase sequence yields instantaneous frequency, which can then be quantized
                      to recover the transmitted symbols. This mathematical elegance—reducing FM demodulation to phase differentiation—
                      illustrates why SDR has become the tool of choice for radio protocol analysis and security research.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      For security researchers, SDR provides unprecedented capability to capture, analyze, and manipulate radio
                      signals at every layer of the protocol stack. Raw IQ recordings preserve complete information about the
                      transmitted signal, enabling offline analysis with different parameters, algorithm development without
                      access to live RF sources, and reproducible experimentation impossible with traditional radio equipment.
                      The transition from received RF energy to decoded DMR frames involves a processing chain: antenna → RF
                      front-end → ADC → decimation/filtering → frequency correction → demodulation → symbol timing recovery →
                      frame synchronization → protocol decoding. Each stage presents opportunities for both analysis and potential
                      exploitation, and the open-source nature of SDR software allows researchers to inspect and modify every
                      algorithmic component.
                    </Typography>
                  </Box>

                  {/* Deep Theory: Digital Signal Processing Chain */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      The Digital Signal Processing Chain for DMR Reception
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Transforming raw IQ samples into decoded DMR audio and metadata requires a carefully designed signal processing
                      chain, each stage building upon the output of the previous. Understanding this chain is essential for
                      troubleshooting reception issues, optimizing performance, and identifying potential vulnerabilities in
                      the decoding process. The chain begins with sample rate conversion—most SDRs capture at rates far higher
                      than needed for a single 12.5 kHz DMR channel, and decimation filters reduce the data rate while rejecting
                      adjacent channel interference. A typical workflow might capture at 2.4 MS/s and decimate by 100 to achieve
                      24 kS/s, comfortably sampling the ~12 kHz occupied bandwidth of the DMR signal.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Frequency correction compensates for oscillator offset and drift in both the transmitter and receiver.
                      Affordable SDRs like RTL-SDR use low-cost crystal oscillators that may be tens of parts per million off
                      their nominal frequency, translating to kilohertz of error at UHF. Automatic Frequency Control (AFC)
                      algorithms estimate and correct this offset by analyzing the received signal—for DMR, the known SYNC
                      patterns or the center frequency of the 4FSK constellation provide suitable references. Without proper
                      AFC, the frequency offset causes the 4FSK symbols to drift across decision boundaries, dramatically
                      increasing the bit error rate or rendering demodulation entirely impossible.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Symbol timing recovery ensures that samples are taken at the optimal instant within each symbol period—
                      the point where the signal has stabilized after transitioning from the previous symbol and eye opening
                      is maximum. For DMR's 4800 symbol-per-second rate, each symbol spans approximately 5 samples at 24 kS/s,
                      but the optimal sampling instant rarely coincides exactly with available samples. Timing recovery algorithms
                      such as Mueller-Muller or Gardner use correlations between adjacent samples to estimate the timing error
                      and drive an interpolator that synthesizes samples at the correct instants. The recovered symbol stream
                      is then passed to a slicer that quantizes the continuous-valued symbols to one of four 4FSK levels,
                      yielding the raw dibit stream for further protocol processing.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Frame synchronization identifies the boundaries of DMR bursts within the continuous stream of received
                      symbols. This is accomplished by correlating the received sequence against the known 48-bit SYNC patterns
                      that mark each burst type (voice, data, CSBK, etc.). When correlation exceeds a threshold, the receiver
                      has found a burst boundary and can parse the remaining fields—CACH, voice payload, embedded signaling—
                      according to the DMR frame structure. Robust synchronization must handle errors in the SYNC pattern
                      caused by channel noise, tolerate frequency and timing offsets that haven't yet been fully corrected,
                      and avoid false triggers from random data that accidentally resembles a SYNC pattern. The interplay between
                      these stages—each depending on others for optimal performance—makes DMR SDR receiver design both challenging
                      and rewarding for signal processing practitioners.
                    </Typography>
                  </Box>

                  {/* Deep Theory: Signal Analysis Techniques */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Advanced Signal Analysis Techniques for Security Research
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Beyond basic reception, security researchers employ sophisticated signal analysis techniques to extract
                      intelligence from DMR transmissions, identify transmitter characteristics, and detect anomalies that
                      may indicate malicious activity. Spectral analysis using the Fast Fourier Transform (FFT) reveals the
                      frequency-domain structure of signals, enabling identification of modulation type, bandwidth measurement,
                      detection of spurious emissions, and identification of adjacent channel activity. Time-frequency representations
                      such as spectrograms (waterfall displays) show how spectral content evolves over time, making TDMA slot
                      boundaries visible and revealing the bursty nature of DMR transmissions.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Radio fingerprinting techniques can identify individual transmitters based on unique characteristics of
                      their RF emissions—subtle variations in carrier frequency stability, modulation index, power-on transients,
                      and spurious emissions that arise from manufacturing tolerances and component aging. These fingerprints
                      can potentially track individual radios across different locations and times, detect when a radio ID has
                      been spoofed (the RF fingerprint doesn't match the claimed ID), and correlate anonymous transmissions to
                      specific devices. While fingerprinting is challenging in practice—requiring clean signal captures and
                      extensive training data—its potential applications in DMR security monitoring are significant.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Direction finding and geolocation techniques exploit multiple receiving antennas to determine the bearing
                      or position of a transmitter. Simple implementations use directional antennas manually rotated to find
                      maximum signal strength, while sophisticated systems employ antenna arrays with phase-coherent receivers
                      to compute angle-of-arrival. Time-difference-of-arrival (TDOA) methods using multiple geographically
                      separated receivers can locate transmitters to within tens of meters—useful for finding rogue transmitters,
                      validating claimed GPS positions, and detecting when a single radio ID appears at physically impossible
                      locations (suggesting spoofing). These techniques require significant infrastructure but provide powerful
                      capabilities for DMR network security monitoring.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Machine learning approaches are increasingly applied to radio signal analysis, enabling automated classification
                      of signals, anomaly detection, and pattern recognition at scales impossible for human analysts. Convolutional
                      neural networks trained on spectrogram images can identify modulation types with high accuracy, while
                      recurrent networks excel at analyzing time-series data such as symbol sequences or traffic patterns.
                      For DMR security, ML systems can learn normal network behavior—typical talk group usage patterns, common
                      radio IDs, expected transmission times—and flag deviations that may indicate reconnaissance, spoofing,
                      or other malicious activity. The combination of SDR capture capability with ML analysis tools creates
                      powerful automated monitoring systems for protecting DMR infrastructure.
                    </Typography>
                  </Box>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        IQ Sample Capture & Analysis
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`# IQ Sample Capture for DMR Analysis
════════════════════════════════════════════════════════════

# Capture raw IQ samples with RTL-SDR
rtl_sdr -f 445500000 -s 2400000 -g 40 capture.iq

# Parameters explained:
# -f 445500000  : Center frequency (445.5 MHz)
# -s 2400000    : Sample rate (2.4 MS/s, covers 12.5kHz DMR)
# -g 40         : Gain (0-50, adjust for best SNR)

# Convert to complex float for analysis
import numpy as np

# Load 8-bit unsigned IQ samples
raw = np.fromfile('capture.iq', dtype=np.uint8)
# Convert to complex float (-1 to +1)
iq = (raw.astype(np.float32) - 127.5) / 127.5
iq_complex = iq[0::2] + 1j * iq[1::2]

# Downsample to DMR rate (24 kHz adequate for 12.5 kHz signal)
from scipy.signal import resample_poly
iq_dmr = resample_poly(iq_complex, 1, 100)  # 2.4M -> 24k

# Find DMR signal power
power_spectrum = np.abs(np.fft.fftshift(np.fft.fft(iq_dmr[:4096])))**2
print(f"Signal detected: {10*np.log10(np.max(power_spectrum)):.1f} dB")

# 4FSK Demodulation basics
# DMR uses 4-level FSK with ±1.944 kHz and ±648 Hz deviations
# Frequency discriminator approach:
phase = np.angle(iq_dmr)
freq = np.diff(np.unwrap(phase)) * 24000 / (2*np.pi)  # Hz`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        GNU Radio DMR Flowgraph
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        GNU Radio can be used to build custom DMR signal processing pipelines.
                      </Typography>
                      <CodeBlock
                        code={`# GNU Radio DMR Receiver Flowgraph (Python)
════════════════════════════════════════════════════════════

from gnuradio import gr, blocks, analog, filter
from gnuradio.filter import firdes
import osmosdr

class dmr_receiver(gr.top_block):
    def __init__(self, freq=445500000, gain=40):
        gr.top_block.__init__(self)

        # RTL-SDR Source
        self.src = osmosdr.source(args="numchan=1")
        self.src.set_sample_rate(2400000)
        self.src.set_center_freq(freq)
        self.src.set_gain(gain)

        # Low-pass filter (12.5 kHz channel)
        lpf_taps = firdes.low_pass(1.0, 2400000, 6250, 1000)
        self.lpf = filter.fir_filter_ccf(100, lpf_taps)  # Decimate to 24kHz

        # FM Demodulation (frequency discriminator)
        self.demod = analog.quadrature_demod_cf(24000/(2*3.14159*4800))

        # Symbol timing recovery (4800 symbols/sec)
        self.clock = digital.symbol_sync_ff(
            digital.TED_MUELLER_AND_MULLER,
            24000/4800,  # Samples per symbol
            0.045,       # Loop bandwidth
            1.0,         # Damping factor
            1.0,         # Max deviation
            1,           # Output sps
        )

        # 4FSK Slicer (map to 2-bit symbols)
        # Levels: -3, -1, +1, +3 -> 00, 01, 10, 11
        self.slicer = blocks.threshold_ff(-2, 2)

        # Output to file
        self.sink = blocks.file_sink(gr.sizeof_float, "dmr_symbols.raw")

        # Connect flowgraph
        self.connect(self.src, self.lpf, self.demod, self.clock, self.sink)

# Run the receiver
if __name__ == '__main__':
    tb = dmr_receiver(freq=445500000)
    tb.run()`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        4FSK Demodulation Details
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`DMR 4FSK Modulation Parameters
════════════════════════════════════════════════════════════

Symbol Mapping (Gray coded):
┌─────────┬────────────────┬─────────────┐
│ Dibits  │ Freq Deviation │ Normalized  │
├─────────┼────────────────┼─────────────┤
│   01    │   +1.944 kHz   │    +3       │
│   00    │   +0.648 kHz   │    +1       │
│   10    │   -0.648 kHz   │    -1       │
│   11    │   -1.944 kHz   │    -3       │
└─────────┴────────────────┴─────────────┘

Symbol Rate: 4800 symbols/second
Bits per Symbol: 2 (dibits)
Gross Data Rate: 9600 bps
Channel Bandwidth: 12.5 kHz

Demodulation Steps:
1. Receive RF signal at carrier frequency
2. Mix down to baseband (IQ samples)
3. Low-pass filter to channel bandwidth
4. FM discriminate (phase derivative)
5. Symbol timing recovery (match 4800 sym/s)
6. Slice to 4 levels (+3, +1, -1, -3)
7. Map to dibits (Gray decode)
8. Assemble into DMR frames

# Python 4FSK slicer:
def slice_4fsk(samples):
    symbols = []
    for s in samples:
        if s > 2:
            symbols.append(0b01)   # +3
        elif s > 0:
            symbols.append(0b00)   # +1
        elif s > -2:
            symbols.append(0b10)   # -1
        else:
            symbols.append(0b11)   # -3
    return symbols`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Waterfall Analysis & Signal Identification
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Identifying DMR signals in a waterfall display:
                      </Typography>
                      <CodeBlock
                        code={`DMR Signal Characteristics on Waterfall
════════════════════════════════════════════════════════════

Visual Identification:
┌────────────────────────────────────────────────────────┐
│  Frequency (kHz offset from center)                     │
│  -6.25        0        +6.25                            │
│    │          │          │                              │
│    ▼          ▼          ▼                              │
│  ════════════════════════                               │
│  ║  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ║  <- DMR Signal (~12.5kHz wide) │
│  ║  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ║                                 │
│  ║  ▓▓▓▓░░░░░░▓▓▓▓▓▓  ║  <- Time slots visible         │
│  ║  ▓▓▓▓░░░░░░▓▓▓▓▓▓  ║     (alternating bursts)       │
│  ║  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ║                                 │
│  ════════════════════════                               │
│                                                         │
│  Time →                                                 │
└────────────────────────────────────────────────────────┘

DMR vs Other Digital Modes:
┌──────────┬─────────────┬────────────────────────────────┐
│ Mode     │ Bandwidth   │ Visual Characteristics          │
├──────────┼─────────────┼────────────────────────────────┤
│ DMR      │ 12.5 kHz    │ Two-slot TDMA, bursty           │
│ P25      │ 12.5 kHz    │ Continuous, C4FM modulation     │
│ NXDN     │ 6.25 kHz    │ Narrower, 4FSK similar to DMR   │
│ D-STAR   │ 6.25 kHz    │ GMSK, distinct pattern          │
│ dPMR     │ 6.25 kHz    │ FDMA, two channels in 12.5 kHz  │
│ TETRA    │ 25 kHz      │ 4-slot TDMA, wider signal       │
└──────────┴─────────────┴────────────────────────────────┘

# Automated detection in Python:
def detect_dmr(power_spectrum, sample_rate):
    # Check bandwidth (~12.5 kHz)
    threshold = np.max(power_spectrum) - 10  # 10 dB below peak
    signal_bins = np.where(power_spectrum > threshold)[0]
    bandwidth = len(signal_bins) * sample_rate / len(power_spectrum)

    if 10000 < bandwidth < 15000:
        print("Possible DMR signal detected")
        return True
    return False`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Reconnaissance Section */}
              <Box id="reconnaissance" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <SearchIcon /> DMR Reconnaissance
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Passive Signal Discovery
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`# RTL-SDR + DSD+ Setup for DMR Monitoring

# 1. Install RTL-SDR drivers
# Windows: Zadig for driver installation
# Linux: apt install rtl-sdr

# 2. Find DMR signals with SDR#
# Look for 12.5 kHz wide signals with characteristic
# 4FSK pattern (4 distinct frequency levels)

# 3. Configure DSD+ for DMR
# Set input to RTL-SDR via virtual audio cable
# or use FMP (Fast Lane) mode for direct SDR input

# Common DMR frequency ranges to monitor:
# UHF Business:    450-470 MHz
# UHF Ham:         420-450 MHz (region dependent)
# VHF Business:    150-174 MHz
# VHF Ham:         144-148 MHz

# DSD+ command line example:
dsdplus.exe -i rtl_fm -o speakers -f 445.5M -g 40`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Extracting Metadata
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        DMR transmissions contain valuable metadata in headers and embedded signaling:
                      </Typography>
                      <CodeBlock
                        code={`Extractable DMR Metadata:
═══════════════════════════════════════════════════════════

From Link Control (LC) Headers:
├── Source Radio ID (24-bit)
├── Destination ID (24-bit, radio or talk group)
├── Call Type (Group/Private/All Call)
├── Feature Set ID
└── Service Options (priority, encryption indicator)

From Embedded Signaling:
├── Color Code (4-bit)
├── Privacy Indicator (encrypted flag)
├── Link Control Start/Stop
└── Talker Alias (if enabled)

From GPS/Location Data:
├── Latitude/Longitude
├── Speed and heading
├── Timestamp
└── Radio ID (who is where)

# Using dmrshark or dsd-fme for metadata extraction:
# These tools decode and log all DMR metadata

OSINT Correlation:
├── RadioID.net - Amateur ID database
├── FCC ULS - US license database
├── RepeaterBook - Repeater frequencies
└── Radioreference - Commercial frequencies`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Network Mapping
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`DMR Network Mapping Process:
═══════════════════════════════════════════════════════════

1. Identify Active Frequencies
   └── Scan UHF/VHF bands for DMR signals

2. Capture Repeater Information
   ├── Input/Output frequencies
   ├── Color Code
   ├── Time slots in use
   └── Active talk groups

3. Build Radio ID Database
   ├── Log all source/destination IDs
   ├── Correlate with RadioID.net
   ├── Map organizational structure
   └── Identify high-value targets

4. Traffic Analysis
   ├── Peak usage times
   ├── Communication patterns
   ├── Key personnel (frequent transmitters)
   └── Emergency vs routine traffic

5. Infrastructure Discovery
   ├── Repeater locations (from GPS)
   ├── IP Site Connect topology
   ├── Linked talk groups
   └── Master/slave relationships

Example Network Map Output:
┌─────────────────────────────────────────────┐
│ Repeater: 445.500 MHz, CC: 1               │
├─────────────────────────────────────────────┤
│ TS1: TG 1234 (Operations)                   │
│      Active IDs: 1001, 1002, 1003, 1015    │
│ TS2: TG 5678 (Maintenance)                  │
│      Active IDs: 2001, 2002                 │
└─────────────────────────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Exploitation Section */}
              <Box id="exploitation" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <BugReportIcon /> DMR Exploitation Techniques
                  </Typography>

                  <Alert severity="error" sx={{ mb: 3, bgcolor: alpha(theme.error, 0.1), color: theme.text }}>
                    <Typography variant="body2">
                      <strong>Legal Warning:</strong> These techniques are for authorized security testing only.
                      Unauthorized transmission or interference with radio systems is a federal crime.
                    </Typography>
                  </Alert>

                  {/* Deep Theory: Attack Methodology */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Attack Methodology and Threat Modeling for DMR Systems
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Effective security assessment of DMR systems requires a systematic approach to identifying vulnerabilities,
                      understanding attack prerequisites, and evaluating potential impact. Unlike traditional IT systems where
                      the attacker typically requires network access, DMR attacks can often be conducted from any location within
                      radio range—potentially miles away—making physical security measures largely ineffective against determined
                      adversaries. The attack surface encompasses the RF channel itself, the protocol implementation in radios
                      and infrastructure equipment, the IP backhaul connecting sites, and the human operators who configure and
                      use the system.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      A comprehensive threat model for DMR should consider adversary capabilities across a spectrum from passive
                      monitoring to active transmission. At the passive end, an attacker with only receive capability can still
                      gather significant intelligence: monitoring unencrypted communications reveals operational information,
                      traffic analysis exposes patterns and relationships even when content is encrypted, and metadata such as
                      radio IDs and GPS positions may leak sensitive location and organizational data. Moving to active attacks,
                      an adversary with transmit capability gains the ability to inject false messages, impersonate authorized
                      users, and deny service through jamming. The cost barrier for active attacks has dropped dramatically with
                      affordable TX-capable SDRs like HackRF, fundamentally changing the threat landscape.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The kill chain for DMR attacks typically follows a reconnaissance-weaponization-exploitation pattern adapted
                      from cyber operations. Reconnaissance involves passive monitoring to enumerate frequencies in use, identify
                      talk groups and radio IDs, map organizational structure, and characterize encryption (or lack thereof).
                      Weaponization prepares the attack tools: configuring SDR software for the target frequencies, programming
                      radios with harvested IDs, developing injection payloads, or setting up jamming equipment. Exploitation
                      executes the attack at an operationally significant moment—impersonating a supervisor during a critical
                      operation, replaying emergency traffic to cause confusion, or jamming communications during an incident
                      when radios are most needed. Understanding this progression enables defenders to implement controls that
                      disrupt the attack chain at multiple points.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Impact assessment for DMR attacks must consider both direct and cascading effects. Direct impacts include
                      compromise of communication confidentiality (eavesdropping), integrity (message injection or modification),
                      and availability (denial of service). Cascading effects arise when DMR serves as a control channel for
                      other systems: SCADA commands transmitted over DMR could be injected to manipulate industrial processes,
                      GPS location data could be spoofed to misdirect resources, and false emergency traffic could trigger
                      inappropriate responses from public safety agencies. The criticality of systems that depend on DMR
                      communications—sometimes far beyond the radio system itself—drives the importance of thorough security
                      assessment and appropriate protective measures.
                    </Typography>
                  </Box>

                  {/* Deep Theory: Passive Intelligence Gathering */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Passive Intelligence Gathering and Traffic Analysis
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Even without the ability to decrypt voice content, passive monitoring of DMR systems reveals a wealth of
                      intelligence valuable to both security researchers and potential adversaries. Every DMR transmission
                      broadcasts metadata in the clear: source and destination radio IDs, talk group assignments, call types
                      (group, private, all-call), GPS coordinates when location services are enabled, and the Privacy Indicator
                      flag showing whether encryption is active. This metadata, accumulated over time, enables detailed mapping
                      of organizational structure, communication patterns, and operational rhythms without ever breaking
                      encryption.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Traffic analysis techniques extracted from signals intelligence practice apply directly to DMR networks.
                      The volume of traffic on specific talk groups correlates with operational activity levels, enabling prediction
                      of when significant events are occurring or about to occur. Communication graph analysis—mapping which radio
                      IDs communicate with which others—reveals organizational hierarchy and identifies high-value targets such
                      as supervisory or dispatch positions. Temporal patterns expose shift schedules, routine check-in procedures,
                      and response times. Cross-referencing observed radio IDs with public databases like RadioID.net (for amateur
                      systems) or FCC license records can deanonymize users and link radio activity to specific individuals or
                      organizations.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      GPS data transmitted over DMR presents particularly severe privacy and security risks. Many commercial and
                      public safety systems enable location services that broadcast radio positions with each transmission or
                      at regular polling intervals. When this location data is transmitted unencrypted—a common configuration
                      even on systems using voice encryption—any receiver can track the real-time movements of all transmitting
                      radios. For public safety applications, this could enable criminals to track patrol car locations; for
                      commercial applications, competitor surveillance of delivery routes or field service territories becomes
                      trivially possible. The aggregate location history of a radio fleet over time reveals patterns that may
                      be even more sensitive than individual position reports.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Metadata protection requires specific countermeasures beyond voice encryption. While AES-256 protects the
                      content of conversations, the radio IDs, talk groups, and other header information remain visible in
                      standard DMR implementations. Some high-security systems implement header encryption or use indirect
                      addressing schemes that obscure the actual identities of communicating parties, but these features are
                      not universally available or deployed. Organizations concerned about metadata exposure must carefully
                      evaluate their threat model, consider whether standard DMR meets their security requirements, and potentially
                      implement additional operational security measures such as randomized or pooled radio assignments, talk
                      group rotation, and GPS transmission policies that balance operational utility against surveillance risk.
                    </Typography>
                  </Box>

                  {/* Deep Theory: Active Attack Vectors */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Active Attack Vectors and Their Operational Impact
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Active attacks against DMR systems require transmit capability, elevating both the technical complexity
                      and legal risk compared to passive monitoring. However, the impact potential is correspondingly greater:
                      active attacks can directly affect system operations through impersonation, message injection, replay,
                      and denial of service. The fundamental vulnerability enabling most active attacks is the lack of cryptographic
                      authentication in standard DMR—radios claim their identity through self-reported IDs without any proof
                      that they are entitled to use those identities. This authentication gap allows an attacker with a properly
                      configured radio or SDR to transmit as any claimed identity.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Identity spoofing attacks exploit the self-reported nature of DMR radio IDs to impersonate legitimate
                      users. After reconnaissance identifies valid radio IDs and their associated roles (supervisor, dispatch,
                      security, etc.), an attacker programs their equipment with a stolen ID and transmits as that user. On
                      systems without encryption, this provides complete impersonation capability—voice messages appear to come
                      from the legitimate radio. Even on encrypted systems, spoofed IDs may gain access to restricted talk groups
                      if access control is based solely on ID rather than cryptographic keys. The impact ranges from confusion
                      and embarrassment to operational disruption if false orders are issued under a supervisor's identity.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Replay attacks capture legitimate transmissions and retransmit them at a later time, potentially causing
                      duplicate actions or confusion. Unlike IP networks where replay attacks are commonly mitigated through
                      timestamps and sequence numbers, many DMR systems—particularly those using Basic Privacy or no encryption—
                      lack effective replay protection. A captured "all clear" message could be replayed after an actual emergency
                      to prematurely stand down response resources; a routine status check could be replayed continuously to
                      create the appearance of normal operations while actual personnel are incapacitated. Systems using AES
                      encryption with proper implementation typically include sequence numbers and timestamps that detect replays,
                      but the protection is only effective when encryption is consistently enabled and keys are properly managed.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Denial of service through RF jamming represents the most blunt but potentially most disruptive attack vector.
                      Because radio communications depend on the shared electromagnetic spectrum, any sufficiently powerful
                      interfering signal can prevent legitimate communications—regardless of encryption, authentication, or
                      any other protocol-level protection. Jamming attacks range from simple continuous carrier transmission
                      that blocks all traffic on a frequency, to sophisticated selective jamming that targets specific time
                      slots, users, or protocol elements while allowing some traffic to pass (making detection more difficult).
                      Physical layer attacks like jamming fundamentally cannot be prevented through cryptographic means; mitigation
                      requires detection capabilities, contingency communication plans, and potentially legal prosecution of
                      identified jammers.
                    </Typography>
                  </Box>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="High Risk" size="small" sx={{ bgcolor: alpha(theme.error, 0.2), color: theme.error }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Radio ID Spoofing
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Radios can be programmed with arbitrary IDs, allowing impersonation of other users
                        or access to restricted talk groups.
                      </Typography>
                      <CodeBlock
                        code={`Radio ID Spoofing Attack Vector:
═══════════════════════════════════════════════════════════

Vulnerability:
- Radio IDs are self-reported, not authenticated
- No cryptographic verification of identity
- Systems trust the ID in the transmission

Attack Process:
1. Monitor target network for valid radio IDs
2. Identify high-privilege IDs (supervisors, dispatch)
3. Program your radio with stolen ID
4. Transmit as impersonated user

Impact:
├── Unauthorized talk group access
├── Impersonation of personnel
├── Issue false commands
├── Bypass logging (actions attributed to victim)
└── Social engineering attacks

Mitigation:
├── AES encryption with key management
├── OTAR (Over-The-Air Rekeying)
├── Radio ID validation lists
└── Voice recognition (human verification)`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Medium Risk" size="small" sx={{ bgcolor: alpha(theme.warning, 0.2), color: theme.warning }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Replay Attacks
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Capture legitimate transmissions and replay them to cause confusion or
                        trigger automated systems.
                      </Typography>
                      <CodeBlock
                        code={`DMR Replay Attack:
═══════════════════════════════════════════════════════════

# 1. Capture DMR transmission with SDR
hackrf_transfer -r capture.raw -f 445500000 -s 2000000

# 2. Process and extract DMR frames
# (Using specialized DMR tools)

# 3. Replay captured transmission
hackrf_transfer -t capture.raw -f 445500000 -s 2000000

Attack Scenarios:
├── Replay "all clear" after emergency
├── Re-trigger automated responses
├── Cause dispatch confusion
├── Cover for physical intrusion
└── Denial of service via constant replay

Limitations:
├── AES encryption with timestamps defeats replay
├── Sequence numbers can detect duplicates
├── May be noticed by operators
└── Requires TX-capable hardware

Defense:
├── Enable AES encryption
├── Use timestamped messages
├── Train operators to verify
└── Monitor for duplicate transmissions`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Passive" size="small" sx={{ bgcolor: alpha(theme.info, 0.2), color: theme.info }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Breaking Basic Privacy
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Basic Privacy (BP) Cryptanalysis:
═══════════════════════════════════════════════════════════

# BP uses 16-bit XOR key (0x0000 - 0xFFFF)
# Key space: 65,536 possibilities

Method 1: Brute Force
---------------------------------
for key in range(0, 65536):
    decrypted = bytearray()
    for i, byte in enumerate(ciphertext):
        decrypted.append(byte ^ ((key >> (8 * (i % 2))) & 0xFF))

    if is_valid_ambe_frame(decrypted):
        print(f"Key found: 0x{key:04x}")
        break

# Time to crack: < 1 second on modern CPU

Method 2: Known Plaintext
---------------------------------
# AMBE silence frame is known:
SILENCE = bytes([0x00, 0x00, ...])  # Known pattern

# If we capture encrypted silence:
key = encrypted_silence XOR SILENCE

Method 3: Statistical Analysis
---------------------------------
# AMBE+2 has predictable bit patterns
# Frequency analysis reveals key bits

DSD+ Decryption:
- Some versions support BP key entry
- Enter 4-digit hex key (0000-FFFF)
- Real-time decryption of BP traffic`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="DoS" size="small" sx={{ bgcolor: alpha(theme.error, 0.2), color: theme.error }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Denial of Service
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Radio systems are inherently vulnerable to jamming and denial of service.
                      </Typography>
                      <CodeBlock
                        code={`DMR DoS Attack Vectors:
═══════════════════════════════════════════════════════════

1. RF Jamming
   ├── Continuous carrier on frequency
   ├── Noise generation
   ├── Illegal but effective
   └── Requires TX hardware

2. Protocol Exploitation
   ├── Invalid frame flooding
   ├── Malformed CACH data
   ├── Color code collisions
   └── Talk group flooding

3. Repeater Abuse
   ├── Continuous transmission (kerchunking)
   ├── Invalid registration attempts
   ├── Resource exhaustion
   └── Time slot monopolization

4. Selective Jamming
   ├── Target specific time slot
   ├── Jam only during headers
   ├── Disrupt handshake signaling
   └── More sophisticated, harder to detect

Physical Layer Jamming:
- Even AES-256 encrypted systems vulnerable
- Can't encrypt the RF carrier itself
- Defense: Frequency hopping, spread spectrum
- DMR doesn't support frequency hopping`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Firmware Security Section */}
              <Box id="firmware" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <MemoryIcon /> DMR Firmware Security
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    Exploring firmware vulnerabilities, custom firmware projects, and radio hardware security research.
                  </Typography>

                  <Alert severity="info" sx={{ mb: 3, bgcolor: alpha(theme.info, 0.1), color: theme.text }}>
                    <Typography variant="body2">
                      Custom firmware enables security research but may void warranties and potentially violate regulations
                      if used improperly. Always operate within legal boundaries.
                    </Typography>
                  </Alert>

                  {/* Deep Theory: Embedded Systems Security */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Embedded Systems Security in Radio Equipment
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      DMR radios are embedded systems—specialized computers running firmware that implements radio functionality
                      on microcontrollers with limited resources and direct hardware access. Understanding embedded security
                      principles is essential for assessing radio vulnerability, conducting firmware analysis, and developing
                      protective measures. Unlike general-purpose computers with operating system isolation, memory protection,
                      and security features developed over decades, embedded radio firmware often runs bare-metal or with minimal
                      RTOS support, presenting attack surfaces and exploitation techniques distinct from traditional computing
                      platforms.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The typical DMR radio architecture centers on an ARM microcontroller (commonly STM32F4 series) paired with
                      a dedicated DMR baseband chip (such as the HR-C5000) that handles the signal processing aspects of the
                      protocol. The microcontroller runs the user interface, manages radio configuration, implements encryption
                      (when software-based), and coordinates with the baseband. This division of labor creates multiple firmware
                      images that may be independently vulnerable: the main application firmware, the baseband firmware, and
                      potentially bootloader code that executes before the main application. Security researchers must consider
                      all these components when analyzing a radio's security posture.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Memory corruption vulnerabilities—buffer overflows, format string bugs, integer overflows—exist in radio
                      firmware just as they do in other software. The consequences may be particularly severe: corrupting memory
                      in a radio could alter transmitted RF characteristics, modify encryption keys, or enable persistent
                      backdoors that survive firmware updates. Codeplug parsing presents an especially rich attack surface—
                      radios must interpret complex configuration files that specify channels, contacts, encryption settings,
                      and other parameters, and vulnerabilities in the parsing code could be exploited by providing a maliciously
                      crafted codeplug that triggers memory corruption when loaded. Security assessments should include fuzzing
                      codeplug parsers with malformed inputs.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Cryptographic implementation flaws in embedded systems often stem from the resource constraints of the
                      platform. Developers may choose weak algorithms to save code space, use poor random number generators
                      because hardware entropy sources are unavailable, or implement crypto incorrectly due to complexity.
                      Side-channel attacks are particularly relevant to embedded crypto—the power consumption, electromagnetic
                      emissions, and timing variations of a microcontroller during cryptographic operations can leak key
                      information to an attacker with physical access to the device. Radios handling sensitive encryption
                      keys should implement countermeasures such as constant-time algorithms, power consumption masking, and
                      RF shielding, but many commercial products lack such protections.
                    </Typography>
                  </Box>

                  {/* Deep Theory: Reverse Engineering Methodology */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Firmware Reverse Engineering Methodology
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Reverse engineering DMR radio firmware combines hardware hacking techniques to extract the firmware image
                      with software analysis methods to understand its functionality and identify vulnerabilities. The process
                      typically begins with physical analysis of the radio's circuit board to identify components, locate debug
                      interfaces, and understand the hardware architecture. Key components to identify include the main
                      microcontroller (often marked with part number and manufacturer logo), external flash memory chips, debug
                      header connections, and UART test points that may provide console access.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Firmware extraction methods depend on the target's security configuration. Debug interfaces like JTAG or
                      Serial Wire Debug (SWD) provide the most complete access—with an appropriate debugger connected, the
                      entire memory space can be read, including internal flash and RAM contents. However, many production
                      radios enable Read Protection (RDP) features that prevent debug access to flash memory. Lower RDP levels
                      may be bypassed through techniques like glitching the microcontroller during boot to skip the protection
                      check, or exploiting vulnerabilities in the debug protocol itself. The highest protection levels may
                      require destructive analysis techniques like chip decapping and electron microscopy.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Once firmware is extracted, static analysis using disassemblers like Ghidra or IDA Pro reveals the code
                      structure, function boundaries, and data flows. ARM Cortex-M firmware analysis benefits from the consistent
                      architecture—the vector table at the start of flash provides entry points for the reset handler and
                      interrupt service routines, and the calling convention makes function identification relatively straightforward.
                      Identifying string references, imported functions, and known library code helps map the firmware's functionality.
                      For DMR radios specifically, analysts look for the AMBE vocoder implementation (often as a binary blob
                      licensed from DVSI), encryption routines, codeplug parsing logic, and RF control interfaces.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Dynamic analysis through debugging provides runtime visibility unavailable from static analysis alone.
                      Setting breakpoints at suspected vulnerable functions, watching memory locations for corruption, and
                      tracing execution through complex code paths all accelerate vulnerability discovery. For radios with
                      debug interfaces accessible, connecting a debugger like OpenOCD enables single-stepping through code,
                      inspecting register and memory state, and even patching firmware in-place to observe modified behavior.
                      The combination of static and dynamic analysis—understanding code structure through disassembly, then
                      validating hypotheses through debugging—provides the most thorough approach to firmware security assessment.
                    </Typography>
                  </Box>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        MD380/MD390 Firmware Analysis
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        The TYT MD-380/390 is one of the most researched DMR radios due to its hackable nature.
                      </Typography>
                      <CodeBlock
                        code={`MD380 Firmware Architecture
════════════════════════════════════════════════════════════

Hardware:
├── STM32F405 ARM Cortex-M4 (168 MHz)
├── HR-C5000 DMR baseband chip
├── AT45DB041D SPI Flash (512KB)
└── LCD display + keypad matrix

Firmware Memory Map:
┌────────────────┬─────────────┬───────────────────────────┐
│ Address        │ Size        │ Contents                   │
├────────────────┼─────────────┼───────────────────────────┤
│ 0x08000000     │ 16 KB       │ Bootloader                 │
│ 0x08004000     │ ~350 KB     │ Main firmware              │
│ 0x0800C000     │ ~100 KB     │ DSP/AMBE code              │
│ 0x20000000     │ 128 KB      │ SRAM                       │
└────────────────┴─────────────┴───────────────────────────┘

Codeplug Structure (SPI Flash):
├── 0x00000-0x0FFFF  : Settings, zones, scan lists
├── 0x10000-0x1FFFF  : Channels (1000 max)
├── 0x20000-0x2FFFF  : Contacts (1000 max)
├── 0x30000-0x3FFFF  : Talk groups, RX groups
└── 0x40000-0x7FFFF  : Reserved / GPS data

# Dump firmware using md380tools:
md380-tool spiflashread filename.bin
md380-tool hexdump | less

# Patch firmware for research:
md380-tool flashfirmware patched.bin`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        OpenGD77 Custom Firmware
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        OpenGD77 is an open-source firmware for GD-77, DM-1801, and similar radios.
                      </Typography>
                      <CodeBlock
                        code={`OpenGD77 Features & Security Research
════════════════════════════════════════════════════════════

Supported Radios:
├── Radioddity GD-77, GD-77S
├── Baofeng DM-1801, RD-5R
├── TYT MD-9600, MD-UV380/390
└── Various clones

Security Research Features:
┌────────────────────────────────────────────────────────────┐
│ • Promiscuous mode (receive all talk groups)               │
│ • Monitor mode (listen to both time slots)                 │
│ • DMR ID display (show source/destination)                 │
│ • Talker alias display                                     │
│ • RSSI display for signal analysis                         │
│ • Direct frequency entry                                   │
│ • Extended frequency range (research only!)                │
│ • Last heard list with Radio IDs                           │
└────────────────────────────────────────────────────────────┘

Building from Source:
# Clone repository
git clone https://github.com/rogerclarkmelbourne/OpenGD77.git

# Install ARM toolchain
sudo apt install gcc-arm-none-eabi

# Build firmware
cd OpenGD77/firmware
make -f Makefile.GD-77

# Output: OpenGD77.bin

Installation:
1. Backup original firmware first!
2. Use manufacturer CPS to enter firmware update mode
3. Flash OpenGD77 using OpenGD77 CPS
4. Configure codeplug with OpenGD77 CPS`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Firmware Vulnerability Classes
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        {[
                          { vuln: "Buffer Overflow", desc: "SMS/contact parsing vulnerabilities in codeplug handling", severity: "High" },
                          { vuln: "Hardcoded Keys", desc: "Some radios have debug/service keys in firmware", severity: "Medium" },
                          { vuln: "Debug Interfaces", desc: "JTAG/SWD left enabled, UART debug consoles", severity: "High" },
                          { vuln: "Weak Crypto", desc: "Poor RNG, predictable IVs, key derivation flaws", severity: "High" },
                          { vuln: "Integer Overflow", desc: "Frequency/channel number handling bugs", severity: "Medium" },
                          { vuln: "Format String", desc: "Display name formatting vulnerabilities", severity: "Medium" },
                        ].map((item, idx) => (
                          <Grid item xs={12} md={6} key={idx}>
                            <Paper sx={{ p: 2, bgcolor: theme.bgCode, height: "100%" }}>
                              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                                <Typography variant="subtitle2" sx={{ color: theme.primary }}>{item.vuln}</Typography>
                                <Chip
                                  label={item.severity}
                                  size="small"
                                  sx={{
                                    bgcolor: item.severity === "High" ? alpha(theme.error, 0.2) : alpha(theme.warning, 0.2),
                                    color: item.severity === "High" ? theme.error : theme.warning,
                                    fontSize: "0.65rem",
                                  }}
                                />
                              </Box>
                              <Typography variant="caption" sx={{ color: theme.textMuted }}>{item.desc}</Typography>
                            </Paper>
                          </Grid>
                        ))}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        JTAG/SWD Hardware Access
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Hardware Debug Access (STM32 Radios)
════════════════════════════════════════════════════════════

Required Equipment:
├── ST-Link V2 or J-Link debugger ($15-50)
├── Fine-tip soldering equipment
├── 0.1" header pins
└── OpenOCD software

SWD Pinout (MD-380 example):
┌─────────────────────────────────────┐
│  Board Edge                          │
│  ┌───┬───┬───┬───┐                  │
│  │GND│CLK│DIO│3V3│ <- SWD Header    │
│  └───┴───┴───┴───┘                  │
│        ↑   ↑                         │
│      SWCLK SWDIO                     │
└─────────────────────────────────────┘

OpenOCD Configuration:
# openocd.cfg
source [find interface/stlink.cfg]
source [find target/stm32f4x.cfg]
reset_config srst_only

# Connect and dump firmware
openocd -f openocd.cfg

# In OpenOCD telnet (localhost:4444):
> halt
> flash read_image firmware_dump.bin 0x08000000 0x100000

# GDB connection:
arm-none-eabi-gdb firmware.elf
(gdb) target remote localhost:3333
(gdb) monitor reset halt
(gdb) break main
(gdb) continue

Security Note:
- Many newer radios have RDP (Read Protection) enabled
- Level 1 RDP prevents flash reads but allows debug
- Level 2 RDP is permanent, bricks debug interface
- Check datasheet before attempting!`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Detection & Monitoring Section */}
              <Box id="detection" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <RouterIcon /> Detection & Monitoring
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    Techniques for detecting malicious activity on DMR networks and monitoring for security anomalies.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Anomaly Detection Signatures
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <TableContainer component={Paper} sx={{ bgcolor: theme.bgCode, mb: 2 }}>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Attack Type</TableCell>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Detection Signature</TableCell>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Severity</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {[
                              { attack: "ID Spoofing", sig: "Same Radio ID from multiple locations/RSSI patterns", sev: "High" },
                              { attack: "Replay Attack", sig: "Duplicate sequence numbers, identical frame patterns", sev: "High" },
                              { attack: "Rogue Radio", sig: "Unknown Radio ID attempting registration", sev: "Medium" },
                              { attack: "Jamming", sig: "Continuous carrier, elevated noise floor", sev: "Critical" },
                              { attack: "GPS Spoofing", sig: "Impossible location changes, speed anomalies", sev: "Medium" },
                              { attack: "Encryption Probe", sig: "Repeated calls with encryption bit toggled", sev: "Low" },
                              { attack: "Talk Group Scan", sig: "Rapid sequential talk group monitoring", sev: "Low" },
                            ].map((row, idx) => (
                              <TableRow key={idx}>
                                <TableCell sx={{ color: theme.secondary }}>{row.attack}</TableCell>
                                <TableCell sx={{ color: theme.textMuted, fontSize: "0.8rem" }}>{row.sig}</TableCell>
                                <TableCell>
                                  <Chip
                                    label={row.sev}
                                    size="small"
                                    sx={{
                                      bgcolor: row.sev === "Critical" ? alpha(theme.error, 0.3) :
                                               row.sev === "High" ? alpha(theme.error, 0.2) :
                                               row.sev === "Medium" ? alpha(theme.warning, 0.2) : alpha(theme.info, 0.2),
                                      color: row.sev === "Critical" || row.sev === "High" ? theme.error :
                                             row.sev === "Medium" ? theme.warning : theme.info,
                                      fontSize: "0.65rem",
                                    }}
                                  />
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Monitoring Script Example
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`#!/usr/bin/env python3
# DMR Anomaly Detection Monitor
# Educational example - monitor your own authorized systems only

import json
from datetime import datetime, timedelta
from collections import defaultdict

class DMRMonitor:
    def __init__(self):
        self.radio_history = defaultdict(list)  # ID -> [(timestamp, rssi, location)]
        self.sequence_cache = {}                 # (src, dst) -> last_seq
        self.authorized_ids = set()              # Whitelist
        self.alerts = []

    def load_authorized_ids(self, filename):
        """Load whitelist of authorized Radio IDs"""
        with open(filename) as f:
            self.authorized_ids = set(json.load(f))

    def process_frame(self, frame):
        """Process a decoded DMR frame for anomalies"""
        src_id = frame.get('source_id')
        dst_id = frame.get('dest_id')
        timestamp = datetime.now()
        rssi = frame.get('rssi', 0)
        gps = frame.get('gps')
        seq = frame.get('sequence')

        # Detection 1: Unknown Radio ID
        if src_id not in self.authorized_ids:
            self.alert('ROGUE_RADIO', f'Unknown ID {src_id} detected', 'MEDIUM')

        # Detection 2: ID appearing from multiple locations
        if gps and src_id in self.radio_history:
            last = self.radio_history[src_id][-1]
            if last[2]:  # Has previous GPS
                distance = self.calc_distance(last[2], gps)
                time_diff = (timestamp - last[0]).total_seconds()
                if time_diff > 0:
                    speed = distance / time_diff  # m/s
                    if speed > 100:  # >360 km/h impossible
                        self.alert('GPS_ANOMALY',
                            f'ID {src_id} moved {distance:.0f}m in {time_diff:.0f}s',
                            'MEDIUM')

        # Detection 3: RSSI anomaly (possible spoofing)
        if src_id in self.radio_history:
            recent = [h[1] for h in self.radio_history[src_id][-10:]]
            if recent and abs(rssi - sum(recent)/len(recent)) > 20:
                self.alert('RSSI_ANOMALY',
                    f'ID {src_id} RSSI jump: {rssi} (avg: {sum(recent)/len(recent):.0f})',
                    'LOW')

        # Detection 4: Replay attack (duplicate sequence)
        key = (src_id, dst_id)
        if key in self.sequence_cache:
            if seq == self.sequence_cache[key]:
                self.alert('REPLAY_ATTACK',
                    f'Duplicate seq {seq} from {src_id}', 'HIGH')
        self.sequence_cache[key] = seq

        # Update history
        self.radio_history[src_id].append((timestamp, rssi, gps))

    def alert(self, alert_type, message, severity):
        alert = {
            'time': datetime.now().isoformat(),
            'type': alert_type,
            'message': message,
            'severity': severity
        }
        self.alerts.append(alert)
        print(f"[{severity}] {alert_type}: {message}")

# Usage with DSD+ log parsing or real-time feed`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        SIEM Integration for DMR
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Enterprise DMR systems can integrate with SIEM for centralized monitoring.
                      </Typography>
                      <CodeBlock
                        code={`DMR Events for SIEM Integration
════════════════════════════════════════════════════════════

Log Format (JSON):
{
  "timestamp": "2024-01-15T14:30:22Z",
  "event_type": "dmr_call",
  "source_id": "1234567",
  "dest_id": "TG:12345",
  "call_type": "group",
  "duration_ms": 4500,
  "encrypted": false,
  "repeater_id": "REP001",
  "rssi_dbm": -85,
  "slot": 1,
  "color_code": 1,
  "gps": {"lat": 40.7128, "lon": -74.0060}
}

Splunk Alert Queries:

# Detect unknown Radio IDs
index=dmr event_type=dmr_call
| lookup authorized_radios source_id OUTPUT is_authorized
| where isnull(is_authorized)
| stats count by source_id, repeater_id

# Detect potential replay attacks
index=dmr event_type=dmr_call
| stats count dc(repeater_id) as repeaters by source_id, _time span=1s
| where count > 1 AND repeaters > 1

# GPS anomaly detection (impossible speed)
index=dmr event_type=dmr_call gps.lat=*
| sort source_id, _time
| streamstats current=f last(gps.lat) as prev_lat last(gps.lon) as prev_lon
    last(_time) as prev_time by source_id
| eval distance=... # Haversine formula
| eval speed=distance/(_time-prev_time)
| where speed > 100

# High-value target monitoring
index=dmr event_type=dmr_call dest_id IN ("TG:911", "TG:DISPATCH")
| table _time, source_id, dest_id, repeater_id`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Case Studies Section */}
              <Box id="case-studies" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <HistoryEduIcon /> Real-World Case Studies
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        DEF CON Research: "Hacking Police DMR" (2019)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="info" sx={{ mb: 2, bgcolor: alpha(theme.info, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          Security researchers demonstrated vulnerabilities in law enforcement DMR systems at DEF CON 27.
                        </Typography>
                      </Alert>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Key findings from the research:
                      </Typography>
                      <List dense>
                        {[
                          "Many departments using Basic Privacy (easily broken)",
                          "Radio IDs not validated - spoofing trivial",
                          "GPS data transmitted unencrypted",
                          "Lack of OTAR leaves static keys vulnerable",
                          "Encryption often disabled for 'convenience'",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <WarningIcon sx={{ fontSize: 16, color: theme.warning }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Amateur Radio Security Research
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        The amateur radio community provides a legal platform for DMR security research:
                      </Typography>
                      <List dense>
                        {[
                          "Encryption prohibited on amateur bands (fully analyzable)",
                          "Brandmeister API provides talk group/ID data",
                          "Open source firmware projects (OpenGD77, md380tools)",
                          "Active research community sharing findings",
                          "Repeater owners often cooperative with researchers",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <CheckCircleIcon sx={{ fontSize: 16, color: theme.success }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", sx: { color: theme.textMuted } }} />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Travis Goodspeed's Radio Research (2016-2020)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Prolific radio security researcher demonstrating firmware extraction and protocol weaknesses.
                      </Typography>
                      <CodeBlock
                        code={`Key Research Contributions:
════════════════════════════════════════════════════════════

MD380Tools Project:
├── First open-source firmware patches for TYT MD-380
├── Documented STM32 memory layout
├── Enabled promiscuous mode monitoring
├── Demonstrated codeplug extraction techniques
└── Published at multiple hacker conferences

Methodology:
1. Hardware reverse engineering (PCB analysis)
2. JTAG/SWD debug interface discovery
3. Firmware extraction and disassembly
4. Protocol analysis using SDR
5. Custom firmware development

Impact:
• Enabled entire community of DMR researchers
• Exposed weak security in consumer DMR radios
• Led to improved firmware security in newer models
• Established legal precedent for radio research

Publications:
• "Reverse Engineering the TYT MD-380" - POC||GTFO
• Multiple DEF CON presentations
• Extensive blog documentation`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        University of Twente DMR Protocol Analysis (2018)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Academic analysis of DMR protocol security and encryption implementation weaknesses.
                      </Typography>
                      <CodeBlock
                        code={`Research Findings:
════════════════════════════════════════════════════════════

Basic Privacy Analysis:
┌─────────────────────────────────────────────────────────┐
│ Vulnerability: 16-bit XOR Key Space                     │
│ Attack Time: < 100ms on commodity hardware              │
│ Success Rate: 100% with known plaintext                 │
│ Mitigation: Use AES-256, never use Basic Privacy        │
└─────────────────────────────────────────────────────────┘

Enhanced Privacy Weaknesses:
├── RC4 implementation uses predictable IVs in some radios
├── Key derivation functions not standardized
├── No forward secrecy - compromised key = all traffic
└── Vendor-specific implementations vary in security

Protocol-Level Findings:
├── Radio IDs transmitted unencrypted (even with AES)
├── Talk group membership leaks traffic patterns
├── GPS data often unencrypted separate from voice
├── No mutual authentication between radio and system
└── Replay protection optional and rarely enabled

Recommendations:
1. Always use AES-256 encryption
2. Implement OTAR for key management
3. Enable sequence numbers for replay detection
4. Consider GPS encryption separately
5. Implement radio ID whitelist validation`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Public Safety Communication Incidents
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha(theme.warning, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          These incidents highlight the real-world impact of DMR security weaknesses in critical infrastructure.
                        </Typography>
                      </Alert>
                      <Grid container spacing={2}>
                        {[
                          {
                            title: "Baltimore City (2018)",
                            issue: "Unencrypted police DMR allowed real-time monitoring",
                            impact: "Criminal suspects could track police movements",
                            resolution: "City migrated to P25 with encryption"
                          },
                          {
                            title: "Detroit EMS (2019)",
                            issue: "Basic Privacy encryption broken by researchers",
                            impact: "Patient information potentially exposed",
                            resolution: "Upgraded to AES-256 encryption"
                          },
                          {
                            title: "UK Rail Network (2020)",
                            issue: "DMR system using default color codes",
                            impact: "Interference from nearby commercial users",
                            resolution: "Reconfigured unique color code allocation"
                          },
                          {
                            title: "European Transit Authority (2021)",
                            issue: "GPS location broadcast unencrypted",
                            impact: "Vehicle tracking possible by anyone with SDR",
                            resolution: "Disabled GPS broadcasting on DMR"
                          },
                        ].map((incident, idx) => (
                          <Grid item xs={12} md={6} key={idx}>
                            <Paper sx={{ p: 2, bgcolor: theme.bgCode, height: "100%" }}>
                              <Typography variant="subtitle2" sx={{ color: theme.primary, mb: 1 }}>{incident.title}</Typography>
                              <Typography variant="caption" sx={{ color: theme.error, display: "block", mb: 0.5 }}>
                                <strong>Issue:</strong> {incident.issue}
                              </Typography>
                              <Typography variant="caption" sx={{ color: theme.warning, display: "block", mb: 0.5 }}>
                                <strong>Impact:</strong> {incident.impact}
                              </Typography>
                              <Typography variant="caption" sx={{ color: theme.success, display: "block" }}>
                                <strong>Resolution:</strong> {incident.resolution}
                              </Typography>
                            </Paper>
                          </Grid>
                        ))}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Defense Section */}
              <Box id="defense" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <ShieldIcon /> Defensive Measures
                  </Typography>

                  {/* Deep Theory: Defense in Depth */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Defense in Depth: A Comprehensive Security Architecture
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Securing DMR communications requires a defense-in-depth strategy that addresses threats at multiple layers,
                      recognizing that no single control provides complete protection. The defense architecture must encompass
                      cryptographic protection of message content, authentication of user identity, access control to network
                      resources, monitoring for anomalous activity, physical security of equipment, and operational procedures
                      that maintain security even when technical controls are compromised. Each layer provides protection against
                      specific threat vectors while compensating for potential failures in other layers.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      At the cryptographic layer, AES-256 encryption represents the minimum acceptable standard for protecting
                      sensitive communications. The decision to encrypt must be made based on threat assessment—not all DMR
                      traffic requires encryption, and the operational overhead of key management argues against unnecessary
                      use. However, any traffic that could cause harm if intercepted (operational details, personal information,
                      security procedures) should be encrypted, and the system design should make encryption the default rather
                      than the exception. Basic Privacy should never be used under any circumstances—its presence creates a
                      false sense of security while providing effectively no protection against even minimally capable adversaries.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Authentication and access control present the greatest challenge in DMR security, as the standard protocol
                      lacks robust mechanisms for verifying radio identity. Network-level controls such as radio ID whitelists—
                      where the system refuses service to unregistered IDs—provide some protection against casual spoofing but
                      can be defeated by any attacker who has observed valid IDs during reconnaissance. Stronger authentication
                      requires cryptographic approaches: systems where radios must prove possession of a secret key before
                      gaining network access, challenge-response protocols that prevent replay of authentication credentials,
                      and continuous authentication that validates identity throughout a session rather than only at initial
                      connection. These capabilities are available in high-end DMR implementations but remain rare in typical
                      commercial deployments.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Monitoring and detection capabilities form a critical but often neglected layer of DMR security. Unlike
                      IP networks where security monitoring tools are mature and widely deployed, radio network monitoring
                      typically requires custom development using SDR technology to passively observe traffic and detect anomalies.
                      Effective monitoring systems track all radio IDs appearing on the network, flag unrecognized identities,
                      detect ID duplication suggesting spoofing (same ID from different locations or with mismatched RF fingerprints),
                      identify unusual traffic patterns (abnormal hours, volumes, or talk group access), and provide alerting
                      to security personnel who can investigate and respond. The investment in monitoring pays dividends in
                      early detection of both malicious activity and legitimate operational issues.
                    </Typography>
                  </Box>

                  {/* Deep Theory: Key Management Best Practices */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Key Management Best Practices for Operational Security
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      The strength of DMR encryption is only as good as the key management practices protecting the cryptographic
                      material. A rigorous key management program encompasses the entire key lifecycle: generation using high-quality
                      random sources, secure distribution to authorized radios, protected storage that prevents unauthorized
                      access, controlled usage that limits key exposure, rotation on regular schedules or in response to security
                      events, and destruction when keys reach end-of-life. Organizations should document their key management
                      procedures, train personnel responsible for key handling, and audit compliance regularly.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Key generation must use cryptographically secure random number generators—never predictable patterns,
                      sequential numbers, dates, or other guessable values. Hardware random number generators or well-designed
                      software PRNGs seeded from multiple entropy sources should be employed. The generated keys should be
                      stored in encrypted form, with the key encryption key (KEK) protected through physical security (secure
                      facility, locked cabinet, controlled access) and logical security (strong passwords, multi-person authorization).
                      Separation of duties ensures that no single individual has complete access to the key management system—
                      one person generates keys while another distributes them, preventing insider compromise.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Key distribution represents the most operationally challenging aspect of DMR security. Traditional methods
                      requiring physical connection to each radio for codeplug updates create logistical barriers to regular
                      key rotation. Over-The-Air Rekeying (OTAR) dramatically improves the situation, enabling rapid distribution
                      of new keys across an entire fleet without physical recall. OTAR also enables emergency rekeying when
                      compromise is suspected—a capability that could be critical if a radio is lost or stolen. Organizations
                      deploying AES encryption should strongly consider OTAR-capable equipment and infrastructure despite the
                      additional cost, as the operational security benefits justify the investment.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Key rotation schedules should balance security against operational burden. More frequent rotation limits
                      the exposure window if keys are compromised but increases management overhead. A risk-based approach
                      considers the sensitivity of protected communications, the threat environment, and the likelihood of
                      undetected compromise. For high-security applications, weekly or monthly rotation may be appropriate;
                      routine commercial use might accept quarterly rotation. Regardless of schedule, procedures must exist
                      for emergency rekeying in response to known or suspected compromise—a lost radio containing encryption
                      keys should trigger immediate rotation across the entire network, not just revocation of the compromised
                      device.
                    </Typography>
                  </Box>

                  {/* Deep Theory: Incident Response */}
                  <Box sx={{ bgcolor: theme.bgNested, p: 3, borderRadius: 2, mb: 3 }}>
                    <Typography variant="h6" sx={{ color: theme.secondary, mb: 2, fontWeight: 600 }}>
                      Incident Response and Recovery Procedures
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Despite preventive controls, security incidents affecting DMR systems will occur, and organizations must
                      be prepared to detect, respond to, and recover from them effectively. Incident response for radio systems
                      requires specialized capabilities that differ significantly from traditional IT incident response—RF
                      monitoring and analysis tools, coordination with spectrum management authorities, and potentially
                      law enforcement involvement for prosecutable offenses. Incident response plans should address specific
                      DMR scenarios: detected spoofing or impersonation, confirmed eavesdropping, jamming attacks, and physical
                      loss or theft of radio equipment.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Detection of DMR security incidents often relies on human observation—radio users noticing unexpected
                      traffic, unfamiliar voices, or communication anomalies—combined with automated monitoring systems that
                      flag technical indicators of compromise. Training users to recognize and report suspicious activity
                      creates a human sensor network that complements technical detection capabilities. Clear reporting
                      procedures, accessible contact information for security personnel, and a culture that encourages
                      reporting without blame or bureaucratic barriers improve the likelihood of early incident detection.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, mb: 2, lineHeight: 1.8 }}>
                      Containment and eradication for DMR incidents may involve immediately rekeying encryption to lock out
                      compromised credentials, disabling specific radio IDs that have been spoofed or stolen, switching to
                      backup frequencies if the primary channel is being jammed, or even temporarily shutting down non-essential
                      communications to limit the attack surface. These actions must be balanced against operational requirements—
                      completely shutting down radio communications may cause more harm than the security incident itself,
                      particularly for public safety organizations where communication is essential to mission execution.
                    </Typography>
                    <Typography variant="body2" sx={{ color: theme.text, lineHeight: 1.8 }}>
                      Post-incident analysis should identify root causes, assess the effectiveness of response actions, and
                      drive improvements to preventive controls. What reconnaissance could the attacker have conducted before
                      the incident? How long did malicious activity continue before detection? Were response procedures followed
                      correctly, and were they effective? What technical or procedural changes would prevent similar incidents
                      in the future? Lessons learned should be documented and shared across the organization, and with industry
                      peers where appropriate, to improve collective defense against DMR security threats. Regulatory or
                      contractual notification requirements (for incidents affecting certain types of data or critical
                      infrastructure) must also be addressed as part of post-incident procedures.
                    </Typography>
                  </Box>

                  <Grid container spacing={2}>
                    {[
                      { title: "Enable AES-256 Encryption", desc: "Use strong encryption, not Basic Privacy. Ensure all radios support it.", icon: <LockIcon />, color: theme.success },
                      { title: "Implement OTAR", desc: "Over-The-Air Rekeying allows secure key updates without physical access.", icon: <SecurityIcon />, color: theme.info },
                      { title: "Radio ID Validation", desc: "Maintain whitelist of authorized radio IDs. Block unknown devices.", icon: <CheckCircleIcon />, color: theme.primary },
                      { title: "Monitor for Anomalies", desc: "Log all traffic, alert on unusual patterns, duplicate IDs, or rogue transmissions.", icon: <SearchIcon />, color: theme.warning },
                      { title: "Physical Security", desc: "Secure radios, codeplugs, and encryption keys. Disable stolen radios immediately.", icon: <ShieldIcon />, color: theme.accent },
                      { title: "Train Users", desc: "Authentication procedures, code words, recognize suspicious activity.", icon: <SchoolIcon />, color: theme.secondary },
                    ].map((item, idx) => (
                      <Grid item xs={12} sm={6} key={idx}>
                        <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%", borderLeft: `4px solid ${item.color}` }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                            <Box sx={{ color: item.color }}>{item.icon}</Box>
                            <Typography variant="subtitle2" sx={{ color: item.color, fontWeight: 600 }}>{item.title}</Typography>
                          </Box>
                          <Typography variant="body2" sx={{ color: theme.textMuted }}>{item.desc}</Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>
              </Box>

              {/* Labs Section */}
              <Box id="labs" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <ScienceIcon /> Hands-On Labs
                  </Typography>

                  <Alert severity="info" sx={{ mb: 3, bgcolor: alpha(theme.info, 0.1), color: theme.text }}>
                    <Typography variant="body2">
                      These labs use receive-only techniques and licensed amateur radio operations.
                      No unauthorized transmission is required or encouraged.
                    </Typography>
                  </Alert>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Beginner" size="small" sx={{ bgcolor: alpha(theme.success, 0.2), color: theme.success }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Lab 1: DMR Signal Reception with RTL-SDR
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`# Lab 1: Setting up DMR Reception
# Requirements: RTL-SDR dongle, SDR# or GQRX, DSD+

# Step 1: Install RTL-SDR drivers
# Windows: Use Zadig to install WinUSB driver
# Linux: sudo apt install rtl-sdr

# Step 2: Test RTL-SDR
rtl_test -t
# Should show: Found 1 device(s)

# Step 3: Find local DMR repeaters
# Visit: RepeaterBook.com
# Search for DMR repeaters in your area
# Note: Frequency, Color Code, Talk Groups

# Step 4: Configure SDR# or GQRX
# - Set frequency to repeater output
# - NFM mode, 12.5 kHz bandwidth
# - Enable squelch to reduce noise

# Step 5: Set up DSD+
# - Configure audio routing (virtual cable or direct)
# - Enable DMR decoding
# - Watch for decoded traffic metadata

# Expected output:
# DMR Slot 1, CC 1, TG 12345, SRC 1234567 -> DST 7654321
# Voice traffic decoded (if unencrypted)`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Intermediate" size="small" sx={{ bgcolor: alpha(theme.warning, 0.2), color: theme.warning }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Lab 2: DMR Metadata Analysis
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`# Lab 2: Extracting and analyzing DMR metadata

# Using DSD+ with logging enabled:
# 1. Enable "Log DMR" in DSD+ options
# 2. Monitor traffic for 30+ minutes
# 3. Analyze the log file

# Log file contains:
# - Timestamps
# - Source/Destination Radio IDs
# - Talk Groups
# - Color Codes
# - Call types (Group/Private)

# Analysis tasks:
# 1. Count unique Radio IDs
# 2. Identify most active users
# 3. Map Talk Group usage patterns
# 4. Detect time-based patterns
# 5. Cross-reference with RadioID.net

# Python analysis script:
import csv
from collections import Counter

radio_ids = []
talk_groups = []

with open('dsd_log.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        radio_ids.append(row['source_id'])
        talk_groups.append(row['talk_group'])

print("Top 10 Active Radios:")
print(Counter(radio_ids).most_common(10))

print("Talk Group Distribution:")
print(Counter(talk_groups).most_common())`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Advanced" size="small" sx={{ bgcolor: alpha(theme.error, 0.2), color: theme.error }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Lab 3: Amateur DMR Operation (Licensed)
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha(theme.warning, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          <strong>Requires:</strong> Valid amateur radio license (Technician or higher in US)
                        </Typography>
                      </Alert>
                      <CodeBlock
                        code={`# Lab 3: Setting up your own DMR station

# 1. Get licensed (if not already)
#    - US: FCC Technician license exam
#    - Study: hamstudy.org
#    - Find exam: arrl.org/find-an-amateur-radio-license-exam-session

# 2. Register for a DMR ID
#    - Visit: radioid.net
#    - Create account with callsign
#    - Receive 7-digit DMR ID

# 3. Program your DMR radio
#    - Download CPS (Customer Programming Software)
#    - Enter your DMR ID
#    - Add local repeaters (from RepeaterBook)
#    - Configure talk groups

# 4. Join Brandmeister network
#    - Create account: brandmeister.network
#    - Link your DMR ID
#    - Configure hotspot (optional)

# 5. Experiment legally:
#    - Test different talk groups
#    - Analyze your own transmissions
#    - Understand protocol in practice
#    - Join DMR security research discussions

# Hotspot setup (for home station):
# - Pi-Star on Raspberry Pi
# - MMDVM modem board
# - Connects radio to internet DMR networks`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Advanced" size="small" sx={{ bgcolor: alpha(theme.error, 0.2), color: theme.error }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Lab 4: DMR Frame Analysis with Wireshark
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Analyze captured DMR traffic at the protocol level using Wireshark with DMR dissector.
                      </Typography>
                      <CodeBlock
                        code={`# Lab 4: DMR Protocol Analysis with Wireshark
# Requirements: Wireshark 3.0+, DMR PCAP samples, dmr_decode tool

# Step 1: Obtain DMR PCAP samples
# Option A: Use publicly available DMR captures (research samples)
# Option B: Capture IP-based DMR traffic (Homebrew/IPSC/MMDVM)
# Option C: Convert IQ recordings to PCAP format

# Step 2: Understand DMR over IP protocols
# - Homebrew protocol (MMDVM): UDP port 62031
# - DMR+ protocol: UDP port 55555
# - IPSC protocol: UDP ports 50000-50100

# Step 3: Wireshark filter examples
# Display filter for DMR Homebrew:
dmr

# Filter by Radio ID:
dmr.src_id == 1234567

# Filter by Talk Group:
dmr.dst_id == 91

# Filter voice frames only:
dmr.data_type == 1

# Step 4: Analyze frame structure
# Key fields to examine:
┌─────────────────────────────────────────────────────────────┐
│ DMR Frame Fields in Wireshark                                │
├─────────────────────────────────────────────────────────────┤
│ dmr.slot          - Time Slot (1 or 2)                       │
│ dmr.src_id        - Source Radio ID (24-bit)                 │
│ dmr.dst_id        - Destination (Radio ID or Talk Group)     │
│ dmr.call_type     - Group/Private/All Call                   │
│ dmr.data_type     - Voice/Data/CSBK/Header                   │
│ dmr.cc            - Color Code (0-15)                        │
│ dmr.seq           - Sequence number                          │
│ dmr.streamid      - Unique call identifier                   │
└─────────────────────────────────────────────────────────────┘

# Step 5: Export analysis
# Statistics > Protocol Hierarchy
# Analyze > Follow > UDP Stream
# File > Export Specified Packets (filtered)

# Python script for PCAP analysis:
from scapy.all import rdpcap, UDP

pcap = rdpcap('dmr_capture.pcap')
for pkt in pcap:
    if UDP in pkt and pkt[UDP].dport == 62031:
        dmr_data = bytes(pkt[UDP].payload)
        src_id = int.from_bytes(dmr_data[5:8], 'big')
        dst_id = int.from_bytes(dmr_data[8:11], 'big')
        print(f"Call: {src_id} -> {dst_id}")`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Expert" size="small" sx={{ bgcolor: alpha(theme.primary, 0.2), color: theme.primary }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Lab 5: Building a DMR Security Monitor
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha(theme.warning, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          <strong>For authorized systems only.</strong> Build monitoring for DMR networks you own or have permission to analyze.
                        </Typography>
                      </Alert>
                      <CodeBlock
                        code={`# Lab 5: Complete DMR Security Monitoring System
# Architecture: RTL-SDR -> DSD+ -> Python Monitor -> Alerts

# Component 1: RTL-SDR Receiver Configuration
# config/sdr_config.json
{
  "frequency": 445500000,
  "sample_rate": 2400000,
  "gain": 40,
  "ppm_correction": 0,
  "squelch_level": -30
}

# Component 2: DSD+ Output Parser
# scripts/dsd_parser.py
import re
import json
from datetime import datetime

class DSDParser:
    DMR_PATTERN = r'DMR Slot (\\d), CC (\\d+), .* TG (\\d+), SRC (\\d+)'

    def parse_line(self, line):
        match = re.search(self.DMR_PATTERN, line)
        if match:
            return {
                'timestamp': datetime.now().isoformat(),
                'slot': int(match.group(1)),
                'color_code': int(match.group(2)),
                'talk_group': int(match.group(3)),
                'source_id': int(match.group(4)),
                'raw': line.strip()
            }
        return None

# Component 3: Security Monitor
# scripts/security_monitor.py
class DMRSecurityMonitor:
    def __init__(self, config_file='config/monitor_config.json'):
        with open(config_file) as f:
            self.config = json.load(f)
        self.authorized_ids = set(self.config['authorized_ids'])
        self.known_talk_groups = set(self.config['talk_groups'])
        self.alert_handlers = []

    def add_alert_handler(self, handler):
        self.alert_handlers.append(handler)

    def process_frame(self, frame):
        alerts = []

        # Rule 1: Unknown Radio ID
        if frame['source_id'] not in self.authorized_ids:
            alerts.append({
                'severity': 'MEDIUM',
                'type': 'UNKNOWN_RADIO',
                'message': f"Unknown Radio ID: {frame['source_id']}",
                'frame': frame
            })

        # Rule 2: Suspicious Talk Group
        if frame['talk_group'] not in self.known_talk_groups:
            alerts.append({
                'severity': 'LOW',
                'type': 'UNKNOWN_TALKGROUP',
                'message': f"Unknown TG: {frame['talk_group']}",
                'frame': frame
            })

        # Dispatch alerts
        for alert in alerts:
            for handler in self.alert_handlers:
                handler(alert)

        return alerts

# Component 4: Alert Handlers
def console_alert(alert):
    print(f"[{alert['severity']}] {alert['type']}: {alert['message']}")

def webhook_alert(alert, webhook_url):
    import requests
    requests.post(webhook_url, json=alert)

def syslog_alert(alert, syslog_server):
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msg = f"<134>{alert['type']}: {alert['message']}"
    sock.sendto(msg.encode(), (syslog_server, 514))

# Main execution
if __name__ == '__main__':
    import sys
    parser = DSDParser()
    monitor = DMRSecurityMonitor()
    monitor.add_alert_handler(console_alert)

    for line in sys.stdin:
        frame = parser.parse_line(line)
        if frame:
            monitor.process_frame(frame)`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Glossary Section */}
              <Box id="glossary" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <MenuBookIcon /> DMR Glossary
                  </Typography>

                  <Grid container spacing={2}>
                    {[
                      { term: "TDMA", def: "Time Division Multiple Access - Two time slots on one channel", cat: "Protocol" },
                      { term: "4FSK", def: "4-level Frequency Shift Keying modulation used by DMR", cat: "Protocol" },
                      { term: "Color Code", def: "4-bit identifier (0-15) separating co-channel systems", cat: "Protocol" },
                      { term: "Talk Group", def: "Virtual channel for group communications", cat: "Protocol" },
                      { term: "AMBE+2", def: "Advanced Multi-Band Excitation vocoder for voice compression", cat: "Protocol" },
                      { term: "CACH", def: "Common Announcement Channel - timing/sync info in DMR frames", cat: "Protocol" },
                      { term: "SYNC", def: "48-bit synchronization pattern identifying burst type", cat: "Protocol" },
                      { term: "EMB", def: "Embedded Signaling - color code and LC data within voice", cat: "Protocol" },
                      { term: "LC", def: "Link Control - source/destination IDs and call info", cat: "Protocol" },
                      { term: "PI", def: "Privacy Indicator - flag showing if encryption is enabled", cat: "Protocol" },
                      { term: "Codeplug", def: "Configuration file programmed into DMR radios", cat: "Hardware" },
                      { term: "Hotspot", def: "Personal device connecting radio to internet DMR networks", cat: "Hardware" },
                      { term: "MMDVM", def: "Multi-Mode Digital Voice Modem for hotspots/repeaters", cat: "Hardware" },
                      { term: "RTL-SDR", def: "Low-cost software-defined radio receiver (~$25)", cat: "Hardware" },
                      { term: "HackRF", def: "TX/RX capable SDR for advanced research", cat: "Hardware" },
                      { term: "Basic Privacy", def: "Weak 16-bit XOR scrambling (NOT secure encryption)", cat: "Security" },
                      { term: "Enhanced Privacy", def: "40-bit RC4 or AES encryption option", cat: "Security" },
                      { term: "AES-256", def: "Advanced Encryption Standard with 256-bit keys", cat: "Security" },
                      { term: "OTAR", def: "Over-The-Air Rekeying for remote key updates", cat: "Security" },
                      { term: "Radio Stun", def: "Remote command to disable a radio over-the-air", cat: "Security" },
                      { term: "Brandmeister", def: "Largest worldwide amateur DMR network", cat: "Network" },
                      { term: "TGIF", def: "The Group of International Friends - alternative DMR network", cat: "Network" },
                      { term: "IP Site Connect", def: "Linking DMR repeaters over IP networks", cat: "Network" },
                      { term: "Capacity Plus", def: "Single-site trunking for up to 12 DMR channels", cat: "Network" },
                    ].map((item, idx) => (
                      <Grid item xs={12} md={6} key={idx}>
                        <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%", border: `1px solid ${theme.border}` }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                            <Typography variant="subtitle2" sx={{ color: theme.primary, fontWeight: 600 }}>{item.term}</Typography>
                            <Chip
                              label={item.cat}
                              size="small"
                              sx={{
                                fontSize: "0.65rem",
                                height: 18,
                                bgcolor: item.cat === "Protocol" ? alpha(theme.info, 0.2) :
                                         item.cat === "Security" ? alpha(theme.error, 0.2) :
                                         item.cat === "Hardware" ? alpha(theme.success, 0.2) : alpha(theme.accent, 0.2),
                                color: item.cat === "Protocol" ? theme.info :
                                       item.cat === "Security" ? theme.error :
                                       item.cat === "Hardware" ? theme.success : theme.accent,
                              }}
                            />
                          </Box>
                          <Typography variant="body2" sx={{ color: theme.textMuted }}>{item.def}</Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>
              </Box>

              {/* Resources Section */}
              <Box id="resources" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <MenuBookIcon /> Resources & References
                  </Typography>

                  <Grid container spacing={3}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle1" sx={{ color: theme.secondary, mb: 2 }}>Official Standards & Documentation</Typography>
                      <List dense>
                        {[
                          { name: "ETSI TS 102 361-1", desc: "DMR Air Interface Protocol", url: "etsi.org" },
                          { name: "ETSI TS 102 361-2", desc: "DMR Voice & Generic Services", url: "etsi.org" },
                          { name: "ETSI TS 102 361-3", desc: "DMR Data Protocol", url: "etsi.org" },
                          { name: "ETSI TS 102 361-4", desc: "DMR Trunking Protocol", url: "etsi.org" },
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.5 }}>
                            <ListItemIcon sx={{ minWidth: 28 }}>
                              <MenuBookIcon sx={{ fontSize: 16, color: theme.info }} />
                            </ListItemIcon>
                            <ListItemText
                              primary={item.name}
                              secondary={item.desc}
                              primaryTypographyProps={{ variant: "body2", sx: { color: theme.text, fontWeight: 500 } }}
                              secondaryTypographyProps={{ variant: "caption", sx: { color: theme.textMuted } }}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>

                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle1" sx={{ color: theme.secondary, mb: 2 }}>Open Source Projects</Typography>
                      <List dense>
                        {[
                          { name: "md380tools", desc: "TYT MD-380/390 firmware tools", url: "github.com/travisgoodspeed/md380tools" },
                          { name: "OpenGD77", desc: "Custom firmware for GD-77/DM-1801", url: "github.com/rogerclarkmelbourne/OpenGD77" },
                          { name: "DSD+", desc: "Digital Speech Decoder", url: "dsdplus.com" },
                          { name: "op25", desc: "P25/DMR decoder for GNU Radio", url: "github.com/boatbod/op25" },
                          { name: "dmr_utils", desc: "Python DMR protocol library", url: "github.com/n0mjs710/dmr_utils" },
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.5 }}>
                            <ListItemIcon sx={{ minWidth: 28 }}>
                              <BuildIcon sx={{ fontSize: 16, color: theme.success }} />
                            </ListItemIcon>
                            <ListItemText
                              primary={item.name}
                              secondary={item.desc}
                              primaryTypographyProps={{ variant: "body2", sx: { color: theme.text, fontWeight: 500 } }}
                              secondaryTypographyProps={{ variant: "caption", sx: { color: theme.textMuted } }}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>

                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle1" sx={{ color: theme.secondary, mb: 2 }}>Reference Databases</Typography>
                      <List dense>
                        {[
                          { name: "RadioID.net", desc: "DMR user ID registration database" },
                          { name: "RepeaterBook.com", desc: "Worldwide repeater directory" },
                          { name: "Brandmeister.network", desc: "Brandmeister network dashboard" },
                          { name: "RadioReference.com", desc: "Frequency and system database" },
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.5 }}>
                            <ListItemIcon sx={{ minWidth: 28 }}>
                              <SearchIcon sx={{ fontSize: 16, color: theme.accent }} />
                            </ListItemIcon>
                            <ListItemText
                              primary={item.name}
                              secondary={item.desc}
                              primaryTypographyProps={{ variant: "body2", sx: { color: theme.text, fontWeight: 500 } }}
                              secondaryTypographyProps={{ variant: "caption", sx: { color: theme.textMuted } }}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>

                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle1" sx={{ color: theme.secondary, mb: 2 }}>Research & Presentations</Typography>
                      <List dense>
                        {[
                          { name: "DEF CON 27", desc: "DMR security research presentations" },
                          { name: "CCC Congress", desc: "Radio hacking talks archive" },
                          { name: "POC||GTFO", desc: "MD380 reverse engineering articles" },
                          { name: "Ham radio security lists", desc: "Amateur security research forums" },
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.5 }}>
                            <ListItemIcon sx={{ minWidth: 28 }}>
                              <SchoolIcon sx={{ fontSize: 16, color: theme.primary }} />
                            </ListItemIcon>
                            <ListItemText
                              primary={item.name}
                              secondary={item.desc}
                              primaryTypographyProps={{ variant: "body2", sx: { color: theme.text, fontWeight: 500 } }}
                              secondaryTypographyProps={{ variant: "caption", sx: { color: theme.textMuted } }}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>
                  </Grid>
                </Paper>
              </Box>

              {/* Legal Section */}
              <Box id="legal" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <GavelIcon /> Legal & Ethical Considerations
                  </Typography>

                  <Alert severity="error" sx={{ mb: 3, bgcolor: alpha(theme.error, 0.1), color: theme.text }}>
                    <Typography variant="body2">
                      <strong>Federal Law (US - 47 U.S.C. § 333):</strong> Willful or malicious interference with
                      radio communications is punishable by fines up to $100,000 and/or imprisonment up to one year.
                    </Typography>
                  </Alert>

                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, borderLeft: `4px solid ${theme.success}` }}>
                        <Typography variant="subtitle2" sx={{ color: theme.success, mb: 1 }}>Legal Activities</Typography>
                        <List dense>
                          {[
                            "Receive-only monitoring (in most jurisdictions)",
                            "Amateur radio operation with license",
                            "Security research on your own systems",
                            "Academic research with proper authorization",
                            "Decoding unencrypted amateur traffic",
                          ].map((item, idx) => (
                            <ListItem key={idx} sx={{ py: 0, pl: 0 }}>
                              <ListItemIcon sx={{ minWidth: 20 }}>
                                <CheckCircleIcon sx={{ fontSize: 14, color: theme.success }} />
                              </ListItemIcon>
                              <ListItemText primary={item} primaryTypographyProps={{ variant: "caption", sx: { color: theme.textMuted } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, borderLeft: `4px solid ${theme.error}` }}>
                        <Typography variant="subtitle2" sx={{ color: theme.error, mb: 1 }}>Illegal Activities</Typography>
                        <List dense>
                          {[
                            "Transmitting without authorization",
                            "Jamming or interfering with communications",
                            "Impersonating emergency services",
                            "Breaking encryption on non-owned systems",
                            "Intercepting private communications",
                          ].map((item, idx) => (
                            <ListItem key={idx} sx={{ py: 0, pl: 0 }}>
                              <ListItemIcon sx={{ minWidth: 20 }}>
                                <WarningIcon sx={{ fontSize: 14, color: theme.error }} />
                              </ListItemIcon>
                              <ListItemText primary={item} primaryTypographyProps={{ variant: "caption", sx: { color: theme.textMuted } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                  </Grid>
                </Paper>
              </Box>

              {/* Quiz Section */}
              <Box id="quiz-section" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <QuizIcon /> Knowledge Check
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.textMuted, mb: 3 }}>
                    Test your understanding of DMR security with {QUIZ_QUESTION_COUNT} randomly selected questions.
                  </Typography>
                  <QuizSection questions={quizQuestions} accentColor={theme.primary} questionsPerQuiz={QUIZ_QUESTION_COUNT} />
                </Paper>
              </Box>

              {/* Back Button */}
              <Box sx={{ textAlign: "center", mt: 4 }}>
                <Button
                  variant="outlined"
                  startIcon={<ArrowBackIcon />}
                  onClick={() => navigate("/learn")}
                  sx={{
                    borderColor: theme.primary,
                    color: theme.primary,
                    "&:hover": {
                      borderColor: theme.primaryLight,
                      bgcolor: alpha(theme.primary, 0.1),
                    },
                  }}
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
          PaperProps={{
            sx: { bgcolor: theme.bgCard, width: 280 },
          }}
        >
          <Box sx={{ p: 2 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
              <Typography variant="subtitle1" sx={{ color: theme.primary, fontWeight: 600 }}>
                Navigation
              </Typography>
              <IconButton onClick={() => setNavDrawerOpen(false)} sx={{ color: theme.text }}>
                <CloseIcon />
              </IconButton>
            </Box>
            <List>
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
                    bgcolor: "transparent",
                    width: "100%",
                    textAlign: "left",
                    "&:hover": {
                      bgcolor: alpha(theme.primary, 0.1),
                    },
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 32, color: theme.primary }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.label}
                    primaryTypographyProps={{
                      variant: "body2",
                      sx: { color: theme.text },
                    }}
                  />
                </ListItem>
              ))}
            </List>
          </Box>
        </Drawer>

        {/* Mobile FABs */}
        <Box
          sx={{
            display: { xs: "flex", md: "none" },
            position: "fixed",
            bottom: 16,
            right: 16,
            flexDirection: "column",
            gap: 1,
          }}
        >
          <Fab
            size="small"
            onClick={scrollToTop}
            sx={{ bgcolor: theme.bgCard, color: theme.text, "&:hover": { bgcolor: theme.bgNested } }}
          >
            <KeyboardArrowUpIcon />
          </Fab>
          <Fab
            size="small"
            onClick={() => setNavDrawerOpen(true)}
            sx={{ bgcolor: theme.primary, color: "white", "&:hover": { bgcolor: theme.primaryLight } }}
          >
            <RadioIcon />
          </Fab>
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default DMRHackingPage;
