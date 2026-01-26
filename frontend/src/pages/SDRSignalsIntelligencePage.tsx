import React, { useState, useEffect } from "react";
import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  useMediaQuery,
  Grid,
  Card,
  CardContent,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Divider,
  Button,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  keyframes,
  Tabs,
  Tab,
  Breadcrumbs,
  Link as MuiLink,
  Alert,
  Drawer,
  Fab,
  IconButton,
  LinearProgress,
  Avatar,
  ListItemButton,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import RadioIcon from "@mui/icons-material/Radio";
import SettingsInputAntennaIcon from "@mui/icons-material/SettingsInputAntenna";
import WifiIcon from "@mui/icons-material/Wifi";
import SecurityIcon from "@mui/icons-material/Security";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SettingsIcon from "@mui/icons-material/Settings";
import TimelineIcon from "@mui/icons-material/Timeline";
import WarningIcon from "@mui/icons-material/Warning";
import DnsIcon from "@mui/icons-material/Dns";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import MemoryIcon from "@mui/icons-material/Memory";
import InfoIcon from "@mui/icons-material/Info";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import AnalyticsIcon from "@mui/icons-material/Analytics";
import StorageIcon from "@mui/icons-material/Storage";
import DeviceHubIcon from "@mui/icons-material/DeviceHub";
import RouterIcon from "@mui/icons-material/Router";
import TerminalIcon from "@mui/icons-material/Terminal";
import GppMaybeIcon from "@mui/icons-material/GppMaybe";
import ShieldIcon from "@mui/icons-material/Shield";
import HubIcon from "@mui/icons-material/Hub";
import SpeedIcon from "@mui/icons-material/Speed";
import GraphicEqIcon from "@mui/icons-material/GraphicEq";
import SatelliteAltIcon from "@mui/icons-material/SatelliteAlt";
import CellTowerIcon from "@mui/icons-material/CellTower";
import BluetoothIcon from "@mui/icons-material/Bluetooth";
import NfcIcon from "@mui/icons-material/Nfc";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import FlightIcon from "@mui/icons-material/Flight";
import DirectionsCarIcon from "@mui/icons-material/DirectionsCar";
import HomeIcon from "@mui/icons-material/Home";
import LocalHospitalIcon from "@mui/icons-material/LocalHospital";
import FactoryIcon from "@mui/icons-material/Factory";
import VisibilityIcon from "@mui/icons-material/Visibility";
import SearchIcon from "@mui/icons-material/Search";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import SchoolIcon from "@mui/icons-material/School";
import AttachMoneyIcon from "@mui/icons-material/AttachMoney";
import GavelIcon from "@mui/icons-material/Gavel";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import QuizIcon from "@mui/icons-material/Quiz";
import RadarIcon from "@mui/icons-material/Radar";
import PsychologyIcon from "@mui/icons-material/Psychology";
import HistoryIcon from "@mui/icons-material/History";
import PublicIcon from "@mui/icons-material/Public";
import TrackChangesIcon from "@mui/icons-material/TrackChanges";
import BoltIcon from "@mui/icons-material/Bolt";
import SignalCellularAltIcon from "@mui/icons-material/SignalCellularAlt";
import ExploreIcon from "@mui/icons-material/Explore";
import PeopleIcon from "@mui/icons-material/People";
import AssessmentIcon from "@mui/icons-material/Assessment";
import MilitaryTechIcon from "@mui/icons-material/MilitaryTech";
import LearnPageLayout from "../components/LearnPageLayout";

// Theme colors for consistent styling
const sdrTheme = {
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

// Tab panel component
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

// Animations
const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-8px); }
`;

const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
`;

const wave = keyframes`
  0% { transform: translateX(-100%); }
  100% { transform: translateX(100%); }
`;

// ==================== DATA DEFINITIONS ====================

// SDR Hardware Options
const SDR_HARDWARE = [
  {
    name: "RTL-SDR v3/v4",
    price: "$25-40",
    frequency: "500 kHz - 1.7 GHz",
    bandwidth: "2.4 MHz",
    bits: "8-bit",
    description: "Best entry-level SDR. Excellent for learning, ADS-B, FM, weather satellites, pagers, and most common signals.",
    pros: ["Extremely affordable", "Huge community support", "Works out of the box", "Direct sampling for HF"],
    cons: ["Limited bandwidth", "8-bit ADC limits dynamic range", "Receive only"],
    bestFor: ["Beginners", "ADS-B", "Weather satellites", "FM radio", "Pagers"],
    color: "#10b981",
  },
  {
    name: "HackRF One",
    price: "$300-350",
    frequency: "1 MHz - 6 GHz",
    bandwidth: "20 MHz",
    bits: "8-bit",
    description: "Versatile TX/RX SDR covering huge frequency range. Great for research and replay attacks.",
    pros: ["Transmit capability", "Wide frequency range", "Open source hardware", "Good community"],
    cons: ["Half-duplex only", "8-bit ADC", "Needs good filtering"],
    bestFor: ["Security research", "Replay attacks", "Protocol analysis", "Wide-band scanning"],
    color: "#8b5cf6",
  },
  {
    name: "ADALM-Pluto",
    price: "$150-200",
    frequency: "325 MHz - 3.8 GHz",
    bandwidth: "20 MHz",
    bits: "12-bit",
    description: "Affordable full-duplex SDR from Analog Devices. Can be hacked to extend range.",
    pros: ["Full duplex", "12-bit ADC", "Hackable to 70 MHz - 6 GHz", "USB powered"],
    cons: ["Limited stock frequency range", "Smaller community", "Can run hot"],
    bestFor: ["Learning DSP", "Full-duplex experiments", "Cellular research", "Educational"],
    color: "#3b82f6",
  },
  {
    name: "LimeSDR Mini",
    price: "$200-250",
    frequency: "10 MHz - 3.5 GHz",
    bandwidth: "30.72 MHz",
    bits: "12-bit",
    description: "Compact full-duplex SDR with good bandwidth. Great for cellular and LTE research.",
    pros: ["Full duplex", "Good bandwidth", "Open source", "MIMO capable (full LimeSDR)"],
    cons: ["Needs good USB3", "Can be finicky", "Requires filtering"],
    bestFor: ["LTE/cellular", "MIMO experiments", "Full-duplex protocols"],
    color: "#22c55e",
  },
  {
    name: "USRP B200/B210",
    price: "$1,100-1,800",
    frequency: "70 MHz - 6 GHz",
    bandwidth: "56 MHz",
    bits: "12-bit",
    description: "Professional-grade SDR from Ettus/NI. Industry standard for serious research.",
    pros: ["Excellent performance", "Full duplex", "Rock solid", "Great documentation"],
    cons: ["Expensive", "Overkill for beginners", "Requires good host PC"],
    bestFor: ["Professional research", "Academic labs", "High-performance applications"],
    color: "#f59e0b",
  },
  {
    name: "Airspy R2/Mini",
    price: "$170-200",
    frequency: "24 MHz - 1.8 GHz",
    bandwidth: "10 MHz",
    bits: "12-bit",
    description: "High-quality receive-only SDR with excellent dynamic range. Great for weak signal work.",
    pros: ["Excellent sensitivity", "12-bit ADC", "Low noise", "Spyverter for HF"],
    cons: ["Receive only", "More expensive than RTL-SDR", "Limited bandwidth"],
    bestFor: ["Weak signal reception", "HF with Spyverter", "High-quality recordings"],
    color: "#06b6d4",
  },
];

// RF Frequency Bands
const FREQUENCY_BANDS = [
  { band: "VLF", range: "3-30 kHz", wavelength: "100-10 km", uses: "Submarine comms, time signals", color: "#6b7280" },
  { band: "LF", range: "30-300 kHz", wavelength: "10-1 km", uses: "Navigation, AM longwave", color: "#8b5cf6" },
  { band: "MF", range: "300 kHz - 3 MHz", wavelength: "1000-100 m", uses: "AM broadcast, maritime", color: "#3b82f6" },
  { band: "HF", range: "3-30 MHz", wavelength: "100-10 m", uses: "Shortwave, amateur radio, military", color: "#06b6d4" },
  { band: "VHF", range: "30-300 MHz", wavelength: "10-1 m", uses: "FM radio, TV, air traffic, marine", color: "#10b981" },
  { band: "UHF", range: "300 MHz - 3 GHz", wavelength: "100-10 cm", uses: "TV, cellular, WiFi, GPS, Bluetooth", color: "#22c55e" },
  { band: "SHF", range: "3-30 GHz", wavelength: "10-1 cm", uses: "Radar, satellite, 5G mmWave", color: "#f59e0b" },
  { band: "EHF", range: "30-300 GHz", wavelength: "10-1 mm", uses: "Radio astronomy, security scanners", color: "#ef4444" },
];

// Common Modulation Types
const MODULATION_TYPES = [
  {
    name: "AM (Amplitude Modulation)",
    description: "Signal encoded in carrier amplitude. Simple but inefficient.",
    uses: ["AM radio", "Aircraft comms", "CB radio"],
    signature: "Carrier with sidebands",
  },
  {
    name: "FM (Frequency Modulation)",
    description: "Signal encoded in carrier frequency. Better noise immunity.",
    uses: ["FM radio", "Two-way radio", "Analog TV audio"],
    signature: "Constant amplitude, varying frequency",
  },
  {
    name: "SSB (Single Sideband)",
    description: "AM with carrier and one sideband removed. Efficient for voice.",
    uses: ["Amateur radio", "Marine", "Military HF"],
    signature: "No carrier, single sideband",
  },
  {
    name: "FSK (Frequency Shift Keying)",
    description: "Digital modulation using frequency shifts for 0s and 1s.",
    uses: ["Pagers", "POCSAG", "FLEX", "AIS"],
    signature: "Discrete frequency jumps",
  },
  {
    name: "PSK (Phase Shift Keying)",
    description: "Digital modulation using phase changes. Common in modern systems.",
    uses: ["WiFi", "Satellite", "LTE"],
    signature: "Constellation diagram patterns",
  },
  {
    name: "OFDM (Orthogonal FDM)",
    description: "Multiple subcarriers for high data rates. Resistant to multipath.",
    uses: ["WiFi", "LTE", "DVB-T", "DAB"],
    signature: "Wide flat spectrum with many subcarriers",
  },
  {
    name: "ASK/OOK (On-Off Keying)",
    description: "Simplest digital modulation. Carrier on/off for 1/0.",
    uses: ["Car key fobs", "Garage doors", "Simple remotes"],
    signature: "Bursts of carrier",
  },
  {
    name: "GFSK (Gaussian FSK)",
    description: "FSK with Gaussian filter for reduced bandwidth.",
    uses: ["Bluetooth", "DECT phones", "Nordic RF"],
    signature: "Smooth frequency transitions",
  },
];

// SDR Software Tools
const SDR_SOFTWARE = [
  {
    name: "GNU Radio",
    type: "Framework",
    platform: "Linux/Windows/Mac",
    description: "Open-source signal processing framework. Create custom receivers/transmitters with flowgraphs.",
    features: ["Visual flowgraph editor", "Python scripting", "Huge block library", "Real-time processing"],
    url: "gnuradio.org",
    color: "#3b82f6",
  },
  {
    name: "SDR# (SDRSharp)",
    type: "Receiver",
    platform: "Windows",
    description: "Popular general-purpose SDR receiver with plugin ecosystem.",
    features: ["Easy to use", "Many plugins", "Good for beginners", "Fast scanning"],
    url: "airspy.com",
    color: "#10b981",
  },
  {
    name: "GQRX",
    type: "Receiver",
    platform: "Linux/Mac",
    description: "Open-source SDR receiver based on GNU Radio. Great for Linux users.",
    features: ["GNU Radio backend", "Remote control", "Audio recording", "Bookmarks"],
    url: "gqrx.dk",
    color: "#8b5cf6",
  },
  {
    name: "SDR++",
    type: "Receiver",
    platform: "Cross-platform",
    description: "Modern, fast, cross-platform SDR receiver with clean UI.",
    features: ["Fast waterfall", "Module system", "Low CPU usage", "Active development"],
    url: "github.com/AlexandreRouworthy/SDRPlusPlus",
    color: "#22c55e",
  },
  {
    name: "Universal Radio Hacker (URH)",
    type: "Analysis",
    platform: "Cross-platform",
    description: "Analyze unknown wireless protocols. Record, demodulate, decode, and replay.",
    features: ["Protocol analysis", "Fuzzing", "Simulation", "Replay attacks"],
    url: "github.com/jopohl/urh",
    color: "#ef4444",
  },
  {
    name: "Inspectrum",
    type: "Analysis",
    platform: "Linux",
    description: "Analyze captured RF signals. Great for reverse engineering protocols.",
    features: ["Waterfall analysis", "Symbol extraction", "Cursor measurements", "Export data"],
    url: "github.com/miek/inspectrum",
    color: "#f59e0b",
  },
  {
    name: "rtl_433",
    type: "Decoder",
    platform: "Cross-platform",
    description: "Decode 433 MHz ISM band devices: weather stations, sensors, tire pressure monitors.",
    features: ["200+ device protocols", "JSON output", "MQTT integration", "Automatic detection"],
    url: "github.com/merbanan/rtl_433",
    color: "#06b6d4",
  },
  {
    name: "dump1090",
    type: "Decoder",
    platform: "Cross-platform",
    description: "ADS-B decoder for tracking aircraft. Shows planes on a map in real-time.",
    features: ["Aircraft tracking", "Web interface", "FlightAware feed", "BaseStation output"],
    url: "github.com/flightaware/dump1090",
    color: "#8b5cf6",
  },
];

// Signal Targets for Security Research
const SIGNAL_TARGETS = [
  {
    category: "Automotive",
    icon: <DirectionsCarIcon />,
    color: "#ef4444",
    targets: [
      { name: "Key Fobs (315/433 MHz)", risk: "High", description: "Rolling code vulnerabilities, replay attacks" },
      { name: "TPMS (315/433 MHz)", risk: "Medium", description: "Tire pressure sensors, tracking, spoofing" },
      { name: "RKE Systems", risk: "High", description: "Remote keyless entry, relay attacks" },
      { name: "Immobilizers", risk: "High", description: "Transponder cloning, cryptographic weaknesses" },
    ],
  },
  {
    category: "IoT & Smart Home",
    icon: <HomeIcon />,
    color: "#f59e0b",
    targets: [
      { name: "Z-Wave (908 MHz)", risk: "Medium", description: "Home automation, S0 security issues" },
      { name: "Zigbee (2.4 GHz)", risk: "Medium", description: "Smart devices, key extraction" },
      { name: "433 MHz Sensors", risk: "Low", description: "Weather stations, doorbells, no encryption" },
      { name: "LoRa (868/915 MHz)", risk: "Low", description: "Long range IoT, often unencrypted" },
    ],
  },
  {
    category: "Wireless Networks",
    icon: <WifiIcon />,
    color: "#3b82f6",
    targets: [
      { name: "WiFi (2.4/5 GHz)", risk: "Varies", description: "WPA2/3 attacks, PMKID, deauth" },
      { name: "Bluetooth (2.4 GHz)", risk: "Medium", description: "BLE sniffing, KNOB attack, tracking" },
      { name: "DECT (1.9 GHz)", risk: "High", description: "Cordless phones, often weak encryption" },
      { name: "NFC (13.56 MHz)", risk: "Medium", description: "Payment cards, access control" },
    ],
  },
  {
    category: "Cellular & Paging",
    icon: <CellTowerIcon />,
    color: "#8b5cf6",
    targets: [
      { name: "GSM (850-1900 MHz)", risk: "High", description: "A5/1 encryption broken, IMSI catchers" },
      { name: "LTE (700-2600 MHz)", risk: "Medium", description: "Downgrade attacks, tracking" },
      { name: "POCSAG Pagers", risk: "High", description: "Hospital pagers, usually unencrypted" },
      { name: "P25 (VHF/UHF)", risk: "Varies", description: "Public safety, encryption optional" },
    ],
  },
  {
    category: "Aviation & Maritime",
    icon: <FlightIcon />,
    color: "#06b6d4",
    targets: [
      { name: "ADS-B (1090 MHz)", risk: "High", description: "Aircraft tracking, no authentication" },
      { name: "ACARS (VHF)", risk: "Medium", description: "Aircraft data link, mostly plaintext" },
      { name: "AIS (162 MHz)", risk: "Medium", description: "Ship tracking, spoofing possible" },
      { name: "VHF Marine", risk: "Low", description: "Ship communications, unencrypted" },
    ],
  },
  {
    category: "Satellite",
    icon: <SatelliteAltIcon />,
    color: "#10b981",
    targets: [
      { name: "GPS L1 (1575 MHz)", risk: "High", description: "Spoofing, jamming attacks" },
      { name: "NOAA/Meteor (137 MHz)", risk: "Low", description: "Weather satellite images" },
      { name: "Iridium (1616 MHz)", risk: "Medium", description: "Satellite phone, some vulnerabilities" },
      { name: "Inmarsat (1.5 GHz)", risk: "Medium", description: "Maritime/aviation satcom" },
    ],
  },
  {
    category: "Industrial",
    icon: <FactoryIcon />,
    color: "#dc2626",
    targets: [
      { name: "ISM Band Sensors", risk: "Medium", description: "Industrial sensors, weak security" },
      { name: "Wireless HART", risk: "Medium", description: "Process automation, some encryption" },
      { name: "Utility Meters", risk: "Medium", description: "Smart meters, protocol analysis" },
      { name: "SCADA Wireless", risk: "High", description: "Critical infrastructure, legacy security" },
    ],
  },
];

// SIGINT Concepts
const SIGINT_CONCEPTS = [
  {
    term: "COMINT",
    full: "Communications Intelligence",
    description: "Intelligence from intercepted communications between people or systems.",
    examples: ["Radio intercepts", "Phone calls", "Data transmissions"],
  },
  {
    term: "ELINT",
    full: "Electronic Intelligence",
    description: "Intelligence from non-communication electronic emissions like radar.",
    examples: ["Radar signatures", "Navigation beacons", "Jamming signals"],
  },
  {
    term: "FISINT",
    full: "Foreign Instrumentation Signals Intelligence",
    description: "Intelligence from foreign aerospace, weapons, and test systems.",
    examples: ["Missile telemetry", "Satellite signals", "Test range data"],
  },
  {
    term: "MASINT",
    full: "Measurement and Signature Intelligence",
    description: "Intelligence from analysis of physical phenomena and signatures.",
    examples: ["RF fingerprinting", "Signal characterization", "Emitter identification"],
  },
];

// GNU Radio Basics
const GNU_RADIO_BLOCKS = [
  { category: "Sources", blocks: ["RTL-SDR Source", "File Source", "Signal Source", "UHD Source", "Audio Source"], color: "#10b981" },
  { category: "Sinks", blocks: ["File Sink", "Audio Sink", "QT GUI Sink", "UDP Sink", "ZMQ Sink"], color: "#3b82f6" },
  { category: "Filters", blocks: ["Low Pass Filter", "Band Pass Filter", "FFT Filter", "Frequency Xlating FIR"], color: "#8b5cf6" },
  { category: "Demodulators", blocks: ["FM Demod", "AM Demod", "GFSK Demod", "PSK Demod", "Quadrature Demod"], color: "#f59e0b" },
  { category: "Math", blocks: ["Multiply", "Add", "Complex to Mag", "Threshold", "AGC"], color: "#ef4444" },
  { category: "Synchronization", blocks: ["Clock Recovery MM", "Polyphase Clock Sync", "Symbol Sync", "PLL"], color: "#06b6d4" },
];

// Common Attacks
const RF_ATTACKS = [
  {
    attack: "Replay Attack",
    description: "Record a valid transmission and replay it later to trigger the same action.",
    targets: ["Garage doors", "Old car fobs", "Simple remotes"],
    defense: "Rolling codes, timestamps, challenge-response",
    difficulty: "Easy",
    color: "#ef4444",
  },
  {
    attack: "Jamming",
    description: "Overwhelm a receiver with noise to prevent legitimate signals from being received.",
    targets: ["GPS", "WiFi", "Cellular", "Any RF system"],
    defense: "Spread spectrum, frequency hopping, directional antennas",
    difficulty: "Easy",
    color: "#dc2626",
  },
  {
    attack: "Relay/Amplification",
    description: "Extend the range of a legitimate signal to bypass proximity requirements.",
    targets: ["Keyless car entry", "NFC payments", "Access cards"],
    defense: "UWB ranging, motion detection, timeouts",
    difficulty: "Medium",
    color: "#f59e0b",
  },
  {
    attack: "Spoofing",
    description: "Generate fake signals that appear legitimate to the target system.",
    targets: ["GPS", "ADS-B", "AIS", "Cellular base stations"],
    defense: "Authentication, signal validation, multi-source verification",
    difficulty: "Medium-Hard",
    color: "#8b5cf6",
  },
  {
    attack: "Protocol Downgrade",
    description: "Force a system to use a weaker, more vulnerable protocol version.",
    targets: ["Cellular (LTE to 2G)", "WiFi", "Bluetooth"],
    defense: "Minimum security requirements, disable legacy protocols",
    difficulty: "Medium",
    color: "#3b82f6",
  },
  {
    attack: "Side-Channel Analysis",
    description: "Extract information from unintended RF emissions or timing.",
    targets: ["Crypto devices", "Keyboards", "Displays"],
    defense: "Shielding, constant-time operations, noise injection",
    difficulty: "Hard",
    color: "#06b6d4",
  },
];

// Antenna Types
const ANTENNA_TYPES = [
  {
    type: "Whip/Monopole",
    gain: "2-5 dBi",
    pattern: "Omnidirectional",
    use: "General purpose, included with most SDRs",
    frequency: "Wide range depending on length",
  },
  {
    type: "Dipole",
    gain: "2-3 dBi",
    pattern: "Omnidirectional (donut)",
    use: "Simple, effective, easy to build",
    frequency: "Tuned to specific frequency",
  },
  {
    type: "Discone",
    gain: "0-2 dBi",
    pattern: "Omnidirectional",
    use: "Wideband scanning, 25-1300 MHz typical",
    frequency: "Very wide bandwidth",
  },
  {
    type: "Yagi-Uda",
    gain: "6-15 dBi",
    pattern: "Directional",
    use: "Weak signal reception, direction finding",
    frequency: "Narrowband, tuned",
  },
  {
    type: "Log Periodic",
    gain: "5-8 dBi",
    pattern: "Directional",
    use: "Wideband directional, EMC testing",
    frequency: "Wide bandwidth",
  },
  {
    type: "Parabolic Dish",
    gain: "15-40 dBi",
    pattern: "Highly directional",
    use: "Satellite reception, long distance",
    frequency: "Usually microwave",
  },
  {
    type: "Patch/Microstrip",
    gain: "5-9 dBi",
    pattern: "Directional",
    use: "GPS, satellite, compact applications",
    frequency: "Single frequency or narrow band",
  },
  {
    type: "Helical",
    gain: "8-15 dBi",
    pattern: "Directional, circular polarization",
    use: "Satellite tracking, circular polarized signals",
    frequency: "Usually specific design frequency",
  },
];

// Legal Considerations by Region
const LEGAL_CONSIDERATIONS = [
  {
    region: "General Principles",
    rules: [
      "Receiving is generally legal in most countries",
      "Transmitting requires a license in most cases",
      "Intercepting private communications may be illegal",
      "Jamming is illegal almost everywhere",
      "Equipment restrictions vary by country",
    ],
    color: "#3b82f6",
  },
  {
    region: "United States",
    rules: [
      "Reception is legal except for cellular voice (ECPA)",
      "Ham license (Technician+) for transmitting on amateur bands",
      "ISM bands allow low-power unlicensed transmission",
      "FCC Part 15/97 regulations apply",
      "Military/government frequencies are restricted",
    ],
    color: "#10b981",
  },
  {
    region: "European Union",
    rules: [
      "Reception generally legal",
      "Varies by country within EU",
      "ETSI standards for equipment",
      "Amateur licenses required for TX",
      "Some countries restrict SDR sales",
    ],
    color: "#8b5cf6",
  },
  {
    region: "Research Exemptions",
    rules: [
      "Academic research may have exemptions",
      "Faraday cages/shielded rooms for contained testing",
      "Coordination with authorities recommended",
      "Document your research purpose",
      "CTF/educational contexts generally safe",
    ],
    color: "#f59e0b",
  },
];

// Command Line Tools
const CLI_TOOLS = [
  {
    tool: "rtl_sdr",
    description: "Basic RTL-SDR capture to file",
    commands: [
      "rtl_sdr -f 433920000 -s 2048000 capture.bin",
      "rtl_sdr -f 1090000000 -s 2000000 -g 50 adsb.bin",
    ],
  },
  {
    tool: "rtl_fm",
    description: "FM demodulation and audio output",
    commands: [
      "rtl_fm -f 100.1M -M wbfm -s 200000 -r 48000 | aplay -r 48000 -f S16_LE",
      "rtl_fm -f 162.550M -M fm -s 22050 | aplay -r 22050 -f S16_LE",
    ],
  },
  {
    tool: "rtl_433",
    description: "Decode 433 MHz ISM devices",
    commands: [
      "rtl_433 -f 433920000",
      "rtl_433 -F json -M utc",
      "rtl_433 -R 40 -f 315000000  # Specific protocol",
    ],
  },
  {
    tool: "dump1090",
    description: "ADS-B aircraft tracking",
    commands: [
      "dump1090 --interactive",
      "dump1090 --net --net-http-port 8080",
    ],
  },
  {
    tool: "hackrf_transfer",
    description: "HackRF capture/transmit",
    commands: [
      "hackrf_transfer -r capture.bin -f 433920000 -s 2000000",
      "hackrf_transfer -t replay.bin -f 433920000 -s 2000000",
    ],
  },
  {
    tool: "inspectrum",
    description: "Analyze recorded signals",
    commands: [
      "inspectrum capture.bin  # Open in GUI",
    ],
  },
];

// ==================== ADDITIONAL DATA ====================

// SDR Beginner Projects
const BEGINNER_PROJECTS = [
  {
    name: "FM Radio Receiver",
    difficulty: "Easy",
    time: "30 min",
    description: "Listen to local FM radio stations using your SDR",
    equipment: ["RTL-SDR", "Telescopic antenna"],
    frequency: "88-108 MHz",
    software: "SDR# or GQRX",
    steps: [
      "Connect RTL-SDR with antenna",
      "Open SDR# and select RTL-SDR device",
      "Set mode to WFM (Wideband FM)",
      "Tune to a local FM station (e.g., 100.1 MHz)",
      "Adjust gain for best reception",
    ],
  },
  {
    name: "ADS-B Aircraft Tracking",
    difficulty: "Easy",
    time: "1 hour",
    description: "Track aircraft in real-time on a map",
    equipment: ["RTL-SDR", "1090 MHz antenna or discone"],
    frequency: "1090 MHz",
    software: "dump1090, FlightAware",
    steps: [
      "Install dump1090 or tar1090",
      "Connect SDR with appropriate antenna",
      "Run dump1090 --interactive",
      "Open web interface to see aircraft on map",
      "Optionally feed data to FlightAware/FlightRadar24",
    ],
  },
  {
    name: "NOAA Weather Satellite",
    difficulty: "Medium",
    time: "2-3 hours",
    description: "Receive APT images from NOAA weather satellites",
    equipment: ["RTL-SDR", "V-dipole or QFH antenna"],
    frequency: "137.1, 137.62, 137.9125 MHz",
    software: "GQRX, WXtoImg, SatDump",
    steps: [
      "Build or buy 137 MHz antenna",
      "Track satellite passes using N2YO or Gpredict",
      "Record pass in GQRX (FM mode, 48kHz bandwidth)",
      "Process recording with WXtoImg or SatDump",
      "Decode image with weather data",
    ],
  },
  {
    name: "433 MHz ISM Band Decoding",
    difficulty: "Easy",
    time: "1 hour",
    description: "Decode weather stations, car key fobs, tire pressure sensors",
    equipment: ["RTL-SDR", "Antenna tuned for 433 MHz"],
    frequency: "433.92 MHz",
    software: "rtl_433",
    steps: [
      "Install rtl_433",
      "Run: rtl_433 -f 433920000",
      "Observe decoded signals from nearby devices",
      "Identify your weather station, doorbell, etc.",
      "Export to JSON or MQTT for home automation",
    ],
  },
  {
    name: "Pager (POCSAG) Decoding",
    difficulty: "Medium",
    time: "1 hour",
    description: "Decode unencrypted pager messages (educational purposes)",
    equipment: ["RTL-SDR", "Wideband antenna"],
    frequency: "Varies by region (929 MHz US, 153 MHz EU)",
    software: "SDR#, PDW, multimon-ng",
    steps: [
      "Research legal frequencies in your area",
      "Tune SDR to pager frequency",
      "Set NFM mode with ~12.5 kHz bandwidth",
      "Pipe audio to multimon-ng or PDW",
      "Observe POCSAG/FLEX messages",
    ],
  },
  {
    name: "Meteor-M2 Satellite Images",
    difficulty: "Medium",
    time: "3-4 hours",
    description: "Receive high-quality LRPT images from Russian weather satellite",
    equipment: ["RTL-SDR", "137 MHz antenna (QFH recommended)"],
    frequency: "137.1 MHz",
    software: "SatDump, LRPTDecoder",
    steps: [
      "Track Meteor-M2 passes",
      "Set SDR to 137.1 MHz, QPSK mode",
      "Record entire pass (10-15 minutes)",
      "Process with SatDump",
      "Get color composite images",
    ],
  },
];

// Protocol Analysis Examples
const PROTOCOL_ANALYSIS = [
  {
    protocol: "LoRa/LoRaWAN",
    frequency: "868 MHz (EU) / 915 MHz (US)",
    modulation: "CSS (Chirp Spread Spectrum)",
    description: "Long-range IoT protocol used for sensors, meters, tracking",
    security: "AES-128 encryption in LoRaWAN, but often misconfigured",
    tools: ["SDR++", "GNU Radio gr-lora", "LoRa_PHY_Coder"],
    research: [
      "Capture and analyze LoRa packets",
      "Check for missing encryption",
      "Identify device types and network structure",
      "GPS trackers often use unencrypted LoRa",
    ],
  },
  {
    protocol: "Z-Wave",
    frequency: "908.42 MHz (US) / 868.42 MHz (EU)",
    modulation: "FSK",
    description: "Home automation protocol for smart locks, thermostats, sensors",
    security: "S0 security has known vulnerabilities, S2 is more secure",
    tools: ["EZ-Wave", "Scapy-radio", "HackRF"],
    research: [
      "Capture pairing process",
      "S0 downgrade attacks",
      "Replay door lock commands",
      "Analyze network topology",
    ],
  },
  {
    protocol: "Zigbee",
    frequency: "2.4 GHz",
    modulation: "O-QPSK",
    description: "Mesh network protocol for smart home devices",
    security: "AES-128, but key management often weak",
    tools: ["KillerBee", "Attify Zigbee Framework", "CC2531 sniffer"],
    research: [
      "Capture and decrypt traffic",
      "Key extraction during pairing",
      "Firmware analysis",
      "Network mapping",
    ],
  },
  {
    protocol: "TPMS (Tire Pressure Monitoring)",
    frequency: "315 MHz (US) / 433 MHz (EU/Asia)",
    modulation: "ASK/FSK",
    description: "Transmits tire pressure and temperature from each wheel",
    security: "No encryption, unique sensor IDs",
    tools: ["rtl_433", "GNU Radio", "HackRF"],
    research: [
      "Vehicle tracking via TPMS IDs",
      "Spoofing tire pressure alerts",
      "Privacy implications",
      "Range testing",
    ],
  },
  {
    protocol: "AIS (Automatic Identification System)",
    frequency: "161.975 MHz / 162.025 MHz",
    modulation: "GMSK",
    description: "Ship identification and tracking system",
    security: "No authentication or encryption",
    tools: ["rtl-ais", "AIS Catcher", "GNU Radio gr-ais"],
    research: [
      "Track ships in real-time",
      "Analyze ship movements",
      "AIS spoofing research (legal implications)",
      "Maritime security assessment",
    ],
  },
  {
    protocol: "P25 (Project 25)",
    frequency: "Various VHF/UHF",
    modulation: "C4FM/FDMA",
    description: "Public safety radio system (police, fire, EMS)",
    security: "DES/AES encryption optional, often unencrypted",
    tools: ["OP25", "DSD+", "SDRTrunk"],
    research: [
      "Monitor public safety communications",
      "Analyze trunked radio systems",
      "Encryption detection",
      "System mapping",
    ],
  },
];

// RF Lab Setup Guide
const LAB_SETUP = [
  {
    level: "Beginner Lab (~$50-100)",
    items: [
      "RTL-SDR v3 or v4 ($25-40)",
      "Telescopic antenna (included)",
      "USB extension cable ($5)",
      "SDR# or GQRX (free software)",
    ],
    capabilities: "FM radio, ADS-B, weather satellites, ISM band, pagers",
  },
  {
    level: "Intermediate Lab (~$300-500)",
    items: [
      "HackRF One ($300)",
      "ANT500 antenna ($30)",
      "LNA (Low Noise Amplifier) ($30)",
      "Discone antenna ($50)",
      "GNU Radio + URH",
    ],
    capabilities: "TX/RX, replay attacks, protocol analysis, wide-band scanning",
  },
  {
    level: "Advanced Lab (~$1000-2000)",
    items: [
      "USRP B200 or LimeSDR ($400-1000)",
      "Spectrum analyzer ($200-500)",
      "Directional antennas ($100-200)",
      "RF shielding/Faraday cage ($200-400)",
      "Signal generator ($100-300)",
    ],
    capabilities: "Full-duplex, MIMO, professional research, cellular analysis",
  },
  {
    level: "Professional Lab (~$5000+)",
    items: [
      "USRP X310 or similar ($5000+)",
      "Professional spectrum analyzer",
      "Calibrated antennas",
      "Shielded room",
      "Oscilloscope with RF probes",
    ],
    capabilities: "Academic/commercial research, standards development, certification testing",
  },
];

// Satellite Frequencies Reference
const SATELLITE_FREQUENCIES = [
  {
    satellite: "NOAA 15/18/19",
    frequency: "137.62 / 137.9125 / 137.1 MHz",
    mode: "APT (Analog)",
    description: "Weather satellite images, 2 passes per day each",
    antenna: "V-dipole, QFH, or turnstile",
  },
  {
    satellite: "Meteor-M2",
    frequency: "137.1 MHz",
    mode: "LRPT (Digital QPSK)",
    description: "High-quality color weather images",
    antenna: "QFH or turnstile recommended",
  },
  {
    satellite: "ISS (SSTV Events)",
    frequency: "145.8 MHz",
    mode: "FM SSTV",
    description: "Slow-scan TV images during special events",
    antenna: "2m dipole or Yagi",
  },
  {
    satellite: "GPS L1",
    frequency: "1575.42 MHz",
    mode: "BPSK",
    description: "GPS navigation signals",
    antenna: "Patch antenna with LNA",
  },
  {
    satellite: "Iridium (Flares)",
    frequency: "1616-1626.5 MHz",
    mode: "QPSK",
    description: "Satellite phone network",
    antenna: "Wideband L-band antenna",
  },
  {
    satellite: "Inmarsat",
    frequency: "1525-1559 MHz",
    mode: "Various",
    description: "Maritime/aviation satellite communications",
    antenna: "L-band patch or helix",
  },
  {
    satellite: "GOES Weather",
    frequency: "1694.1 MHz",
    mode: "HRIT/EMWIN",
    description: "High-resolution weather data",
    antenna: "1m+ dish with LNA",
  },
];

// Security Research Ethics
const RESEARCH_ETHICS = [
  {
    principle: "Authorization",
    description: "Only analyze signals from systems you own or have explicit permission to test",
    examples: ["Your own IoT devices", "Authorized penetration tests", "CTF competitions"],
  },
  {
    principle: "Minimal Impact",
    description: "Avoid actions that could disrupt services or harm others",
    examples: ["Never jam signals", "Don't replay attacks on production systems", "Use Faraday cages for TX testing"],
  },
  {
    principle: "Responsible Disclosure",
    description: "Report vulnerabilities to vendors before public disclosure",
    examples: ["Contact security teams", "Allow reasonable fix time", "Coordinate disclosure"],
  },
  {
    principle: "Legal Compliance",
    description: "Know and follow local RF regulations",
    examples: ["No unlicensed TX", "Respect frequency allocations", "Obtain ham license for experiments"],
  },
  {
    principle: "Privacy Respect",
    description: "Don't collect or store personal communications",
    examples: ["Don't record private conversations", "Anonymize research data", "Delete captures after analysis"],
  },
];

// ==================== EW/COMINT THEORY DATA ====================

// Electronic Warfare Components
const EW_COMPONENTS = [
  {
    name: "Electronic Attack (EA)",
    aka: "ECM - Electronic Countermeasures",
    description: "Actions taken to prevent or reduce an enemy's effective use of the electromagnetic spectrum through the use of electromagnetic energy. This includes jamming, deception, and directed energy weapons.",
    subcategories: [
      {
        name: "Jamming",
        description: "Deliberate radiation of electromagnetic energy to disrupt enemy communications or radar systems. Can be noise jamming (broadband interference), spot jamming (targeting specific frequencies), or sweep jamming (cycling through frequencies).",
        examples: ["Barrage jamming", "Spot jamming", "Deceptive jamming", "Smart jamming"],
      },
      {
        name: "Deception",
        description: "Manipulation of electromagnetic emissions to mislead enemy sensors. Includes creating false targets, masking real signals, or manipulating signal characteristics.",
        examples: ["Meaconing (rebroadcasting nav signals)", "Spoofing", "False target generation", "Chaff/flares"],
      },
      {
        name: "Directed Energy",
        description: "Use of focused electromagnetic energy to damage or destroy enemy equipment. High-Power Microwave (HPM) weapons can disable electronics from a distance.",
        examples: ["HPM weapons", "Electromagnetic pulse (EMP)", "Laser dazzlers"],
      },
    ],
    color: "#ef4444",
  },
  {
    name: "Electronic Protection (EP)",
    aka: "ECCM - Electronic Counter-Countermeasures",
    description: "Actions taken to ensure friendly use of the electromagnetic spectrum despite enemy electronic warfare efforts. Includes hardening systems, using resistant waveforms, and employing frequency agility.",
    subcategories: [
      {
        name: "Frequency Management",
        description: "Dynamic control of operating frequencies to avoid detection and jamming. Includes frequency hopping, spread spectrum techniques, and adaptive frequency selection.",
        examples: ["Frequency hopping", "Direct Sequence Spread Spectrum (DSSS)", "Adaptive frequency selection"],
      },
      {
        name: "Signal Processing",
        description: "Advanced processing techniques to extract desired signals from noise and interference. Includes nulling, beamforming, and adaptive filtering.",
        examples: ["Adaptive nulling", "Phased array beamforming", "Spatial filtering"],
      },
      {
        name: "Physical Hardening",
        description: "Protection of equipment against electromagnetic interference and attack. Includes shielding, filtering, and EMP protection.",
        examples: ["Faraday cages", "Tempest shielding", "Surge protection", "Optical isolation"],
      },
    ],
    color: "#10b981",
  },
  {
    name: "Electronic Warfare Support (ES)",
    aka: "ESM - Electronic Support Measures",
    description: "Actions to search for, intercept, identify, and locate electromagnetic emissions for threat recognition, targeting, and operational planning. The foundation of SIGINT operations.",
    subcategories: [
      {
        name: "Signal Detection",
        description: "Sensing and detecting electromagnetic emissions across the spectrum. Requires sensitive receivers, wideband antennas, and real-time processing capabilities.",
        examples: ["Spectrum monitoring", "Threshold detection", "Correlation detection"],
      },
      {
        name: "Signal Analysis",
        description: "Detailed examination of detected signals to extract intelligence. Includes technical analysis of waveform characteristics and content analysis of communications.",
        examples: ["Modulation recognition", "Protocol analysis", "Content extraction"],
      },
      {
        name: "Emitter Location",
        description: "Determining the geographic position of signal sources using various techniques. Critical for targeting and situational awareness.",
        examples: ["Direction finding (DF)", "Time Difference of Arrival (TDOA)", "Frequency Difference of Arrival (FDOA)"],
      },
    ],
    color: "#3b82f6",
  },
];

// COMINT Analysis Methodology
const COMINT_METHODOLOGY = [
  {
    phase: "Collection Planning",
    description: "Defining intelligence requirements and tasking collection assets. Involves prioritizing targets, allocating resources, and coordinating with other intelligence disciplines.",
    activities: [
      "Define Essential Elements of Information (EEI)",
      "Identify target frequencies and networks",
      "Task appropriate collection platforms",
      "Coordinate spectrum access and deconfliction",
      "Establish collection schedules and priorities",
    ],
    color: "#8b5cf6",
  },
  {
    phase: "Signal Acquisition",
    description: "Detecting and capturing target communications. Requires appropriate antenna systems, receivers, and recording capabilities. Must account for propagation conditions and target behavior.",
    activities: [
      "Deploy appropriate antenna systems",
      "Configure receivers for target parameters",
      "Monitor for target activity",
      "Record raw signal data",
      "Verify signal quality and coverage",
    ],
    color: "#3b82f6",
  },
  {
    phase: "Signal Processing",
    description: "Converting raw RF signals into usable data. Includes demodulation, decoding, and decryption. May require specialized processing for complex waveforms.",
    activities: [
      "Demodulate captured signals",
      "Decode protocols and formats",
      "Apply cryptanalysis if encrypted",
      "Extract metadata (timing, frequency, power)",
      "Isolate individual channels from multiplexed signals",
    ],
    color: "#06b6d4",
  },
  {
    phase: "Content Analysis",
    description: "Extracting intelligence from decoded communications. Includes translation, transcription, and interpretation. Analysts must understand cultural and technical context.",
    activities: [
      "Transcribe voice communications",
      "Translate foreign language content",
      "Identify speakers and call signs",
      "Extract key information and entities",
      "Correlate with other intelligence sources",
    ],
    color: "#10b981",
  },
  {
    phase: "Traffic Analysis",
    description: "Deriving intelligence from communication patterns without accessing content. Even encrypted communications reveal information through their metadata.",
    activities: [
      "Map network topology and relationships",
      "Identify command structures",
      "Detect activity patterns and anomalies",
      "Correlate communications with events",
      "Track changes in communication behavior",
    ],
    color: "#f59e0b",
  },
  {
    phase: "Reporting & Dissemination",
    description: "Producing intelligence products for consumers. Reports must be timely, accurate, and actionable. Must protect sources and methods while maximizing intelligence value.",
    activities: [
      "Produce SIGINT reports",
      "Classify and protect sensitive information",
      "Disseminate to authorized consumers",
      "Maintain databases and archives",
      "Support follow-on collection and analysis",
    ],
    color: "#ef4444",
  },
];

// ELINT Radar Parameters
const ELINT_PARAMETERS = [
  {
    parameter: "Pulse Repetition Frequency (PRF)",
    description: "The rate at which radar pulses are transmitted. Higher PRF provides better velocity resolution but shorter unambiguous range.",
    significance: "Identifies radar type, operating mode, and capabilities. Military radars often use staggered or jittered PRF for ECCM.",
    typical: "100 Hz - 500 kHz depending on radar type",
  },
  {
    parameter: "Pulse Width (PW)",
    description: "Duration of each transmitted pulse. Shorter pulses provide better range resolution; longer pulses carry more energy for detection of small targets.",
    significance: "Combined with PRF, determines duty cycle and average power. Variable PW indicates pulse compression capability.",
    typical: "0.1 µs - 100 µs",
  },
  {
    parameter: "Radio Frequency (RF)",
    description: "The carrier frequency of the radar signal. Determines propagation characteristics, antenna size, and target interaction.",
    significance: "Frequency band indicates radar role: surveillance (lower), tracking (higher), fire control (microwave/mmWave).",
    typical: "Band dependent: L (1-2 GHz), S (2-4 GHz), C (4-8 GHz), X (8-12 GHz), Ku/K/Ka (12-40 GHz)",
  },
  {
    parameter: "Scan Type & Rate",
    description: "Pattern of antenna movement: mechanical rotation, electronic scanning (phased array), or combinations.",
    significance: "Scan pattern reveals radar's search/track capability. AESA radars can perform multiple functions simultaneously.",
    typical: "Mechanical: 6-60 RPM; Electronic: microseconds",
  },
  {
    parameter: "Signal-to-Noise Ratio (SNR)",
    description: "Ratio of received signal power to noise floor. Critical for detection probability and measurement accuracy.",
    significance: "Higher SNR enables detection at greater range or of smaller targets. Affected by jamming and interference.",
    typical: "Detection threshold typically 10-15 dB",
  },
  {
    parameter: "Antenna Patterns",
    description: "Main lobe, side lobes, and back lobes of the radar antenna. Determines angular coverage and susceptibility to jamming.",
    significance: "Side lobe levels affect vulnerability to deception jamming. Modern radars use low-sidelobe designs.",
    typical: "Main lobe: 1-10° beamwidth; Side lobes: -20 to -40 dB",
  },
];

// Direction Finding Techniques
const DF_TECHNIQUES = [
  {
    technique: "Amplitude Comparison (Watson-Watt)",
    description: "Uses two or more directional antennas to determine signal bearing from amplitude ratios. Simple and fast but limited accuracy.",
    accuracy: "2-10° typical",
    advantages: ["Simple implementation", "Fast acquisition", "Works on short signals"],
    limitations: ["Limited accuracy", "Requires good antenna calibration", "Affected by multipath"],
    applications: ["HF direction finding", "Search and rescue", "Initial threat warning"],
  },
  {
    technique: "Phase Interferometry",
    description: "Measures phase difference between antennas separated by known baseline. Very high accuracy possible with multiple baselines.",
    accuracy: "0.1-1° achievable",
    advantages: ["High accuracy", "Good sensitivity", "Well-suited for automation"],
    limitations: ["Ambiguity resolution required for long baselines", "Narrowband signals only", "Requires stable phase reference"],
    applications: ["Precision location", "ELINT systems", "Satellite tracking"],
  },
  {
    technique: "Doppler/Pseudo-Doppler",
    description: "Uses moving or switched antennas to create Doppler shift proportional to bearing. Common in VHF/UHF direction finding.",
    accuracy: "1-5°",
    advantages: ["Good for mobile platforms", "Works well in multipath", "Moderate cost"],
    limitations: ["Requires signal duration", "Mechanical or switching complexity", "Frequency dependent"],
    applications: ["Mobile radio DF", "Wildlife tracking", "Amateur radio DF"],
  },
  {
    technique: "Time Difference of Arrival (TDOA)",
    description: "Multiple receivers measure arrival time differences to locate emitter on hyperbolic curves. Passive geolocation technique.",
    accuracy: "Meters to kilometers depending on geometry",
    advantages: ["Passive operation", "Works on any signal", "Good for moving targets"],
    limitations: ["Requires precise synchronization", "Multiple stations needed", "Geometry dependent"],
    applications: ["Cell phone location (E911)", "SIGINT geolocation", "Aircraft tracking"],
  },
  {
    technique: "Frequency Difference of Arrival (FDOA)",
    description: "Uses Doppler shift differences measured at multiple moving receivers. Often combined with TDOA for improved accuracy.",
    accuracy: "Varies with platform geometry",
    advantages: ["Works with moving platforms", "Complements TDOA", "Good for satellite SIGINT"],
    limitations: ["Requires relative motion", "Complex processing", "Integration time required"],
    applications: ["Satellite SIGINT", "Airborne SIGINT", "Maritime surveillance"],
  },
  {
    technique: "Correlative Interferometry",
    description: "Compares measured antenna patterns against calibrated database. Combines amplitude and phase for robust DF.",
    accuracy: "1-3°",
    advantages: ["Robust to multipath", "Works with complex antenna arrays", "Good performance on cluttered environments"],
    limitations: ["Requires extensive calibration", "Database storage", "Computationally intensive"],
    applications: ["Urban DF", "Shipboard systems", "Complex terrain"],
  },
];

// Traffic Analysis Concepts
const TRAFFIC_ANALYSIS_CONCEPTS = [
  {
    concept: "Network Analysis",
    description: "Mapping the structure of communication networks by observing who communicates with whom, when, and how often. Even without content, network structure reveals organizational hierarchy and relationships.",
    techniques: ["Contact chaining", "Social network analysis", "Hub identification", "Cluster analysis"],
    intelligence_value: "Identifies key nodes, command relationships, and network vulnerabilities",
  },
  {
    concept: "Pattern of Life (POL)",
    description: "Establishing baseline communication patterns for targets to detect anomalies. Regular schedules, typical contacts, and normal behavior serve as reference for detecting significant changes.",
    techniques: ["Temporal analysis", "Behavioral baselining", "Anomaly detection", "Trend analysis"],
    intelligence_value: "Predicts activities, detects operational security changes, identifies significant events",
  },
  {
    concept: "Communication Flow Analysis",
    description: "Examining the volume, timing, and direction of communications to understand information flow within organizations. Bursts of activity often correlate with significant events.",
    techniques: ["Volume analysis", "Peak detection", "Flow mapping", "Correlation with events"],
    intelligence_value: "Early warning of operations, identification of decision-making processes",
  },
  {
    concept: "Protocol Analysis",
    description: "Understanding communication protocols to extract maximum metadata. Protocol headers, handshakes, and control messages contain valuable intelligence even in encrypted systems.",
    techniques: ["Header analysis", "Protocol fingerprinting", "Handshake analysis", "Error message exploitation"],
    intelligence_value: "Equipment identification, software versions, configuration details",
  },
  {
    concept: "Geospatial-Temporal Correlation",
    description: "Correlating communication activity with geographic locations and time. Movement patterns of emitters reveal operational activities and relationships.",
    techniques: ["Movement tracking", "Co-location analysis", "Meeting detection", "Pattern matching"],
    intelligence_value: "Activity location, meeting identification, operational planning detection",
  },
];

// Historical SIGINT Evolution
const SIGINT_HISTORY = [
  {
    era: "Pre-WWI & WWI (1900-1918)",
    developments: [
      "Early radio intercept stations",
      "Room 40 British Naval Intelligence",
      "Zimmermann Telegram intercept",
      "First dedicated SIGINT units",
    ],
    significance: "Established SIGINT as critical intelligence discipline. Demonstrated strategic value of communications intelligence.",
  },
  {
    era: "Interwar & WWII (1919-1945)",
    developments: [
      "ULTRA - breaking Enigma",
      "MAGIC - breaking Japanese codes",
      "Y Service intercept network",
      "Traffic analysis techniques",
      "HFDF (Huff-Duff) for U-boat location",
    ],
    significance: "SIGINT contributed decisively to Allied victory. Established techniques still relevant today.",
  },
  {
    era: "Cold War (1945-1991)",
    developments: [
      "NSA/GCHQ establishment",
      "ECHELON global network",
      "Satellite SIGINT (ELINT/COMINT)",
      "Submarine cable tapping",
      "Advanced cryptanalysis",
    ],
    significance: "Global SIGINT infrastructure development. Technical collection capabilities expanded dramatically.",
  },
  {
    era: "Digital Age (1991-2010)",
    developments: [
      "Internet communications intercept",
      "Mobile phone networks",
      "Fiber optic tapping",
      "Metadata analysis programs",
      "Lawful intercept frameworks",
    ],
    significance: "Explosion of communications volume. Shift from targeted to bulk collection capabilities.",
  },
  {
    era: "Modern Era (2010-Present)",
    developments: [
      "5G/IoT challenges",
      "End-to-end encryption proliferation",
      "AI/ML for analysis",
      "Quantum computing threats",
      "Commercial SIGINT capabilities",
    ],
    significance: "Democratization of SIGINT tools. Encryption as default creates access challenges.",
  },
];

// Spectrum Operations
const SPECTRUM_OPERATIONS = [
  {
    operation: "Spectrum Surveillance",
    description: "Continuous monitoring of electromagnetic spectrum to detect unauthorized emissions, maintain situational awareness, and support spectrum management.",
    functions: ["24/7 monitoring", "Automated detection", "Anomaly alerting", "Historical analysis"],
    tools: ["Spectrum analyzers", "SDR receivers", "Direction finders", "Database systems"],
    color: "#3b82f6",
  },
  {
    operation: "Electromagnetic Battle Management (EMBM)",
    description: "Real-time management of friendly and hostile electromagnetic emissions during operations. Coordinates EA, EP, and ES activities.",
    functions: ["Deconfliction", "Dynamic spectrum allocation", "Threat response", "Effects coordination"],
    tools: ["C2 systems", "Spectrum managers", "EW coordination cells", "Battle management aids"],
    color: "#f59e0b",
  },
  {
    operation: "Spectrum Maneuver",
    description: "Dynamic movement through the electromagnetic spectrum to avoid detection, jamming, or interference while maintaining communications.",
    functions: ["Frequency hopping coordination", "Adaptive waveforms", "Cognitive radio", "Spectrum agility"],
    tools: ["Software-defined radios", "Cognitive systems", "ECCM equipment", "Spread spectrum radios"],
    color: "#10b981",
  },
];

// SIGINT Platform Types
const SIGINT_PLATFORMS = [
  {
    type: "Ground-Based Fixed",
    description: "Permanent installations with large antenna arrays and extensive processing capabilities. Provide continuous coverage of assigned areas.",
    examples: ["GCHQ Bude", "NSA Sugar Grove", "Pine Gap"],
    capabilities: ["Large aperture antennas", "HFDF networks", "Satellite downlinks", "24/7 operation"],
    limitations: ["Fixed location", "Limited mobility", "Vulnerable to targeting"],
  },
  {
    type: "Ground-Based Mobile",
    description: "Transportable systems that can be deployed to support operations. Range from vehicle-mounted to man-portable systems.",
    examples: ["AN/TLQ-17A", "Prophet system", "Man-portable SIGINT"],
    capabilities: ["Tactical mobility", "Quick deployment", "Organic to units"],
    limitations: ["Limited processing", "Shorter range", "Requires logistics support"],
  },
  {
    type: "Airborne",
    description: "Aircraft-mounted systems providing wide-area coverage and line-of-sight advantages. Include dedicated SIGINT aircraft and pods.",
    examples: ["RC-135 Rivet Joint", "EP-3E Aries", "MQ-9 SIGINT variants"],
    capabilities: ["Wide area coverage", "High altitude advantage", "Rapid repositioning", "TDOA/FDOA geolocation"],
    limitations: ["Flight endurance", "Weather dependent", "Operating costs"],
  },
  {
    type: "Space-Based",
    description: "Satellite systems providing global coverage. Include dedicated SIGINT satellites and shared reconnaissance platforms.",
    examples: ["MENTOR (Orion)", "TRUMPET", "Intruder class"],
    capabilities: ["Global coverage", "Persistent presence", "High altitude access", "Difficult to counter"],
    limitations: ["Orbital constraints", "Launch costs", "Collection geometry"],
  },
  {
    type: "Maritime",
    description: "Ship and submarine-based systems for maritime and coastal SIGINT. Submarines provide covert access to denied areas.",
    examples: ["SSN SIGINT suites", "TAGOS class", "Surface ship ESM"],
    capabilities: ["Forward deployed", "Covert collection", "Cable access (submarines)"],
    limitations: ["Limited antenna size", "Platform constraints", "Environmental challenges"],
  },
];

// ==================== COMPONENT ====================

export default function SDRSignalsIntelligencePage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const isMobile = useMediaQuery(theme.breakpoints.down("lg"));

  // State for tabs
  const [hardwareTab, setHardwareTab] = React.useState(0);
  const [targetsTab, setTargetsTab] = React.useState(0);
  const [toolsTab, setToolsTab] = React.useState(0);
  const [ewTab, setEwTab] = React.useState(0);

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");

  const accent = "#8b5cf6"; // Purple accent for SDR theme

  // Section navigation items - expanded with EW/COMINT sections
  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <InfoIcon /> },
    { id: "what-is-sdr", label: "What is SDR?", icon: <RadioIcon /> },
    { id: "sigint-overview", label: "SIGINT Overview", icon: <VisibilityIcon /> },
    { id: "ew-fundamentals", label: "EW Fundamentals", icon: <BoltIcon /> },
    { id: "comint-deep-dive", label: "COMINT Deep Dive", icon: <PeopleIcon /> },
    { id: "elint-radar", label: "ELINT & Radar Intel", icon: <RadarIcon /> },
    { id: "direction-finding", label: "Direction Finding", icon: <ExploreIcon /> },
    { id: "traffic-analysis", label: "Traffic Analysis", icon: <AssessmentIcon /> },
    { id: "sigint-history", label: "SIGINT History", icon: <HistoryIcon /> },
    { id: "sigint-platforms", label: "Collection Platforms", icon: <SatelliteAltIcon /> },
    { id: "spectrum-ops", label: "Spectrum Operations", icon: <TrackChangesIcon /> },
    { id: "counter-sigint", label: "Counter-SIGINT", icon: <SecurityIcon /> },
    { id: "hardware", label: "SDR Hardware", icon: <MemoryIcon /> },
    { id: "rf-fundamentals", label: "RF Fundamentals", icon: <GraphicEqIcon /> },
    { id: "antennas", label: "Antenna Guide", icon: <SettingsInputAntennaIcon /> },
    { id: "software", label: "SDR Software", icon: <CodeIcon /> },
    { id: "targets", label: "Signal Targets", icon: <GppMaybeIcon /> },
    { id: "attacks", label: "RF Attacks", icon: <SecurityIcon /> },
    { id: "gnuradio", label: "GNU Radio", icon: <HubIcon /> },
    { id: "cli-tools", label: "CLI Tools", icon: <TerminalIcon /> },
    { id: "projects", label: "Beginner Projects", icon: <SchoolIcon /> },
    { id: "protocols", label: "Protocol Analysis", icon: <DeviceHubIcon /> },
    { id: "satellites", label: "Satellite Frequencies", icon: <SatelliteAltIcon /> },
    { id: "lab-setup", label: "Lab Setup", icon: <BuildIcon /> },
    { id: "legal", label: "Legal & Ethics", icon: <GavelIcon /> },
    { id: "resources", label: "Resources", icon: <MenuBookIcon /> },
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

  // Scroll to top
  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });

  // Progress calculation
  const currentIndex = sectionNavItems.findIndex((item) => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / sectionNavItems.length) * 100 : 0;

  const pageContext = `Comprehensive SDR & Signals Intelligence guide covering:
- SDR hardware: RTL-SDR, HackRF, ADALM-Pluto, LimeSDR, USRP, Airspy
- RF fundamentals: frequency bands, modulation types (AM, FM, FSK, PSK, OFDM)
- SDR software: GNU Radio, SDR#, GQRX, SDR++, URH, rtl_433, dump1090
- Signal targets: automotive, IoT, wireless networks, cellular, aviation, satellite, industrial
- SIGINT concepts: COMINT, ELINT, FISINT, MASINT
- RF attacks: replay, jamming, relay, spoofing, protocol downgrade
- Antenna types and selection
- GNU Radio basics and flowgraph blocks
- Command line tools: rtl_sdr, rtl_fm, rtl_433, hackrf_transfer
- Legal considerations for RF research
- Beginner projects and lab setup
- Protocol analysis examples
- Satellite frequency reference`;

  // Sidebar navigation component (DMR-style)
  const sidebarNav = (
    <Box sx={{ position: "sticky", top: 24 }}>
      <Paper
        sx={{
          bgcolor: sdrTheme.bgCard,
          border: `1px solid ${sdrTheme.border}`,
          borderRadius: 2,
          p: 2,
        }}
      >
        <Typography variant="subtitle2" sx={{ color: sdrTheme.primary, mb: 2, fontWeight: 600 }}>
          NAVIGATION
        </Typography>
        {/* Progress */}
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" sx={{ color: sdrTheme.textMuted }}>
              Progress
            </Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: sdrTheme.primary }}>
              {Math.round(progressPercent)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 4,
              borderRadius: 2,
              bgcolor: alpha(sdrTheme.primary, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: sdrTheme.primary,
                borderRadius: 2,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1.5, borderColor: sdrTheme.border }} />
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
                bgcolor: activeSection === item.id ? alpha(sdrTheme.primary, 0.15) : "transparent",
                width: "100%",
                textAlign: "left",
                "&:hover": {
                  bgcolor: alpha(sdrTheme.primary, 0.1),
                },
              }}
            >
              <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? sdrTheme.primary : sdrTheme.textMuted }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  variant: "body2",
                  sx: { 
                    color: activeSection === item.id ? sdrTheme.text : sdrTheme.textMuted,
                    fontWeight: activeSection === item.id ? 600 : 400,
                  },
                }}
              />
            </ListItem>
          ))}
        </List>
      </Paper>
    </Box>
  );

  return (
    <LearnPageLayout pageTitle="SDR & Signals Intelligence" pageContext={pageContext}>
      <Box sx={{ bgcolor: sdrTheme.bgDark, minHeight: "100vh", py: 4 }}>
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
                  borderColor: sdrTheme.primary,
                  color: sdrTheme.primary,
                  "&:hover": {
                    bgcolor: alpha(sdrTheme.primary, 0.1),
                    borderColor: sdrTheme.primaryLight,
                  },
                }}
              />

        {/* Hero Section */}
        <Paper
          id="intro"
          sx={{
            p: 5,
            mb: 5,
            borderRadius: 4,
            bgcolor: sdrTheme.bgCard,
            border: `1px solid ${sdrTheme.border}`,
            background: `linear-gradient(135deg, ${sdrTheme.bgCard} 0%, ${alpha(sdrTheme.primary, 0.1)} 100%)`,
            position: "relative",
            overflow: "hidden",
          }}
        >
          {/* Animated wave decoration */}
          <Box
            sx={{
              position: "absolute",
              top: 0,
              left: 0,
              right: 0,
              height: 4,
              background: `linear-gradient(90deg, transparent, ${alpha(sdrTheme.primary, 0.5)}, ${alpha(sdrTheme.secondary, 0.5)}, transparent)`,
              animation: `${wave} 3s ease-in-out infinite`,
            }}
          />
          {/* Floating decorations */}
          <Box
            sx={{
              position: "absolute",
              top: -50,
              right: -50,
              width: 200,
              height: 200,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#8b5cf6", 0.2)} 0%, transparent 70%)`,
              animation: `${float} 6s ease-in-out infinite`,
            }}
          />
          <Box
            sx={{
              position: "absolute",
              bottom: -30,
              left: "20%",
              width: 150,
              height: 150,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#06b6d4", 0.15)} 0%, transparent 70%)`,
              animation: `${float} 8s ease-in-out infinite`,
              animationDelay: "-2s",
            }}
          />

          <Box sx={{ position: "relative", zIndex: 1 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, #8b5cf6 0%, #06b6d4 100%)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#8b5cf6", 0.4)}`,
                  animation: `${float} 4s ease-in-out infinite`,
                }}
              >
                <RadioIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800 }}>
                  SDR & Signals Intelligence
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ mt: 0.5 }}>
                  Master software-defined radio for security research, signal analysis, and RF exploration
                </Typography>
              </Box>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, maxWidth: 800 }}>
              Software Defined Radio (SDR) transforms RF signals into digital data for analysis and manipulation.
              This guide covers hardware selection, signal fundamentals, analysis techniques, and security research applications
              across automotive, IoT, wireless, cellular, and satellite domains.
            </Typography>

            <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
              <Chip icon={<SettingsInputAntennaIcon />} label="RF Fundamentals" color="primary" />
              <Chip icon={<MemoryIcon />} label="SDR Hardware" variant="outlined" />
              <Chip icon={<GraphicEqIcon />} label="Signal Analysis" variant="outlined" />
              <Chip icon={<SecurityIcon />} label="Security Research" variant="outlined" />
              <Chip icon={<GavelIcon />} label="Legal Considerations" variant="outlined" />
            </Box>
          </Box>
        </Paper>

        {/* Quick Stats */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          {[
            { value: "3", label: "EW Pillars", icon: <BoltIcon />, color: "#ef4444" },
            { value: "6", label: "COMINT Phases", icon: <PeopleIcon />, color: "#8b5cf6" },
            { value: "6+", label: "DF Techniques", icon: <ExploreIcon />, color: "#3b82f6" },
            { value: "5", label: "Platform Types", icon: <SatelliteAltIcon />, color: "#10b981" },
          ].map((stat, idx) => (
            <Grid item xs={6} md={3} key={idx}>
              <Paper
                sx={{
                  p: 3,
                  textAlign: "center",
                  borderRadius: 3,
                  border: `1px solid ${alpha(stat.color, 0.2)}`,
                  background: `linear-gradient(135deg, ${alpha(stat.color, 0.05)} 0%, transparent 100%)`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    boxShadow: `0 8px 30px ${alpha(stat.color, 0.2)}`,
                  },
                }}
              >
                <Box sx={{ color: stat.color, mb: 1 }}>{stat.icon}</Box>
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

        {/* ==================== SIGINT OVERVIEW ==================== */}
        <Paper
          id="sigint-overview"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.08)} 0%, ${alpha("#3b82f6", 0.05)} 100%)`,
            border: `1px solid ${alpha("#8b5cf6", 0.25)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <VisibilityIcon sx={{ color: "#8b5cf6" }} />
            Signals Intelligence (SIGINT) Overview
          </Typography>
          
          <Typography variant="body1" sx={{ mb: 3 }}>
            <strong>Signals Intelligence (SIGINT)</strong> is the intelligence discipline concerned with the interception, 
            collection, analysis, and exploitation of electromagnetic signals. It represents one of the most valuable sources 
            of intelligence in modern warfare and security operations, providing insight into adversary intentions, capabilities, 
            and activities that cannot be obtained through other means.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            SIGINT encompasses several sub-disciplines, each focused on different aspects of electromagnetic emissions. 
            <strong> Communications Intelligence (COMINT)</strong> focuses on intercepted communications between individuals or systems—voice 
            conversations, text messages, emails, and data transmissions. <strong>Electronic Intelligence (ELINT)</strong> deals with 
            non-communication electromagnetic emissions, primarily radar systems, navigation aids, and weapons guidance systems. 
            <strong>Foreign Instrumentation Signals Intelligence (FISINT)</strong> targets telemetry, beaconing, and command signals 
            from foreign weapons systems and aerospace vehicles.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            The value of SIGINT lies in its ability to provide direct access to adversary decision-making. Unlike Human Intelligence 
            (HUMINT), which relies on individuals who may misunderstand, lie, or be compromised, SIGINT intercepts the actual 
            communications and signals used by targets. This directness makes SIGINT extremely valuable, but also requires 
            sophisticated technical capabilities and careful analysis to extract meaningful intelligence.
          </Typography>

          <Grid container spacing={3}>
            {[
              {
                term: "COMINT",
                full: "Communications Intelligence",
                description: "Intelligence derived from intercepted communications. Includes voice, text, data, and video communications. Requires understanding of languages, protocols, and communication patterns.",
                examples: ["Radio intercepts", "Phone calls", "Email/chat", "Data links"],
                color: "#8b5cf6",
              },
              {
                term: "ELINT",
                full: "Electronic Intelligence",
                description: "Intelligence from non-communication electronic emissions, primarily radar and electronic warfare systems. Critical for understanding adversary air defense and weapon systems.",
                examples: ["Radar signatures", "Navigation beacons", "Jamming signals", "Guidance systems"],
                color: "#3b82f6",
              },
              {
                term: "FISINT",
                full: "Foreign Instrumentation Signals Intelligence",
                description: "Intelligence from foreign aerospace, surface, and subsurface systems. Focuses on telemetry from missile tests, satellite operations, and weapons development.",
                examples: ["Missile telemetry", "Satellite signals", "Test range data", "Space launches"],
                color: "#06b6d4",
              },
              {
                term: "MASINT",
                full: "Measurement and Signature Intelligence",
                description: "Intelligence from analysis of physical phenomena and signatures. Includes radar intelligence (RADINT), nuclear intelligence (NUCINT), and unintentional radiation exploitation.",
                examples: ["RF fingerprinting", "Radar imaging", "Nuclear detection", "Acoustic signatures"],
                color: "#10b981",
              },
            ].map((concept) => (
              <Grid item xs={12} md={6} key={concept.term}>
                <Paper sx={{ p: 3, height: "100%", border: `1px solid ${alpha(concept.color, 0.3)}`, bgcolor: alpha(concept.color, 0.02) }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: concept.color, mb: 0.5 }}>{concept.term}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                    {concept.full}
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>{concept.description}</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {concept.examples.map((ex) => (
                      <Chip key={ex} label={ex} size="small" sx={{ bgcolor: alpha(concept.color, 0.1), fontSize: "0.7rem" }} />
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="info" sx={{ mt: 3 }}>
            <Typography variant="body2">
              <strong>Modern Challenges:</strong> The proliferation of encryption, the explosion of communications volume, and 
              the increasing sophistication of adversary operational security (OPSEC) have transformed SIGINT from a relatively 
              straightforward intercept discipline into a complex technical challenge requiring advanced signal processing, 
              cryptanalysis, and data analytics capabilities.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== EW FUNDAMENTALS ==================== */}
        <Paper
          id="ew-fundamentals"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#ef4444", 0.08)} 0%, ${alpha("#f59e0b", 0.05)} 100%)`,
            border: `1px solid ${alpha("#ef4444", 0.25)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <BoltIcon sx={{ color: "#ef4444" }} />
            Electronic Warfare (EW) Fundamentals
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            <strong>Electronic Warfare (EW)</strong> encompasses all military actions involving the use of electromagnetic energy 
            and directed energy to control the electromagnetic spectrum or to attack an enemy. EW is divided into three primary 
            components: Electronic Attack (EA), Electronic Protection (EP), and Electronic Warfare Support (ES). Understanding 
            these pillars is essential for anyone working in signals intelligence, as they define both the offensive and 
            defensive dimensions of electromagnetic spectrum operations.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            The electromagnetic spectrum has become as critical a domain of warfare as land, sea, air, and space. Modern military 
            operations are completely dependent on the spectrum—for communications, navigation, targeting, and intelligence. 
            Control of the spectrum can determine the outcome of battles; denial of spectrum access can render sophisticated 
            weapons systems useless. This reality has driven continuous advancement in both EW attack and protection capabilities, 
            creating an ongoing technical arms race.
          </Typography>

          <Tabs
            value={ewTab}
            onChange={(_, v) => setEwTab(v)}
            sx={{ borderBottom: 1, borderColor: "divider", mb: 3 }}
          >
            {EW_COMPONENTS.map((comp, idx) => (
              <Tab
                key={comp.name}
                label={comp.name.split(" (")[0]}
                sx={{ color: comp.color }}
              />
            ))}
          </Tabs>

          {EW_COMPONENTS.map((comp, idx) => (
            <TabPanel key={comp.name} value={ewTab} index={idx}>
              <Box sx={{ mb: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: comp.color, mb: 1 }}>
                  {comp.name}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 2 }}>
                  Also known as: {comp.aka}
                </Typography>
                <Typography variant="body1" sx={{ mb: 3 }}>
                  {comp.description}
                </Typography>

                <Grid container spacing={3}>
                  {comp.subcategories.map((sub) => (
                    <Grid item xs={12} md={4} key={sub.name}>
                      <Card sx={{ height: "100%", bgcolor: alpha(comp.color, 0.03), border: `1px solid ${alpha(comp.color, 0.2)}` }}>
                        <CardContent>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>{sub.name}</Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                            {sub.description}
                          </Typography>
                          <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5 }}>Examples:</Typography>
                          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                            {sub.examples.map((ex) => (
                              <Chip key={ex} label={ex} size="small" variant="outlined" sx={{ fontSize: "0.65rem", height: 22 }} />
                            ))}
                          </Box>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Box>
            </TabPanel>
          ))}

          <Alert severity="warning" sx={{ mt: 2 }}>
            <Typography variant="body2">
              <strong>Legal Notice:</strong> Electronic Attack capabilities (jamming, spoofing) are strictly controlled and 
              generally illegal for civilian use. Study these concepts for defensive awareness and academic understanding only.
              Unauthorized jamming can endanger lives and carries severe criminal penalties.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== COMINT DEEP DIVE ==================== */}
        <Paper
          id="comint-deep-dive"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.08)} 0%, ${alpha("#6366f1", 0.05)} 100%)`,
            border: `1px solid ${alpha("#8b5cf6", 0.25)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <PeopleIcon sx={{ color: "#8b5cf6" }} />
            COMINT Deep Dive: The Intelligence Cycle
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            <strong>Communications Intelligence (COMINT)</strong> is arguably the most valuable SIGINT sub-discipline because 
            it provides direct access to what adversaries are saying and thinking. From intercepted radio communications that 
            revealed enemy intentions in World War II to modern digital communications analysis, COMINT has repeatedly proven 
            decisive in military and intelligence operations. The COMINT process follows a structured methodology that transforms 
            raw intercepted signals into actionable intelligence.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            The modern COMINT environment presents unprecedented challenges. The volume of global communications has exploded 
            exponentially, making collection and processing increasingly difficult. End-to-end encryption has become the default 
            for many communication platforms, limiting access to content. Adversaries have become more sophisticated in their 
            operational security, using encrypted messaging, avoiding patterns, and employing counter-surveillance techniques. 
            Despite these challenges, COMINT remains essential because metadata—the information about communications rather than 
            content—often reveals as much as the content itself.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 3 }}>The COMINT Analysis Cycle</Typography>

          <Grid container spacing={3}>
            {COMINT_METHODOLOGY.map((phase, idx) => (
              <Grid item xs={12} md={6} key={phase.phase}>
                <Card
                  sx={{
                    height: "100%",
                    bgcolor: alpha(phase.color, 0.03),
                    border: `1px solid ${alpha(phase.color, 0.25)}`,
                    position: "relative",
                    overflow: "visible",
                  }}
                >
                  <Box
                    sx={{
                      position: "absolute",
                      top: -15,
                      left: 20,
                      width: 30,
                      height: 30,
                      borderRadius: "50%",
                      bgcolor: phase.color,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: "white",
                      fontWeight: 700,
                      fontSize: "0.9rem",
                      boxShadow: `0 4px 12px ${alpha(phase.color, 0.4)}`,
                    }}
                  >
                    {idx + 1}
                  </Box>
                  <CardContent sx={{ pt: 3 }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: phase.color, mb: 1 }}>
                      {phase.phase}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {phase.description}
                    </Typography>
                    <Divider sx={{ my: 1.5 }} />
                    <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 1 }}>Key Activities:</Typography>
                    <List dense disablePadding>
                      {phase.activities.map((activity, aidx) => (
                        <ListItem key={aidx} disableGutters sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 20 }}>
                            <CheckCircleIcon sx={{ fontSize: 12, color: phase.color }} />
                          </ListItemIcon>
                          <ListItemText primary={activity} primaryTypographyProps={{ variant: "caption" }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Alert severity="info" sx={{ mt: 3 }}>
            <Typography variant="body2">
              <strong>From Tactical to Strategic:</strong> COMINT operates at multiple levels. Tactical COMINT supports 
              immediate military operations, often in near-real-time. Operational COMINT supports campaign planning and 
              force disposition. Strategic COMINT addresses national-level intelligence requirements, often involving 
              long-term analysis and pattern recognition.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== ELINT & RADAR INTELLIGENCE ==================== */}
        <Paper
          id="elint-radar"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.08)} 0%, ${alpha("#0891b2", 0.05)} 100%)`,
            border: `1px solid ${alpha("#06b6d4", 0.25)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <RadarIcon sx={{ color: "#06b6d4" }} />
            ELINT & Radar Intelligence
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            <strong>Electronic Intelligence (ELINT)</strong> focuses on non-communication electromagnetic emissions, with 
            radar systems being the primary target. Understanding enemy radar capabilities is critical for military planning—it 
            determines how aircraft can approach targets, how ships can operate, and how ground forces can maneuver. ELINT 
            collection and analysis has been a crucial intelligence discipline since World War II, when understanding German 
            radar systems was essential for Allied bombing campaigns.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            Radar ELINT involves intercepting, recording, and analyzing radar emissions to characterize system capabilities, 
            identify specific emitter types, and develop countermeasures. Every radar system has a unique "fingerprint" 
            determined by its technical parameters—pulse characteristics, frequency, scan patterns, and signal processing. 
            By cataloging these fingerprints, analysts can identify specific radar types, determine their capabilities, and 
            even track individual systems as they move.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            Modern radar systems present significant ELINT challenges. Low Probability of Intercept (LPI) radars use techniques 
            like frequency agility, pulse compression, and power management to make detection difficult. Active Electronically 
            Scanned Arrays (AESA) can rapidly change frequency and beam direction, complicating interception. Despite these 
            challenges, ELINT remains essential because radar emissions are difficult to completely hide—radars must emit 
            energy to function.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 3 }}>Key Radar Parameters for ELINT Analysis</Typography>

          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: "transparent" }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700, width: "20%" }}>Parameter</TableCell>
                  <TableCell sx={{ fontWeight: 700, width: "35%" }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700, width: "30%" }}>Intelligence Significance</TableCell>
                  <TableCell sx={{ fontWeight: 700, width: "15%" }}>Typical Values</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {ELINT_PARAMETERS.map((param) => (
                  <TableRow key={param.parameter} hover>
                    <TableCell sx={{ fontWeight: 600, color: "#06b6d4" }}>{param.parameter}</TableCell>
                    <TableCell>{param.description}</TableCell>
                    <TableCell><Typography variant="body2" color="text.secondary">{param.significance}</Typography></TableCell>
                    <TableCell><Typography variant="caption" sx={{ fontFamily: "monospace" }}>{param.typical}</Typography></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.2)}`, height: "100%" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 2 }}>Radar Types by Function</Typography>
                <List dense disablePadding>
                  {[
                    { type: "Early Warning", desc: "Long-range surveillance, low PRF, L/S-band", examples: "AN/FPS-117, P-18" },
                    { type: "Acquisition/GCI", desc: "Medium range, target assignment", examples: "AN/TPS-77, Bar Lock" },
                    { type: "Fire Control", desc: "High accuracy tracking, X/Ku-band", examples: "AN/TPQ-36, Flap Lid" },
                    { type: "Missile Guidance", desc: "Terminal guidance, very narrow beam", examples: "Straight Flush, Hot Shot" },
                    { type: "Airborne Intercept", desc: "Fighter radar, multi-mode", examples: "AN/APG-77, N011M" },
                  ].map((radar) => (
                    <ListItem key={radar.type} disableGutters sx={{ flexDirection: "column", alignItems: "flex-start", mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{radar.type}</Typography>
                      <Typography variant="caption" color="text.secondary">{radar.desc}</Typography>
                      <Typography variant="caption" sx={{ fontStyle: "italic" }}>Examples: {radar.examples}</Typography>
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.2)}`, height: "100%" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>ELINT Analysis Process</Typography>
                <List dense disablePadding>
                  {[
                    "Intercept and record raw RF emissions",
                    "Measure pulse parameters (PW, PRF, RF, scan)",
                    "Search emitter databases for matches",
                    "Characterize unknown emitters",
                    "Geolocate emitter position",
                    "Correlate with other intelligence",
                    "Update Electronic Order of Battle (EOB)",
                    "Develop countermeasures/tactics",
                  ].map((step, idx) => (
                    <ListItem key={idx} disableGutters>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <Typography variant="caption" sx={{ fontWeight: 700, color: "#f59e0b" }}>{idx + 1}.</Typography>
                      </ListItemIcon>
                      <ListItemText primary={step} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== DIRECTION FINDING ==================== */}
        <Paper
          id="direction-finding"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#10b981", 0.08)} 0%, ${alpha("#059669", 0.05)} 100%)`,
            border: `1px solid ${alpha("#10b981", 0.25)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <ExploreIcon sx={{ color: "#10b981" }} />
            Direction Finding (DF) & Geolocation
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            <strong>Direction Finding (DF)</strong> is the art and science of determining the direction from which a radio 
            signal originates. When multiple DF stations work together, they can triangulate the actual position of a transmitter 
            through a process called <strong>geolocation</strong>. DF has been a critical SIGINT capability since World War I, 
            when it was used to locate enemy radio stations. Today, DF techniques range from simple amplitude comparison to 
            sophisticated multi-platform systems using advanced signal processing.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            The importance of geolocation cannot be overstated. Knowing what an adversary is communicating is valuable; knowing 
            where they are communicating from transforms that intelligence into actionable targeting data. During World War II, 
            High-Frequency Direction Finding (HF/DF, pronounced "Huff-Duff") was crucial in locating German U-boats, contributing 
            significantly to winning the Battle of the Atlantic. Modern DF systems can locate cell phones, radios, and even 
            brief digital transmissions with remarkable precision.
          </Typography>

          <Typography variant="body1" sx={{ mb: 4 }}>
            Modern geolocation systems often combine multiple techniques—TDOA and FDOA, for example—to improve accuracy and 
            work with increasingly brief and frequency-agile signals. The proliferation of GPS and network timing has enabled 
            precise synchronization between geographically distributed receivers, dramatically improving TDOA accuracy. 
            Space-based SIGINT systems can geolocate emitters globally using combinations of these techniques.
          </Typography>

          <Grid container spacing={3}>
            {DF_TECHNIQUES.map((tech) => (
              <Grid item xs={12} md={6} key={tech.technique}>
                <Card sx={{ height: "100%", border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>
                      {tech.technique}
                    </Typography>
                    <Chip label={`Accuracy: ${tech.accuracy}`} size="small" sx={{ mb: 2, bgcolor: alpha("#10b981", 0.1) }} />
                    
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {tech.description}
                    </Typography>

                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="caption" sx={{ fontWeight: 600, color: "#10b981", display: "block", mb: 0.5 }}>
                          Advantages:
                        </Typography>
                        <List dense disablePadding>
                          {tech.advantages.map((adv, idx) => (
                            <ListItem key={idx} disableGutters sx={{ py: 0.1 }}>
                              <ListItemIcon sx={{ minWidth: 16 }}>
                                <CheckCircleIcon sx={{ fontSize: 10, color: "#10b981" }} />
                              </ListItemIcon>
                              <ListItemText primary={adv} primaryTypographyProps={{ variant: "caption" }} />
                            </ListItem>
                          ))}
                        </List>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" sx={{ fontWeight: 600, color: "#ef4444", display: "block", mb: 0.5 }}>
                          Limitations:
                        </Typography>
                        <List dense disablePadding>
                          {tech.limitations.map((lim, idx) => (
                            <ListItem key={idx} disableGutters sx={{ py: 0.1 }}>
                              <ListItemIcon sx={{ minWidth: 16 }}>
                                <WarningIcon sx={{ fontSize: 10, color: "#ef4444" }} />
                              </ListItemIcon>
                              <ListItemText primary={lim} primaryTypographyProps={{ variant: "caption" }} />
                            </ListItem>
                          ))}
                        </List>
                      </Grid>
                    </Grid>

                    <Divider sx={{ my: 1.5 }} />
                    <Typography variant="caption" sx={{ fontWeight: 600 }}>Applications: </Typography>
                    <Typography variant="caption" color="text.secondary">{tech.applications.join(", ")}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== TRAFFIC ANALYSIS ==================== */}
        <Paper
          id="traffic-analysis"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.08)} 0%, ${alpha("#d97706", 0.05)} 100%)`,
            border: `1px solid ${alpha("#f59e0b", 0.25)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <AssessmentIcon sx={{ color: "#f59e0b" }} />
            Traffic Analysis: Intelligence Without Content
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            <strong>Traffic Analysis (TA)</strong> is the discipline of deriving intelligence from the external characteristics 
            of communications without accessing the content itself. Even when communications are encrypted—making the content 
            unreadable—the metadata reveals valuable intelligence: who is communicating with whom, when, how often, and for 
            how long. Traffic analysis has been a critical intelligence technique since before electronic communications, 
            when analysts would study the patterns of messenger traffic.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            The power of traffic analysis lies in what patterns reveal. A sudden increase in communications between military 
            headquarters and field units might indicate an impending operation. Changes in call signs or communication protocols 
            might signal organizational changes. The timing of communications relative to known events can confirm relationships 
            and identify key decision-makers. During World War II, traffic analysis of encrypted German communications provided 
            valuable intelligence even before Enigma was broken.
          </Typography>

          <Typography variant="body1" sx={{ mb: 4 }}>
            Modern traffic analysis has become even more powerful with advances in data analytics and machine learning. 
            Social network analysis techniques can map complex relationship networks from communication patterns. Anomaly 
            detection algorithms can identify significant changes in behavior. Correlation with other data sources—imagery, 
            HUMINT, open source—can provide context that makes traffic analysis findings actionable. In an era of widespread 
            encryption, traffic analysis has regained importance as a primary intelligence source.
          </Typography>

          <Grid container spacing={3}>
            {TRAFFIC_ANALYSIS_CONCEPTS.map((concept) => (
              <Grid item xs={12} md={6} key={concept.concept}>
                <Card sx={{ height: "100%", border: `1px solid ${alpha("#f59e0b", 0.2)}`, bgcolor: alpha("#f59e0b", 0.02) }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>
                      {concept.concept}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {concept.description}
                    </Typography>

                    <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5 }}>Techniques:</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                      {concept.techniques.map((tech) => (
                        <Chip key={tech} label={tech} size="small" variant="outlined" sx={{ fontSize: "0.65rem", height: 22 }} />
                      ))}
                    </Box>

                    <Paper sx={{ p: 1.5, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                      <Typography variant="caption" sx={{ fontWeight: 600, color: "#10b981" }}>Intelligence Value: </Typography>
                      <Typography variant="caption">{concept.intelligence_value}</Typography>
                    </Paper>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Alert severity="success" sx={{ mt: 3 }}>
            <Typography variant="body2">
              <strong>Metadata Matters:</strong> "We kill people based on metadata" - former NSA/CIA director Michael Hayden. 
              This stark statement underscores the operational value of traffic analysis. Even without content, patterns of 
              communication can reveal networks, identify targets, and support operations.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== SIGINT HISTORY ==================== */}
        <Accordion id="sigint-history" sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <HistoryIcon sx={{ color: "#8b5cf6" }} />
              Historical Evolution of SIGINT
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body1" sx={{ mb: 3 }}>
              Understanding SIGINT's history provides essential context for modern capabilities and challenges. From the 
              first radio intercepts to today's global surveillance networks, SIGINT has continuously evolved in response 
              to technological change and operational requirements.
            </Typography>

            <Grid container spacing={3}>
              {SIGINT_HISTORY.map((era) => (
                <Grid item xs={12} md={6} key={era.era}>
                  <Paper sx={{ p: 3, height: "100%", border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>{era.era}</Typography>
                    <List dense disablePadding>
                      {era.developments.map((dev, idx) => (
                        <ListItem key={idx} disableGutters sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 20 }}>
                            <CheckCircleIcon sx={{ fontSize: 12, color: "#8b5cf6" }} />
                          </ListItemIcon>
                          <ListItemText primary={dev} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                    <Divider sx={{ my: 1.5 }} />
                    <Typography variant="caption" sx={{ fontStyle: "italic", color: "text.secondary" }}>
                      {era.significance}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* ==================== SIGINT PLATFORMS ==================== */}
        <Paper
          id="sigint-platforms"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.08)} 0%, ${alpha("#1d4ed8", 0.05)} 100%)`,
            border: `1px solid ${alpha("#3b82f6", 0.25)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SatelliteAltIcon sx={{ color: "#3b82f6" }} />
            SIGINT Collection Platforms
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            SIGINT collection requires specialized platforms designed to intercept electromagnetic emissions across the spectrum. 
            These platforms range from fixed ground installations with massive antenna arrays to satellites orbiting hundreds of 
            miles above Earth. Each platform type offers different capabilities and trade-offs in terms of coverage, persistence, 
            access, and vulnerability.
          </Typography>

          <Typography variant="body1" sx={{ mb: 4 }}>
            The choice of collection platform depends on the target, the required persistence, and the operational environment. 
            Ground-based systems provide continuous coverage of fixed areas; airborne systems offer flexibility and can access 
            line-of-sight targets; space-based systems provide global coverage but with orbital constraints. Modern SIGINT 
            operations typically employ multi-INT architectures that combine platforms to achieve comprehensive coverage.
          </Typography>

          <Grid container spacing={3}>
            {SIGINT_PLATFORMS.map((platform) => (
              <Grid item xs={12} md={6} key={platform.type}>
                <Card sx={{ height: "100%", border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                      {platform.type}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {platform.description}
                    </Typography>

                    <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5 }}>Examples:</Typography>
                    <Typography variant="body2" sx={{ mb: 2, fontStyle: "italic" }}>{platform.examples.join(", ")}</Typography>

                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Paper sx={{ p: 1.5, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
                          <Typography variant="caption" sx={{ fontWeight: 600, color: "#10b981", display: "block", mb: 0.5 }}>
                            Capabilities:
                          </Typography>
                          {platform.capabilities.map((cap, idx) => (
                            <Typography key={idx} variant="caption" sx={{ display: "block" }}>• {cap}</Typography>
                          ))}
                        </Paper>
                      </Grid>
                      <Grid item xs={6}>
                        <Paper sx={{ p: 1.5, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
                          <Typography variant="caption" sx={{ fontWeight: 600, color: "#ef4444", display: "block", mb: 0.5 }}>
                            Limitations:
                          </Typography>
                          {platform.limitations.map((lim, idx) => (
                            <Typography key={idx} variant="caption" sx={{ display: "block" }}>• {lim}</Typography>
                          ))}
                        </Paper>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== SPECTRUM OPERATIONS ==================== */}
        <Paper
          id="spectrum-ops"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.08)} 0%, ${alpha("#ef4444", 0.05)} 100%)`,
            border: `1px solid ${alpha("#f59e0b", 0.25)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TrackChangesIcon sx={{ color: "#f59e0b" }} />
            Spectrum Operations & Electromagnetic Battle Management
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            <strong>Electromagnetic Spectrum Operations (EMSO)</strong> encompasses the coordinated military actions to exploit, 
            attack, protect, and manage the electromagnetic environment. In modern warfare, control of the electromagnetic 
            spectrum can be as decisive as control of terrain, airspace, or maritime approaches. The spectrum has become a 
            contested domain where adversaries compete for advantage through electronic attack, protection, and intelligence.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            <strong>Electromagnetic Battle Management (EMBM)</strong> is the dynamic coordination and integration of joint 
            electromagnetic spectrum operations across all three EW functions (EA, EP, ES) while integrating with cyberspace 
            operations, SIGINT, and kinetic operations. EMBM ensures that friendly use of the spectrum is protected while 
            denying effective use to adversaries. This requires real-time spectrum awareness, rapid decision-making, and 
            sophisticated command and control systems.
          </Typography>

          <Typography variant="body1" sx={{ mb: 4 }}>
            Modern spectrum operations face unique challenges. The proliferation of wireless devices has made the spectrum 
            increasingly congested, complicating both signal detection and spectrum management. Adversary systems employ 
            sophisticated Low Probability of Intercept (LPI) and Low Probability of Detection (LPD) techniques. Cognitive 
            and adaptive systems can automatically change frequency, power, and waveform to evade detection or maintain 
            communications through jamming. Effective spectrum operations require continuous monitoring, analysis, and 
            adaptation.
          </Typography>

          <Grid container spacing={3}>
            {SPECTRUM_OPERATIONS.map((op) => (
              <Grid item xs={12} md={4} key={op.operation}>
                <Card sx={{ height: "100%", border: `1px solid ${alpha(op.color, 0.3)}`, bgcolor: alpha(op.color, 0.02) }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: op.color, mb: 1 }}>
                      {op.operation}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {op.description}
                    </Typography>
                    
                    <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5 }}>Key Functions:</Typography>
                    <List dense disablePadding>
                      {op.functions.map((func, idx) => (
                        <ListItem key={idx} disableGutters sx={{ py: 0.1 }}>
                          <ListItemIcon sx={{ minWidth: 16 }}>
                            <CheckCircleIcon sx={{ fontSize: 10, color: op.color }} />
                          </ListItemIcon>
                          <ListItemText primary={func} primaryTypographyProps={{ variant: "caption" }} />
                        </ListItem>
                      ))}
                    </List>

                    <Divider sx={{ my: 1.5 }} />
                    <Typography variant="caption" sx={{ fontWeight: 600 }}>Tools: </Typography>
                    <Typography variant="caption" color="text.secondary">{op.tools.join(", ")}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Box sx={{ mt: 4 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>The Spectrum Kill Chain</Typography>
            <Paper sx={{ p: 3, bgcolor: "background.paper" }}>
              <Grid container spacing={1} alignItems="center">
                {[
                  { step: "Detect", desc: "Identify emissions of interest", icon: "🔍" },
                  { step: "Locate", desc: "Geolocate the emitter", icon: "📍" },
                  { step: "Identify", desc: "Characterize & classify", icon: "🏷️" },
                  { step: "Track", desc: "Maintain awareness", icon: "📡" },
                  { step: "Target", desc: "EA or kinetic targeting", icon: "🎯" },
                  { step: "Assess", desc: "Evaluate effectiveness", icon: "📊" },
                ].map((item, idx, arr) => (
                  <React.Fragment key={item.step}>
                    <Grid item xs={6} sm={4} md={2}>
                      <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                        <Typography variant="h5" sx={{ mb: 0.5 }}>{item.icon}</Typography>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>{item.step}</Typography>
                        <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                      </Paper>
                    </Grid>
                  </React.Fragment>
                ))}
              </Grid>
            </Paper>
          </Box>
        </Paper>

        {/* ==================== COUNTER-SIGINT ==================== */}
        <Accordion id="counter-sigint" sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <SecurityIcon sx={{ color: "#ef4444" }} />
              Counter-SIGINT & Operational Security
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body1" sx={{ mb: 3 }}>
              <strong>Counter-SIGINT (C-SIGINT)</strong> encompasses measures taken to deny or degrade adversary SIGINT 
              operations. Understanding C-SIGINT is essential both for developing effective collection strategies (anticipating 
              target countermeasures) and for protecting friendly communications and electronic emissions from hostile exploitation.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3 }}>
              Effective C-SIGINT requires understanding how SIGINT systems work and exploiting their limitations. Collection 
              systems have finite sensitivity, bandwidth, and processing capacity. Analysts have limited time and attention. 
              By operating within these constraints—using low power, brief transmissions, spread spectrum, or encrypted 
              communications—targets can significantly reduce their SIGINT signature.
            </Typography>

            <Grid container spacing={3}>
              {[
                {
                  title: "COMSEC (Communications Security)",
                  items: ["End-to-end encryption", "Frequency hopping", "Spread spectrum", "Burst transmission", "Traffic flow security"],
                  color: "#8b5cf6",
                },
                {
                  title: "EMSEC (Emission Security)",
                  items: ["TEMPEST shielding", "Power control", "Directional antennas", "Minimize transmission time", "Spectrum discipline"],
                  color: "#3b82f6",
                },
                {
                  title: "OPSEC (Operational Security)",
                  items: ["Need-to-know", "Procedural controls", "Cover & deception", "Pattern avoidance", "Secure planning"],
                  color: "#10b981",
                },
                {
                  title: "Active Countermeasures",
                  items: ["Jamming (self-protect)", "Deception emissions", "Decoys", "Electronic feints", "Frequency management"],
                  color: "#f59e0b",
                },
              ].map((cat) => (
                <Grid item xs={12} md={6} key={cat.title}>
                  <Paper sx={{ p: 3, height: "100%", border: `1px solid ${alpha(cat.color, 0.25)}`, bgcolor: alpha(cat.color, 0.03) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: cat.color, mb: 2 }}>{cat.title}</Typography>
                    <List dense disablePadding>
                      {cat.items.map((item, idx) => (
                        <ListItem key={idx} disableGutters sx={{ py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 20 }}>
                            <CheckCircleIcon sx={{ fontSize: 12, color: cat.color }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Alert severity="info" sx={{ mt: 3 }}>
              <Typography variant="body2">
                <strong>The SIGINT/C-SIGINT Arms Race:</strong> Every advance in collection capability drives development of 
                new countermeasures, which in turn drives new collection techniques. This dynamic has accelerated in the 
                digital age, with encryption becoming widespread and cognitive/AI systems enabling rapid adaptation on both sides.
              </Typography>
            </Alert>
          </AccordionDetails>
        </Accordion>

        {/* ==================== WHAT IS SDR ==================== */}
        <Paper id="what-is-sdr" sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <InfoIcon sx={{ color: "#8b5cf6" }} />
            What is Software Defined Radio?
          </Typography>
          
          <Typography variant="body1" sx={{ mb: 3 }}>
            Traditional radios use hardware components (filters, mixers, amplifiers) tuned for specific frequencies and modulations.
            <strong> Software Defined Radio (SDR)</strong> replaces these with software, allowing a single device to receive and
            transmit across a wide frequency range with any modulation type. This flexibility has democratized access to radio 
            technology that was once the exclusive domain of military and intelligence agencies.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            The SDR revolution began in the 1990s with military research into flexible radio systems that could be reconfigured 
            in software. The release of inexpensive DVB-T dongles (RTL-SDR) in 2012, which could be repurposed as general-purpose 
            SDR receivers, sparked an explosion of civilian interest in radio experimentation. Today, SDR technology underpins 
            everything from cellular base stations to amateur radio experimentation to security research.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3 }}>
            For security researchers and intelligence professionals, SDR provides unprecedented capability to analyze the 
            electromagnetic spectrum. The same receiver can tune from HF radio bands through microwave frequencies, switching 
            between analog voice, digital protocols, and radar signals. Combined with powerful signal processing software, 
            SDR enables analysis that once required millions of dollars in specialized equipment.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>
                  How SDR Works
                </Typography>
                <List dense disablePadding>
                  {[
                    "Antenna captures RF signals across wide bandwidth",
                    "ADC (Analog-to-Digital Converter) digitizes the signal",
                    "Digital samples sent to computer via USB",
                    "Software processes, filters, and demodulates",
                    "Output: audio, data, or protocol decode",
                  ].map((step, idx) => (
                    <ListItem key={idx} disableGutters>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <Typography variant="body2" sx={{ fontWeight: 700, color: "#10b981" }}>{idx + 1}.</Typography>
                      </ListItemIcon>
                      <ListItemText primary={step} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                  Why SDR for Security Research?
                </Typography>
                <List dense disablePadding>
                  {[
                    "Analyze proprietary wireless protocols",
                    "Reverse engineer unknown signals",
                    "Test RF security of IoT devices",
                    "Research automotive key fob security",
                    "Capture and replay wireless transmissions",
                    "Build custom receivers/transmitters",
                  ].map((item, idx) => (
                    <ListItem key={idx} disableGutters>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== SDR HARDWARE ==================== */}
        <Paper id="hardware" sx={{ p: 4, mb: 4, borderRadius: 3 }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <MemoryIcon sx={{ color: "#8b5cf6" }} />
            SDR Hardware Comparison
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Choose the right SDR for your budget and use case. Start with RTL-SDR to learn, upgrade as needed.
          </Typography>
          
          <Typography variant="body1" sx={{ mb: 3 }}>
            The SDR hardware landscape ranges from $25 USB dongles suitable for beginners to multi-thousand dollar professional 
            systems used in research labs and military applications. The key specifications to consider are frequency range 
            (what signals you can receive), bandwidth (how much spectrum you can capture simultaneously), ADC resolution 
            (dynamic range and sensitivity), and transmit capability (receive-only vs. transceiver).
          </Typography>

          <Grid container spacing={3}>
            {SDR_HARDWARE.map((sdr) => (
              <Grid item xs={12} md={6} key={sdr.name}>
                <Card
                  sx={{
                    height: "100%",
                    borderRadius: 3,
                    border: `1px solid ${alpha(sdr.color, 0.3)}`,
                    transition: "all 0.3s ease",
                    "&:hover": {
                      transform: "translateY(-4px)",
                      boxShadow: `0 8px 30px ${alpha(sdr.color, 0.2)}`,
                    },
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 2 }}>
                      <Typography variant="h6" sx={{ fontWeight: 700 }}>
                        {sdr.name}
                      </Typography>
                      <Chip
                        icon={<AttachMoneyIcon sx={{ fontSize: 16 }} />}
                        label={sdr.price}
                        size="small"
                        sx={{ bgcolor: alpha(sdr.color, 0.1), color: sdr.color, fontWeight: 600 }}
                      />
                    </Box>

                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {sdr.description}
                    </Typography>

                    <Grid container spacing={1} sx={{ mb: 2 }}>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="text.secondary">Frequency:</Typography>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>{sdr.frequency}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="text.secondary">Bandwidth:</Typography>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>{sdr.bandwidth}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="text.secondary">ADC:</Typography>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>{sdr.bits}</Typography>
                      </Grid>
                    </Grid>

                    <Divider sx={{ my: 1.5 }} />

                    <Box sx={{ mb: 1 }}>
                      <Typography variant="caption" sx={{ fontWeight: 600, color: "#10b981" }}>Pros:</Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                        {sdr.pros.slice(0, 3).map((pro) => (
                          <Chip key={pro} label={pro} size="small" sx={{ fontSize: "0.65rem", height: 20, bgcolor: alpha("#10b981", 0.1) }} />
                        ))}
                      </Box>
                    </Box>

                    <Box sx={{ mb: 1 }}>
                      <Typography variant="caption" sx={{ fontWeight: 600, color: "#ef4444" }}>Cons:</Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                        {sdr.cons.slice(0, 2).map((con) => (
                          <Chip key={con} label={con} size="small" sx={{ fontSize: "0.65rem", height: 20, bgcolor: alpha("#ef4444", 0.1) }} />
                        ))}
                      </Box>
                    </Box>

                    <Box>
                      <Typography variant="caption" sx={{ fontWeight: 600, color: sdr.color }}>Best For:</Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                        {sdr.bestFor.map((use) => (
                          <Chip key={use} label={use} size="small" variant="outlined" sx={{ fontSize: "0.65rem", height: 20 }} />
                        ))}
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Alert severity="info" sx={{ mt: 3 }}>
            <Typography variant="body2">
              <strong>Recommendation:</strong> Start with an RTL-SDR v3/v4 (~$30). It covers most beginner projects and has
              excellent community support. Upgrade to HackRF if you need transmit capability, or LimeSDR for full-duplex research.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== RF FUNDAMENTALS ==================== */}
        <Accordion id="rf-fundamentals" defaultExpanded sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <GraphicEqIcon sx={{ color: "#06b6d4" }} />
              RF Fundamentals
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            {/* Frequency Bands */}
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Frequency Bands</Typography>
            <TableContainer component={Paper} sx={{ mb: 4 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700 }}>Band</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Frequency Range</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Wavelength</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Common Uses</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {FREQUENCY_BANDS.map((band) => (
                    <TableRow key={band.band} hover>
                      <TableCell>
                        <Chip label={band.band} size="small" sx={{ bgcolor: alpha(band.color, 0.2), fontWeight: 600 }} />
                      </TableCell>
                      <TableCell sx={{ fontFamily: "monospace" }}>{band.range}</TableCell>
                      <TableCell>{band.wavelength}</TableCell>
                      <TableCell>{band.uses}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Modulation Types */}
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Modulation Types</Typography>
            <Grid container spacing={2}>
              {MODULATION_TYPES.map((mod) => (
                <Grid item xs={12} sm={6} md={4} key={mod.name}>
                  <Paper sx={{ p: 2, height: "100%", border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>{mod.name}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                      {mod.description}
                    </Typography>
                    <Typography variant="caption" sx={{ fontWeight: 600 }}>Uses: </Typography>
                    <Typography variant="caption" color="text.secondary">{mod.uses.join(", ")}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* ==================== ANTENNAS ==================== */}
        <Accordion id="antennas" sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <SettingsInputAntennaIcon sx={{ color: "#f59e0b" }} />
              Antenna Selection Guide
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body1" sx={{ mb: 3 }}>
              The antenna is often more important than the SDR itself. A good antenna dramatically improves reception.
            </Typography>

            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Gain</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Pattern</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Best Use</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Frequency</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {ANTENNA_TYPES.map((ant) => (
                    <TableRow key={ant.type} hover>
                      <TableCell sx={{ fontWeight: 600 }}>{ant.type}</TableCell>
                      <TableCell>{ant.gain}</TableCell>
                      <TableCell>{ant.pattern}</TableCell>
                      <TableCell>{ant.use}</TableCell>
                      <TableCell>{ant.frequency}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <Alert severity="info" sx={{ mt: 2 }}>
              <Typography variant="body2">
                <strong>Quick Tips:</strong> For general scanning, use a discone or wideband whip. For weak signals,
                use a directional Yagi. For satellites, consider a QFH (Quadrifilar Helix) or turnstile antenna.
              </Typography>
            </Alert>
          </AccordionDetails>
        </Accordion>

        {/* ==================== SDR SOFTWARE ==================== */}
        <Paper id="software" sx={{ p: 4, mb: 4, borderRadius: 3 }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon sx={{ color: "#3b82f6" }} />
            SDR Software Tools
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Essential software for receiving, analyzing, and decoding signals.
          </Typography>

          <Grid container spacing={3}>
            {SDR_SOFTWARE.map((sw) => (
              <Grid item xs={12} sm={6} md={4} key={sw.name}>
                <Card
                  sx={{
                    height: "100%",
                    borderRadius: 2,
                    borderTop: `4px solid ${sw.color}`,
                    transition: "all 0.3s ease",
                    "&:hover": {
                      transform: "translateY(-4px)",
                      boxShadow: `0 8px 30px ${alpha(sw.color, 0.2)}`,
                    },
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{sw.name}</Typography>
                      <Chip label={sw.type} size="small" sx={{ bgcolor: alpha(sw.color, 0.1) }} />
                    </Box>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                      {sw.platform}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {sw.description}
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {sw.features.map((feat) => (
                        <Chip key={feat} label={feat} size="small" variant="outlined" sx={{ fontSize: "0.65rem", height: 20 }} />
                      ))}
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== SIGNAL TARGETS ==================== */}
        <Paper
          id="targets"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#ef4444", 0.05)} 0%, ${alpha("#f59e0b", 0.03)} 100%)`,
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <GppMaybeIcon sx={{ color: "#ef4444" }} />
            Signal Targets for Security Research
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Common RF systems and their security research potential. Always ensure proper authorization.
          </Typography>

          <Tabs
            value={targetsTab}
            onChange={(_, v) => setTargetsTab(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ borderBottom: 1, borderColor: "divider", mb: 2 }}
          >
            {SIGNAL_TARGETS.map((target, idx) => (
              <Tab key={target.category} icon={target.icon} iconPosition="start" label={target.category} />
            ))}
          </Tabs>

          {SIGNAL_TARGETS.map((target, idx) => (
            <TabPanel key={target.category} value={targetsTab} index={idx}>
              <Grid container spacing={2}>
                {target.targets.map((t) => (
                  <Grid item xs={12} sm={6} key={t.name}>
                    <Paper
                      sx={{
                        p: 2,
                        border: `1px solid ${alpha(target.color, 0.2)}`,
                        bgcolor: alpha(target.color, 0.02),
                      }}
                    >
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{t.name}</Typography>
                        <Chip
                          label={`Risk: ${t.risk}`}
                          size="small"
                          sx={{
                            bgcolor: t.risk === "High" ? alpha("#ef4444", 0.1) : t.risk === "Medium" ? alpha("#f59e0b", 0.1) : alpha("#10b981", 0.1),
                            color: t.risk === "High" ? "#ef4444" : t.risk === "Medium" ? "#f59e0b" : "#10b981",
                            fontWeight: 600,
                            fontSize: "0.7rem",
                          }}
                        />
                      </Box>
                      <Typography variant="body2" color="text.secondary">{t.description}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </TabPanel>
          ))}

          <Alert severity="warning" sx={{ mt: 3 }}>
            <Typography variant="body2">
              <strong>Legal Warning:</strong> Only analyze signals you own or have explicit permission to test.
              Intercepting private communications or transmitting without a license is illegal in most jurisdictions.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== RF ATTACKS ==================== */}
        <Paper id="attacks" sx={{ p: 4, mb: 4, borderRadius: 3 }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#dc2626" }} />
            Common RF Attack Techniques
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Understanding attack vectors helps design better defenses. For authorized testing only.
          </Typography>

          <Grid container spacing={3}>
            {RF_ATTACKS.map((attack) => (
              <Grid item xs={12} md={6} key={attack.attack}>
                <Card
                  sx={{
                    height: "100%",
                    borderRadius: 2,
                    border: `1px solid ${alpha(attack.color, 0.3)}`,
                    bgcolor: alpha(attack.color, 0.02),
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{attack.attack}</Typography>
                      <Chip label={attack.difficulty} size="small" sx={{ bgcolor: alpha(attack.color, 0.1) }} />
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {attack.description}
                    </Typography>

                    <Box sx={{ mb: 1 }}>
                      <Typography variant="caption" sx={{ fontWeight: 600 }}>Targets: </Typography>
                      <Typography variant="caption" color="text.secondary">{attack.targets.join(", ")}</Typography>
                    </Box>

                    <Box sx={{ p: 1.5, bgcolor: alpha("#10b981", 0.05), borderRadius: 1, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                      <Typography variant="caption" sx={{ fontWeight: 600, color: "#10b981" }}>Defense: </Typography>
                      <Typography variant="caption">{attack.defense}</Typography>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== SIGINT CONCEPTS ==================== */}
        <Accordion id="sigint" sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <VisibilityIcon sx={{ color: "#8b5cf6" }} />
              SIGINT Concepts
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body1" sx={{ mb: 3 }}>
              Signals Intelligence (SIGINT) is intelligence gathering through interception of signals. Understanding these
              concepts helps in both offensive security research and defensive countermeasures.
            </Typography>

            <Grid container spacing={2}>
              {SIGINT_CONCEPTS.map((concept) => (
                <Grid item xs={12} sm={6} key={concept.term}>
                  <Paper sx={{ p: 2, height: "100%", border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6" }}>{concept.term}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                      {concept.full}
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 1 }}>{concept.description}</Typography>
                    <Typography variant="caption" sx={{ fontWeight: 600 }}>Examples: </Typography>
                    <Typography variant="caption" color="text.secondary">{concept.examples.join(", ")}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* ==================== GNU RADIO ==================== */}
        <Accordion id="gnuradio" sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <HubIcon sx={{ color: "#3b82f6" }} />
              GNU Radio Basics
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body1" sx={{ mb: 3 }}>
              GNU Radio is the most powerful SDR framework. You build signal processing pipelines by connecting blocks
              in a flowgraph. Here are the essential block categories:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {GNU_RADIO_BLOCKS.map((cat) => (
                <Grid item xs={12} sm={6} md={4} key={cat.category}>
                  <Paper sx={{ p: 2, borderLeft: `4px solid ${cat.color}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: cat.color, mb: 1 }}>
                      {cat.category}
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {cat.blocks.map((block) => (
                        <Chip key={block} label={block} size="small" variant="outlined" sx={{ fontSize: "0.65rem", height: 20 }} />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 2, bgcolor: "#1e1e1e" }}>
              <Typography variant="subtitle2" sx={{ color: "#4ec9b0", mb: 1 }}>Example: Simple FM Receiver Flowgraph</Typography>
              <Box component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`RTL-SDR Source (f=100.1e6, sample_rate=2.4e6)
    |
    v
Low Pass Filter (cutoff=100e3, decimation=10)
    |
    v
WBFM Receive (audio_rate=48000)
    |
    v
Multiply Const (volume=0.5)
    |
    v
Audio Sink (sample_rate=48000)`}
              </Box>
            </Paper>

            <Alert severity="info" sx={{ mt: 2 }}>
              <Typography variant="body2">
                <strong>Learning Path:</strong> Start with GNU Radio Companion (GRC) - the visual editor. Build simple receivers
                (FM radio, NOAA satellites) before moving to custom protocol decoding.
              </Typography>
            </Alert>
          </AccordionDetails>
        </Accordion>

        {/* ==================== CLI TOOLS ==================== */}
        <Accordion id="cli-tools" sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <TerminalIcon sx={{ color: "#10b981" }} />
              Command Line Tools
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body1" sx={{ mb: 3 }}>
              Essential command-line tools for SDR capture, processing, and decoding.
            </Typography>

            {CLI_TOOLS.map((tool) => (
              <Paper key={tool.tool} sx={{ p: 2, mb: 2, bgcolor: "#1e1e1e" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#10b981", mb: 0.5 }}>
                  {tool.tool}
                </Typography>
                <Typography variant="caption" sx={{ color: "#808080", display: "block", mb: 1 }}>
                  {tool.description}
                </Typography>
                {tool.commands.map((cmd, idx) => (
                  <Box key={idx} sx={{ mb: 0.5 }}>
                    <Box component="code" sx={{ color: "#d4d4d4", fontFamily: "monospace", fontSize: "0.85rem" }}>
                      $ {cmd}
                    </Box>
                  </Box>
                ))}
              </Paper>
            ))}
          </AccordionDetails>
        </Accordion>

        {/* ==================== BEGINNER PROJECTS ==================== */}
        <Paper id="projects" sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <SchoolIcon sx={{ color: "#10b981" }} />
            Beginner SDR Projects
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Hands-on projects to build your SDR skills. Start with the easiest and work your way up.
          </Typography>

          <Grid container spacing={3}>
            {BEGINNER_PROJECTS.map((project) => (
              <Grid item xs={12} md={6} key={project.name}>
                <Card sx={{ height: "100%", borderRadius: 2, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 2 }}>
                      <Typography variant="h6" sx={{ fontWeight: 700 }}>{project.name}</Typography>
                      <Box sx={{ display: "flex", gap: 0.5 }}>
                        <Chip
                          label={project.difficulty}
                          size="small"
                          sx={{
                            bgcolor: project.difficulty === "Easy" ? alpha("#10b981", 0.1) : alpha("#f59e0b", 0.1),
                            color: project.difficulty === "Easy" ? "#10b981" : "#f59e0b",
                            fontWeight: 600,
                          }}
                        />
                        <Chip label={project.time} size="small" variant="outlined" />
                      </Box>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {project.description}
                    </Typography>
                    <Box sx={{ mb: 1 }}>
                      <Typography variant="caption" sx={{ fontWeight: 600 }}>Frequency: </Typography>
                      <Typography variant="caption" sx={{ fontFamily: "monospace" }}>{project.frequency}</Typography>
                    </Box>
                    <Box sx={{ mb: 1 }}>
                      <Typography variant="caption" sx={{ fontWeight: 600 }}>Software: </Typography>
                      <Typography variant="caption">{project.software}</Typography>
                    </Box>
                    <Divider sx={{ my: 1.5 }} />
                    <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5 }}>Steps:</Typography>
                    <List dense disablePadding>
                      {project.steps.map((step, idx) => (
                        <ListItem key={idx} disableGutters sx={{ py: 0.1 }}>
                          <ListItemIcon sx={{ minWidth: 20 }}>
                            <Typography variant="caption" sx={{ fontWeight: 600, color: "#10b981" }}>{idx + 1}.</Typography>
                          </ListItemIcon>
                          <ListItemText primary={step} primaryTypographyProps={{ variant: "caption" }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== PROTOCOL ANALYSIS ==================== */}
        <Paper id="protocols" sx={{ p: 4, mb: 4, borderRadius: 3 }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <DeviceHubIcon sx={{ color: "#8b5cf6" }} />
            Protocol Analysis Examples
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Common wireless protocols you can analyze with SDR for security research.
          </Typography>

          {PROTOCOL_ANALYSIS.map((proto) => (
            <Accordion key={proto.protocol} sx={{ mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{proto.protocol}</Typography>
                  <Chip label={proto.frequency} size="small" variant="outlined" sx={{ fontFamily: "monospace" }} />
                  <Chip label={proto.modulation} size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1) }} />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ mb: 2 }}>{proto.description}</Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#f59e0b", mb: 1 }}>Security Notes</Typography>
                      <Typography variant="body2">{proto.security}</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#3b82f6", mb: 1 }}>Tools</Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {proto.tools.map((tool) => (
                          <Chip key={tool} label={tool} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                        ))}
                      </Box>
                    </Paper>
                  </Grid>
                </Grid>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mt: 2, mb: 1 }}>Research Areas:</Typography>
                <List dense disablePadding>
                  {proto.research.map((item, idx) => (
                    <ListItem key={idx} disableGutters sx={{ py: 0.1 }}>
                      <ListItemIcon sx={{ minWidth: 20 }}>
                        <CheckCircleIcon sx={{ fontSize: 14, color: "#8b5cf6" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </AccordionDetails>
            </Accordion>
          ))}
        </Paper>

        {/* ==================== SATELLITE FREQUENCIES ==================== */}
        <Paper id="satellites" sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <SatelliteAltIcon sx={{ color: "#06b6d4" }} />
            Satellite Frequency Reference
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Popular satellites you can receive with consumer SDR equipment.
          </Typography>

          <TableContainer component={Paper} sx={{ bgcolor: "transparent" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Satellite</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Frequency</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Mode</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Antenna</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {SATELLITE_FREQUENCIES.map((sat) => (
                  <TableRow key={sat.satellite} hover>
                    <TableCell sx={{ fontWeight: 600 }}>{sat.satellite}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace" }}>{sat.frequency}</TableCell>
                    <TableCell><Chip label={sat.mode} size="small" sx={{ fontSize: "0.7rem" }} /></TableCell>
                    <TableCell>{sat.description}</TableCell>
                    <TableCell>{sat.antenna}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* ==================== LAB SETUP ==================== */}
        <Paper id="lab-setup" sx={{ p: 4, mb: 4, borderRadius: 3 }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <BuildIcon sx={{ color: "#f59e0b" }} />
            RF Lab Setup Guide
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Build your SDR lab based on budget and goals.
          </Typography>

          <Grid container spacing={3}>
            {LAB_SETUP.map((lab) => (
              <Grid item xs={12} md={6} key={lab.level}>
                <Card sx={{ height: "100%", borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>{lab.level}</Typography>
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Equipment:</Typography>
                    <List dense disablePadding>
                      {lab.items.map((item, idx) => (
                        <ListItem key={idx} disableGutters sx={{ py: 0.1 }}>
                          <ListItemIcon sx={{ minWidth: 20 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: "#f59e0b" }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                    <Divider sx={{ my: 1.5 }} />
                    <Typography variant="caption" sx={{ fontWeight: 600 }}>Capabilities: </Typography>
                    <Typography variant="caption" color="text.secondary">{lab.capabilities}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== LEGAL & ETHICS ==================== */}
        <Paper
          id="legal"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.1)} 0%, ${alpha("#ef4444", 0.05)} 100%)`,
            border: `1px solid ${alpha("#f59e0b", 0.3)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <GavelIcon sx={{ color: "#f59e0b" }} />
            Legal Considerations
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            RF research has legal implications. Know the rules before you start.
          </Typography>

          <Grid container spacing={3}>
            {LEGAL_CONSIDERATIONS.map((region) => (
              <Grid item xs={12} md={6} key={region.region}>
                <Paper sx={{ p: 2, height: "100%", borderLeft: `4px solid ${region.color}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: region.color, mb: 1 }}>
                    {region.region}
                  </Typography>
                  <List dense disablePadding>
                    {region.rules.map((rule, idx) => (
                      <ListItem key={idx} disableGutters sx={{ py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <CheckCircleIcon sx={{ fontSize: 14, color: region.color }} />
                        </ListItemIcon>
                        <ListItemText primary={rule} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Research Ethics */}
          <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2 }}>Research Ethics</Typography>
          <Grid container spacing={2}>
            {RESEARCH_ETHICS.map((ethic) => (
              <Grid item xs={12} sm={6} md={4} key={ethic.principle}>
                <Paper sx={{ p: 2, height: "100%", bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 0.5 }}>{ethic.principle}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{ethic.description}</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {ethic.examples.map((ex) => (
                      <Chip key={ex} label={ex} size="small" variant="outlined" sx={{ fontSize: "0.65rem", height: 20 }} />
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="error" sx={{ mt: 3 }}>
            <Typography variant="body2">
              <strong>Important:</strong> Jamming is illegal almost everywhere and can disrupt emergency services.
              Transmitting without a license can result in significant fines. When in doubt, receive only.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== RESOURCES ==================== */}
        <Paper id="resources" sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <MenuBookIcon sx={{ color: "#8b5cf6" }} />
            Learning Resources
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Recommended resources to continue your SDR journey.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, height: "100%", borderLeft: `4px solid #10b981` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>Websites</Typography>
                <List dense disablePadding>
                  {[
                    "rtl-sdr.com - RTL-SDR tutorials & news",
                    "sigidwiki.com - Signal identification database",
                    "sdr-radio.com - SDR software & guides",
                    "arrl.org - Amateur radio resources",
                    "radioreference.com - Frequency database",
                  ].map((item, idx) => (
                    <ListItem key={idx} disableGutters sx={{ py: 0.1 }}>
                      <ListItemIcon sx={{ minWidth: 20 }}>
                        <CheckCircleIcon sx={{ fontSize: 12, color: "#10b981" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, height: "100%", borderLeft: `4px solid #3b82f6` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Books</Typography>
                <List dense disablePadding>
                  {[
                    "Software Defined Radio for Engineers",
                    "ARRL Handbook for Radio Communications",
                    "Practical Signal Processing",
                    "The Art of Electronics",
                    "Field Expedient SDR (free PDF)",
                  ].map((item, idx) => (
                    <ListItem key={idx} disableGutters sx={{ py: 0.1 }}>
                      <ListItemIcon sx={{ minWidth: 20 }}>
                        <CheckCircleIcon sx={{ fontSize: 12, color: "#3b82f6" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, height: "100%", borderLeft: `4px solid #8b5cf6` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>Communities</Typography>
                <List dense disablePadding>
                  {[
                    "r/RTLSDR - Reddit community",
                    "r/amateurradio - Ham radio subreddit",
                    "RTL-SDR Discord server",
                    "GNU Radio mailing list",
                    "SIGINT/ELINT groups",
                  ].map((item, idx) => (
                    <ListItem key={idx} disableGutters sx={{ py: 0.1 }}>
                      <ListItemIcon sx={{ minWidth: 20 }}>
                        <CheckCircleIcon sx={{ fontSize: 12, color: "#8b5cf6" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== GETTING STARTED ==================== */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            background: `linear-gradient(135deg, ${alpha("#10b981", 0.1)} 0%, ${alpha("#059669", 0.05)} 100%)`,
            border: `1px solid ${alpha("#10b981", 0.3)}`,
            borderRadius: 3,
          }}
        >
          <Typography variant="h6" fontWeight={600} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SchoolIcon color="success" />
            Getting Started Checklist
          </Typography>
          <Grid container spacing={2}>
            {[
              "Get an RTL-SDR v3/v4 dongle ($25-40)",
              "Install SDR# (Windows) or GQRX (Linux/Mac)",
              "Listen to FM radio to verify setup works",
              "Explore the frequency spectrum in your area",
              "Try decoding ADS-B aircraft (dump1090)",
              "Receive NOAA weather satellite images",
              "Install Universal Radio Hacker for analysis",
              "Build a simple dipole antenna for a specific frequency",
              "Learn GNU Radio basics with tutorials",
              "Join the RTL-SDR community Discord/Reddit",
              "Study modulation types you encounter",
              "Document interesting signals you find",
            ].map((step, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                  <CheckCircleIcon fontSize="small" color="success" sx={{ mt: 0.25 }} />
                  <Typography variant="body2">{step}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== RELATED RESOURCES ==================== */}
        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, textAlign: "center", bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
          <RadioIcon sx={{ fontSize: 48, color: "#8b5cf6", mb: 2 }} />
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
            Continue Learning
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Explore related topics for RF and wireless security research.
          </Typography>
          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", justifyContent: "center" }}>
            <Button variant="outlined" component={Link} to="/learn/wireless-pentesting">
              Wireless Pentesting
            </Button>
            <Button variant="outlined" component={Link} to="/learn/dmr-hacking">
              DMR Hacking
            </Button>
            <Button variant="outlined" component={Link} to="/learn/counter-uas">
              Counter-UAS & Drones
            </Button>
            <Button variant="outlined" component={Link} to="/learn/arp-dns-poisoning">
              ARP/DNS Poisoning
            </Button>
          </Box>
        </Paper>

        {/* Bottom Navigation */}
        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: sdrTheme.primary, color: sdrTheme.primary }}
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
            sx: { bgcolor: sdrTheme.bgCard, width: 280 },
          }}
        >
          <Box sx={{ p: 2 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
              <Typography variant="subtitle1" sx={{ color: sdrTheme.primary, fontWeight: 600 }}>
                Navigation
              </Typography>
              <IconButton onClick={() => setNavDrawerOpen(false)} sx={{ color: sdrTheme.text }}>
                <CloseIcon />
              </IconButton>
            </Box>
            {/* Progress */}
            <Box sx={{ mb: 2 }}>
              <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
                <Typography variant="caption" sx={{ color: sdrTheme.textMuted }}>
                  Progress
                </Typography>
                <Typography variant="caption" sx={{ fontWeight: 600, color: sdrTheme.primary }}>
                  {Math.round(progressPercent)}%
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={progressPercent}
                sx={{
                  height: 4,
                  borderRadius: 2,
                  bgcolor: alpha(sdrTheme.primary, 0.1),
                  "& .MuiLinearProgress-bar": {
                    bgcolor: sdrTheme.primary,
                    borderRadius: 2,
                  },
                }}
              />
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
                    bgcolor: activeSection === item.id ? alpha(sdrTheme.primary, 0.15) : "transparent",
                    width: "100%",
                    textAlign: "left",
                    "&:hover": {
                      bgcolor: alpha(sdrTheme.primary, 0.1),
                    },
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? sdrTheme.primary : sdrTheme.textMuted }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.label}
                    primaryTypographyProps={{
                      variant: "body2",
                      sx: { 
                        color: activeSection === item.id ? sdrTheme.text : sdrTheme.textMuted,
                        fontWeight: activeSection === item.id ? 600 : 400,
                      },
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
            sx={{ bgcolor: sdrTheme.bgCard, color: sdrTheme.text, "&:hover": { bgcolor: sdrTheme.bgNested } }}
          >
            <KeyboardArrowUpIcon />
          </Fab>
          <Fab
            size="small"
            onClick={() => setNavDrawerOpen(true)}
            sx={{ bgcolor: sdrTheme.primary, color: "white", "&:hover": { bgcolor: sdrTheme.primaryLight } }}
          >
            <RadioIcon />
          </Fab>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
