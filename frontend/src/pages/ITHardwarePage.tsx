import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Container,
  Typography,
  Paper,
  Grid,
  Chip,
  alpha,
  useTheme,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  Button,
  Drawer,
  Fab,
  IconButton,
  Tooltip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  LinearProgress,
  useMediaQuery,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import MemoryIcon from "@mui/icons-material/Memory";
import StorageIcon from "@mui/icons-material/Storage";
import DeveloperBoardIcon from "@mui/icons-material/DeveloperBoard";
import CableIcon from "@mui/icons-material/Cable";
import PowerIcon from "@mui/icons-material/Power";
import ComputerIcon from "@mui/icons-material/Computer";
import PrintIcon from "@mui/icons-material/Print";
import UsbIcon from "@mui/icons-material/Usb";
import SettingsInputHdmiIcon from "@mui/icons-material/SettingsInputHdmi";
import SpeedIcon from "@mui/icons-material/Speed";
import ThermostatIcon from "@mui/icons-material/Thermostat";
import BuildIcon from "@mui/icons-material/Build";
import RouterIcon from "@mui/icons-material/Router";
import MonitorIcon from "@mui/icons-material/Monitor";
import KeyboardIcon from "@mui/icons-material/Keyboard";
import MouseIcon from "@mui/icons-material/Mouse";
import SdStorageIcon from "@mui/icons-material/SdStorage";
import SettingsIcon from "@mui/icons-material/Settings";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import QuizIcon from "@mui/icons-material/Quiz";
import SchoolIcon from "@mui/icons-material/School";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import LaptopIcon from "@mui/icons-material/Laptop";
import { Link, useNavigate } from "react-router-dom";

const ACCENT_COLOR = "#8b5cf6";
const QUIZ_QUESTION_COUNT = 10;

const selectRandomQuestions = (questions: QuizQuestion[], count: number) =>
  [...questions].sort(() => Math.random() - 0.5).slice(0, count);

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "CPU",
    question: "What does CPU stand for?",
    options: ["Central Processing Unit", "Core Processing Unit", "Computer Power Unit", "Central Performance Utility"],
    correctAnswer: 0,
    explanation: "CPU stands for Central Processing Unit.",
  },
  {
    id: 2,
    topic: "CPU",
    question: "Which CPU component stores frequently used data for quick access?",
    options: ["Cache", "RAM", "SSD", "GPU"],
    correctAnswer: 0,
    explanation: "CPU cache stores frequently used data close to the processor.",
  },
  {
    id: 3,
    topic: "CPU",
    question: "More CPU cores generally help with:",
    options: ["Parallel workloads", "Lower voltage only", "Larger monitors", "Faster storage only"],
    correctAnswer: 0,
    explanation: "More cores improve performance on parallel tasks.",
  },
  {
    id: 4,
    topic: "Memory",
    question: "RAM is considered:",
    options: ["Volatile memory", "Non-volatile storage", "Permanent storage", "A CPU register"],
    correctAnswer: 0,
    explanation: "RAM is volatile; it loses data when power is removed.",
  },
  {
    id: 5,
    topic: "Memory",
    question: "Which memory type detects and corrects errors?",
    options: ["ECC", "DDR3", "SO-DIMM", "SRAM only"],
    correctAnswer: 0,
    explanation: "ECC memory can detect and correct errors.",
  },
  {
    id: 6,
    topic: "Memory",
    question: "Laptop memory modules are commonly called:",
    options: ["SO-DIMM", "DIMM", "VRAM", "Cache line"],
    correctAnswer: 0,
    explanation: "SO-DIMM modules are used in laptops and small form factors.",
  },
  {
    id: 7,
    topic: "Motherboard",
    question: "Which component connects all hardware together?",
    options: ["Motherboard", "PSU", "GPU", "SSD"],
    correctAnswer: 0,
    explanation: "The motherboard provides the main interconnects.",
  },
  {
    id: 8,
    topic: "Motherboard",
    question: "The chipset primarily manages:",
    options: ["Communication between CPU, memory, and devices", "Power conversion", "Display output", "Printer drivers"],
    correctAnswer: 0,
    explanation: "Chipsets coordinate communication between key system components.",
  },
  {
    id: 9,
    topic: "Firmware",
    question: "What is BIOS/UEFI used for?",
    options: ["Initialize hardware and start boot", "Render graphics", "Store user files", "Provide internet access"],
    correctAnswer: 0,
    explanation: "BIOS/UEFI initializes hardware and starts the boot process.",
  },
  {
    id: 10,
    topic: "Firmware",
    question: "What is the typical CMOS battery type?",
    options: ["CR2032", "AA", "AAA", "18650"],
    correctAnswer: 0,
    explanation: "CR2032 is the common CMOS battery type.",
  },
  {
    id: 11,
    topic: "Expansion",
    question: "Which slot is typically used for a discrete GPU?",
    options: ["PCIe x16", "PCIe x1", "M.2", "SATA"],
    correctAnswer: 0,
    explanation: "GPUs typically use PCIe x16 slots.",
  },
  {
    id: 12,
    topic: "Storage",
    question: "Which interface is used by most SATA SSDs?",
    options: ["SATA", "PCIe", "USB", "Thunderbolt"],
    correctAnswer: 0,
    explanation: "SATA SSDs connect via SATA interfaces.",
  },
  {
    id: 13,
    topic: "Storage",
    question: "NVMe drives communicate over:",
    options: ["PCIe", "SATA", "USB 2.0", "IDE"],
    correctAnswer: 0,
    explanation: "NVMe uses PCIe lanes for high performance.",
  },
  {
    id: 14,
    topic: "Storage",
    question: "Which storage device has moving parts?",
    options: ["HDD", "SSD", "NVMe", "USB flash"],
    correctAnswer: 0,
    explanation: "Hard disk drives use spinning platters.",
  },
  {
    id: 15,
    topic: "Storage",
    question: "TRIM is associated with:",
    options: ["SSDs", "Optical drives", "PSUs", "Fans"],
    correctAnswer: 0,
    explanation: "TRIM helps SSDs manage deleted blocks efficiently.",
  },
  {
    id: 16,
    topic: "Storage",
    question: "RAID 0 provides:",
    options: ["Performance without redundancy", "Redundancy only", "Parity with redundancy", "Mirroring only"],
    correctAnswer: 0,
    explanation: "RAID 0 stripes data for speed but has no redundancy.",
  },
  {
    id: 17,
    topic: "Storage",
    question: "RAID 1 provides:",
    options: ["Mirroring for redundancy", "Striping for speed", "Parity with striping", "No redundancy"],
    correctAnswer: 0,
    explanation: "RAID 1 mirrors data across drives.",
  },
  {
    id: 18,
    topic: "Storage",
    question: "RAID 5 requires at least:",
    options: ["3 drives", "2 drives", "4 drives", "1 drive"],
    correctAnswer: 0,
    explanation: "RAID 5 uses distributed parity across three or more drives.",
  },
  {
    id: 19,
    topic: "Power",
    question: "PSU stands for:",
    options: ["Power Supply Unit", "Primary System Utility", "Power Storage Unit", "Peripheral Supply Unit"],
    correctAnswer: 0,
    explanation: "PSU stands for Power Supply Unit.",
  },
  {
    id: 20,
    topic: "Power",
    question: "80 Plus certification indicates:",
    options: ["Power efficiency", "Network speed", "CPU cores", "Memory size"],
    correctAnswer: 0,
    explanation: "80 Plus ratings measure power efficiency.",
  },
  {
    id: 21,
    topic: "Power",
    question: "The standard motherboard power connector is:",
    options: ["24-pin ATX", "6-pin PCIe", "8-pin EPS", "SATA power"],
    correctAnswer: 0,
    explanation: "Most modern motherboards use a 24-pin ATX connector.",
  },
  {
    id: 22,
    topic: "Power",
    question: "The CPU power connector is typically:",
    options: ["8-pin EPS", "24-pin ATX", "SATA power", "Molex only"],
    correctAnswer: 0,
    explanation: "CPUs are powered by 8-pin EPS connectors.",
  },
  {
    id: 23,
    topic: "Cooling",
    question: "Thermal paste is used to:",
    options: ["Improve heat transfer", "Increase voltage", "Clean contacts", "Lock CPU pins"],
    correctAnswer: 0,
    explanation: "Thermal paste improves heat transfer between CPU and cooler.",
  },
  {
    id: 24,
    topic: "Cooling",
    question: "Thermal throttling happens when:",
    options: ["A CPU reduces speed due to heat", "A PSU shuts down", "RAM fails to boot", "Storage is full"],
    correctAnswer: 0,
    explanation: "CPUs throttle to prevent overheating.",
  },
  {
    id: 25,
    topic: "Cooling",
    question: "Good case airflow helps with:",
    options: ["Lower temperatures", "Higher voltage", "More storage", "Faster internet"],
    correctAnswer: 0,
    explanation: "Airflow removes heat from components.",
  },
  {
    id: 26,
    topic: "Ports",
    question: "USB 2.0 maximum speed is about:",
    options: ["480 Mbps", "5 Gbps", "10 Gbps", "20 Gbps"],
    correctAnswer: 0,
    explanation: "USB 2.0 is 480 Mbps.",
  },
  {
    id: 27,
    topic: "Ports",
    question: "USB-C is known for:",
    options: ["Reversible connector", "Analog video only", "Single speed only", "No power delivery"],
    correctAnswer: 0,
    explanation: "USB-C is reversible and supports multiple protocols.",
  },
  {
    id: 28,
    topic: "Ports",
    question: "HDMI carries:",
    options: ["Digital audio and video", "Analog video only", "Power only", "Network traffic only"],
    correctAnswer: 0,
    explanation: "HDMI carries both audio and video digitally.",
  },
  {
    id: 29,
    topic: "Ports",
    question: "DisplayPort supports:",
    options: ["Daisy chaining monitors", "Only analog output", "PS/2 devices", "IDE drives"],
    correctAnswer: 0,
    explanation: "DisplayPort can daisy chain compatible monitors.",
  },
  {
    id: 30,
    topic: "Ports",
    question: "VGA is:",
    options: ["Analog video", "Digital audio", "Optical", "Network"],
    correctAnswer: 0,
    explanation: "VGA is an older analog video standard.",
  },
  {
    id: 31,
    topic: "Networking",
    question: "RJ-45 is used for:",
    options: ["Ethernet", "VGA", "SATA", "Audio out"],
    correctAnswer: 0,
    explanation: "RJ-45 connectors are used for Ethernet cables.",
  },
  {
    id: 32,
    topic: "Networking",
    question: "Cat5e typically supports:",
    options: ["1 Gbps", "10 Gbps only", "100 Mbps max", "No networking"],
    correctAnswer: 0,
    explanation: "Cat5e supports gigabit Ethernet in many cases.",
  },
  {
    id: 33,
    topic: "Networking",
    question: "Fiber optic cable is best for:",
    options: ["Long distance and high bandwidth", "Short runs only", "Analog audio", "Power delivery"],
    correctAnswer: 0,
    explanation: "Fiber supports long distances and high speeds.",
  },
  {
    id: 34,
    topic: "Peripherals",
    question: "Laser printers use:",
    options: ["Toner", "Liquid ink", "Thermal paper only", "Ribbon only"],
    correctAnswer: 0,
    explanation: "Laser printers use toner powder.",
  },
  {
    id: 35,
    topic: "Peripherals",
    question: "Inkjet printers use:",
    options: ["Liquid ink", "Toner", "Filament", "Thermal paste"],
    correctAnswer: 0,
    explanation: "Inkjet printers spray liquid ink.",
  },
  {
    id: 36,
    topic: "Peripherals",
    question: "A monitor resolution of 1920x1080 is called:",
    options: ["1080p", "720p", "4K", "8K"],
    correctAnswer: 0,
    explanation: "1920x1080 is commonly called 1080p.",
  },
  {
    id: 37,
    topic: "Graphics",
    question: "VRAM is used for:",
    options: ["Graphics data storage", "Power regulation", "CPU caching", "Audio mixing"],
    correctAnswer: 0,
    explanation: "VRAM stores textures and frame buffers for GPUs.",
  },
  {
    id: 38,
    topic: "Graphics",
    question: "Integrated graphics are:",
    options: ["Built into the CPU or chipset", "Always faster than discrete GPUs", "Always require PCIe x16", "Only used in servers"],
    correctAnswer: 0,
    explanation: "Integrated graphics are built into the CPU or chipset.",
  },
  {
    id: 39,
    topic: "Storage",
    question: "SATA III provides up to:",
    options: ["6 Gbps", "1.5 Gbps", "3 Gbps", "12 Gbps"],
    correctAnswer: 0,
    explanation: "SATA III is 6 Gbps.",
  },
  {
    id: 40,
    topic: "Troubleshooting",
    question: "POST stands for:",
    options: ["Power-On Self-Test", "Primary Output System Test", "Program Operation Startup Test", "Power-On System Transfer"],
    correctAnswer: 0,
    explanation: "POST is Power-On Self-Test.",
  },
  {
    id: 41,
    topic: "Troubleshooting",
    question: "Beep codes typically indicate:",
    options: ["Hardware errors", "Successful OS update", "Network connectivity", "Printer status"],
    correctAnswer: 0,
    explanation: "Beep codes are used to signal hardware issues during boot.",
  },
  {
    id: 42,
    topic: "Troubleshooting",
    question: "SMART is used to monitor:",
    options: ["Drive health", "CPU temperature", "Network traffic", "Printer ink"],
    correctAnswer: 0,
    explanation: "SMART provides drive health indicators.",
  },
  {
    id: 43,
    topic: "Troubleshooting",
    question: "A system that powers on but shows no display could be caused by:",
    options: ["Loose video cable", "Too much disk space", "A full recycle bin", "Wrong mouse DPI"],
    correctAnswer: 0,
    explanation: "Display issues often stem from cables or GPU seating.",
  },
  {
    id: 44,
    topic: "Maintenance",
    question: "ESD protection is important because:",
    options: ["Static can damage components", "It improves performance", "It reduces noise", "It saves power"],
    correctAnswer: 0,
    explanation: "Static discharge can damage sensitive electronics.",
  },
  {
    id: 45,
    topic: "Maintenance",
    question: "A common ESD safety tool is:",
    options: ["Anti-static wrist strap", "Hammer", "Paper towel", "Magnet"],
    correctAnswer: 0,
    explanation: "Wrist straps help prevent static discharge.",
  },
  {
    id: 46,
    topic: "Maintenance",
    question: "Dust buildup can lead to:",
    options: ["Overheating", "More storage", "Better airflow", "Faster boot"],
    correctAnswer: 0,
    explanation: "Dust restricts airflow and increases heat.",
  },
  {
    id: 47,
    topic: "Form Factors",
    question: "Which is the smallest common desktop form factor?",
    options: ["Mini-ITX", "Micro-ATX", "ATX", "E-ATX"],
    correctAnswer: 0,
    explanation: "Mini-ITX is a compact form factor.",
  },
  {
    id: 48,
    topic: "Form Factors",
    question: "ATX is typically:",
    options: ["Full-size desktop form factor", "Laptop-only", "Server-only", "Tablet-only"],
    correctAnswer: 0,
    explanation: "ATX is a standard full-size desktop form factor.",
  },
  {
    id: 49,
    topic: "Storage",
    question: "M.2 drives can use:",
    options: ["SATA or NVMe", "IDE only", "USB only", "SCSI only"],
    correctAnswer: 0,
    explanation: "M.2 slots can support SATA or NVMe depending on the board.",
  },
  {
    id: 50,
    topic: "Storage",
    question: "Optical drives commonly use:",
    options: ["SATA", "PCIe", "M.2", "USB internal only"],
    correctAnswer: 0,
    explanation: "Most optical drives connect via SATA.",
  },
  {
    id: 51,
    topic: "Power",
    question: "A UPS is used for:",
    options: ["Backup power and surge protection", "GPU acceleration", "Audio processing", "Cooling only"],
    correctAnswer: 0,
    explanation: "UPS devices provide temporary power during outages.",
  },
  {
    id: 52,
    topic: "Power",
    question: "A surge protector mainly guards against:",
    options: ["Voltage spikes", "Low disk space", "Slow Wi-Fi", "High CPU usage"],
    correctAnswer: 0,
    explanation: "Surge protectors guard against spikes.",
  },
  {
    id: 53,
    topic: "Firmware",
    question: "Updating BIOS/UEFI is called:",
    options: ["Flashing", "Formatting", "Defragmenting", "Imaging"],
    correctAnswer: 0,
    explanation: "Firmware updates are called flashing.",
  },
  {
    id: 54,
    topic: "Firmware",
    question: "Secure Boot helps prevent:",
    options: ["Unauthorized bootloaders", "Low disk space", "Network outages", "Printer jams"],
    correctAnswer: 0,
    explanation: "Secure Boot blocks unsigned bootloaders.",
  },
  {
    id: 55,
    topic: "Security",
    question: "TPM stands for:",
    options: ["Trusted Platform Module", "Total Power Management", "Trusted Peripheral Manager", "Transport Protocol Module"],
    correctAnswer: 0,
    explanation: "TPM is the Trusted Platform Module.",
  },
  {
    id: 56,
    topic: "Graphics",
    question: "A GPU primarily accelerates:",
    options: ["Graphics and parallel compute", "Disk IO only", "Audio output only", "Power conversion"],
    correctAnswer: 0,
    explanation: "GPUs are optimized for parallel workloads.",
  },
  {
    id: 57,
    topic: "Cables",
    question: "SATA data cables connect:",
    options: ["Storage devices to motherboard", "Monitors to GPU", "Keyboards to PC", "PSU to wall outlet"],
    correctAnswer: 0,
    explanation: "SATA data cables connect drives to the motherboard.",
  },
  {
    id: 58,
    topic: "Cables",
    question: "A 6-pin or 8-pin PCIe power cable is used for:",
    options: ["GPUs", "SATA drives", "Case fans only", "Keyboards"],
    correctAnswer: 0,
    explanation: "These power cables feed discrete GPUs.",
  },
  {
    id: 59,
    topic: "Troubleshooting",
    question: "A system powers off under load; a likely cause is:",
    options: ["Insufficient PSU wattage", "Too much RAM", "New mouse driver", "Wallpaper resolution"],
    correctAnswer: 0,
    explanation: "An underpowered PSU can cause shutdowns.",
  },
  {
    id: 60,
    topic: "Troubleshooting",
    question: "A PC beeps continuously at boot; one likely cause is:",
    options: ["Memory not seated", "Too many icons", "Full SSD", "Wrong time zone"],
    correctAnswer: 0,
    explanation: "Memory issues often trigger POST beeps.",
  },
  {
    id: 61,
    topic: "Maintenance",
    question: "Cable management helps with:",
    options: ["Airflow and serviceability", "CPU frequency", "RAM speed", "Disk encryption"],
    correctAnswer: 0,
    explanation: "Good cable management improves airflow and maintenance.",
  },
  {
    id: 62,
    topic: "Displays",
    question: "DisplayPort and HDMI are both:",
    options: ["Digital video interfaces", "Analog-only standards", "Power connectors", "Memory sockets"],
    correctAnswer: 0,
    explanation: "Both are digital display interfaces.",
  },
  {
    id: 63,
    topic: "Displays",
    question: "DVI is primarily:",
    options: ["Digital video", "Audio only", "Network only", "Power only"],
    correctAnswer: 0,
    explanation: "DVI is a digital video interface.",
  },
  {
    id: 64,
    topic: "Networking",
    question: "A home router combines:",
    options: ["Switch, router, and wireless AP", "GPU and CPU", "Printer and scanner", "PSU and battery"],
    correctAnswer: 0,
    explanation: "Home routers typically combine multiple network functions.",
  },
  {
    id: 65,
    topic: "Storage",
    question: "HDD performance is influenced by:",
    options: ["RPM and cache", "Monitor size", "Keyboard layout", "USB color"],
    correctAnswer: 0,
    explanation: "Higher RPM and cache improve HDD performance.",
  },
  {
    id: 66,
    topic: "Memory",
    question: "Dual-channel memory improves:",
    options: ["Memory bandwidth", "Disk storage", "Screen brightness", "Network latency"],
    correctAnswer: 0,
    explanation: "Dual-channel increases memory bandwidth.",
  },
  {
    id: 67,
    topic: "Storage",
    question: "SATA power connectors provide:",
    options: ["Power to drives", "Video signals", "Network packets", "Audio input"],
    correctAnswer: 0,
    explanation: "SATA power cables deliver power to storage devices.",
  },
  {
    id: 68,
    topic: "Troubleshooting",
    question: "No power at all often indicates:",
    options: ["PSU or power cable issue", "Wrong wallpaper", "Mouse battery", "DNS failure"],
    correctAnswer: 0,
    explanation: "A dead system often points to PSU or power issues.",
  },
  {
    id: 69,
    topic: "Troubleshooting",
    question: "A system clock that resets often indicates:",
    options: ["Dead CMOS battery", "Bad GPU driver", "Low RAM", "Loose SATA cable"],
    correctAnswer: 0,
    explanation: "A weak CMOS battery causes time resets.",
  },
  {
    id: 70,
    topic: "Peripherals",
    question: "A KVM switch allows:",
    options: ["One keyboard/mouse/monitor to control multiple PCs", "Multiple GPUs in one PC", "More RAM per slot", "Faster boot times"],
    correctAnswer: 0,
    explanation: "KVM switches share a keyboard, video, and mouse across systems.",
  },
  {
    id: 71,
    topic: "Security",
    question: "Full disk encryption on laptops often uses:",
    options: ["TPM-backed keys", "BNC connectors", "DVI cables", "POST codes"],
    correctAnswer: 0,
    explanation: "TPM can store encryption keys securely.",
  },
  {
    id: 72,
    topic: "Memory",
    question: "DDR stands for:",
    options: ["Double Data Rate", "Direct Disk Routing", "Dynamic Device Read", "Dual Disk Range"],
    correctAnswer: 0,
    explanation: "DDR means Double Data Rate memory.",
  },
  {
    id: 73,
    topic: "Power",
    question: "A PSU with too little wattage can cause:",
    options: ["System instability under load", "Extra storage space", "Faster Wi-Fi", "Lower CPU temperature"],
    correctAnswer: 0,
    explanation: "Insufficient power can cause crashes or shutdowns.",
  },
  {
    id: 74,
    topic: "Maintenance",
    question: "Which tool is best for cleaning dust inside a PC?",
    options: ["Compressed air", "Water spray", "Vacuum on high", "Steel brush"],
    correctAnswer: 0,
    explanation: "Compressed air safely removes dust.",
  },
  {
    id: 75,
    topic: "Storage",
    question: "NAS stands for:",
    options: ["Network Attached Storage", "New Access System", "Network Allocation Service", "Node Array Storage"],
    correctAnswer: 0,
    explanation: "NAS is Network Attached Storage.",
  },
];

const ITHardwarePage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [quizPool] = useState<QuizQuestion[]>(() =>
    selectRandomQuestions(quizQuestions, QUIZ_QUESTION_COUNT)
  );

  const accent = ACCENT_COLOR;

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "cpu", label: "CPU", icon: <DeveloperBoardIcon /> },
    { id: "ram", label: "RAM", icon: <MemoryIcon /> },
    { id: "motherboard", label: "Motherboard", icon: <ComputerIcon /> },
    { id: "storage", label: "Storage", icon: <StorageIcon /> },
    { id: "psu", label: "PSU", icon: <PowerIcon /> },
    { id: "gpu", label: "GPU", icon: <SpeedIcon /> },
    { id: "cooling", label: "Cooling Systems", icon: <ThermostatIcon /> },
    { id: "video-cables", label: "Video Cables", icon: <SettingsInputHdmiIcon /> },
    { id: "usb-cables", label: "USB Cables", icon: <UsbIcon /> },
    { id: "internal-cables", label: "Internal Cables", icon: <CableIcon /> },
    { id: "network-cables", label: "Network Cables", icon: <RouterIcon /> },
    { id: "laptop-hardware", label: "Laptop Hardware", icon: <LaptopIcon /> },
    { id: "peripherals", label: "Peripherals", icon: <MonitorIcon /> },
    { id: "security-hardware", label: "Security Hardware", icon: <SecurityIcon /> },
    { id: "troubleshooting", label: "Troubleshooting", icon: <BugReportIcon /> },
    { id: "maintenance", label: "Maintenance", icon: <ThermostatIcon /> },
    { id: "comptia", label: "CompTIA A+", icon: <BuildIcon /> },
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

  const pageContext = "A comprehensive guide to computer hardware components including CPU, RAM, motherboard, storage devices, PSU, and GPU. Covers cables and connectors like HDMI, DisplayPort, USB standards, SATA, and network cables. Includes peripherals like keyboards, mice, monitors, printers. Also covers troubleshooting POST codes, boot issues, common hardware problems, and maintenance best practices. Relevant for CompTIA A+ certification.";

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
    <LearnPageLayout
      pageTitle="IT Hardware Fundamentals"
      pageContext={pageContext}
    >
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
            "&:hover": { bgcolor: "#7c3aed" },
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
          {/* Back to Hub Button */}
          <Chip
            component={Link}
            to="/learn"
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            clickable
            variant="outlined"
            sx={{ borderRadius: 2, mb: 3 }}
          />

        {/* Page Header */}
        <Box sx={{ mb: 6 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <MemoryIcon sx={{ fontSize: 48, color: "#8b5cf6" }} />
            <Typography variant="h3" sx={{ fontWeight: 800 }}>
              IT Hardware Fundamentals
            </Typography>
          </Box>
          <Typography variant="h6" color="text.secondary" sx={{ mb: 3, maxWidth: 900 }}>
            A comprehensive guide to computer hardware components, peripherals, cables, and connectors.
            Understanding hardware is essential for troubleshooting, building systems, and IT support roles.
          </Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            {["CompTIA A+", "Hardware", "Troubleshooting", "PC Building", "IT Support"].map((tag) => (
              <Chip key={tag} label={tag} size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1) }} />
            ))}
          </Box>
        </Box>

        {/* Introduction Section */}
        <Paper id="intro" sx={{ p: 4, mb: 4, borderRadius: 3, background: "linear-gradient(135deg, rgba(139,92,246,0.05) 0%, rgba(59,130,246,0.05) 100%)", border: "2px solid", borderColor: alpha("#8b5cf6", 0.2) }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            📖 What You'll Learn
          </Typography>
          <Typography variant="body1" sx={{ mb: 3 }}>
            This guide covers the essential hardware knowledge needed for IT certifications like CompTIA A+ and 
            real-world IT support. From understanding how CPUs and RAM work to identifying cable types and 
            troubleshooting common hardware issues, you'll gain the foundational knowledge every IT professional needs.
          </Typography>
          <Grid container spacing={2}>
            {[
              { title: "Core Components", desc: "CPU, RAM, Motherboard, Storage, PSU, GPU" },
              { title: "Cables & Connectors", desc: "USB, HDMI, DisplayPort, SATA, Power cables" },
              { title: "Peripherals", desc: "Monitors, Keyboards, Mice, Printers, Scanners" },
              { title: "Form Factors", desc: "ATX, Micro-ATX, Mini-ITX, Laptop components" },
              { title: "Troubleshooting", desc: "POST codes, diagnostics, common failures" },
              { title: "Maintenance", desc: "Cleaning, thermal paste, cable management" },
            ].map((item) => (
              <Grid item xs={6} md={4} key={item.title}>
                <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Beginner's Analogy Section */}
        <Alert severity="success" icon={<SchoolIcon />} sx={{ mb: 4 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
            🏠 Think of Your Computer Like a House
          </Typography>
          <Typography variant="body2" sx={{ mb: 2 }}>
            Understanding computer hardware is much easier when you relate it to things you already know. 
            Here's a helpful analogy that makes the complex world of PC components click:
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="body2" sx={{ mb: 1 }}>
                • <strong>CPU (Processor)</strong> = The homeowner's brain, making all the decisions and doing the thinking
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                • <strong>RAM (Memory)</strong> = Your desk workspace - the bigger it is, the more projects you can have open at once
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                • <strong>Storage (SSD/HDD)</strong> = Filing cabinets and closets where you keep everything long-term
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                • <strong>Motherboard</strong> = The house's foundation and walls that connect all the rooms together
              </Typography>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="body2" sx={{ mb: 1 }}>
                • <strong>PSU (Power Supply)</strong> = The electrical panel that brings power to everything in the house
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                • <strong>GPU (Graphics Card)</strong> = A specialized art studio for creating and displaying visuals
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                • <strong>Cables</strong> = The plumbing and electrical wiring that connects everything
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                • <strong>Case</strong> = The actual walls and roof of the house protecting everything inside
              </Typography>
            </Grid>
          </Grid>
        </Alert>

        {/* Why Hardware Knowledge Matters */}
        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03) }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#3b82f6" }}>
            🔧 Why Hardware Knowledge Matters
          </Typography>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Whether you're pursuing an IT career, building your own gaming PC, or just want to understand 
            what's happening inside your computer, hardware knowledge is invaluable. It's the foundation 
            that makes everything else in computing possible.
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, bgcolor: "background.paper", borderRadius: 2, height: "100%", border: "1px solid", borderColor: alpha("#3b82f6", 0.2) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>💼 Career Benefits</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>IT Support & Help Desk:</strong> Troubleshoot and fix hardware issues for users, 
                  from "my computer won't turn on" to "my USB ports stopped working."
                </Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>System Administration:</strong> Spec out new workstations, plan hardware upgrades, 
                  and manage server infrastructure.
                </Typography>
                <Typography variant="body2">
                  <strong>Security Professional:</strong> Understand hardware vulnerabilities, physical security 
                  risks, and how attackers might exploit hardware (TPM, BIOS attacks, BadUSB).
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, bgcolor: "background.paper", borderRadius: 2, height: "100%", border: "1px solid", borderColor: alpha("#22c55e", 0.2) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>💰 Money Savings</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>DIY Repairs:</strong> Replacing a failed hard drive or adding RAM yourself saves 
                  hundreds versus paying a repair shop or buying new.
                </Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>Informed Purchases:</strong> Don't fall for marketing hype. Know what specs actually 
                  matter for your use case and avoid overpaying.
                </Typography>
                <Typography variant="body2">
                  <strong>Extended Lifespan:</strong> Proper maintenance and targeted upgrades can keep a 
                  computer running smoothly for years longer than expected.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, bgcolor: "background.paper", borderRadius: 2, height: "100%", border: "1px solid", borderColor: alpha("#f59e0b", 0.2) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>🎮 Personal Projects</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>Custom PC Builds:</strong> Build a gaming rig, home server, NAS, or workstation 
                  tailored exactly to your needs and budget.
                </Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>
                  <strong>Home Lab:</strong> Set up virtualization servers, practice networking, or create 
                  a cybersecurity testing environment.
                </Typography>
                <Typography variant="body2">
                  <strong>Tinkering & Learning:</strong> Old computers become learning platforms. Practice 
                  upgrades, test configurations, and experiment without risk.
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* Getting Started Tips */}
        <Alert severity="info" sx={{ mb: 4 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
            🚀 Getting Started Tips for Beginners
          </Typography>
          <Typography variant="body2" sx={{ mb: 2 }}>
            Hardware can seem intimidating at first, but here's the secret: <strong>it's mostly just plugging 
            things in correctly</strong>. Modern components are designed with foolproof connectors that only 
            fit one way. Start simple and build your confidence:
          </Typography>
          <Typography variant="body2" sx={{ mb: 1 }}>
            <strong>1. Look Inside:</strong> Open up an old computer (or ask permission to look at someone's). 
            Identify the main components. They're bigger and more distinct than you might think.
          </Typography>
          <Typography variant="body2" sx={{ mb: 1 }}>
            <strong>2. Watch Build Videos:</strong> Watching someone build a PC on YouTube demystifies the process. 
            Channels like Linus Tech Tips, JayzTwoCents, and Gamers Nexus are great resources.
          </Typography>
          <Typography variant="body2" sx={{ mb: 1 }}>
            <strong>3. Hands-On Practice:</strong> The best way to learn is by doing. Upgrade RAM, install a new 
            SSD, or replace thermal paste. Start with low-risk tasks on older machines.
          </Typography>
          <Typography variant="body2">
            <strong>4. Use This Guide:</strong> Scroll through each section, focus on what interests you, and 
            take the quiz at the end. Return to reference specific topics when you need them.
          </Typography>
        </Alert>

        {/* ========== CORE COMPONENTS SECTION ========== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>CORE COMPONENTS</Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* CPU */}
        <Accordion id="cpu" defaultExpanded sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ef4444", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <DeveloperBoardIcon sx={{ color: "#ef4444" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>CPU (Central Processing Unit)</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              The "brain" of the computer - executes instructions, performs calculations, and coordinates all hardware operations. 
              Modern CPUs contain billions of transistors on a silicon die.
            </Alert>

            {/* Beginner Explanation */}
            <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, border: "1px solid", borderColor: alpha("#ef4444", 0.2) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
                🧠 Understanding CPUs: The Brain Analogy
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                Imagine your CPU as the brain of a very fast mathematician who can only do one simple calculation at a time, 
                but can do <strong>billions of these calculations per second</strong>. Everything your computer does - from displaying 
                this webpage to playing a video game - ultimately comes down to the CPU executing billions of tiny instructions.
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                <strong>What does "3.5 GHz" actually mean?</strong> It means the CPU's internal clock "ticks" 3.5 billion times 
                per second. On each tick, the CPU can do work - fetch data, add numbers, compare values, etc. Higher GHz generally 
                means faster single-task performance, but it's not the only factor.
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                <strong>Why do cores matter?</strong> Think of cores as separate brains that can work independently. A 4-core CPU 
                is like having 4 mathematicians working at 4 different desks. They can each work on different problems simultaneously, 
                which is why more cores help with multitasking and parallel workloads (like video editing or running multiple VMs).
              </Typography>
              <Typography variant="body2">
                <strong>The catch:</strong> Not all tasks can be split across multiple cores. Some things must happen in sequence 
                (like following a recipe step-by-step). This is why games often benefit more from faster single-core performance 
                than from having tons of cores.
              </Typography>
            </Paper>

            {/* How CPUs Actually Work */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>How CPUs Execute Instructions</Typography>
            <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#ef4444", 0.02), borderRadius: 2 }}>
              <Typography variant="body2" sx={{ mb: 2 }}>
                Every CPU follows a basic cycle called <strong>Fetch-Decode-Execute</strong>:
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, bgcolor: "background.paper", borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>1. Fetch</Typography>
                    <Typography variant="body2">
                      The CPU grabs the next instruction from memory (RAM). Instructions are just numbers that 
                      the CPU interprets as commands like "add these two values" or "store this result."
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, bgcolor: "background.paper", borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>2. Decode</Typography>
                    <Typography variant="body2">
                      The CPU figures out what the instruction means. Different parts of the instruction tell it 
                      what operation to do and what data to use.
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, bgcolor: "background.paper", borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>3. Execute</Typography>
                    <Typography variant="body2">
                      The CPU performs the operation - arithmetic, memory access, comparison, etc. The result 
                      might be stored back to memory or used immediately for the next instruction.
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>
              <Typography variant="body2" sx={{ mt: 2 }}>
                Modern CPUs use <strong>pipelining</strong> to overlap these stages - while one instruction is executing, 
                the next one is being decoded, and another is being fetched. This is like an assembly line, dramatically 
                increasing throughput.
              </Typography>
            </Paper>
            
            {/* CPU Architecture Overview */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 2 }}>CPU Architecture Components</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>Cores & Threads</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>• <strong>Core:</strong> Independent processing unit that executes instructions</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>• <strong>Thread:</strong> Virtual core created by hyperthreading/SMT</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>• <strong>Hyperthreading (Intel):</strong> 2 threads per core</Typography>
                  <Typography variant="body2">• <strong>SMT (AMD):</strong> Simultaneous Multi-Threading</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>Clock Speed & Boost</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>• <strong>Base Clock:</strong> Guaranteed minimum frequency (GHz)</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>• <strong>Boost Clock:</strong> Maximum turbo frequency under load</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>• <strong>Overclocking:</strong> Running above rated speeds (K/X series)</Typography>
                  <Typography variant="body2">• <strong>Power Limits:</strong> PL1 (sustained), PL2 (burst)</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* CPU Cache Hierarchy */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Cache Hierarchy</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Cache Level</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Typical Size</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Latency</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Shared?</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { level: "L1 Cache", size: "32-64 KB/core", latency: "~4 cycles", shared: "Per core", purpose: "Instruction & data cache, fastest" },
                    { level: "L2 Cache", size: "256 KB-1 MB/core", latency: "~12 cycles", shared: "Per core", purpose: "Secondary cache, frequently used data" },
                    { level: "L3 Cache", size: "8-96+ MB", latency: "~40 cycles", shared: "All cores", purpose: "Shared cache, reduces RAM access" },
                  ].map((row) => (
                    <TableRow key={row.level}>
                      <TableCell sx={{ fontWeight: 600, color: "#ef4444" }}>{row.level}</TableCell>
                      <TableCell>{row.size}</TableCell>
                      <TableCell>{row.latency}</TableCell>
                      <TableCell>{row.shared}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.purpose}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* CPU Platform Features */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>CPU Platform Features</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    Memory Controller & PCIe Lanes
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Memory channels:</strong> Dual-channel on consumer, quad-channel on HEDT/workstations.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Supported DDR:</strong> CPU generation defines DDR4 vs DDR5 compatibility.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>PCIe lanes:</strong> CPU lanes handle GPU/NVMe; chipset lanes add extra devices.
                  </Typography>
                  <Typography variant="body2">
                    <strong>iGPU:</strong> Integrated graphics can drive displays without a discrete GPU.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>
                    Virtualization & Instruction Sets
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>VT-x/AMD-V:</strong> Hardware virtualization for running virtual machines.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>VT-d/IOMMU:</strong> Device passthrough for VMs and advanced I/O.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>AES-NI:</strong> Accelerates encryption and TLS workloads.
                  </Typography>
                  <Typography variant="body2">
                    <strong>AVX/AVX2:</strong> Vector instructions that speed up media and scientific apps.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Intel vs AMD */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Intel vs AMD Comparison</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: "#0071c5", borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0071c5", mb: 2 }}>Intel Processors</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}><strong>Current Gen:</strong> 13th/14th Gen Core (Raptor Lake)</Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Product Lines:</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Core i3:</strong> Entry-level, 4-6 cores</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Core i5:</strong> Mainstream, 6-14 cores</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Core i7:</strong> High-performance, 8-20 cores</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Core i9:</strong> Enthusiast, 16-24 cores</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>• <strong>Xeon:</strong> Server/workstation, ECC support</Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Desktop Sockets:</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>LGA 1700:</strong> 12th-14th Gen Core</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>LGA 1200:</strong> 10th-11th Gen Core</Typography>
                  <Typography variant="body2">• <strong>LGA 2066:</strong> HEDT X-series</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: "#ed1c24", borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ed1c24", mb: 2 }}>AMD Processors</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}><strong>Current Gen:</strong> Ryzen 7000/9000 Series (Zen 4/5)</Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Product Lines:</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Ryzen 3:</strong> Entry-level, 4 cores</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Ryzen 5:</strong> Mainstream, 6 cores</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Ryzen 7:</strong> High-performance, 8 cores</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Ryzen 9:</strong> Enthusiast, 12-16 cores</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>• <strong>Threadripper:</strong> HEDT, 24-96 cores</Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Desktop Sockets:</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>AM5:</strong> Ryzen 7000+ (DDR5, PCIe 5.0)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>AM4:</strong> Ryzen 1000-5000</Typography>
                  <Typography variant="body2">• <strong>sTRX4/sWRX8:</strong> Threadripper</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* TDP and Cooling */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>TDP & Cooling Requirements</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>TDP Range</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>CPU Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Recommended Cooling</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Example CPUs</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { tdp: "35-65W", type: "Low Power/Mobile", cooling: "Stock cooler, low-profile", example: "Core i5 T-series, Ryzen 5 65W" },
                    { tdp: "65-105W", type: "Mainstream Desktop", cooling: "Stock cooler, tower air cooler", example: "Core i5/i7, Ryzen 5/7" },
                    { tdp: "125-170W", type: "High Performance", cooling: "Large tower cooler, 240mm AIO", example: "Core i9, Ryzen 9" },
                    { tdp: "200W+", type: "HEDT/Enthusiast", cooling: "360mm AIO, custom loop", example: "Threadripper, Xeon W" },
                  ].map((row) => (
                    <TableRow key={row.tdp}>
                      <TableCell sx={{ fontWeight: 600, color: "#ef4444" }}>{row.tdp}</TableCell>
                      <TableCell>{row.type}</TableCell>
                      <TableCell>{row.cooling}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.example}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Suffix Naming */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>CPU Naming Suffixes</Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#0071c5", 0.05), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0071c5", mb: 1 }}>Intel Suffixes</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>K:</strong> Unlocked for overclocking</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>F:</strong> No integrated graphics</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>KF:</strong> Unlocked + no iGPU</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>T:</strong> Low power (35W TDP)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>S:</strong> Special edition</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>H:</strong> Mobile high-performance</Typography>
                  <Typography variant="body2">• <strong>U:</strong> Mobile ultra-low power</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ed1c24", 0.05), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ed1c24", mb: 1 }}>AMD Suffixes</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>X:</strong> Higher performance bin</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>X3D:</strong> 3D V-Cache (gaming)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>G:</strong> Integrated Radeon graphics</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>GE:</strong> Low power with iGPU</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>HS:</strong> Mobile high-performance thin</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>HX:</strong> Mobile extreme performance</Typography>
                  <Typography variant="body2">• <strong>U:</strong> Mobile ultra-low power</Typography>
                </Paper>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* RAM */}
        <Accordion id="ram" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#3b82f6", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <MemoryIcon sx={{ color: "#3b82f6" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6" }}>RAM (Random Access Memory)</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              Volatile memory providing fast temporary storage for active programs and data. 
              RAM speed and capacity directly impact system responsiveness and multitasking capability.
            </Alert>
            
            {/* DDR Generations */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>DDR Generation Comparison</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#3b82f6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Generation</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Speed Range</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Voltage</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Pins (DIMM)</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Key Position</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Max Capacity</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { gen: "DDR3", speed: "800-2133 MHz", volt: "1.5V (1.35V LP)", pins: "240", key: "Center-offset", max: "16GB/DIMM" },
                    { gen: "DDR4", speed: "2133-5333 MHz", volt: "1.2V", pins: "288", key: "Different notch", max: "128GB/DIMM" },
                    { gen: "DDR5", speed: "4800-8400+ MHz", volt: "1.1V", pins: "288", key: "Different notch", max: "256GB/DIMM" },
                  ].map((row) => (
                    <TableRow key={row.gen}>
                      <TableCell sx={{ fontWeight: 600, color: "#3b82f6" }}>{row.gen}</TableCell>
                      <TableCell>{row.speed}</TableCell>
                      <TableCell>{row.volt}</TableCell>
                      <TableCell>{row.pins}</TableCell>
                      <TableCell>{row.key}</TableCell>
                      <TableCell>{row.max}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* RAM Specs Explained */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Understanding RAM Specifications</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Speed & Frequency</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>• <strong>MHz Rating:</strong> Transfer rate (DDR4-3200 = 3200 MT/s)</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>• <strong>XMP/EXPO:</strong> Overclock profiles for rated speeds</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>• <strong>JEDEC:</strong> Standard speeds without XMP</Typography>
                  <Typography variant="body2">• <strong>Bandwidth:</strong> MHz × 8 bytes (DDR4-3200 = 25.6 GB/s)</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Latency (CAS Latency)</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>• <strong>CL (CAS):</strong> Column Address Strobe delay</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>• <strong>tRCD:</strong> Row to Column delay</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>• <strong>tRP:</strong> Row Precharge time</Typography>
                  <Typography variant="body2">• <strong>Timings:</strong> Listed as CL16-18-18-36 format</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* True Latency Formula */}
            <Alert severity="success" sx={{ mb: 3 }}>
              <strong>True Latency Formula:</strong> (CAS Latency ÷ Speed in MHz) × 2000 = nanoseconds<br/>
              Example: DDR4-3200 CL16 = (16 ÷ 3200) × 2000 = 10ns | DDR5-6000 CL30 = (30 ÷ 6000) × 2000 = 10ns
            </Alert>

            {/* Form Factors */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>RAM Form Factors</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#3b82f6", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>DIMM (Desktop)</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Full-size desktop memory</Typography>
                  <Typography variant="body2">• DDR4: 288 pins, 133.35mm</Typography>
                  <Typography variant="body2">• DDR5: 288 pins, different notch</Typography>
                  <Typography variant="body2">• Not interchangeable</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#3b82f6", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>SO-DIMM (Laptop)</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Compact laptop memory</Typography>
                  <Typography variant="body2">• DDR4: 260 pins, 69.6mm</Typography>
                  <Typography variant="body2">• DDR5: 262 pins</Typography>
                  <Typography variant="body2">• Used in laptops, NUCs, SFF PCs</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#3b82f6", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>LPDDR (Mobile)</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Low-power soldered memory</Typography>
                  <Typography variant="body2">• LPDDR4X/LPDDR5</Typography>
                  <Typography variant="body2">• Soldered to motherboard</Typography>
                  <Typography variant="body2">• Non-upgradeable</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Channel Configuration */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Memory Channels & Configuration</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Channel Configurations</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Single Channel:</strong> 1 DIMM, 1x bandwidth</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Dual Channel:</strong> 2 DIMMs (matched), 2x bandwidth</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Quad Channel:</strong> 4 DIMMs (HEDT/Server), 4x bandwidth</Typography>
                  <Typography variant="body2">• <strong>Flex Mode:</strong> Asymmetric capacity dual-channel</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Slot Population</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>A2/B2 slots:</strong> Populate first for dual-channel</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Color coding:</strong> Match slots of same color</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Daisy chain:</strong> Populate furthest slots first</Typography>
                  <Typography variant="body2">• <strong>T-Topology:</strong> Populate closest slots first</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* ECC vs Non-ECC */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>ECC vs Non-ECC Memory</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#3b82f6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Feature</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Non-ECC (Unbuffered)</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>ECC (Unbuffered)</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>ECC Registered (RDIMM)</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { feature: "Error Correction", nonecc: "None", ecc: "Single-bit correction", rdimm: "Single-bit + detection" },
                    { feature: "Use Case", nonecc: "Consumer desktops", ecc: "Workstations", rdimm: "Servers, high-capacity" },
                    { feature: "CPU Support", nonecc: "All CPUs", ecc: "Xeon, Threadripper, AMD Pro", rdimm: "Server CPUs only" },
                    { feature: "Cost", nonecc: "Lowest", ecc: "~10-20% more", rdimm: "Premium" },
                    { feature: "Capacity", nonecc: "Up to 128GB", ecc: "Up to 128GB", rdimm: "Up to 2TB+" },
                  ].map((row) => (
                    <TableRow key={row.feature}>
                      <TableCell sx={{ fontWeight: 600, color: "#3b82f6" }}>{row.feature}</TableCell>
                      <TableCell>{row.nonecc}</TableCell>
                      <TableCell>{row.ecc}</TableCell>
                      <TableCell>{row.rdimm}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Motherboard */}
        <Accordion id="motherboard" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#22c55e", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <DeveloperBoardIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>Motherboard</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              The main circuit board connecting all components. The motherboard determines CPU compatibility, 
              RAM type, expansion options, and connectivity features.
            </Alert>
            
            {/* Form Factors */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Motherboard Form Factors</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Form Factor</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Dimensions</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>PCIe Slots</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>RAM Slots</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Use Case</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { ff: "E-ATX", dims: "305 × 330mm", pcie: "7+", ram: "8", use: "HEDT workstations, servers" },
                    { ff: "ATX", dims: "305 × 244mm", pcie: "7", ram: "4", use: "Standard desktops, gaming" },
                    { ff: "Micro-ATX", dims: "244 × 244mm", pcie: "4", ram: "2-4", use: "Compact builds, budget" },
                    { ff: "Mini-ITX", dims: "170 × 170mm", pcie: "1", ram: "2", use: "SFF builds, HTPCs" },
                    { ff: "Mini-DTX", dims: "203 × 170mm", pcie: "2", ram: "2", use: "Compact enthusiast" },
                  ].map((row) => (
                    <TableRow key={row.ff}>
                      <TableCell sx={{ fontWeight: 600, color: "#22c55e" }}>{row.ff}</TableCell>
                      <TableCell>{row.dims}</TableCell>
                      <TableCell>{row.pcie}</TableCell>
                      <TableCell>{row.ram}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.use}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Chipsets */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Chipsets & Tiers</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: "#0071c5", borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0071c5", mb: 2 }}>Intel Chipsets (LGA 1700)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Z790/Z690:</strong> Full overclocking, DDR5, PCIe 5.0</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>B760/B660:</strong> No CPU OC, memory OC, mainstream</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>H770/H670:</strong> No OC, more I/O than B-series</Typography>
                  <Typography variant="body2">• <strong>H610:</strong> Entry-level, basic features</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: "#ed1c24", borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ed1c24", mb: 2 }}>AMD Chipsets (AM5)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>X670E:</strong> Full PCIe 5.0 GPU + NVMe, OC</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>X670:</strong> PCIe 5.0 NVMe only, full OC</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>B650E:</strong> PCIe 5.0 GPU, enthusiast features</Typography>
                  <Typography variant="body2">• <strong>B650:</strong> Mainstream, PCIe 4.0 GPU</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Power Delivery & Internal Headers */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Power Delivery & Internal Headers</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    VRM Quality & Power Stages
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>VRM phases:</strong> More phases usually means cleaner power and lower temps.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Heatsinks:</strong> Larger VRM heatsinks help sustained loads and boosts.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>EPS connectors:</strong> 8-pin (or 8+4) for stable CPU power delivery.
                  </Typography>
                  <Typography variant="body2">
                    <strong>Capacitors/chokes:</strong> Higher quality parts improve longevity.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                    Front Panel, USB, and Fan Headers
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Front panel:</strong> Power/reset buttons, HDD/Power LEDs.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>USB headers:</strong> USB 2.0, USB 3.x, and USB-C front panel.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Fan headers:</strong> PWM (4-pin) vs DC (3-pin) control.
                  </Typography>
                  <Typography variant="body2">
                    <strong>RGB headers:</strong> 12V RGB vs 5V ARGB (not interchangeable).
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Expansion Slots */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Expansion Slots & Interfaces</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>PCIe Slots</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>PCIe x16:</strong> GPUs (16 lanes)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>PCIe x4:</strong> NVMe adapters, RAID cards</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>PCIe x1:</strong> Sound cards, USB expansion</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>PCIe 5.0:</strong> 64 GB/s (x16 slot)</Typography>
                  <Typography variant="body2">• <strong>PCIe 4.0:</strong> 32 GB/s (x16 slot)</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>M.2 Slots</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>M.2 2280:</strong> Standard NVMe/SATA size</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>M-Key:</strong> NVMe (PCIe x4)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>B-Key:</strong> SATA or PCIe x2</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>E-Key:</strong> WiFi/Bluetooth cards</Typography>
                  <Typography variant="body2">• <strong>Heatsinks:</strong> Required for Gen 4/5 NVMe</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>SATA Ports</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>SATA III:</strong> 6 Gbps (600 MB/s)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Port count:</strong> Usually 4-8 ports</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>RAID support:</strong> 0, 1, 5, 10</Typography>
                  <Typography variant="body2">• <strong>Sharing:</strong> May share bandwidth with M.2</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* I/O Panel */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Rear I/O Panel Connectivity</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Common Ports</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>USB 3.2 Gen 2:</strong> Type-A (10 Gbps)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>USB-C:</strong> Often Gen 2 or Thunderbolt</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>USB 2.0:</strong> Keyboards, mice</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Audio:</strong> 3.5mm jacks, optical S/PDIF</Typography>
                  <Typography variant="body2">• <strong>PS/2:</strong> Legacy keyboard/mouse (some boards)</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Network & Display</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Ethernet:</strong> 1G, 2.5G, or 10G LAN</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>WiFi:</strong> WiFi 6E/7 (on select boards)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>HDMI 2.1:</strong> 4K@120Hz (iGPU output)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>DisplayPort:</strong> 1.4/2.0 (iGPU output)</Typography>
                  <Typography variant="body2">• <strong>BIOS Flashback:</strong> USB BIOS update button</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* BIOS/UEFI */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>BIOS vs UEFI</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Feature</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Legacy BIOS</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>UEFI</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { feature: "Interface", bios: "Text-based, keyboard only", uefi: "GUI with mouse support" },
                    { feature: "Boot Mode", bios: "MBR (Master Boot Record)", uefi: "GPT (GUID Partition Table)" },
                    { feature: "Drive Support", bios: "Max 2.2TB partitions", uefi: "Unlimited partition size" },
                    { feature: "Boot Speed", bios: "Slower", uefi: "Fast Boot, Instant Wake" },
                    { feature: "Security", bios: "Limited", uefi: "Secure Boot, TPM support" },
                    { feature: "Architecture", bios: "16-bit", uefi: "32/64-bit" },
                  ].map((row) => (
                    <TableRow key={row.feature}>
                      <TableCell sx={{ fontWeight: 600, color: "#22c55e" }}>{row.feature}</TableCell>
                      <TableCell>{row.bios}</TableCell>
                      <TableCell>{row.uefi}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Storage */}
        <Accordion id="storage" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#f59e0b", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <StorageIcon sx={{ color: "#f59e0b" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>Storage Devices</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              Non-volatile storage for operating systems, applications, and data. Modern systems typically 
              use a combination of fast NVMe SSDs for the OS and larger HDDs for bulk storage.
            </Alert>
            
            {/* Storage Types Comparison */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Storage Types Comparison</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Interface</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Speed (Read)</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Latency</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Best For</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { type: "HDD (7200 RPM)", iface: "SATA III", speed: "~180 MB/s", latency: "5-10ms", best: "Bulk storage, archives" },
                    { type: "HDD (5400 RPM)", iface: "SATA III", speed: "~100 MB/s", latency: "8-15ms", best: "NAS, backup, laptops" },
                    { type: "SATA SSD", iface: "SATA III", speed: "~550 MB/s", latency: "0.1ms", best: "Budget upgrades" },
                    { type: "NVMe Gen 3", iface: "PCIe 3.0 x4", speed: "~3,500 MB/s", latency: "0.02ms", best: "Gaming, general use" },
                    { type: "NVMe Gen 4", iface: "PCIe 4.0 x4", speed: "~7,000 MB/s", latency: "0.01ms", best: "Content creation, gaming" },
                    { type: "NVMe Gen 5", iface: "PCIe 5.0 x4", speed: "~14,000 MB/s", latency: "0.01ms", best: "Enthusiast, pro workloads" },
                  ].map((row) => (
                    <TableRow key={row.type}>
                      <TableCell sx={{ fontWeight: 600, color: "#f59e0b" }}>{row.type}</TableCell>
                      <TableCell>{row.iface}</TableCell>
                      <TableCell>{row.speed}</TableCell>
                      <TableCell>{row.latency}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.best}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* HDD Deep Dive */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>HDD (Hard Disk Drive) Details</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>How HDDs Work</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Magnetic platters spin at 5400-15000 RPM</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Read/write heads move across platter surface</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Data stored in sectors and tracks</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Seek time + rotational latency = access time</Typography>
                  <Typography variant="body2">• Cache buffer: 64-256MB DRAM</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>HDD Recording Technologies</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>CMR:</strong> Conventional Magnetic Recording (best reliability)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>SMR:</strong> Shingled Magnetic Recording (higher density, slower write)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>PMR:</strong> Perpendicular Magnetic Recording</Typography>
                  <Typography variant="body2">• <strong>HAMR:</strong> Heat-Assisted (emerging, 30TB+)</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* SSD Deep Dive */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>SSD (Solid State Drive) Details</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>NAND Flash Types</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>SLC:</strong> 1 bit/cell - Fastest, most durable, expensive</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>MLC:</strong> 2 bits/cell - Good balance, enterprise</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>TLC:</strong> 3 bits/cell - Consumer mainstream</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>QLC:</strong> 4 bits/cell - High capacity, lower endurance</Typography>
                  <Typography variant="body2">• <strong>3D NAND:</strong> Stacked layers for density</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>SSD Components</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Controller:</strong> Brain of SSD, manages NAND</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>DRAM Cache:</strong> Mapping table, faster access</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>HMB:</strong> Host Memory Buffer (DRAM-less SSDs)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>SLC Cache:</strong> Pseudo-SLC for burst writes</Typography>
                  <Typography variant="body2">• <strong>Over-provisioning:</strong> Reserved space for wear leveling</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* SSD Endurance & Reliability */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>SSD Endurance & Reliability</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Metric</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Meaning</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Why It Matters</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { metric: "TBW", meaning: "Total bytes you can write over the drive's life", why: "Higher TBW means better endurance" },
                    { metric: "DWPD", meaning: "Drive writes per day (enterprise metric)", why: "Indicates heavy write workload capability" },
                    { metric: "MTBF", meaning: "Mean time between failures", why: "Reliability estimate over large populations" },
                    { metric: "Power-loss protection", meaning: "Capacitors flush data on sudden power loss", why: "Protects data integrity in servers" },
                    { metric: "Warranty", meaning: "Typical 3-5 years for consumer SSDs", why: "Signals vendor confidence and support" },
                  ].map((row) => (
                    <TableRow key={row.metric}>
                      <TableCell sx={{ fontWeight: 600, color: "#f59e0b" }}>{row.metric}</TableCell>
                      <TableCell>{row.meaning}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.why}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Form Factors */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Storage Form Factors</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#f59e0b", 0.3), borderRadius: 2, height: "100%", textAlign: "center" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>3.5" HDD</Typography>
                  <Typography variant="body2" color="text.secondary">Desktop HDDs</Typography>
                  <Typography variant="body2">Up to 24TB</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#f59e0b", 0.3), borderRadius: 2, height: "100%", textAlign: "center" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>2.5" Drive</Typography>
                  <Typography variant="body2" color="text.secondary">SATA SSD / Laptop HDD</Typography>
                  <Typography variant="body2">Up to 8TB (SSD)</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#f59e0b", 0.3), borderRadius: 2, height: "100%", textAlign: "center" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>M.2 2280</Typography>
                  <Typography variant="body2" color="text.secondary">NVMe / SATA</Typography>
                  <Typography variant="body2">22mm × 80mm</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#f59e0b", 0.3), borderRadius: 2, height: "100%", textAlign: "center" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>U.2 / U.3</Typography>
                  <Typography variant="body2" color="text.secondary">Enterprise NVMe</Typography>
                  <Typography variant="body2">2.5" with NVMe</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* RAID Levels */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>RAID Configurations</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>RAID Level</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Min Drives</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Redundancy</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Capacity</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Use Case</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { level: "RAID 0 (Stripe)", min: "2", redun: "None", cap: "100%", use: "Performance, non-critical data" },
                    { level: "RAID 1 (Mirror)", min: "2", redun: "1 drive", cap: "50%", use: "OS drive, critical data" },
                    { level: "RAID 5 (Parity)", min: "3", redun: "1 drive", cap: "(N-1)/N", use: "NAS, file servers" },
                    { level: "RAID 6 (Dual Parity)", min: "4", redun: "2 drives", cap: "(N-2)/N", use: "Large arrays, archives" },
                    { level: "RAID 10 (1+0)", min: "4", redun: "1 per mirror", cap: "50%", use: "Databases, high performance" },
                  ].map((row) => (
                    <TableRow key={row.level}>
                      <TableCell sx={{ fontWeight: 600, color: "#f59e0b" }}>{row.level}</TableCell>
                      <TableCell>{row.min}</TableCell>
                      <TableCell>{row.redun}</TableCell>
                      <TableCell>{row.cap}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.use}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Storage Health & Monitoring */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Storage Health Monitoring</Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>S.M.A.R.T. Attributes</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Reallocated Sectors:</strong> Bad sector count</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Power-On Hours:</strong> Total usage time</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Temperature:</strong> Current/max temps</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Pending Sectors:</strong> Sectors awaiting remap</Typography>
                  <Typography variant="body2">• <strong>TBW (SSD):</strong> Terabytes Written lifetime</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Monitoring Tools</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>CrystalDiskInfo:</strong> Windows S.M.A.R.T. viewer</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>CrystalDiskMark:</strong> Benchmark speeds</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>HD Sentinel:</strong> Health monitoring</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Manufacturer Tools:</strong> Samsung Magician, WD Dashboard</Typography>
                  <Typography variant="body2">• <strong>TRIM:</strong> SSD garbage collection (enabled by default)</Typography>
                </Paper>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* PSU */}
        <Accordion id="psu" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#8b5cf6", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <PowerIcon sx={{ color: "#8b5cf6" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>PSU (Power Supply Unit)</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              Converts AC power from the wall outlet to regulated DC power for computer components. 
              A quality PSU is critical for system stability, efficiency, and component longevity.
            </Alert>
            
            {/* 80+ Efficiency */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>80 PLUS Efficiency Ratings</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Rating</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>20% Load</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>50% Load</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>100% Load</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Target Market</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { rating: "80+ White", l20: "80%", l50: "80%", l100: "80%", market: "Budget systems" },
                    { rating: "80+ Bronze", l20: "82%", l50: "85%", l100: "82%", market: "Entry-level, office" },
                    { rating: "80+ Silver", l20: "85%", l50: "88%", l100: "85%", market: "Mainstream" },
                    { rating: "80+ Gold", l20: "87%", l50: "90%", l100: "87%", market: "Gaming, enthusiast" },
                    { rating: "80+ Platinum", l20: "90%", l50: "92%", l100: "89%", market: "High-end, workstation" },
                    { rating: "80+ Titanium", l20: "92%", l50: "94%", l100: "90%", market: "Server, enterprise" },
                  ].map((row) => (
                    <TableRow key={row.rating}>
                      <TableCell sx={{ fontWeight: 600, color: "#8b5cf6" }}>{row.rating}</TableCell>
                      <TableCell>{row.l20}</TableCell>
                      <TableCell>{row.l50}</TableCell>
                      <TableCell>{row.l100}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.market}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Modularity */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>PSU Modularity Types</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#8b5cf6", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6" }}>Non-Modular</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>All cables permanently attached</Typography>
                  <Typography variant="body2">✅ Cheapest option</Typography>
                  <Typography variant="body2">✅ No lost cables</Typography>
                  <Typography variant="body2">❌ Cable clutter</Typography>
                  <Typography variant="body2">❌ Harder to manage</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#8b5cf6", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6" }}>Semi-Modular</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Essential cables attached, others detachable</Typography>
                  <Typography variant="body2">✅ Good balance</Typography>
                  <Typography variant="body2">✅ 24-pin/CPU always ready</Typography>
                  <Typography variant="body2">✅ Less clutter</Typography>
                  <Typography variant="body2">❌ Some fixed cables</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#8b5cf6", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6" }}>Fully Modular</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>All cables detachable</Typography>
                  <Typography variant="body2">✅ Best cable management</Typography>
                  <Typography variant="body2">✅ Custom cable options</Typography>
                  <Typography variant="body2">✅ Cleanest builds</Typography>
                  <Typography variant="body2">❌ Most expensive</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Connectors */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>PSU Connectors & Cables</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Connector</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Pins</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Voltage</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { conn: "ATX 24-pin", pins: "24 (20+4)", volt: "3.3V, 5V, 12V", purpose: "Main motherboard power" },
                    { conn: "EPS 8-pin", pins: "8 (4+4)", volt: "12V", purpose: "CPU power" },
                    { conn: "PCIe 8-pin", pins: "8 (6+2)", volt: "12V", purpose: "GPU power (150W)" },
                    { conn: "PCIe 12VHPWR", pins: "16", volt: "12V", purpose: "RTX 40 series (up to 600W)" },
                    { conn: "SATA Power", pins: "15", volt: "3.3V, 5V, 12V", purpose: "Storage drives" },
                    { conn: "Molex 4-pin", pins: "4", volt: "5V, 12V", purpose: "Legacy fans, drives" },
                    { conn: "Floppy 4-pin", pins: "4", volt: "5V, 12V", purpose: "Legacy (rare)" },
                  ].map((row) => (
                    <TableRow key={row.conn}>
                      <TableCell sx={{ fontWeight: 600, color: "#8b5cf6" }}>{row.conn}</TableCell>
                      <TableCell>{row.pins}</TableCell>
                      <TableCell>{row.volt}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.purpose}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* ATX 3.0 & PCIe 5.0 */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>ATX 3.0 and PCIe 5.0 Power</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>What's New</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>ATX 3.0:</strong> Designed for modern GPUs with short power spikes.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>12VHPWR:</strong> Single cable delivers up to 600W for high-end GPUs.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>12V-2x6:</strong> Updated connector with improved sensing pins.
                  </Typography>
                  <Typography variant="body2">
                    <strong>Efficiency targets:</strong> Better low-load efficiency and standby power.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>Build Tips</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Use native cables:</strong> Avoid splitters if a 12VHPWR cable is provided.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Check seating:</strong> Fully insert the connector until it clicks.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Prevent sharp bends:</strong> Reduce strain near the connector.
                  </Typography>
                  <Typography variant="body2">
                    <strong>Room for airflow:</strong> High-end GPUs increase case heat load.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Wattage Calculator */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Wattage Guidelines</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>Typical System Requirements</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Office PC:</strong> 300-400W</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Gaming (Mid):</strong> 550-650W</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Gaming (High):</strong> 750-850W</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Enthusiast:</strong> 1000W+</Typography>
                  <Typography variant="body2">• <strong>Rule:</strong> Target 50-80% load for best efficiency</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>Component Power Draw</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>CPU:</strong> 65-250W (check TDP)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>GPU:</strong> 75-450W (check TBP)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Motherboard:</strong> 50-80W</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>RAM:</strong> 3-5W per stick</Typography>
                  <Typography variant="body2">• <strong>Storage:</strong> 5-15W per drive</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Rails & Protections */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Rails & Safety Features</Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>Power Rails</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>+12V Rail:</strong> CPU, GPU, drives (main power)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>+5V Rail:</strong> USB, SATA, logic circuits</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>+3.3V Rail:</strong> RAM, chipset, low-power</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>-12V Rail:</strong> Legacy (minimal use)</Typography>
                  <Typography variant="body2">• <strong>+5VSB:</strong> Standby power (always on)</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>Protection Features</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>OVP:</strong> Over Voltage Protection</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>UVP:</strong> Under Voltage Protection</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>OCP:</strong> Over Current Protection</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>OPP:</strong> Over Power Protection</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>SCP:</strong> Short Circuit Protection</Typography>
                  <Typography variant="body2">• <strong>OTP:</strong> Over Temperature Protection</Typography>
                </Paper>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* GPU */}
        <Accordion id="gpu" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#06b6d4", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <SpeedIcon sx={{ color: "#06b6d4" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#06b6d4" }}>GPU (Graphics Processing Unit)</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              Handles graphics rendering, video output, and parallel processing tasks. GPUs contain 
              thousands of cores optimized for simultaneous calculations, making them essential for 
              gaming, content creation, AI/ML, and scientific computing.
            </Alert>
            
            {/* GPU Types */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>GPU Types</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#06b6d4", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Integrated Graphics (iGPU)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Built into the CPU die</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Shares system RAM (no dedicated VRAM)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Lower power consumption</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Intel UHD/Iris:</strong> Basic tasks, light gaming</Typography>
                  <Typography variant="body2">• <strong>AMD APUs:</strong> Radeon Graphics (stronger gaming)</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#06b6d4", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Discrete Graphics (dGPU)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Separate expansion card</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Dedicated VRAM (GDDR6/GDDR6X)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Much higher performance</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Requires PCIe slot and power connectors</Typography>
                  <Typography variant="body2">• <strong>Examples:</strong> GeForce, Radeon, Quadro, Pro</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* NVIDIA vs AMD */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>NVIDIA vs AMD Comparison</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: "#76b900", borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#76b900", mb: 2 }}>NVIDIA GeForce</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}><strong>Current Gen:</strong> RTX 40 Series (Ada Lovelace)</Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Product Tiers:</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>RTX 4060/Ti:</strong> 1080p gaming</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>RTX 4070/Ti/Super:</strong> 1440p gaming</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>RTX 4080/Super:</strong> 4K gaming</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>• <strong>RTX 4090:</strong> Flagship, 4K/8K</Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Key Features:</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• RT Cores: Ray tracing acceleration</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Tensor Cores: AI/DLSS upscaling</Typography>
                  <Typography variant="body2">• NVENC: Hardware video encoding</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: "#ed1c24", borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ed1c24", mb: 2 }}>AMD Radeon</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}><strong>Current Gen:</strong> RX 7000 Series (RDNA 3)</Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Product Tiers:</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>RX 7600:</strong> 1080p gaming</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>RX 7700 XT:</strong> 1440p gaming</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>RX 7800 XT:</strong> 1440p high</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>• <strong>RX 7900 XT/XTX:</strong> 4K gaming</Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Key Features:</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• Ray Accelerators: RT hardware</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• FSR: FidelityFX upscaling</Typography>
                  <Typography variant="body2">• VCN: Video Core Next encoding</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* GPU Specs Explained */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Understanding GPU Specifications</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Specification</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Impact</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { spec: "CUDA/Stream Processors", desc: "Parallel processing cores", impact: "Raw compute power" },
                    { spec: "VRAM Amount", desc: "Video memory (6-24GB)", impact: "Texture quality, resolution, AI models" },
                    { spec: "VRAM Type", desc: "GDDR6, GDDR6X, HBM3", impact: "Memory bandwidth" },
                    { spec: "Memory Bus", desc: "128-384 bit width", impact: "Data transfer rate" },
                    { spec: "Base Clock", desc: "Guaranteed core frequency", impact: "Minimum performance" },
                    { spec: "Boost Clock", desc: "Maximum turbo frequency", impact: "Peak performance" },
                    { spec: "TBP/TDP", desc: "Total Board Power", impact: "PSU requirements, heat" },
                  ].map((row) => (
                    <TableRow key={row.spec}>
                      <TableCell sx={{ fontWeight: 600, color: "#06b6d4" }}>{row.spec}</TableCell>
                      <TableCell>{row.desc}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.impact}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Cooling & Form Factor */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Cooling & Physical Fit</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Cooling Styles</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Open-air:</strong> Multiple fans, best for well-ventilated cases.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Blower:</strong> Exhausts heat out the back, louder but controlled airflow.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Hybrid/AIO:</strong> Liquid cooling for lower temps and noise.
                  </Typography>
                  <Typography variant="body2">
                    <strong>Thermal limits:</strong> Modern GPUs throttle to protect themselves.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Case Compatibility</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Length/height:</strong> Check case clearance before purchase.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Slot width:</strong> Many cards are 2.5 to 4 slots thick.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    <strong>Power connectors:</strong> Verify PCIe or 12VHPWR requirements.
                  </Typography>
                  <Typography variant="body2">
                    <strong>Support brackets:</strong> Prevent sag on heavy cards.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Display Outputs */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Display Outputs & Standards</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Common Outputs</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>HDMI 2.1:</strong> 4K@120Hz, 8K@60Hz, VRR</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>DisplayPort 2.0:</strong> 8K@60Hz, DSC</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>USB-C:</strong> DP Alt Mode, power delivery</Typography>
                  <Typography variant="body2">• <strong>DVI-D:</strong> Legacy (being phased out)</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Sync Technologies</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>V-Sync:</strong> Locks to display refresh (input lag)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>G-Sync:</strong> NVIDIA variable refresh rate</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>FreeSync:</strong> AMD variable refresh rate</Typography>
                  <Typography variant="body2">• <strong>HDMI VRR:</strong> Standard variable refresh</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Professional & Workstation GPUs */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Professional/Workstation GPUs</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Brand</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Product Line</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Use Cases</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Key Features</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { brand: "NVIDIA", line: "RTX A-Series / Quadro", use: "CAD, 3D modeling, video", feat: "ECC VRAM, ISV certification, multi-GPU" },
                    { brand: "NVIDIA", line: "Data Center (H100, A100)", use: "AI training, HPC", feat: "HBM memory, NVLink, massive VRAM" },
                    { brand: "AMD", line: "Radeon Pro", use: "CAD, content creation", feat: "ISV certification, ECC memory" },
                    { brand: "AMD", line: "Instinct", use: "AI/ML, data center", feat: "HBM memory, high compute" },
                    { brand: "Intel", line: "Arc Pro", use: "Content creation", feat: "AV1 encoding, ray tracing" },
                  ].map((row) => (
                    <TableRow key={row.line}>
                      <TableCell sx={{ fontWeight: 600 }}>{row.brand}</TableCell>
                      <TableCell sx={{ fontWeight: 600, color: "#06b6d4" }}>{row.line}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.use}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.feat}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* ========== CABLES & CONNECTORS SECTION ========== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 6 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>COOLING & THERMAL MANAGEMENT</Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Cooling Systems */}
        <Accordion id="cooling" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#06b6d4", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <ThermostatIcon sx={{ color: "#06b6d4" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#06b6d4" }}>Cooling Systems & Thermal Management</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              Heat is the enemy of computer components. Every electrical component generates heat, and if not properly 
              dissipated, it leads to thermal throttling, instability, and premature failure. Effective cooling is 
              essential for performance and longevity.
            </Alert>

            {/* Why Cooling Matters */}
            <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
                🌡️ Why Cooling Matters: The Pizza Oven Analogy
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                Think of your CPU like a tiny pizza oven that's constantly running. The oven (CPU) does useful work, 
                but it produces a lot of heat as a byproduct. If you don't vent that heat, the oven gets hotter and 
                hotter until it starts burning everything (thermal throttling) or shuts down to protect itself.
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                <strong>What happens when components overheat?</strong>
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                • <strong>Thermal Throttling:</strong> The CPU/GPU automatically reduces speed to generate less heat. 
                Performance drops, but damage is prevented.
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                • <strong>System Instability:</strong> Random crashes, blue screens, and freezes often trace back to 
                overheating components.
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                • <strong>Reduced Lifespan:</strong> Constant high temperatures accelerate component degradation 
                through electromigration and other effects.
              </Typography>
              <Typography variant="body2">
                • <strong>Emergency Shutdown:</strong> At critical temps (usually 100-105°C for CPUs), systems 
                will power off immediately to prevent permanent damage.
              </Typography>
            </Paper>

            {/* Cooling Types */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Types of CPU Coolers</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#06b6d4", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Stock Coolers</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Included with most CPUs</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✅ Free with CPU purchase</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✅ Adequate for stock speeds</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✅ Easy installation</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>❌ Limited cooling capacity</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>❌ Often louder under load</Typography>
                  <Typography variant="body2">❌ Not suitable for overclocking</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#06b6d4", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Tower Air Coolers</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Heat pipes + heatsink + fan(s)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✅ Excellent performance/price</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✅ No pump failure risk</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✅ Often very quiet</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✅ Good for overclocking</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>❌ Large, may block RAM</Typography>
                  <Typography variant="body2">❌ Heavy (check case support)</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#06b6d4", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>AIO Liquid Coolers</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Closed-loop water cooling</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✅ Excellent cooling capacity</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✅ Compact CPU block</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✅ Great for overclocking</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✅ Aesthetic appeal</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>❌ Pump failure risk</Typography>
                  <Typography variant="body2">❌ More expensive</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* How Air Cooling Works */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>How Air Cooling Works</Typography>
            <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#06b6d4", 0.02), borderRadius: 2 }}>
              <Typography variant="body2" sx={{ mb: 2 }}>
                Air cooling relies on three principles: <strong>conduction, convection, and thermal mass</strong>.
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={3}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>1. Contact</Typography>
                  <Typography variant="body2">
                    The cooler's base plate makes direct contact with the CPU's IHS (Integrated Heat Spreader). 
                    Thermal paste fills microscopic gaps for better heat transfer.
                  </Typography>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>2. Heat Pipes</Typography>
                  <Typography variant="body2">
                    Sealed copper pipes containing fluid that evaporates at the hot end and condenses at the cold 
                    end, rapidly moving heat away from the CPU.
                  </Typography>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>3. Heatsink</Typography>
                  <Typography variant="body2">
                    Aluminum or copper fins provide massive surface area for heat to dissipate into the 
                    surrounding air through convection.
                  </Typography>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>4. Fans</Typography>
                  <Typography variant="body2">
                    Fans force air through the heatsink fins, replacing warm air with cool air and dramatically 
                    improving heat dissipation.
                  </Typography>
                </Grid>
              </Grid>
            </Paper>

            {/* AIO Liquid Cooling Explained */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>How AIO Liquid Cooling Works</Typography>
            <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#06b6d4", 0.02), borderRadius: 2 }}>
              <Typography variant="body2" sx={{ mb: 2 }}>
                All-In-One (AIO) liquid coolers use water's superior heat capacity to move heat from the CPU to a 
                remote radiator:
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={3}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>CPU Block</Typography>
                  <Typography variant="body2">
                    A copper plate contacts the CPU and contains channels where coolant absorbs heat. 
                    An integrated pump circulates the liquid.
                  </Typography>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Tubes</Typography>
                  <Typography variant="body2">
                    Flexible rubber or braided tubes carry warm coolant to the radiator and return cool 
                    coolant to the CPU block.
                  </Typography>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Radiator</Typography>
                  <Typography variant="body2">
                    Available in 120mm, 240mm, 280mm, 360mm, etc. Larger radiators have more surface area 
                    for better heat dissipation.
                  </Typography>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Fans</Typography>
                  <Typography variant="body2">
                    Mounted on the radiator to pull or push air through the fins. Can be configured as 
                    intake or exhaust depending on case layout.
                  </Typography>
                </Grid>
              </Grid>
            </Paper>

            {/* Radiator Sizes */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>AIO Radiator Size Guide</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Radiator Size</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Fan Configuration</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Cooling Capacity</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Best For</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { size: "120mm", fans: "1x 120mm", cap: "~150W TDP", best: "ITX builds, budget AIOs" },
                    { size: "240mm", fans: "2x 120mm", cap: "~200W TDP", best: "Mainstream CPUs (i5, R5)" },
                    { size: "280mm", fans: "2x 140mm", cap: "~250W TDP", best: "High-end CPUs, quieter" },
                    { size: "360mm", fans: "3x 120mm", cap: "~300W TDP", best: "i7/i9, R7/R9, overclocking" },
                    { size: "420mm", fans: "3x 140mm", cap: "~350W TDP", best: "HEDT, extreme overclocking" },
                  ].map((row) => (
                    <TableRow key={row.size}>
                      <TableCell sx={{ fontWeight: 600, color: "#06b6d4" }}>{row.size}</TableCell>
                      <TableCell>{row.fans}</TableCell>
                      <TableCell>{row.cap}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.best}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Thermal Paste */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Thermal Paste Guide</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>What It Does</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    Even with seemingly flat surfaces, microscopic imperfections create tiny air gaps between the 
                    CPU and cooler. Air is a terrible thermal conductor, so thermal paste fills these gaps with a 
                    thermally conductive compound, improving heat transfer by up to 10-15°C.
                  </Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Types of Thermal Paste</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Ceramic/Silicon:</strong> Non-conductive, safe, moderate performance
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Metal-based:</strong> Best performance, electrically conductive (risky)
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Carbon-based:</strong> Good performance, non-conductive, easy cleanup
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Application Methods</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Pea Method:</strong> Small pea-sized dot in center. Pressure spreads it evenly.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>X Method:</strong> Thin X pattern corner-to-corner. Good for larger CPUs.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Spread Method:</strong> Manually spread thin layer. Risk of air bubbles.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    • <strong>Line Method:</strong> Thin vertical line. Works well for rectangular dies.
                  </Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Popular Brands</Typography>
                  <Typography variant="body2">
                    Noctua NT-H1, Thermal Grizzly Kryonaut, Arctic MX-4, Cooler Master MasterGel
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Case Airflow */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Case Airflow Best Practices</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Positive Pressure</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    More intake fans than exhaust. Air enters through filtered intakes, exits through gaps. 
                    <strong> Reduces dust accumulation</strong> since unfiltered gaps push air out, not in.
                  </Typography>
                  <Typography variant="body2">
                    <strong>Example:</strong> 3 front intake, 1 rear exhaust
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Negative Pressure</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    More exhaust than intake. Pulls air through any opening. <strong>Better cooling</strong> 
                    but dust enters unfiltered openings.
                  </Typography>
                  <Typography variant="body2">
                    <strong>Example:</strong> 1 rear + 2 top exhaust, 1 front intake
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Balanced/Neutral</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    Equal intake and exhaust. Good airflow but still allows dust through unfiltered gaps. 
                    <strong> Common default configuration.</strong>
                  </Typography>
                  <Typography variant="body2">
                    <strong>Example:</strong> 2 front intake, 2 rear/top exhaust
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Fan Specifications */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Understanding Fan Specifications</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Specification</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>What It Means</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Higher Value Means</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { spec: "RPM (Speed)", meaning: "Revolutions per minute", higher: "More airflow but more noise" },
                    { spec: "CFM (Airflow)", meaning: "Cubic feet per minute of air moved", higher: "Better for case fans, open heatsinks" },
                    { spec: "Static Pressure (mmH₂O)", meaning: "Force of air pushed through resistance", higher: "Better for radiators, dense heatsinks" },
                    { spec: "dB(A) (Noise)", meaning: "Sound level at max speed", higher: "Louder (look for <25dB for quiet)" },
                    { spec: "PWM", meaning: "4-pin, speed controlled by motherboard", higher: "Dynamic speed based on temp" },
                    { spec: "DC", meaning: "3-pin, speed controlled by voltage", higher: "Simpler but less precise control" },
                  ].map((row) => (
                    <TableRow key={row.spec}>
                      <TableCell sx={{ fontWeight: 600, color: "#06b6d4" }}>{row.spec}</TableCell>
                      <TableCell>{row.meaning}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.higher}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* ========== CABLES & CONNECTORS SECTION ========== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 6 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>CABLES & CONNECTORS</Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Video Cables */}
        <Accordion id="video-cables" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ec4899", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <SettingsInputHdmiIcon sx={{ color: "#ec4899" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#ec4899" }}>Video/Display Cables</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              Display cables carry video signals from GPU to monitor. Modern cables also support audio, 
              variable refresh rate (VRR), and high dynamic range (HDR).
            </Alert>

            {/* Modern Standards */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Modern Display Standards</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#ec4899", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Standard</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Max Resolution</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Max Refresh</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Bandwidth</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Features</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { std: "HDMI 2.1a", res: "10K", refresh: "120Hz (4K)", bw: "48 Gbps", feat: "VRR, ALLM, eARC, QMS" },
                    { std: "HDMI 2.0b", res: "4K", refresh: "60Hz (4K)", bw: "18 Gbps", feat: "HDR10, HLG, 4:4:4" },
                    { std: "DisplayPort 2.1", res: "16K", refresh: "240Hz (4K)", bw: "80 Gbps", feat: "DSC, HDR, MST" },
                    { std: "DisplayPort 1.4a", res: "8K", refresh: "120Hz (4K)", bw: "32.4 Gbps", feat: "HDR10, DSC, MST" },
                    { std: "Thunderbolt 4", res: "8K", refresh: "60Hz (dual 4K)", bw: "40 Gbps", feat: "DP 2.0 Alt Mode, USB4" },
                    { std: "USB-C DP Alt", res: "8K", refresh: "60Hz", bw: "32.4 Gbps", feat: "Power delivery, data" },
                  ].map((row) => (
                    <TableRow key={row.std}>
                      <TableCell sx={{ fontWeight: 600, color: "#ec4899" }}>{row.std}</TableCell>
                      <TableCell>{row.res}</TableCell>
                      <TableCell>{row.refresh}</TableCell>
                      <TableCell>{row.bw}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.feat}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* HDMI Details */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>HDMI (High-Definition Multimedia Interface)</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ec4899", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>HDMI Connector Types</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Type A:</strong> Standard (19 pins) - TVs, monitors</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Type C (Mini):</strong> Smaller devices, cameras</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Type D (Micro):</strong> Mobile devices, tablets</Typography>
                  <Typography variant="body2">• <strong>Type E:</strong> Automotive (locking connector)</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ec4899", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>HDMI 2.1 Features</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>VRR:</strong> Variable Refresh Rate</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>ALLM:</strong> Auto Low Latency Mode</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>eARC:</strong> Enhanced Audio Return Channel</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>QFT:</strong> Quick Frame Transport</Typography>
                  <Typography variant="body2">• <strong>DSC:</strong> Display Stream Compression</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* DisplayPort Details */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>DisplayPort</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ec4899", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>DP Connector Types</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Full Size DP:</strong> Standard 20-pin connector</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Mini DisplayPort:</strong> Laptops, compact devices</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>USB-C Alt Mode:</strong> DP over USB-C cable</Typography>
                  <Typography variant="body2">• <strong>Locking mechanism:</strong> Prevents accidental disconnect</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ec4899", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>DP Unique Features</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>MST:</strong> Multi-Stream Transport (daisy chain)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Adaptive Sync:</strong> FreeSync/G-Sync Compatible</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>DSC:</strong> 3:1 compression for higher res</Typography>
                  <Typography variant="body2">• <strong>No licensing:</strong> Royalty-free standard</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Legacy Standards */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Legacy Display Standards</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#ec4899", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Standard</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Signal Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Max Resolution</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Audio</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { std: "DVI-D (Dual Link)", sig: "Digital", res: "2560×1600@60Hz", audio: "No", notes: "24+1 pins, common on older GPUs" },
                    { std: "DVI-I", sig: "Digital + Analog", res: "1920×1200@60Hz", audio: "No", notes: "29 pins, VGA adapter compatible" },
                    { std: "VGA (D-Sub)", sig: "Analog", res: "2048×1536@85Hz", audio: "No", notes: "15-pin, legacy CRT/LCD" },
                    { std: "Component (YPbPr)", sig: "Analog", res: "1080i", audio: "No", notes: "3 RCA cables, older TVs" },
                    { std: "Composite (RCA)", sig: "Analog", res: "480i", audio: "Separate", notes: "Single yellow cable, lowest quality" },
                    { std: "S-Video", sig: "Analog", res: "480i", audio: "No", notes: "4-pin mini-DIN, better than composite" },
                  ].map((row) => (
                    <TableRow key={row.std}>
                      <TableCell sx={{ fontWeight: 600, color: "#ec4899" }}>{row.std}</TableCell>
                      <TableCell>{row.sig}</TableCell>
                      <TableCell>{row.res}</TableCell>
                      <TableCell>{row.audio}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.notes}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* USB */}
        <Accordion id="usb-cables" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#14b8a6", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <UsbIcon sx={{ color: "#14b8a6" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#14b8a6" }}>USB Standards & Connectors</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              Universal Serial Bus (USB) is the standard for connecting peripherals. Modern USB standards 
              support data transfer, power delivery, and alternate modes for video output.
            </Alert>

            {/* USB Standards */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>USB Standards & Speeds</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#14b8a6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Standard</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Marketing Name</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Speed</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Max Power</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Connectors</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { std: "USB 1.1", mkt: "Full-Speed", speed: "12 Mbps", power: "500mA (2.5W)", conn: "Type-A, Type-B" },
                    { std: "USB 2.0", mkt: "Hi-Speed", speed: "480 Mbps", power: "500mA (2.5W)", conn: "Type-A, Mini, Micro" },
                    { std: "USB 3.2 Gen 1", mkt: "SuperSpeed", speed: "5 Gbps", power: "900mA (4.5W)", conn: "Type-A (blue), Type-C" },
                    { std: "USB 3.2 Gen 2", mkt: "SuperSpeed+", speed: "10 Gbps", power: "3A (15W)", conn: "Type-A, Type-C" },
                    { std: "USB 3.2 Gen 2x2", mkt: "SuperSpeed 20Gbps", speed: "20 Gbps", power: "3A (15W)", conn: "Type-C only" },
                    { std: "USB4 Gen 2x2", mkt: "USB4 20Gbps", speed: "20 Gbps", power: "100W (PD)", conn: "Type-C only" },
                    { std: "USB4 Gen 3x2", mkt: "USB4 40Gbps", speed: "40 Gbps", power: "240W (EPR)", conn: "Type-C only" },
                    { std: "USB4 v2.0", mkt: "USB4 80Gbps", speed: "80 Gbps", power: "240W (EPR)", conn: "Type-C only" },
                  ].map((row) => (
                    <TableRow key={row.std}>
                      <TableCell sx={{ fontWeight: 600, color: "#14b8a6" }}>{row.std}</TableCell>
                      <TableCell>{row.mkt}</TableCell>
                      <TableCell>{row.speed}</TableCell>
                      <TableCell>{row.power}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.conn}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Connector Types */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>USB Connector Types</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={6} md={3}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#14b8a6", 0.3), borderRadius: 2, textAlign: "center", height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#14b8a6" }}>Type-A</Typography>
                  <Typography variant="body2" color="text.secondary">Standard rectangular</Typography>
                  <Typography variant="body2">Hosts, hubs, chargers</Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} md={3}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#14b8a6", 0.3), borderRadius: 2, textAlign: "center", height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#14b8a6" }}>Type-B</Typography>
                  <Typography variant="body2" color="text.secondary">Square connector</Typography>
                  <Typography variant="body2">Printers, scanners</Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} md={3}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#14b8a6", 0.3), borderRadius: 2, textAlign: "center", height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#14b8a6" }}>Type-C</Typography>
                  <Typography variant="body2" color="text.secondary">Reversible oval</Typography>
                  <Typography variant="body2">Modern universal</Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} md={3}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#14b8a6", 0.3), borderRadius: 2, textAlign: "center", height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#14b8a6" }}>Micro-B</Typography>
                  <Typography variant="body2" color="text.secondary">Small flat connector</Typography>
                  <Typography variant="body2">Phones, devices</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* USB Type-C Features */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>USB Type-C Capabilities</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#14b8a6", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#14b8a6", mb: 1 }}>Power Delivery (PD)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Standard:</strong> 5V, 9V, 15V, 20V</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>PD 3.0:</strong> Up to 100W (20V @ 5A)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>PD 3.1 (EPR):</strong> Up to 240W (48V @ 5A)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>PPS:</strong> Programmable Power Supply</Typography>
                  <Typography variant="body2">• <strong>Fast charging:</strong> Negotiates optimal voltage</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#14b8a6", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#14b8a6", mb: 1 }}>Alternate Modes</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>DisplayPort:</strong> Video output via DP Alt Mode</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>HDMI:</strong> HDMI Alt Mode (less common)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Thunderbolt:</strong> 40/80 Gbps, PCIe tunneling</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>MHL:</strong> Mobile High-Definition Link</Typography>
                  <Typography variant="body2">• <strong>Audio:</strong> USB Audio Class (headphones)</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Color Coding */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>USB Port Color Coding</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#14b8a6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Color</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Standard</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Speed</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { color: "⬛ Black", std: "USB 2.0", speed: "480 Mbps", notes: "Hi-Speed, most peripherals" },
                    { color: "🟦 Blue", std: "USB 3.0/3.1 Gen 1", speed: "5 Gbps", notes: "SuperSpeed, internal pins" },
                    { color: "🔷 Teal/Cyan", std: "USB 3.1 Gen 2", speed: "10 Gbps", notes: "SuperSpeed+" },
                    { color: "🟥 Red", std: "USB 3.2 Gen 2x2", speed: "20 Gbps", notes: "Or always-on charging port" },
                    { color: "🟨 Yellow", std: "Always-On/Sleep", speed: "Varies", notes: "Charges when PC is off" },
                    { color: "🟩 Green", std: "Qualcomm Quick Charge", speed: "Varies", notes: "Fast charging support" },
                  ].map((row) => (
                    <TableRow key={row.color}>
                      <TableCell sx={{ fontWeight: 600 }}>{row.color}</TableCell>
                      <TableCell sx={{ color: "#14b8a6" }}>{row.std}</TableCell>
                      <TableCell>{row.speed}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.notes}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Internal Cables */}
        <Accordion id="internal-cables" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#f97316", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <CableIcon sx={{ color: "#f97316" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#f97316" }}>Internal Cables & Power Connectors</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              Internal cables connect your components inside the case. Understanding these cables is essential 
              for building PCs, upgrading hardware, and troubleshooting power or connectivity issues.
            </Alert>

            {/* Beginner Guide */}
            <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#f97316", 0.03), borderRadius: 2 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
                🔌 Internal Cables: The Nervous System
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                Think of internal cables as your PC's nervous system. Just like nerves carry signals and blood 
                vessels carry nutrients throughout your body, internal cables carry <strong>data</strong> (commands 
                and information) and <strong>power</strong> (electricity) to every component.
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                <strong>Good news for beginners:</strong> Modern connectors are designed to only fit one way! 
                You literally cannot plug most cables in wrong - the shapes, keying, and pin layouts prevent it. 
                If it doesn't slide in smoothly, don't force it - you probably have it backwards or it's the 
                wrong connector.
              </Typography>
              <Typography variant="body2">
                <strong>Exception:</strong> Front panel connectors (power button, LED, etc.) are tiny individual 
                pins that require checking your motherboard manual. These are the trickiest part of any PC build, 
                but getting them wrong just means buttons/lights won't work - it won't damage anything.
              </Typography>
            </Paper>

            {/* Power Cables */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Power Cables (From PSU)</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#f97316", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Connector</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Pins</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Connects To</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Power Rating</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { conn: "24-pin ATX", pins: "24 (20+4)", to: "Motherboard main power", power: "Up to 300W", notes: "Required for all builds, clips in firmly" },
                    { conn: "8-pin EPS/CPU", pins: "8 (4+4)", to: "CPU power (near socket)", power: "~300W", notes: "Required for CPU, some boards need 2" },
                    { conn: "6-pin PCIe", pins: "6", to: "Graphics card", power: "75W", notes: "Budget/mid GPUs, one cable often" },
                    { conn: "8-pin PCIe", pins: "8 (6+2)", to: "Graphics card", power: "150W", notes: "High-end GPUs, may need multiple" },
                    { conn: "12VHPWR", pins: "16 (12+4)", to: "RTX 40-series GPUs", power: "Up to 600W", notes: "New standard, includes sense pins" },
                    { conn: "SATA Power", pins: "15", to: "Storage, fans, RGB", power: "~55W total", notes: "L-shaped, don't force orientation" },
                    { conn: "Molex 4-pin", pins: "4", to: "Legacy devices", power: "~150W", notes: "Old standard, adapters available" },
                    { conn: "Floppy 4-pin", pins: "4 (small)", to: "Fan controllers, some cards", power: "~10W", notes: "Rare, small Berg connector" },
                  ].map((row) => (
                    <TableRow key={row.conn}>
                      <TableCell sx={{ fontWeight: 600, color: "#f97316" }}>{row.conn}</TableCell>
                      <TableCell>{row.pins}</TableCell>
                      <TableCell>{row.to}</TableCell>
                      <TableCell>{row.power}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.notes}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Data Cables */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Data Cables</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f97316", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>SATA Data Cables</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>What:</strong> Flat cables with L-shaped connectors connecting storage drives to motherboard.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>Speed:</strong> SATA III = 6 Gbps (~550 MB/s practical max)
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>Length:</strong> Typically 30-50cm, don't exceed 1 meter.
                  </Typography>
                  <Typography variant="body2">
                    <strong>Tip:</strong> Look for cables with metal latches for secure connections. Straight and 
                    90-degree angled ends available for different case layouts.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f97316", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>Front Panel Headers</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>What:</strong> Tiny cables connecting case buttons/LEDs to motherboard.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>Includes:</strong> Power SW, Reset SW, HDD LED, Power LED (+/-)
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>Polarity:</strong> Switches don't care, LEDs do (check + and - labels).
                  </Typography>
                  <Typography variant="body2">
                    <strong>Tip:</strong> Consult motherboard manual for exact layout. Many boards include a 
                    Q-connector to make this easier.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* USB Headers */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Internal USB Headers</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#f97316", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Header Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Pins</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>USB Version</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Speed</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Common Uses</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { header: "USB 2.0 Header", pins: "9-pin (10 with key)", ver: "USB 2.0", speed: "480 Mbps", use: "Front USB 2.0 ports, card readers, RGB controllers" },
                    { header: "USB 3.0 Header", pins: "19-pin (20 with key)", ver: "USB 3.2 Gen 1", speed: "5 Gbps", use: "Front USB 3.0 ports (blue internal)" },
                    { header: "USB 3.1 Header", pins: "20-pin (Key-A)", ver: "USB 3.2 Gen 2", speed: "10 Gbps", use: "Front USB 3.1 ports, newer cases" },
                    { header: "USB-C Header", pins: "20-pin (Key-A)", ver: "USB 3.2 Gen 2", speed: "10 Gbps", use: "Front USB-C ports, may need adapter" },
                  ].map((row) => (
                    <TableRow key={row.header}>
                      <TableCell sx={{ fontWeight: 600, color: "#f97316" }}>{row.header}</TableCell>
                      <TableCell>{row.pins}</TableCell>
                      <TableCell>{row.ver}</TableCell>
                      <TableCell>{row.speed}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.use}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Fan and RGB Headers */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Fan & RGB Headers</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f97316", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>Fan Headers</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>3-pin DC:</strong> Speed controlled by voltage. Less precise, always-on or stepped.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>4-pin PWM:</strong> Speed controlled by pulse width modulation. Precise temp-based control.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>CPU_FAN:</strong> Dedicated header for CPU cooler. System may not boot without it.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>SYS_FAN:</strong> For case fans. Usually multiple available.
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Pump Header:</strong> For AIO pumps. Runs at full speed or has special curve.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f97316", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>RGB Headers</Typography>
                  <Alert severity="warning" sx={{ mb: 1 }}>
                    <strong>12V RGB and 5V ARGB are NOT compatible!</strong> Connecting to wrong header can damage LEDs.
                  </Alert>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>12V RGB (4-pin):</strong> All LEDs same color. Pin order: 12V-G-R-B
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>5V ARGB (3-pin):</strong> Individual LED control. Pin order: 5V-D-GND (blank pin)
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Tip:</strong> Count pins and check voltage before connecting. 4-pin = 12V, 3-pin = 5V
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Audio Headers */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Audio & Other Headers</Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f97316", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>HD Audio Header</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>9-pin header for front panel audio jacks.</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>HD Audio = modern standard (AAFP header)</Typography>
                  <Typography variant="body2">AC'97 = legacy (same connector, different pinout)</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f97316", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>TPM Header</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>For discrete TPM 2.0 modules.</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>Most modern CPUs have firmware TPM (fTPM).</Typography>
                  <Typography variant="body2">Required for Windows 11 and BitLocker.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f97316", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>Speaker Header</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>4-pin for case speaker (beep codes).</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>Useful for POST diagnostics.</Typography>
                  <Typography variant="body2">Many cases no longer include the speaker.</Typography>
                </Paper>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Network Cables */}
        <Accordion id="network-cables" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#3b82f6", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <RouterIcon sx={{ color: "#3b82f6" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6" }}>Network Cables & Connectors</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              Network cables are the backbone of wired connectivity. Understanding the differences between cable 
              categories, connector types, and when to use wired vs wireless is essential for IT professionals.
            </Alert>

            {/* Beginner Guide */}
            <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
                🌐 Network Cables: The Highway System
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                Think of network cables as highways for data. Just like highways have different lane counts and 
                speed limits, network cables have different capacities. Cat5e is like a two-lane road, Cat6 is a 
                four-lane highway, and fiber optic is a high-speed rail system.
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                <strong>Why wired over wireless?</strong> While WiFi is convenient, Ethernet cables offer:
              </Typography>
              <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Lower Latency:</strong> Critical for gaming and real-time applications</Typography>
              <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Consistent Speed:</strong> No interference from neighbors, microwaves, or walls</Typography>
              <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>More Secure:</strong> Physical access required to intercept traffic</Typography>
              <Typography variant="body2">• <strong>Higher Bandwidth:</strong> Multi-gigabit speeds readily achievable</Typography>
            </Paper>

            {/* Ethernet Cable Categories */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Ethernet Cable Categories</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#3b82f6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Max Speed</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Max Length</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Frequency</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Shielding</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Best Use Case</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { cat: "Cat 5", speed: "100 Mbps", len: "100m", freq: "100 MHz", shield: "UTP", use: "Legacy, avoid for new installs" },
                    { cat: "Cat 5e", speed: "1 Gbps", len: "100m", freq: "100 MHz", shield: "UTP", use: "Home networks, basic office" },
                    { cat: "Cat 6", speed: "10 Gbps", len: "55m (10G) / 100m (1G)", freq: "250 MHz", shield: "UTP/STP", use: "Modern standard, most installs" },
                    { cat: "Cat 6a", speed: "10 Gbps", len: "100m", freq: "500 MHz", shield: "STP", use: "PoE, data centers, professional" },
                    { cat: "Cat 7", speed: "10 Gbps", len: "100m", freq: "600 MHz", shield: "S/FTP", use: "High-interference environments" },
                    { cat: "Cat 7a", speed: "10 Gbps", len: "100m", freq: "1000 MHz", shield: "S/FTP", use: "Future-proofing, AV installs" },
                    { cat: "Cat 8", speed: "25-40 Gbps", len: "30m", freq: "2000 MHz", shield: "S/FTP", use: "Data centers, server rooms" },
                  ].map((row) => (
                    <TableRow key={row.cat}>
                      <TableCell sx={{ fontWeight: 600, color: "#3b82f6" }}>{row.cat}</TableCell>
                      <TableCell>{row.speed}</TableCell>
                      <TableCell>{row.len}</TableCell>
                      <TableCell>{row.freq}</TableCell>
                      <TableCell>{row.shield}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.use}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Shielding Types */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Cable Shielding Types</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#3b82f6", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>UTP</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Unshielded Twisted Pair</Typography>
                  <Typography variant="body2">Most common, cheapest. Fine for most home/office uses.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#3b82f6", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>STP</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Shielded Twisted Pair</Typography>
                  <Typography variant="body2">Overall shield. Better EMI protection.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#3b82f6", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>F/UTP</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Foil over unshielded pairs</Typography>
                  <Typography variant="body2">Overall foil shield, good PoE performance.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: alpha("#3b82f6", 0.3), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>S/FTP</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>Shielded + Foiled pairs</Typography>
                  <Typography variant="body2">Best protection, Cat 7/8 standard. More expensive, stiffer.</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Connectors */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Network Connectors</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>RJ-45 (8P8C)</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    The standard Ethernet connector. 8 pins, 8 contacts. Used for Cat5e through Cat8.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>T568A/T568B:</strong> Wiring standards (most use T568B)
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Straight-through:</strong> Same standard both ends (PC to switch)
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Crossover:</strong> Different standards each end (PC to PC, legacy)
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Other Network Connectors</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>RJ-11:</strong> 6P2C/6P4C, phone lines, DSL modems
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>LC/SC/ST:</strong> Fiber optic connectors (different form factors)
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>BNC:</strong> Coaxial, legacy networking (10BASE2)
                  </Typography>
                  <Typography variant="body2">
                    • <strong>F-Type:</strong> Coaxial for cable internet, TV
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Fiber Optic */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Fiber Optic Cables</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#3b82f6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Core Size</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Max Distance</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Speed</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Use Case</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { type: "Multi-Mode (OM1)", core: "62.5μm", dist: "275m (1G)", speed: "1 Gbps", use: "Legacy, short runs" },
                    { type: "Multi-Mode (OM3)", core: "50μm", dist: "300m (10G)", speed: "10-40 Gbps", use: "Building backbone" },
                    { type: "Multi-Mode (OM4)", core: "50μm", dist: "400m (10G)", speed: "10-100 Gbps", use: "Data center" },
                    { type: "Multi-Mode (OM5)", core: "50μm", dist: "440m (10G)", speed: "100+ Gbps", use: "High-density, SWDM" },
                    { type: "Single-Mode (OS1)", core: "9μm", dist: "10km", speed: "100+ Gbps", use: "Campus, long haul" },
                    { type: "Single-Mode (OS2)", core: "9μm", dist: "200km", speed: "100+ Gbps", use: "Telecom, WAN" },
                  ].map((row) => (
                    <TableRow key={row.type}>
                      <TableCell sx={{ fontWeight: 600, color: "#3b82f6" }}>{row.type}</TableCell>
                      <TableCell>{row.core}</TableCell>
                      <TableCell>{row.dist}</TableCell>
                      <TableCell>{row.speed}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.use}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* PoE */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Power over Ethernet (PoE)</Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>PoE Standards</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>PoE (802.3af):</strong> 15.4W at source, 12.95W at device
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>PoE+ (802.3at):</strong> 30W at source, 25.5W at device
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>PoE++ Type 3 (802.3bt):</strong> 60W at source, 51W at device
                  </Typography>
                  <Typography variant="body2">
                    • <strong>PoE++ Type 4 (802.3bt):</strong> 100W at source, 71W at device
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Common PoE Devices</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>IP Cameras:</strong> Simplifies installation, one cable for data + power
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Wireless Access Points:</strong> Mount anywhere with Ethernet
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>VoIP Phones:</strong> No separate power adapter needed
                  </Typography>
                  <Typography variant="body2">
                    • <strong>IoT Sensors:</strong> Lighting controllers, environmental sensors
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* ========== PERIPHERALS SECTION ========== */}
        <Box id="peripherals" sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 6 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>MOBILE & LAPTOP HARDWARE</Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Laptop Hardware */}
        <Accordion id="laptop-hardware" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#8b5cf6", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <ComputerIcon sx={{ color: "#8b5cf6" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>Laptop & Mobile Hardware</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              Laptops use specialized, compact versions of desktop components. Understanding laptop hardware is 
              essential for mobile device support, repairs, and making informed purchasing decisions. Many components 
              are soldered and non-upgradeable in modern thin laptops.
            </Alert>

            {/* Key Differences */}
            <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                💻 Desktop vs Laptop: Key Differences
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                Laptops face unique challenges: limited space, battery power constraints, and thermal limitations. 
                These constraints drive different design choices than desktops.
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Space & Form Factor</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>SO-DIMM RAM:</strong> ~½ the size of desktop DIMM modules
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>M.2 Storage:</strong> Primary storage, no room for 2.5" drives in thin laptops
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Integrated GPU:</strong> Most laptops use iGPU; gaming laptops add discrete GPU
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Custom Motherboard:</strong> Unique per model, no standardization
                  </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Power & Thermal</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Lower TDP CPUs:</strong> 15W-65W vs 65-250W desktop
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Aggressive Throttling:</strong> Heat builds up faster, more frequent throttling
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Battery Balancing:</strong> Performance vs battery life tradeoffs
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Shared Heatpipe:</strong> CPU and GPU often share cooling system
                  </Typography>
                </Grid>
              </Grid>
            </Paper>

            {/* Laptop CPU Types */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Laptop CPU Naming Conventions</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Suffix</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Brand</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>TDP Range</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Target Use</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { suffix: "U", brand: "Intel/AMD", tdp: "15-28W", use: "Ultrabooks, thin laptops, best battery life" },
                    { suffix: "P", brand: "Intel", tdp: "28W", use: "Performance thin laptops, balanced" },
                    { suffix: "H", brand: "Intel/AMD", tdp: "35-45W", use: "Gaming laptops, workstations" },
                    { suffix: "HX", brand: "Intel/AMD", tdp: "55-65W", use: "Desktop replacement, maximum performance" },
                    { suffix: "HS", brand: "AMD", tdp: "35W", use: "Thin gaming laptops, efficiency" },
                    { suffix: "HK", brand: "Intel", tdp: "45W+", use: "Unlocked for overclocking (rare)" },
                    { suffix: "G", brand: "Intel", tdp: "Various", use: "With integrated Iris graphics" },
                  ].map((row) => (
                    <TableRow key={row.suffix}>
                      <TableCell sx={{ fontWeight: 600, color: "#8b5cf6" }}>{row.suffix}</TableCell>
                      <TableCell>{row.brand}</TableCell>
                      <TableCell>{row.tdp}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.use}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Upgradeable vs Soldered */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Upgradeable vs Soldered Components</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>✅ Usually Upgradeable</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>RAM (some models):</strong> SO-DIMM slots, check specs before buying
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Storage:</strong> M.2 NVMe/SATA usually replaceable
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>WiFi Card:</strong> M.2 E-Key, often replaceable
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Battery:</strong> Usually replaceable (internal or external)
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Thermal Paste:</strong> Can be replaced to improve cooling
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>❌ Usually Soldered/Non-Upgradeable</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>CPU:</strong> BGA (soldered) in nearly all modern laptops
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>GPU:</strong> Discrete GPUs are soldered (MXM rare now)
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>RAM (thin laptops):</strong> LPDDR soldered to motherboard
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Display:</strong> Integrated, though some panels can be swapped
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Keyboard:</strong> Often riveted or glued in place
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Laptop Displays */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Laptop Display Technologies</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Panel Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Pros</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Cons</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Best For</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { type: "TN", pros: "Fast response, cheap", cons: "Poor colors, narrow viewing angles", best: "Budget, basic tasks" },
                    { type: "IPS", pros: "Great colors, wide angles", cons: "Slower response, IPS glow", best: "Creative work, general use" },
                    { type: "VA", pros: "Deep blacks, good contrast", cons: "Slower response, smearing", best: "Content consumption, movies" },
                    { type: "OLED", pros: "Perfect blacks, vibrant colors", cons: "Burn-in risk, expensive", best: "Premium laptops, content creation" },
                    { type: "Mini-LED", pros: "High brightness, good contrast", cons: "Blooming in dark scenes", best: "HDR content, outdoor use" },
                  ].map((row) => (
                    <TableRow key={row.type}>
                      <TableCell sx={{ fontWeight: 600, color: "#8b5cf6" }}>{row.type}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.pros}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.cons}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.best}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Battery & Power */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Battery & Power Management</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>Battery Specifications</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Wh (Watt-hours):</strong> Total capacity. Higher = longer battery life
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Cells:</strong> Internal battery cells (3-cell, 6-cell, etc.)
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Cycle Count:</strong> Charge cycles before degradation (300-1000 typical)
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Battery Health:</strong> Check in OS or BIOS for wear level
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Fast Charging:</strong> USB-PD, proprietary (65W-140W typical)
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>Extending Battery Life</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Charge Limit:</strong> Keep between 20-80% for longevity
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Avoid Heat:</strong> Don't leave plugged in gaming laptops at 100%
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Power Profiles:</strong> Use balanced/power saver when on battery
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Screen Brightness:</strong> Biggest power consumer, reduce when possible
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Background Apps:</strong> Close unnecessary apps draining power
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Common Laptop Issues */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Common Laptop Hardware Issues</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Issue</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Symptoms</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Likely Causes</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Solutions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { issue: "Overheating", sym: "Fan noise, throttling, shutdowns", cause: "Dust, old paste, blocked vents", sol: "Clean vents, repaste, cooling pad" },
                    { issue: "Battery Drain", sym: "Short runtime, won't hold charge", cause: "Old battery, background apps", sol: "Replace battery, check power settings" },
                    { issue: "Display Issues", sym: "Flickering, dead pixels, no backlight", cause: "Cable, inverter, panel failure", sol: "Check cable, replace panel if needed" },
                    { issue: "Keyboard Failure", sym: "Keys stuck, not responding", cause: "Liquid damage, connector loose", sol: "Clean, reseat ribbon, replace keyboard" },
                    { issue: "Won't Power On", sym: "No lights, no fans", cause: "Dead battery, charger, DC jack", sol: "Test charger, try without battery" },
                    { issue: "WiFi Drops", sym: "Intermittent connection", cause: "Antenna, driver, interference", sol: "Update drivers, check antenna cables" },
                  ].map((row) => (
                    <TableRow key={row.issue}>
                      <TableCell sx={{ fontWeight: 600, color: "#8b5cf6" }}>{row.issue}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.sym}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.cause}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.sol}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* ========== PERIPHERALS SECTION ========== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 6 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>PERIPHERALS & I/O</Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Input Devices */}
        <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#22c55e", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <KeyboardIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>Input Devices</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {[
                { name: "Keyboards", desc: "Membrane, Mechanical, Wireless, Ergonomic", icon: <KeyboardIcon /> },
                { name: "Mice", desc: "Optical, Laser, Trackball, Vertical", icon: <MouseIcon /> },
                { name: "Touchpads", desc: "Laptop integrated, external trackpads", icon: <ComputerIcon /> },
                { name: "Scanners", desc: "Flatbed, Sheet-fed, Handheld, Barcode", icon: <SdStorageIcon /> },
                { name: "Webcams", desc: "USB, Integrated, IP cameras", icon: <MonitorIcon /> },
                { name: "Microphones", desc: "USB, XLR, Condenser, Dynamic", icon: <SettingsIcon /> },
              ].map((item) => (
                <Grid item xs={6} md={4} key={item.name}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.name}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3 }}>Keyboard & Mouse Basics</Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Keyboard Types</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>
                  <strong>Membrane:</strong> Quiet, inexpensive, softer feel.
                </Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>
                  <strong>Mechanical:</strong> Individual switches, more durable, tactile feedback.
                </Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>
                  <strong>Optical:</strong> Light-based switches, fast actuation.
                </Typography>
                <Typography variant="body2">
                  <strong>Layout:</strong> Full-size, TKL, 60/65 percent, ergonomic.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Mouse Sensor Specs</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>
                  <strong>DPI/CPI:</strong> Sensitivity range; higher is not always better.
                </Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>
                  <strong>Polling rate:</strong> 125 to 1000 Hz (higher reduces input lag).
                </Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>
                  <strong>IPS:</strong> Inches per second tracking speed.
                </Typography>
                <Typography variant="body2">
                  <strong>Lift-off distance:</strong> How far the mouse can lift before tracking stops.
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

        {/* Output Devices */}
        <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#8b5cf6", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <MonitorIcon sx={{ color: "#8b5cf6" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>Output Devices</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {[
                { name: "Monitors", desc: "LCD, LED, OLED, IPS, TN, VA panels" },
                { name: "Projectors", desc: "DLP, LCD, LED, Laser" },
                { name: "Speakers", desc: "2.0, 2.1, 5.1, 7.1 surround" },
                { name: "Headphones", desc: "Wired, Wireless, USB, Bluetooth" },
              ].map((item) => (
                <Grid item xs={6} md={3} key={item.name}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.name}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3 }}>Monitor Specs Explained</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Spec</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>What It Means</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Impact</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { spec: "Resolution", meaning: "Pixel count (1080p, 1440p, 4K)", impact: "Sharper image but harder on GPU" },
                    { spec: "Refresh rate", meaning: "Times per second the screen updates", impact: "Higher feels smoother, needs more GPU power" },
                    { spec: "Panel type", meaning: "IPS, VA, TN, OLED", impact: "Color accuracy vs response time" },
                    { spec: "Response time", meaning: "Pixel transition speed (ms)", impact: "Lower reduces motion blur" },
                    { spec: "Color gamut", meaning: "sRGB, DCI-P3 coverage", impact: "Important for photo/video work" },
                    { spec: "HDR", meaning: "High Dynamic Range capability", impact: "Better contrast and highlights if content supports it" },
                  ].map((row) => (
                    <TableRow key={row.spec}>
                      <TableCell sx={{ fontWeight: 600, color: "#8b5cf6" }}>{row.spec}</TableCell>
                      <TableCell>{row.meaning}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.impact}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Printers */}
        <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#f59e0b", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <PrintIcon sx={{ color: "#f59e0b" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>Printers & Imaging</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Technology</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Best For</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { type: "Inkjet", tech: "Liquid ink droplets", use: "Photos, low volume, color" },
                    { type: "Laser", tech: "Toner + heat fusion", use: "High volume, text, office" },
                    { type: "Thermal", tech: "Heat-sensitive paper", use: "Receipts, labels, shipping" },
                    { type: "Dot Matrix", tech: "Impact printing", use: "Multi-part forms, legacy" },
                    { type: "3D Printer", tech: "FDM, SLA, SLS", use: "Prototyping, manufacturing" },
                  ].map((row) => (
                    <TableRow key={row.type}>
                      <TableCell sx={{ fontWeight: 600, color: "#f59e0b" }}>{row.type}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.tech}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.use}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* ========== SECURITY HARDWARE SECTION ========== */}
        <Box id="security-hardware" sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 6 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>SECURITY HARDWARE</Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Security Hardware */}
        <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#dc2626", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <SecurityIcon sx={{ color: "#dc2626" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#dc2626" }}>Physical Security & Hardware Authentication</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              Security hardware provides physical protection and hardware-based authentication that's much harder 
              to compromise than software-only solutions. Understanding these technologies is essential for 
              enterprise security, compliance requirements, and protecting sensitive systems.
            </Alert>

            {/* Bank Vault Analogy */}
            <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#dc2626", 0.03), borderRadius: 2 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
                🔐 The Bank Vault Analogy
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                Think of security hardware like different layers of bank security:
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>TPM = The Bank Vault:</strong> A secure room where encryption keys (valuables) are stored. 
                    The vault is designed so even bank employees (the OS) can't access its contents without proper authorization.
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Hardware Security Keys = Safety Deposit Box Keys:</strong> Physical keys you must present 
                    to access your account. Even if someone knows your password (combination), they can't get in without the key.
                  </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Biometrics = Your Identity Verification:</strong> Like the bank verifying your signature 
                    or photo ID - something unique to you that can't be easily copied.
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Cable Locks = Physical Security:</strong> Like bolting down the ATM - it doesn't prevent 
                    all theft, but makes casual theft much harder.
                  </Typography>
                </Grid>
              </Grid>
            </Paper>

            {/* TPM Section */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Trusted Platform Module (TPM)</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>What TPM Does</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Key Storage:</strong> Generates and stores encryption keys that never leave the chip
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>BitLocker Support:</strong> Enables full-disk encryption on Windows
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Secure Boot:</strong> Verifies boot process hasn't been tampered with
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Platform Integrity:</strong> Detects if hardware/firmware has changed
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Credential Guard:</strong> Protects Windows credentials in isolated environment
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>TPM Versions & Types</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>TPM 1.2:</strong> Legacy version, limited algorithms (SHA-1)
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>TPM 2.0:</strong> Current standard, required for Windows 11
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Discrete TPM:</strong> Separate chip on motherboard (most secure)
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>fTPM (Firmware):</strong> Implemented in CPU firmware (AMD/Intel)
                  </Typography>
                  <Typography variant="body2">
                    • <strong>TPM Header:</strong> Connect add-on TPM module via motherboard header
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Hardware Security Keys */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Hardware Security Keys</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#dc2626", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Device</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Protocols</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Connection</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Key Features</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Best For</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { dev: "YubiKey 5", proto: "FIDO2, U2F, OTP, PIV, OpenPGP", conn: "USB-A/C, NFC", feat: "Multi-protocol, durable, waterproof", best: "Enterprise, developers" },
                    { dev: "YubiKey Bio", proto: "FIDO2, U2F", conn: "USB-A/C", feat: "Built-in fingerprint reader", best: "High-security workstations" },
                    { dev: "Google Titan", proto: "FIDO2, U2F", conn: "USB-A/C, NFC, BLE", feat: "Google's attestation, affordable", best: "Google Workspace users" },
                    { dev: "Nitrokey", proto: "FIDO2, OpenPGP, S/MIME", conn: "USB-A", feat: "Open source firmware, EU made", best: "Privacy-conscious users" },
                    { dev: "OnlyKey", proto: "FIDO2, U2F, TOTP, OpenPGP", conn: "USB-A", feat: "Hardware password manager", best: "Password + 2FA combo" },
                    { dev: "SoloKey", proto: "FIDO2, U2F", conn: "USB-A/C, NFC", feat: "Open source, affordable", best: "Budget-conscious security" },
                  ].map((row) => (
                    <TableRow key={row.dev}>
                      <TableCell sx={{ fontWeight: 600, color: "#dc2626" }}>{row.dev}</TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{row.proto}</TableCell>
                      <TableCell>{row.conn}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.feat}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.best}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Biometric Devices */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Biometric Authentication Hardware</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>👆 Fingerprint Readers</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>Types:</strong>
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5, pl: 1 }}>• Capacitive (most common)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5, pl: 1 }}>• Optical (older, less secure)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5, pl: 1 }}>• Ultrasonic (under-display)</Typography>
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    <strong>Integration:</strong> USB dongles, built into laptops/keyboards, 
                    smart card readers with fingerprint
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>👁️ Facial Recognition</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>Technologies:</strong>
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5, pl: 1 }}>• Windows Hello IR camera</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5, pl: 1 }}>• Face ID (Apple) structured light</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5, pl: 1 }}>• 2D camera (less secure)</Typography>
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    <strong>Security:</strong> IR-based is spoof-resistant; 2D camera can be fooled by photos
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>💳 Smart Card Readers</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>Use Cases:</strong>
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5, pl: 1 }}>• PIV/CAC cards (government)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5, pl: 1 }}>• Corporate badge access + login</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5, pl: 1 }}>• PKI certificate storage</Typography>
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    <strong>Types:</strong> Contact, contactless (NFC), combo readers
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Physical Security */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Physical Security Devices</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#dc2626", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Device Type</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Protection</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Common Standards</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Typical Use</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { type: "Kensington Lock", prot: "Laptop theft deterrent", std: "Kensington slot (K-slot)", use: "Offices, libraries, shared spaces" },
                    { type: "Noble Lock", prot: "Alternative lock standard", std: "Noble Wedge slot", use: "Dell laptops, some HP models" },
                    { type: "Cable Locks", prot: "Secure equipment to desk", std: "Various (combination/keyed)", use: "Monitors, docking stations, PCs" },
                    { type: "Privacy Screens", prot: "Visual data protection", std: "Size-specific filters", use: "Public spaces, open offices" },
                    { type: "Port Blockers", prot: "Prevent USB device insertion", std: "USB-A, USB-C, RJ-45 blockers", use: "Kiosks, secure terminals" },
                    { type: "Chassis Intrusion", prot: "Detect case opening", std: "Switch sensor to motherboard", use: "Servers, secure workstations" },
                  ].map((row) => (
                    <TableRow key={row.type}>
                      <TableCell sx={{ fontWeight: 600, color: "#dc2626" }}>{row.type}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.prot}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.std}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.use}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* HSM Section */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Hardware Security Modules (HSM)</Typography>
            <Alert severity="warning" sx={{ mb: 2 }}>
              HSMs are enterprise-grade devices for cryptographic operations. They're expensive but provide 
              the highest level of key protection for banks, certificate authorities, and government systems.
            </Alert>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>HSM Capabilities</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Key Generation:</strong> Cryptographically secure random key generation
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Key Storage:</strong> Tamper-resistant storage, keys never exported in plaintext
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Cryptographic Ops:</strong> Signing, encryption, decryption in hardware
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Tamper Evidence:</strong> Physical tampering destroys keys
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Compliance:</strong> FIPS 140-2/3, Common Criteria certified
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>HSM Form Factors</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Network HSM:</strong> Rack-mounted, shared across servers (Thales, Utimaco)
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>PCIe HSM:</strong> Card installed in server (most common for single-server)
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>USB HSM:</strong> Portable, lower capacity (YubiHSM, Nitrokey HSM)
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>
                    • <strong>Cloud HSM:</strong> Managed HSM service (AWS CloudHSM, Azure Dedicated HSM)
                  </Typography>
                  <Typography variant="body2">
                    • <strong>Payment HSM:</strong> Specialized for banking/PCI compliance
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* ========== TROUBLESHOOTING SECTION ========== */}
        <Box id="troubleshooting" sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 6 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>TROUBLESHOOTING & MAINTENANCE</Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* POST & Boot */}
        <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ef4444", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <BuildIcon sx={{ color: "#ef4444" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>POST Codes & Boot Process</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="warning" sx={{ mb: 3 }}>
              POST (Power-On Self-Test) runs before the OS loads. Understanding POST codes and the boot 
              process is essential for diagnosing hardware issues during startup.
            </Alert>

            {/* Boot Sequence */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Complete Boot Sequence</Typography>
            <Paper sx={{ p: 3, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, mb: 3 }}>
              <Grid container spacing={2}>
                {[
                  { step: "1", title: "Power On", desc: "PSU activates, provides standby power, waits for power button" },
                  { step: "2", title: "PSU Self-Test", desc: "PSU checks voltages, sends Power Good signal to motherboard" },
                  { step: "3", title: "CPU Reset", desc: "CPU receives reset signal, begins executing BIOS/UEFI code" },
                  { step: "4", title: "POST Begins", desc: "Basic hardware initialization, memory test, device detection" },
                  { step: "5", title: "Video Init", desc: "Graphics adapter initialized, display output begins" },
                  { step: "6", title: "BIOS/UEFI", desc: "Full system check, boot device selection, settings load" },
                  { step: "7", title: "Bootloader", desc: "OS bootloader loads (GRUB, Windows Boot Manager)" },
                  { step: "8", title: "OS Kernel", desc: "Operating system kernel loads and initializes" },
                ].map((item) => (
                  <Grid item xs={6} md={3} key={item.step}>
                    <Box sx={{ textAlign: "center" }}>
                      <Typography variant="h4" sx={{ color: "#ef4444", fontWeight: 700 }}>{item.step}</Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                      <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Paper>

            {/* Beep Codes */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Common BIOS Beep Codes</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: "#0071c5", borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0071c5", mb: 2 }}>AMI BIOS Beep Codes</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>1 short:</strong> Normal POST, no errors</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>2 short:</strong> POST error displayed</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>3 short:</strong> Base 64K RAM failure</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>4 short:</strong> System timer failure</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>5 short:</strong> Processor failure</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>6 short:</strong> Keyboard controller error</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>8 short:</strong> Display memory error</Typography>
                  <Typography variant="body2">• <strong>Continuous:</strong> RAM or power issue</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, border: "2px solid", borderColor: "#ed1c24", borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ed1c24", mb: 2 }}>Award/Phoenix BIOS Codes</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>1 long, 2 short:</strong> Video card error</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>1 long, 3 short:</strong> Video card error</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Continuous long:</strong> RAM not detected</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Continuous short:</strong> Power problem</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>1-1-1-3:</strong> CMOS read/write error</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>1-1-4-1:</strong> BIOS ROM checksum error</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>1-2-1-1:</strong> Timer test failure</Typography>
                  <Typography variant="body2">• <strong>1-3-1-1:</strong> DRAM refresh failure</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Debug LED Codes */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Motherboard Debug LEDs</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>LED/Indicator</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Location</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Meaning</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Troubleshooting</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { led: "CPU LED (Red)", loc: "Near CPU socket", meaning: "CPU not detected or failed", fix: "Reseat CPU, check power, verify compatibility" },
                    { led: "DRAM LED (Yellow)", loc: "Near RAM slots", meaning: "RAM not detected or failed", fix: "Reseat RAM, try different slots, check XMP" },
                    { led: "VGA LED (White)", loc: "Near PCIe slots", meaning: "GPU not detected", fix: "Reseat GPU, check power connectors, try different slot" },
                    { led: "BOOT LED (Green)", loc: "Near SATA/M.2", meaning: "No bootable device", fix: "Check storage connections, BIOS boot order" },
                    { led: "Q-Code Display", loc: "2-digit display", meaning: "POST code number", fix: "Consult motherboard manual for specific code" },
                  ].map((row) => (
                    <TableRow key={row.led}>
                      <TableCell sx={{ fontWeight: 600, color: "#ef4444" }}>{row.led}</TableCell>
                      <TableCell>{row.loc}</TableCell>
                      <TableCell>{row.meaning}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.fix}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Common POST Issues */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Common POST Failure Scenarios</Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>No Power (Dead System)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✓ Check PSU switch and power cable</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✓ Test outlet with known-working device</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✓ Verify 24-pin and CPU power connected</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✓ Check front panel power button connection</Typography>
                  <Typography variant="body2">✓ Try PSU paperclip test</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>Powers On, No Display</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✓ Check monitor input source</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✓ Try different video cable/port</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✓ Reseat GPU, check power connectors</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✓ Try integrated graphics (if available)</Typography>
                  <Typography variant="body2">✓ Reseat RAM, try single stick</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>Boot Loop / Restarts</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✓ Clear CMOS (reset BIOS settings)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✓ Remove overclocking settings</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✓ Check CPU cooler mounting</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>✓ Verify RAM compatibility</Typography>
                  <Typography variant="body2">✓ Test with minimal hardware</Typography>
                </Paper>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Common Issues */}
        <Accordion sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#06b6d4", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <SettingsIcon sx={{ color: "#06b6d4" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#06b6d4" }}>Common Hardware Issues & Solutions</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="info" sx={{ mb: 3 }}>
              Systematic troubleshooting is key to resolving hardware issues. Start with the most likely 
              and simplest solutions before moving to more complex diagnostics.
            </Alert>

            {/* Issue Categories */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Hardware Issue Diagnostic Guide</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Symptom</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Likely Causes</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Diagnostic Steps</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Solutions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { sym: "Random Shutdowns", cause: "Overheating, PSU failure, RAM", diag: "Check temps, Event Viewer, memtest", sol: "Clean fans, reseat cooler, test PSU" },
                    { sym: "Blue Screen (BSOD)", cause: "Drivers, RAM, storage, overheating", diag: "Note error code, check minidump", sol: "Update drivers, memtest, chkdsk" },
                    { sym: "Slow Performance", cause: "Storage full, malware, thermal throttle", diag: "Task Manager, disk usage, temps", sol: "Clean disk, scan malware, improve cooling" },
                    { sym: "USB Not Working", cause: "Drivers, power, USB controller", diag: "Device Manager, try different ports", sol: "Update chipset drivers, check BIOS" },
                    { sym: "Audio Issues", cause: "Drivers, connections, settings", diag: "Sound settings, device manager", sol: "Reinstall audio drivers, check defaults" },
                    { sym: "Network Problems", cause: "Driver, cable, adapter failure", diag: "ipconfig, ping, Device Manager", sol: "Reset network, update drivers" },
                    { sym: "Freezing/Lockups", cause: "RAM, storage, drivers, overheating", diag: "Reliability Monitor, memtest", sol: "Test RAM, check storage health" },
                    { sym: "Artifacts on Screen", cause: "GPU overheating, VRAM failure", diag: "GPU stress test, monitor temps", sol: "Clean GPU, check airflow, test in another PC" },
                  ].map((row) => (
                    <TableRow key={row.sym}>
                      <TableCell sx={{ fontWeight: 600, color: "#06b6d4" }}>{row.sym}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.cause}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.diag}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.sol}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Diagnostic Tools */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Essential Diagnostic Tools</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Windows Built-in</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Device Manager:</strong> Hardware status, drivers</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Event Viewer:</strong> System errors, warnings</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Reliability Monitor:</strong> Error history</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Resource Monitor:</strong> Real-time usage</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Memory Diagnostic:</strong> Windows RAM test</Typography>
                  <Typography variant="body2">• <strong>chkdsk:</strong> Disk error checking</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Third-Party Software</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>HWiNFO64:</strong> Comprehensive hardware info</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>CPU-Z:</strong> CPU, RAM, motherboard details</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>GPU-Z:</strong> Graphics card information</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>CrystalDiskInfo:</strong> Storage S.M.A.R.T.</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>MemTest86:</strong> Comprehensive RAM test</Typography>
                  <Typography variant="body2">• <strong>Prime95:</strong> CPU stress test</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>Physical Tools</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Multimeter:</strong> Test PSU voltages</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>PSU Tester:</strong> Quick PSU check</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>POST Card:</strong> Debug code reader</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Cable Tester:</strong> Network/USB cables</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Loopback Plugs:</strong> Port testing</Typography>
                  <Typography variant="body2">• <strong>Anti-static Wrist Strap:</strong> ESD protection</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Troubleshooting Methodology */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Troubleshooting Methodology</Typography>
            <Paper sx={{ p: 3, bgcolor: alpha("#06b6d4", 0.03), borderRadius: 2 }}>
              <Grid container spacing={2}>
                {[
                  { step: "1. Identify", desc: "Gather information about the problem. When did it start? What changed?" },
                  { step: "2. Theory", desc: "Formulate possible causes based on symptoms. Start with most likely." },
                  { step: "3. Test", desc: "Test each theory systematically. Change one variable at a time." },
                  { step: "4. Plan", desc: "Create action plan to resolve the issue once cause is identified." },
                  { step: "5. Implement", desc: "Apply the fix. Replace component, update driver, adjust setting." },
                  { step: "6. Verify", desc: "Confirm the issue is resolved. Test thoroughly under various conditions." },
                  { step: "7. Document", desc: "Record the problem and solution for future reference." },
                ].map((item, index) => (
                  <Grid item xs={12} key={item.step}>
                    <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                      <Typography variant="h6" sx={{ color: "#06b6d4", fontWeight: 700, minWidth: 40 }}>{item.step.split('.')[0]}</Typography>
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.step.split('. ')[1]}</Typography>
                        <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                      </Box>
                    </Box>
                    {index < 6 && <Divider sx={{ mt: 2 }} />}
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </AccordionDetails>
        </Accordion>

        {/* Maintenance */}
        <Accordion id="maintenance" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#22c55e", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <ThermostatIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>Maintenance & Best Practices</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="success" sx={{ mb: 3 }}>
              Regular preventive maintenance extends hardware lifespan, prevents failures, and maintains 
              optimal performance. Most maintenance tasks can be done with basic tools and supplies.
            </Alert>

            {/* Cleaning */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Physical Cleaning</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Dust Removal</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Compressed air:</strong> Fans, heatsinks, vents</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Soft brush:</strong> Circuit boards (ESD-safe)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Vacuum:</strong> Only with anti-static nozzle</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Frequency:</strong> Every 3-6 months</Typography>
                  <Typography variant="body2">• <strong>PSU:</strong> Blow out from back (don't open)</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Contact Cleaning</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Isopropyl alcohol (90%+):</strong> Contacts, pins</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Lint-free cloth:</strong> Circuit boards</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Contact cleaner:</strong> Oxidized connections</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Eraser:</strong> Gold contacts (gently)</Typography>
                  <Typography variant="body2">• <strong>Let dry:</strong> Wait before powering on</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Peripherals</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Keyboard:</strong> Compressed air, keycap removal</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Mouse:</strong> Clean sensor, feet, buttons</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Monitor:</strong> Microfiber cloth (no ammonia)</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Mousepad:</strong> Wash with mild soap</Typography>
                  <Typography variant="body2">• <strong>Headset:</strong> Clean ear pads, mic</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Thermal Management */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Thermal Management</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Thermal Paste Application</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>When:</strong> Every 2-3 years or when temps rise</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Amount:</strong> Pea-sized dot in center</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Removal:</strong> Isopropyl alcohol + lint-free cloth</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Quality paste:</strong> Noctua NT-H1, Thermal Grizzly</Typography>
                  <Typography variant="body2">• <strong>GPU:</strong> More complex, check tutorials first</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Airflow Optimization</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Positive pressure:</strong> More intake than exhaust</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Front intake:</strong> Cool air enters front/bottom</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Rear/Top exhaust:</strong> Hot air exits</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Cable management:</strong> Don't block airflow</Typography>
                  <Typography variant="body2">• <strong>Filters:</strong> Clean monthly if present</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Temperature Targets */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Safe Operating Temperatures</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Component</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Idle</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Load</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Max Safe</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Action Needed</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { comp: "CPU (Desktop)", idle: "30-40°C", load: "60-80°C", max: "95-100°C", action: "Throttling starts" },
                    { comp: "CPU (Laptop)", idle: "35-50°C", load: "70-90°C", max: "100-105°C", action: "Throttling, clean vents" },
                    { comp: "GPU", idle: "30-45°C", load: "65-85°C", max: "90-95°C", action: "Improve case airflow" },
                    { comp: "NVMe SSD", idle: "25-40°C", load: "50-70°C", max: "70-80°C", action: "Add heatsink" },
                    { comp: "HDD", idle: "25-35°C", load: "35-45°C", max: "55°C", action: "Improve cooling, replace" },
                    { comp: "RAM", idle: "30-40°C", load: "40-50°C", max: "80°C", action: "Usually not an issue" },
                    { comp: "Motherboard (VRM)", idle: "40-50°C", load: "60-90°C", max: "110°C", action: "Add VRM fan/heatsink" },
                  ].map((row) => (
                    <TableRow key={row.comp}>
                      <TableCell sx={{ fontWeight: 600, color: "#22c55e" }}>{row.comp}</TableCell>
                      <TableCell>{row.idle}</TableCell>
                      <TableCell>{row.load}</TableCell>
                      <TableCell>{row.max}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem" }}>{row.action}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* Software Maintenance */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Software & Firmware Maintenance</Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Driver Updates</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>GPU drivers:</strong> Monthly from NVIDIA/AMD</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Chipset:</strong> From motherboard manufacturer</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Storage:</strong> NVMe firmware updates</Typography>
                  <Typography variant="body2">• <strong>Peripherals:</strong> Keyboard, mouse firmware</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>BIOS/UEFI Updates</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Check manufacturer:</strong> Support page</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Read changelog:</strong> Security, stability, features</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Use UPS:</strong> Power interruption = brick</Typography>
                  <Typography variant="body2">• <strong>Don't fix what isn't broken:</strong> Only if needed</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Data Backup</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>3-2-1 Rule:</strong> 3 copies, 2 media, 1 offsite</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>System image:</strong> Full system backup</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5 }}>• <strong>Cloud sync:</strong> Important documents</Typography>
                  <Typography variant="body2">• <strong>Test restores:</strong> Verify backup integrity</Typography>
                </Paper>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* CompTIA A+ Exam Topics */}
        <Paper id="comptia" sx={{ p: 4, mt: 6, borderRadius: 3, background: "linear-gradient(135deg, rgba(34,197,94,0.05) 0%, rgba(59,130,246,0.05) 100%)", border: "2px solid", borderColor: alpha("#22c55e", 0.2) }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#22c55e" }}>
            🎯 CompTIA A+ Certification Guide
          </Typography>
          
          {/* Exam Overview */}
          <Alert severity="info" sx={{ mb: 3 }}>
            CompTIA A+ is the industry standard for establishing a career in IT. It consists of two exams 
            that validate foundational IT skills across devices, networking, security, and troubleshooting.
          </Alert>

          {/* Core 1 Exam */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Core 1 (220-1101) - Hardware & Networking
          </Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { domain: "Mobile Devices", weight: "15%", topics: "Laptop hardware, displays, mobile device accessories, connectivity" },
              { domain: "Networking", weight: "20%", topics: "TCP/IP, network hardware, wireless, services & protocols" },
              { domain: "Hardware", weight: "25%", topics: "Motherboards, CPUs, RAM, storage, power supplies, GPUs, peripherals" },
              { domain: "Virtualization & Cloud", weight: "11%", topics: "Cloud computing concepts, virtualization basics" },
              { domain: "Hardware Troubleshooting", weight: "29%", topics: "PC, mobile, network, storage & printer troubleshooting" },
            ].map((d) => (
              <Grid item xs={12} md={4} key={d.domain}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{d.domain}</Typography>
                    <Chip label={d.weight} size="small" sx={{ bgcolor: alpha("#22c55e", 0.2), fontWeight: 700 }} />
                  </Box>
                  <Typography variant="caption" color="text.secondary">{d.topics}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Core 2 Exam */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Core 2 (220-1102) - Software & Security
          </Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { domain: "Operating Systems", weight: "31%", topics: "Windows, macOS, Linux, Chrome OS installation & configuration" },
              { domain: "Security", weight: "25%", topics: "Physical & logical security, malware, social engineering, SOHO security" },
              { domain: "Software Troubleshooting", weight: "22%", topics: "OS problems, PC security issues, malware removal, mobile OS" },
              { domain: "Operational Procedures", weight: "22%", topics: "Documentation, change management, disaster recovery, scripting" },
            ].map((d) => (
              <Grid item xs={12} md={3} key={d.domain}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 2, height: "100%" }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{d.domain}</Typography>
                    <Chip label={d.weight} size="small" sx={{ bgcolor: alpha("#3b82f6", 0.2), fontWeight: 700 }} />
                  </Box>
                  <Typography variant="caption" color="text.secondary">{d.topics}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Exam Details */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Exam Details</Typography>
          <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Detail</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Core 1 (220-1101)</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Core 2 (220-1102)</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { detail: "Number of Questions", c1: "Up to 90", c2: "Up to 90" },
                  { detail: "Question Types", c1: "Multiple choice, drag & drop, PBQs", c2: "Multiple choice, drag & drop, PBQs" },
                  { detail: "Time Limit", c1: "90 minutes", c2: "90 minutes" },
                  { detail: "Passing Score", c1: "675 / 900", c2: "700 / 900" },
                  { detail: "Exam Cost", c1: "~$246 USD", c2: "~$246 USD" },
                  { detail: "Languages", c1: "English, Japanese, Portuguese, Spanish", c2: "English, Japanese, Portuguese, Spanish" },
                ].map((row) => (
                  <TableRow key={row.detail}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.detail}</TableCell>
                    <TableCell>{row.c1}</TableCell>
                    <TableCell>{row.c2}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {/* Study Tips */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>💡 Study Tips & Resources</Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>Study Materials</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Official CompTIA CertMaster Learn</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Professor Messer (free videos)</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Mike Meyers All-in-One Guide</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Jason Dion Practice Exams</Typography>
                <Typography variant="body2">• CompTIA Labs (hands-on)</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Hands-On Practice</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Build/disassemble a PC</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Install various operating systems</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Configure home network/router</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Practice command line (CMD, PowerShell)</Typography>
                <Typography variant="body2">• Use virtual machines for testing</Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>Exam Strategy</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Read questions carefully</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Flag PBQs for later, do MCQs first</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Eliminate obviously wrong answers</Typography>
                <Typography variant="body2" sx={{ mb: 0.5 }}>• Manage time: ~1 min per question</Typography>
                <Typography variant="body2">• Don't leave questions blank</Typography>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* Quiz Section */}
        <Box id="quiz" sx={{ mt: 5 }}>
          <QuizSection
            questions={quizPool}
            accentColor={ACCENT_COLOR}
            title="IT Hardware Fundamentals Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time the page loads."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
        </Box>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#f97316", color: "#f97316" }}
          >
            Back to Learning Hub
          </Button>
        </Box>

        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default ITHardwarePage;
