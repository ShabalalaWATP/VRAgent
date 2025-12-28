import React from "react";
import LearnPageLayout from "../components/LearnPageLayout";
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
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ArrowForwardIcon from "@mui/icons-material/ArrowForward";
import MemoryIcon from "@mui/icons-material/Memory";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import SchoolIcon from "@mui/icons-material/School";
import TerminalIcon from "@mui/icons-material/Terminal";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import Fab from "@mui/material/Fab";
import Zoom from "@mui/material/Zoom";
import useScrollTrigger from "@mui/material/useScrollTrigger";
import SearchIcon from "@mui/icons-material/Search";
import WarningIcon from "@mui/icons-material/Warning";
import GavelIcon from "@mui/icons-material/Gavel";
import PsychologyIcon from "@mui/icons-material/Psychology";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";
import LockIcon from "@mui/icons-material/Lock";
import VisibilityIcon from "@mui/icons-material/Visibility";
import HistoryIcon from "@mui/icons-material/History";
import ExtensionIcon from "@mui/icons-material/Extension";
import StorageIcon from "@mui/icons-material/Storage";
import FolderIcon from "@mui/icons-material/Folder";
import SettingsIcon from "@mui/icons-material/Settings";
import DeveloperBoardIcon from "@mui/icons-material/DeveloperBoard";
import LayersIcon from "@mui/icons-material/Layers";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import DataObjectIcon from "@mui/icons-material/DataObject";
import SpeedIcon from "@mui/icons-material/Speed";
import SyncAltIcon from "@mui/icons-material/SyncAlt";
import { useNavigate } from "react-router-dom";

// Outline sections for future expansion
const outlineSections = [
  {
    id: "elf-format",
    title: "ELF File Format Deep Dive",
    icon: <StorageIcon />,
    color: "#3b82f6",
    status: "Complete",
    description: "ELF headers, sections, segments, symbol tables, and relocation entries explained",
  },
  {
    id: "process-memory",
    title: "Process Memory Layout",
    icon: <MemoryIcon />,
    color: "#8b5cf6",
    status: "Complete",
    description: "Stack, heap, BSS, data, text segments, and memory mapping internals",
  },
  {
    id: "syscalls",
    title: "System Calls & Kernel Interface",
    icon: <TerminalIcon />,
    color: "#06b6d4",
    status: "Complete",
    description: "How user-space communicates with the kernel, syscall numbers, and calling conventions",
  },
  {
    id: "dynamic-linking",
    title: "Dynamic Linking & Loading",
    icon: <SyncAltIcon />,
    color: "#ec4899",
    status: "Complete",
    description: "PLT/GOT, lazy binding, ld.so, shared library resolution, and LD_PRELOAD",
  },
  {
    id: "debugging-linux",
    title: "Debugging on Linux",
    icon: <BugReportIcon />,
    color: "#14b8a6",
    status: "Complete",
    description: "GDB, ptrace, /proc filesystem, strace, ltrace, and debugging symbols",
  },
  {
    id: "binary-protections",
    title: "Binary Protections & Mitigations",
    icon: <SecurityIcon />,
    color: "#f97316",
    status: "Complete",
    description: "ASLR, PIE, NX/DEP, Stack Canaries, RELRO, and how to identify them",
  },
  {
    id: "libc-internals",
    title: "libc & Standard Library Internals",
    icon: <LayersIcon />,
    color: "#6366f1",
    status: "Complete",
    description: "glibc, musl, heap allocator internals (malloc/free), and common functions",
  },
  {
    id: "proc-filesystem",
    title: "The /proc Filesystem",
    icon: <FolderIcon />,
    color: "#0ea5e9",
    status: "Complete",
    description: "Process information, memory maps, file descriptors, and kernel parameters",
  },
  {
    id: "calling-conventions",
    title: "x86-64 Calling Conventions",
    icon: <CodeIcon />,
    color: "#dc2626",
    status: "Complete",
    description: "System V AMD64 ABI, register usage, stack frames, and function prologues",
  },
  {
    id: "signals-handlers",
    title: "Signals & Signal Handlers",
    icon: <DataObjectIcon />,
    color: "#22c55e",
    status: "Complete",
    description: "Signal delivery, handlers, sigaction, and signal-based exploitation",
  },
  {
    id: "ptrace-api",
    title: "ptrace & Process Tracing",
    icon: <SearchIcon />,
    color: "#f97316",
    status: "Complete",
    description: "ptrace syscall, tracee control, register manipulation, and anti-debugging",
  },
  {
    id: "kernel-modules",
    title: "Kernel Modules & Rootkits",
    icon: <DeveloperBoardIcon />,
    color: "#8b5cf6",
    status: "Complete",
    description: "LKM structure, syscall table hooking, hiding techniques, and detection",
  },
  {
    id: "analysis-tools",
    title: "Linux RE Tools & Workflows",
    icon: <BuildIcon />,
    color: "#3b82f6",
    status: "Complete",
    description: "readelf, objdump, nm, radare2, Ghidra, and integrated analysis workflows",
  },
  {
    id: "exploitation-patterns",
    title: "Exploitation Patterns on Linux",
    icon: <LockIcon />,
    color: "#ef4444",
    status: "Complete",
    description: "Stack overflows, format strings, heap exploitation, ROP chains, and ret2libc",
  },
  {
    id: "practice-ctf",
    title: "Practice & CTF Challenges",
    icon: <SchoolIcon />,
    color: "#10b981",
    status: "Complete",
    description: "Linux RE CTFs, crackmes, pwnable challenges, and learning resources",
  },
];

// Quick stats for visual impact
const quickStats = [
  { value: "15", label: "Topics Covered", color: "#3b82f6" },
  { value: "ELF", label: "Binary Format", color: "#ef4444" },
  { value: "x64", label: "Architecture Focus", color: "#10b981" },
  { value: "GDB", label: "Primary Debugger", color: "#8b5cf6" },
];

export default function LinuxInternalsREPage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Linux Internals for Reverse Engineering - Comprehensive guide covering ELF file format, process memory layout, system calls, dynamic linking (PLT/GOT), debugging with GDB, binary protections (ASLR, PIE, NX), libc internals, /proc filesystem, x86-64 calling conventions, signals, ptrace API, kernel modules, Linux RE tools, exploitation patterns, and practice resources.`;

  return (
    <LearnPageLayout pageTitle="Linux Internals for Reverse Engineering" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Back Button */}
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate("/learn")}
          sx={{ mb: 3 }}
        >
          Back to Learning Hub
        </Button>

        {/* Hero Banner */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#f97316", 0.15)} 0%, ${alpha("#3b82f6", 0.15)} 50%, ${alpha("#10b981", 0.15)} 100%)`,
            border: `1px solid ${alpha("#f97316", 0.2)}`,
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
              background: `radial-gradient(circle, ${alpha("#f97316", 0.1)} 0%, transparent 70%)`,
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
              background: `radial-gradient(circle, ${alpha("#10b981", 0.1)} 0%, transparent 70%)`,
            }}
          />
          
          <Box sx={{ position: "relative", zIndex: 1 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, #f97316, #3b82f6)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#f97316", 0.3)}`,
                }}
              >
                <TerminalIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                  Linux Internals for Reverse Engineering
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                  Master the foundations of Linux binary analysis
                </Typography>
              </Box>
            </Box>
            
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
              <Chip label="Intermediate" color="warning" />
              <Chip label="ELF Binaries" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 600 }} />
              <Chip label="Memory Layout" sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444", fontWeight: 600 }} />
              <Chip label="Debugging" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
              <Chip label="Exploitation" sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 600 }} />
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
              label="← Learning Hub"
              size="small"
              clickable
              onClick={() => navigate("/learn")}
              sx={{
                fontWeight: 700,
                fontSize: "0.75rem",
                bgcolor: alpha("#f97316", 0.1),
                color: "#f97316",
                "&:hover": {
                  bgcolor: alpha("#f97316", 0.2),
                },
              }}
            />
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.secondary" }}>
              Quick Navigation
            </Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {[
              { label: "Introduction", id: "intro" },
              { label: "ELF Format", id: "elf-format" },
              { label: "Memory Layout", id: "process-memory" },
              { label: "System Calls", id: "syscalls" },
              { label: "Dynamic Linking", id: "dynamic-linking" },
              { label: "Debugging", id: "debugging-linux" },
              { label: "Protections", id: "binary-protections" },
              { label: "libc", id: "libc-internals" },
              { label: "/proc", id: "proc-filesystem" },
              { label: "Calling Conventions", id: "calling-conventions" },
              { label: "Signals", id: "signals-handlers" },
              { label: "ptrace", id: "ptrace-api" },
              { label: "Kernel Modules", id: "kernel-modules" },
              { label: "Tools", id: "analysis-tools" },
              { label: "Exploitation", id: "exploitation-patterns" },
              { label: "Practice", id: "practice-ctf" },
            ].map((nav) => (
              <Chip
                key={nav.id}
                label={nav.label}
                size="small"
                clickable
                onClick={() => document.getElementById(nav.id)?.scrollIntoView({ behavior: "smooth", block: "start" })}
                sx={{
                  fontWeight: 600,
                  fontSize: "0.75rem",
                  "&:hover": {
                    bgcolor: alpha("#f97316", 0.15),
                    color: "#f97316",
                  },
                }}
              />
            ))}
          </Box>
        </Paper>

        {/* ==================== INTRODUCTION ==================== */}
        <Typography id="intro" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🐧 What You'll Learn
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          A complete foundation in Linux binary internals for effective reverse engineering
        </Typography>

        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Linux is the backbone of modern computing</strong> — from web servers and cloud infrastructure to embedded devices, 
            Android phones, and supercomputers. For reverse engineers, understanding Linux internals is not optional; it's essential. 
            Whether you're analyzing malware, hunting for vulnerabilities, or solving CTF challenges, the ability to understand 
            how Linux binaries work at a fundamental level will set you apart.
          </Typography>
          <Box sx={{ my: 3 }}>
            <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
              Unlike Windows with its PE format, Linux uses the <strong>ELF (Executable and Linkable Format)</strong> — a flexible, 
              powerful format that governs how programs are loaded, linked, and executed. Understanding ELF isn't just about knowing 
              header fields; it's about understanding how your program transforms from a file on disk into running code in memory.
            </Typography>
          </Box>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            This guide takes you on a journey from the <strong>structure of ELF files</strong> through <strong>process memory layout</strong>, 
            <strong>system calls</strong>, <strong>dynamic linking magic</strong>, and <strong>debugging techniques</strong> — all the way to 
            understanding <strong>exploitation patterns</strong> and <strong>kernel-level concepts</strong>. By the end, you'll have the 
            knowledge to analyze any Linux binary with confidence, whether you're using GDB, Ghidra, or radare2.
          </Typography>
        </Paper>

        {/* ==================== WHY LINUX INTERNALS MATTER ==================== */}
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🎯 Why Linux Internals Matter for RE
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding the "why" behind learning these concepts
        </Typography>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981", display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon /> What This Knowledge Enables
              </Typography>
              <List dense>
                {[
                  "Analyze Linux malware and understand its behavior",
                  "Find vulnerabilities in compiled binaries",
                  "Write exploits for buffer overflows and other bugs",
                  "Solve binary exploitation CTF challenges",
                  "Understand how debuggers like GDB actually work",
                  "Identify and bypass anti-debugging techniques",
                  "Reverse engineer network daemons and services",
                  "Analyze firmware and embedded Linux systems",
                  "Understand rootkits and kernel-level threats",
                  "Debug complex multi-threaded applications",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon /> Without This Knowledge
              </Typography>
              <List dense>
                {[
                  "You'll struggle to understand disassembly output",
                  "Debugging will feel like magic instead of science",
                  "Exploit development becomes trial and error",
                  "You won't understand why ASLR breaks your exploits",
                  "PLT/GOT will be confusing mystery sections",
                  "Memory corruption bugs won't make sense",
                  "CTF binary challenges will be frustrating",
                  "Malware analysis will be surface-level only",
                  "You'll miss important indicators of compromise",
                  "Kernel and driver RE will be impossible",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== PREREQUISITES ==================== */}
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📋 Prerequisites
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          What you should know before diving in
        </Typography>

        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                <CheckCircleIcon sx={{ color: "#10b981" }} />
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Required</Typography>
              </Box>
              <List dense>
                {[
                  "Basic Linux command line skills",
                  "Understanding of C programming",
                  "Familiarity with pointers and memory",
                  "Basic understanding of x86/x64 assembly",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText primary={`• ${item}`} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                <TipsAndUpdatesIcon sx={{ color: "#f59e0b" }} />
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Helpful</Typography>
              </Box>
              <List dense>
                {[
                  "Experience with GDB basics",
                  "Understanding of compilation process",
                  "Knowledge of data structures",
                  "Familiarity with hex and binary",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText primary={`• ${item}`} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                <SchoolIcon sx={{ color: "#3b82f6" }} />
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>VRAgent Resources</Typography>
              </Box>
              <List dense>
                {[
                  "Linux Fundamentals page",
                  "Intro to Reverse Engineering",
                  "Debugging 101",
                  "Computer Science Fundamentals",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText primary={`→ ${item}`} primaryTypographyProps={{ variant: "body2", color: "#3b82f6" }} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== SECTION OUTLINE ==================== */}
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📚 What's Covered in This Guide
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          15 comprehensive sections covering all aspects of Linux internals for RE
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {outlineSections.map((section, idx) => (
            <Grid item xs={12} md={6} key={section.id}>
              <Paper
                id={section.id}
                sx={{
                  p: 2.5,
                  borderRadius: 3,
                  border: `1px solid ${alpha(section.color, 0.2)}`,
                  transition: "all 0.3s ease",
                  cursor: "pointer",
                  scrollMarginTop: 180,
                  "&:hover": {
                    transform: "translateY(-2px)",
                    boxShadow: `0 8px 24px ${alpha(section.color, 0.15)}`,
                    borderColor: section.color,
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                  <Box
                    sx={{
                      width: 48,
                      height: 48,
                      borderRadius: 2,
                      bgcolor: alpha(section.color, 0.1),
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: section.color,
                      flexShrink: 0,
                    }}
                  >
                    {section.icon}
                  </Box>
                  <Box sx={{ flexGrow: 1 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        {idx + 1}. {section.title}
                      </Typography>
                      <Chip
                        label={section.status}
                        size="small"
                        sx={{
                          height: 20,
                          fontSize: "0.65rem",
                          fontWeight: 700,
                          bgcolor: section.status === "Complete" 
                            ? alpha("#10b981", 0.15) 
                            : alpha("#f59e0b", 0.15),
                          color: section.status === "Complete" ? "#10b981" : "#f59e0b",
                        }}
                      />
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>
                      {section.description}
                    </Typography>
                  </Box>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== SECTION 1: ELF FORMAT ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
          <Typography id="elf-format-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#3b82f6" }}>
            📦 1. ELF File Format Deep Dive
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Understanding the structure of Linux executables
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            <strong>ELF (Executable and Linkable Format)</strong> is the standard binary format for Linux executables, 
            shared libraries, object files, and core dumps. Every time you compile a C program on Linux, you're creating 
            an ELF file. Understanding this format is fundamental to reverse engineering because it tells you how the 
            binary is organized in memory and where to find critical information.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            ELF File Types
          </Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { type: "ET_EXEC", name: "Executable", desc: "Traditional executable with fixed addresses", color: "#ef4444" },
              { type: "ET_DYN", name: "Shared Object", desc: "Position-independent (PIE executables, .so files)", color: "#10b981" },
              { type: "ET_REL", name: "Relocatable", desc: "Object files (.o) before linking", color: "#8b5cf6" },
              { type: "ET_CORE", name: "Core Dump", desc: "Process memory snapshot for debugging", color: "#f59e0b" },
            ].map((item) => (
              <Grid item xs={6} md={3} key={item.type}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(item.color, 0.05), border: `1px solid ${alpha(item.color, 0.2)}`, height: "100%" }}>
                  <Chip label={item.type} size="small" sx={{ mb: 1, fontFamily: "monospace", fontSize: "0.7rem", bgcolor: alpha(item.color, 0.15), color: item.color }} />
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.name}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            ELF Structure Overview
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#3b82f6", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`┌─────────────────────────────────────┐
│           ELF Header                │  ← Magic bytes, architecture, entry point
│         (52/64 bytes)               │
├─────────────────────────────────────┤
│      Program Headers (Phdr)         │  ← Segments for runtime loading
│    (describes memory segments)      │
├─────────────────────────────────────┤
│                                     │
│           Sections                  │  ← .text, .data, .rodata, .bss, etc.
│      (.text, .data, .bss, ...)     │
│                                     │
├─────────────────────────────────────┤
│      Section Headers (Shdr)         │  ← Section metadata (optional at runtime)
│    (describes each section)         │
└─────────────────────────────────────┘`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Key ELF Header Fields
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#3b82f6", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`$ readelf -h /bin/ls

ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 ...   # 0x7f "ELF" identifies file
  Class:                             ELF64
  Type:                              DYN (Position-Independent Executable)
  Machine:                           Advanced Micro Devices X86-64
  Entry point address:               0x6aa0    # Where execution starts!
  Start of program headers:          64 (bytes into file)
  Start of section headers:          140224 (bytes into file)
  Number of program headers:         13
  Number of section headers:         31`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Important Sections for RE
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { name: ".text", desc: "Executable code - where your disassembly lives", color: "#ef4444" },
              { name: ".data", desc: "Initialized global/static variables", color: "#10b981" },
              { name: ".rodata", desc: "Read-only data (strings, constants)", color: "#3b82f6" },
              { name: ".bss", desc: "Uninitialized data (zeroed at runtime)", color: "#8b5cf6" },
              { name: ".plt/.got", desc: "Dynamic linking tables (critical for exploits!)", color: "#f59e0b" },
              { name: ".symtab", desc: "Symbol table (function/variable names)", color: "#ec4899" },
              { name: ".strtab", desc: "String table for symbol names", color: "#0ea5e9" },
              { name: ".dynamic", desc: "Dynamic linking information", color: "#22c55e" },
            ].map((section) => (
              <Grid item xs={6} md={3} key={section.name}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(section.color, 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: section.color }}>{section.name}</Typography>
                  <Typography variant="caption" color="text.secondary">{section.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
              <TipsAndUpdatesIcon fontSize="small" /> Pro Tip
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Use <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>readelf -S binary</code> to list all sections, 
              and <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>readelf -l binary</code> for program headers (segments). 
              Sections are for linking; segments are for loading!
            </Typography>
          </Box>
        </Paper>

        {/* ==================== SECTION 2: PROCESS MEMORY ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
          <Typography id="process-memory-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#8b5cf6" }}>
            🧠 2. Process Memory Layout
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            How a program exists in memory at runtime
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            When you run an ELF binary, the kernel creates a new process and maps the binary into virtual memory. 
            Understanding this memory layout is crucial for debugging, exploitation, and understanding how programs 
            actually execute. Every process has its own virtual address space that looks roughly the same.
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#8b5cf6", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`High Address (0x7fff...)
┌─────────────────────────────────────┐
│            Kernel Space             │  ← Off-limits to user code
│         (not accessible)            │
├─────────────────────────────────────┤ 0x7fffffff...
│              Stack                  │  ← Local variables, return addresses
│           ↓ grows down              │    (LIFO - Last In, First Out)
│                                     │
├ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
│                                     │
│         (unmapped space)            │  ← Guard pages, random gaps (ASLR)
│                                     │
├ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
│         Shared Libraries            │  ← libc.so, ld-linux.so, etc.
│          (mmap region)              │
├ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
│                                     │
│              Heap                   │  ← malloc'd memory
│           ↑ grows up                │    (dynamic allocation)
│                                     │
├─────────────────────────────────────┤
│              .bss                   │  ← Uninitialized globals (zeroed)
├─────────────────────────────────────┤
│             .data                   │  ← Initialized globals
├─────────────────────────────────────┤
│            .rodata                  │  ← Read-only data (strings)
├─────────────────────────────────────┤
│             .text                   │  ← Executable code
├─────────────────────────────────────┤
│           ELF Headers               │
└─────────────────────────────────────┘ 0x400000 (typical base)
Low Address (0x0)`}
            </Typography>
          </Paper>

          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444", mb: 2 }}>The Stack</Typography>
                <List dense>
                  {[
                    "Grows downward (high → low addresses)",
                    "Stores local variables and function arguments",
                    "Contains return addresses (exploitation target!)",
                    "RSP register points to current top",
                    "RBP typically used as frame pointer",
                    "Each function call creates a new stack frame",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}><CheckCircleIcon sx={{ fontSize: 14, color: "#ef4444" }} /></ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#10b981", mb: 2 }}>The Heap</Typography>
                <List dense>
                  {[
                    "Grows upward (low → high addresses)",
                    "Managed by malloc/free (glibc allocator)",
                    "Used for dynamic memory allocation",
                    "Heap corruption = serious vulnerabilities",
                    "brk/sbrk syscalls extend the heap",
                    "Large allocations use mmap instead",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}><CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} /></ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Viewing Memory Maps: /proc/[pid]/maps
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#8b5cf6", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`$ cat /proc/self/maps

55a4c8a00000-55a4c8a02000 r--p 00000000  08:01 123  /usr/bin/cat  ← ELF header
55a4c8a02000-55a4c8a07000 r-xp 00002000  08:01 123  /usr/bin/cat  ← .text (executable)
55a4c8a07000-55a4c8a0a000 r--p 00007000  08:01 123  /usr/bin/cat  ← .rodata
55a4c8a0b000-55a4c8a0c000 rw-p 0000a000  08:01 123  /usr/bin/cat  ← .data/.bss
55a4c9b00000-55a4c9b21000 rw-p 00000000  00:00 0    [heap]        ← Heap
7f8b12000000-7f8b12200000 r--p 00000000  08:01 456  /lib/libc.so  ← libc
...
7ffd45600000-7ffd45621000 rw-p 00000000  00:00 0    [stack]       ← Stack
7ffd457fe000-7ffd45802000 r--p 00000000  00:00 0    [vvar]
7ffd45802000-7ffd45804000 r-xp 00000000  00:00 0    [vdso]`}
            </Typography>
          </Paper>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.1), border: `1px solid ${alpha("#ef4444", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
              <WarningIcon fontSize="small" /> Security Note
            </Typography>
            <Typography variant="body2" color="text.secondary">
              The permissions column (r-xp, rw-p, etc.) is critical: <strong>r</strong>=read, <strong>w</strong>=write, 
              <strong>x</strong>=execute. Modern systems use <strong>NX (No-Execute)</strong> to prevent code execution 
              from stack/heap. Notice how .text is r-x (execute, no write) while stack is rw- (read-write, no execute).
            </Typography>
          </Box>
        </Paper>

        {/* ==================== SECTION 3: SYSTEM CALLS ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
          <Typography id="syscalls-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#06b6d4" }}>
            📞 3. System Calls & Kernel Interface
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            The gateway between user space and kernel space
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            System calls (syscalls) are the only way user programs can request services from the kernel—like opening files, 
            allocating memory, or creating processes. Understanding syscalls is essential for RE because they reveal 
            exactly what a program is asking the operating system to do.
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#06b6d4", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ color: "#06b6d4", mb: 2, fontWeight: 700 }}>
              How a Syscall Works (x86-64)
            </Typography>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`User Space                          Kernel Space
────────────                         ────────────
                                    
1. Program prepares arguments:
   RAX = syscall number (e.g., 1 for write)
   RDI = 1st argument (fd)
   RSI = 2nd argument (buffer ptr)
   RDX = 3rd argument (count)
   R10 = 4th argument
   R8  = 5th argument
   R9  = 6th argument

2. Execute: syscall instruction
        │
        ▼
   ┌────────────────┐
   │  CPU switches  │ ──────────────▶  Kernel handles request
   │  to ring 0     │                   (validates, executes)
   └────────────────┘
        │
        ◀──────────────────────────────  Return value in RAX
        │                                (or negative errno)
3. Check RAX for result/error`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Common Syscalls for RE
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { num: "0", name: "read", args: "fd, buf, count", desc: "Read from file descriptor" },
              { num: "1", name: "write", args: "fd, buf, count", desc: "Write to file descriptor" },
              { num: "2", name: "open", args: "path, flags, mode", desc: "Open a file" },
              { num: "3", name: "close", args: "fd", desc: "Close a file descriptor" },
              { num: "9", name: "mmap", args: "addr, len, prot, flags, fd, off", desc: "Map memory (very important!)" },
              { num: "10", name: "mprotect", args: "addr, len, prot", desc: "Change memory protections" },
              { num: "59", name: "execve", args: "path, argv, envp", desc: "Execute a program" },
              { num: "60", name: "exit", args: "status", desc: "Terminate process" },
              { num: "57", name: "fork", args: "(none)", desc: "Create child process" },
              { num: "62", name: "kill", args: "pid, sig", desc: "Send signal to process" },
              { num: "101", name: "ptrace", args: "request, pid, addr, data", desc: "Process tracing (debuggers!)" },
              { num: "231", name: "exit_group", args: "status", desc: "Exit all threads" },
            ].map((sc) => (
              <Grid item xs={12} sm={6} md={4} key={sc.num}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}`, height: "100%" }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Chip label={sc.num} size="small" sx={{ bgcolor: "#06b6d4", color: "white", fontWeight: 700, fontFamily: "monospace" }} />
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace" }}>{sc.name}</Typography>
                  </Box>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary", display: "block", mb: 0.5 }}>
                    ({sc.args})
                  </Typography>
                  <Typography variant="body2" color="text.secondary">{sc.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Using strace to Trace Syscalls
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#06b6d4", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`$ strace ./mystery_binary

execve("./mystery_binary", ["./mystery_binary"], ...) = 0
brk(NULL)                               = 0x55f3a8c00000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT
openat(AT_FDCWD, "/etc/ld.so.cache"...) = 3
...
openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3    ← Reading password file!
read(3, "root:x:0:0:root:/root:/bin/bash"..., 4096) = 2847
close(3)                                = 0
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3    ← Opening network socket!
connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("10.0.0.1")}, 16) = 0
                                                 ↑ Connecting to suspicious IP!

# Useful strace flags:
$ strace -f ./binary        # Follow forks/child processes
$ strace -e open ./binary   # Filter to specific syscalls
$ strace -e trace=network   # Trace only network syscalls
$ strace -c ./binary        # Syscall statistics summary`}
            </Typography>
          </Paper>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
              <TipsAndUpdatesIcon fontSize="small" /> RE Pro Tip
            </Typography>
            <Typography variant="body2" color="text.secondary">
              When analyzing malware, <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>strace</code> is 
              your first tool! Look for suspicious syscalls like <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>connect()</code>, 
              <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>execve()</code>, or 
              <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>ptrace(PTRACE_TRACEME)</code> (anti-debugging).
            </Typography>
          </Box>
        </Paper>

        {/* ==================== SECTION 4: DYNAMIC LINKING ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
          <Typography id="dynamic-linking-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#ec4899" }}>
            🔗 4. Dynamic Linking & Loading
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            How shared libraries get resolved at runtime
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            Dynamic linking allows programs to use shared libraries (.so files) instead of bundling all code into the executable. 
            The PLT (Procedure Linkage Table) and GOT (Global Offset Table) are critical data structures that enable this. 
            Understanding them is essential for both exploitation (GOT overwrites) and understanding how function calls work.
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#ec4899", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ color: "#ec4899", mb: 2, fontWeight: 700 }}>
              How Lazy Binding Works (First Call to printf)
            </Typography>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`FIRST CALL to printf():
────────────────────────

Code:     call printf@plt        ; Jump to PLT entry
              │
              ▼
PLT:      ┌─────────────────────────────────────────┐
          │ printf@plt:                             │
          │   jmp [GOT+offset]   ; Read GOT entry   │──┐
          │   push reloc_index   ; (fallback)       │  │
          │   jmp resolver       ; (fallback)       │  │
          └─────────────────────────────────────────┘  │
                                                       │
GOT:      ┌─────────────────────────────────────────┐  │
          │ Initially points back to PLT+6         │◀─┘ (before resolution)
          └─────────────────────────────────────────┘
              │
              ▼ (falls through to resolver)
Resolver: ld-linux.so looks up "printf" in libc.so
              │
              ▼
          Updates GOT entry with actual printf address
              │
              ▼
          Jumps to real printf()

SECOND CALL to printf():
────────────────────────

Code:     call printf@plt
              │
              ▼
PLT:      jmp [GOT+offset]  ───▶  GOT now contains real address!
                                       │
                                       ▼
                                  printf() in libc (direct!)`}
            </Typography>
          </Paper>

          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.2)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#ec4899", mb: 2 }}>PLT (Procedure Linkage Table)</Typography>
                <List dense>
                  {[
                    "Small code stubs in .plt section",
                    "One entry per external function",
                    "Located in executable code (r-x)",
                    "Handles lazy resolution on first call",
                    "call printf → calls printf@plt",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}><ArrowForwardIcon sx={{ fontSize: 14, color: "#ec4899" }} /></ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.2)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#a855f7", mb: 2 }}>GOT (Global Offset Table)</Typography>
                <List dense>
                  {[
                    "Table of function pointers in .got.plt",
                    "Writable memory (rw-) — exploitation target!",
                    "Initially points back to PLT resolver",
                    "Updated with real addresses after resolution",
                    "GOT overwrite = control flow hijacking",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.3, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}><ArrowForwardIcon sx={{ fontSize: 14, color: "#a855f7" }} /></ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Viewing PLT/GOT with objdump & readelf
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#ec4899", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`# View PLT entries
$ objdump -d -j .plt binary

0000000000001030 <puts@plt>:
    1030: ff 25 e2 2f 00 00    jmp    *0x2fe2(%rip)  # GOT entry
    1036: 68 00 00 00 00       push   $0x0           # Relocation index
    103b: e9 e0 ff ff ff       jmp    1020 <_init+0x20>  # Resolver

# View GOT entries
$ readelf -r binary

Relocation section '.rela.plt':
  Offset          Type           Sym. Value    Sym. Name + Addend
000000004018  R_X86_64_JUMP_SL  0000000000000000 puts@GLIBC_2.2.5 + 0
000000004020  R_X86_64_JUMP_SL  0000000000000000 printf@GLIBC_2.2.5 + 0

# In GDB, examine GOT at runtime:
(gdb) x/10gx 0x404000
0x404000: 0x0000000000403e10   # _DYNAMIC
0x404008: 0x00007ffff7ffe2e0   # link_map
0x404010: 0x00007ffff7fdd680   # _dl_runtime_resolve
0x404018: 0x00007ffff7c50d70   # puts (resolved!)
0x404020: 0x0000000000401036   # printf (unresolved, points to PLT)`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            LD_PRELOAD: Hijacking Library Functions
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#ec4899", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`// hook.c - Custom library to intercept puts()
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

// Our malicious/debugging puts
int puts(const char *str) {
    // Get original puts
    int (*original_puts)(const char *) = dlsym(RTLD_NEXT, "puts");
    
    fprintf(stderr, "[HOOK] puts called with: %s\\n", str);
    return original_puts(str);  // Call real puts
}

// Compile: gcc -shared -fPIC -o hook.so hook.c -ldl
// Usage:   LD_PRELOAD=./hook.so ./target_binary

$ LD_PRELOAD=./hook.so ./hello
[HOOK] puts called with: Hello, World!
Hello, World!`}
            </Typography>
          </Paper>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.1), border: `1px solid ${alpha("#ef4444", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
              <WarningIcon fontSize="small" /> Security Implication
            </Typography>
            <Typography variant="body2" color="text.secondary">
              <strong>GOT Overwrite Attack:</strong> If you can write to memory, overwriting a GOT entry lets you redirect 
              function calls. For example, overwrite <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>puts@GOT</code> with 
              <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>system()</code> address. 
              Next time the program calls puts("sh"), it actually runs system("sh")! RELRO protection mitigates this.
            </Typography>
          </Box>
        </Paper>

        {/* ==================== SECTION 5: DEBUGGING ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#14b8a6", 0.2)}` }}>
          <Typography id="debugging-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#14b8a6" }}>
            🔍 5. Debugging on Linux
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            GDB, ptrace, and essential debugging techniques
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            Debugging is the heart of reverse engineering. GDB (GNU Debugger) is the standard Linux debugger, and understanding 
            how it works (via the ptrace syscall) helps you both use it effectively and understand anti-debugging techniques. 
            This section covers essential GDB commands and debugging concepts.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Essential GDB Commands
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { cat: "Running", cmds: ["r / run", "c / continue", "n / next (step over)", "s / step (step into)", "finish (run until return)"] },
              { cat: "Breakpoints", cmds: ["b *0x401234", "b main", "b function+0x10", "info break", "delete 1", "disable/enable 1"] },
              { cat: "Examining", cmds: ["x/10gx $rsp (hex)", "x/10i $rip (disasm)", "x/s 0x402000 (string)", "p $rax (print reg)", "info registers"] },
              { cat: "Memory", cmds: ["vmmap (pwndbg)", "heap (pwndbg)", "find /b 0x400000, 0x500000, 0x41", "set *0x404000 = 0x1234"] },
            ].map((section) => (
              <Grid item xs={12} sm={6} key={section.cat}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#14b8a6", 0.05), border: `1px solid ${alpha("#14b8a6", 0.15)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#14b8a6", mb: 1 }}>{section.cat}</Typography>
                  {section.cmds.map((cmd) => (
                    <Typography key={cmd} variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem", mb: 0.5 }}>
                      • {cmd}
                    </Typography>
                  ))}
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            GDB Session Example
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#14b8a6", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`$ gdb ./vulnerable_binary
(gdb) set disassembly-flavor intel
(gdb) b main
Breakpoint 1 at 0x401156

(gdb) r
Starting program: ./vulnerable_binary
Breakpoint 1, 0x0000000000401156 in main ()

(gdb) disas
Dump of assembler code for function main:
   0x0000000000401152 <+0>:     push   rbp
   0x0000000000401153 <+1>:     mov    rbp,rsp
=> 0x0000000000401156 <+4>:     sub    rsp,0x100         ; 256-byte buffer!
   0x000000000040115d <+11>:    lea    rax,[rbp-0x100]
   0x0000000000401164 <+18>:    mov    rdi,rax
   0x0000000000401167 <+21>:    call   0x401030 <gets@plt>  ; Vulnerable!

(gdb) b *0x401167                    ; Break before gets()
Breakpoint 2 at 0x401167

(gdb) c
Continuing.
Breakpoint 2, 0x0000000000401167 in main ()

(gdb) x/gx $rsp                       ; Check stack pointer
0x7fffffffe000: 0x0000000000000001

(gdb) info frame                      ; View stack frame
Stack level 0, frame at 0x7fffffffe110:
 rip = 0x401167 in main; saved rip = 0x7ffff7c29d90  ; Return address!
 Arglist at 0x7fffffffe100, args:
 Locals at 0x7fffffffe100, Previous frame's sp is 0x7fffffffe110`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            How ptrace Works (Debugger Foundation)
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#14b8a6", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`ptrace() - The syscall that makes debugging possible

PTRACE_ATTACH     - Attach to running process
PTRACE_TRACEME    - Allow parent to trace this process (child calls this)
PTRACE_PEEKTEXT   - Read memory from tracee
PTRACE_POKETEXT   - Write memory to tracee
PTRACE_GETREGS    - Read registers
PTRACE_SETREGS    - Write registers
PTRACE_SINGLESTEP - Execute one instruction
PTRACE_CONT       - Continue execution
PTRACE_DETACH     - Stop tracing

// Anti-debugging check (commonly seen in malware):
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    // Already being traced! Debugger detected!
    exit(1);
}

// Bypass in GDB:
(gdb) catch syscall ptrace
(gdb) commands
> set $rax = 0
> continue
> end`}
            </Typography>
          </Paper>

          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>GDB Enhancements</Typography>
                <List dense>
                  {[
                    { name: "pwndbg", desc: "Best for exploitation (heap cmds)" },
                    { name: "GEF", desc: "Feature-rich, good visualization" },
                    { name: "peda", desc: "Classic, pattern generation" },
                  ].map((tool) => (
                    <ListItem key={tool.name} sx={{ py: 0.3, px: 0 }}>
                      <ListItemText 
                        primary={<Typography variant="body2" sx={{ fontWeight: 600 }}>{tool.name}</Typography>}
                        secondary={tool.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>Other Tools</Typography>
                <List dense>
                  {[
                    { name: "strace", desc: "Trace syscalls" },
                    { name: "ltrace", desc: "Trace library calls" },
                    { name: "radare2 (r2)", desc: "CLI RE framework" },
                  ].map((tool) => (
                    <ListItem key={tool.name} sx={{ py: 0.3, px: 0 }}>
                      <ListItemText 
                        primary={<Typography variant="body2" sx={{ fontWeight: 600 }}>{tool.name}</Typography>}
                        secondary={tool.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== SECTION 6: BINARY PROTECTIONS ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#f97316", 0.2)}` }}>
          <Typography id="protections-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#f97316" }}>
            🛡️ 6. Binary Protections & Mitigations
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Security features that make exploitation harder
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            Modern Linux systems employ multiple security mechanisms to prevent exploitation. Understanding these protections 
            is essential for both offense (exploitation) and defense (secure development). The <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>checksec</code> tool 
            quickly shows which protections a binary has.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Using checksec
          </Typography>
          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#f97316", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`$ checksec --file=./vulnerable_binary

RELRO           STACK CANARY      NX            PIE             
Partial RELRO   No canary found   NX enabled    No PIE          
                    ↑                               ↑
                Exploitable!                   Fixed addresses!

$ checksec --file=/bin/ls   (modern hardened binary)

RELRO           STACK CANARY      NX            PIE             
Full RELRO      Canary found      NX enabled    PIE enabled`}
            </Typography>
          </Paper>

          <Grid container spacing={3} sx={{ mb: 3 }}>
            {[
              {
                name: "ASLR",
                full: "Address Space Layout Randomization",
                color: "#ef4444",
                desc: "Randomizes memory addresses each run",
                how: "Stack, heap, libraries loaded at random addresses",
                bypass: "Information leak, brute force (32-bit), or disable with: echo 0 > /proc/sys/kernel/randomize_va_space",
                check: "cat /proc/sys/kernel/randomize_va_space (0=off, 1=partial, 2=full)",
              },
              {
                name: "NX / DEP",
                full: "No-Execute (Data Execution Prevention)",
                color: "#f59e0b",
                desc: "Stack and heap are non-executable",
                how: "CPU enforces page permissions (can't execute shellcode on stack)",
                bypass: "Return-Oriented Programming (ROP) - chain existing code gadgets",
                check: "readelf -l binary | grep GNU_STACK (RWE = no NX, RW = NX enabled)",
              },
              {
                name: "Stack Canary",
                full: "Stack Smashing Protector",
                color: "#10b981",
                desc: "Random value placed before return address",
                how: "Checked before function returns; if modified → crash",
                bypass: "Leak canary value, format string, or overwrite specific data",
                check: "objdump -d binary | grep -i canary (look for __stack_chk_fail)",
              },
              {
                name: "PIE",
                full: "Position Independent Executable",
                color: "#3b82f6",
                desc: "Entire binary loaded at random address",
                how: "Code uses relative addressing, base randomized",
                bypass: "Need leak of code address to calculate other addresses",
                check: "file binary (shows 'shared object' instead of 'executable')",
              },
              {
                name: "RELRO",
                full: "Relocation Read-Only",
                color: "#8b5cf6",
                desc: "Makes GOT read-only after loading",
                how: "Partial: GOT writable. Full: GOT becomes read-only",
                bypass: "Partial RELRO still allows GOT overwrite. Full RELRO: target other structures",
                check: "readelf -l binary | grep GNU_RELRO",
              },
              {
                name: "Fortify Source",
                full: "Compile-time buffer checks",
                color: "#ec4899",
                desc: "Adds runtime checks to dangerous functions",
                how: "Replaces strcpy with __strcpy_chk when buffer size known",
                bypass: "Only protects when compiler knows buffer size",
                check: "objdump -d binary | grep _chk (fortified functions)",
              },
            ].map((prot) => (
              <Grid item xs={12} md={6} key={prot.name}>
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(prot.color, 0.05), border: `1px solid ${alpha(prot.color, 0.2)}`, height: "100%" }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Chip label={prot.name} size="small" sx={{ bgcolor: prot.color, color: "white", fontWeight: 700 }} />
                  </Box>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>{prot.full}</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600, mb: 1 }}>{prot.desc}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}><strong>How:</strong> {prot.how}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}><strong>Bypass:</strong> {prot.bypass}</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", color: alpha(prot.color, 0.8) }}>{prot.check}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#10b981", 0.1), border: `1px solid ${alpha("#10b981", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#10b981", display: "flex", alignItems: "center", gap: 1 }}>
              <TipsAndUpdatesIcon fontSize="small" /> Compilation Flags for Protections
            </Typography>
            <Typography variant="body2" sx={{ fontFamily: "monospace", mt: 1, color: "text.secondary" }}>
              # Disable protections (for practice):<br />
              gcc -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro vuln.c -o vuln<br /><br />
              # Enable all protections:<br />
              gcc -fstack-protector-all -D_FORTIFY_SOURCE=2 -pie -fPIE -Wl,-z,relro,-z,now vuln.c -o vuln
            </Typography>
          </Box>
        </Paper>

        {/* ==================== SECTION 7: LIBC INTERNALS ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#6366f1", 0.2)}` }}>
          <Typography id="libc-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#6366f1" }}>
            📚 7. libc & Standard Library Internals
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            glibc, memory allocation, and heap fundamentals
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            The C standard library (glibc on Linux) provides essential functions like malloc, printf, and file I/O. 
            Understanding libc internals—especially the heap allocator—is crucial for exploitation. Functions like 
            system() and execve() are common targets for code execution.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
            Important libc Functions for Exploitation
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { name: "system()", desc: "Execute shell command", danger: "HIGH", note: 'system("/bin/sh") = shell!' },
              { name: "execve()", desc: "Replace process with new program", danger: "HIGH", note: "Direct program execution" },
              { name: "__libc_start_main", desc: "Called before main()", danger: "MED", note: "Can be hooked" },
              { name: "printf()", desc: "Format string output", danger: "MED", note: "Format string vulns" },
              { name: "malloc()/free()", desc: "Dynamic memory allocation", danger: "MED", note: "Heap exploitation" },
              { name: "one_gadget", desc: "Magic gadgets in libc", danger: "HIGH", note: "Constraints → shell" },
            ].map((fn) => (
              <Grid item xs={12} sm={6} md={4} key={fn.name}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#6366f1", 0.05), border: `1px solid ${alpha("#6366f1", 0.15)}`, height: "100%" }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace" }}>{fn.name}</Typography>
                    <Chip 
                      label={fn.danger} 
                      size="small" 
                      sx={{ 
                        bgcolor: fn.danger === "HIGH" ? "#ef4444" : "#f59e0b", 
                        color: "white", 
                        fontSize: "0.65rem",
                        height: 18 
                      }} 
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary">{fn.desc}</Typography>
                  <Typography variant="caption" sx={{ color: "#6366f1" }}>{fn.note}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
            Heap Structure (glibc malloc)
          </Typography>
          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#6366f1", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`Heap Chunk Structure (allocated):
┌──────────────────────────────────────────┐
│         prev_size (if prev is free)      │  8 bytes
├──────────────────────────────────────────┤
│  size | A | M | P                        │  8 bytes (size + flags)
├──────────────────────────────────────────┤  A=NON_MAIN_ARENA
│                                          │  M=IS_MMAPPED
│           User Data                      │  P=PREV_INUSE
│         (your malloc'd space)            │
│                                          │
└──────────────────────────────────────────┘

Heap Chunk Structure (freed):
┌──────────────────────────────────────────┐
│              prev_size                   │
├──────────────────────────────────────────┤
│              size | flags                │
├──────────────────────────────────────────┤
│              fd (forward ptr)            │  → Next free chunk
├──────────────────────────────────────────┤
│              bk (backward ptr)           │  → Previous free chunk
├──────────────────────────────────────────┤
│              (unused space)              │
└──────────────────────────────────────────┘

Bins (free chunk storage):
─────────────────────────────
tcache[0-63]     → Per-thread cache (LIFO, fast)
fastbins[0-9]    → Small chunks (16-88 bytes), LIFO
unsorted bin     → Recently freed, any size
small bins       → < 512 bytes, sorted by size
large bins       → ≥ 512 bytes, sorted by size`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>
            Finding libc Addresses
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#6366f1", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`# Find libc base address (ASLR makes this change each run)
$ ldd /bin/ls | grep libc
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8b12345000)

# Find function offset in libc
$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " system"
  1481: 0000000000050d70    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5

# So: system_address = libc_base + 0x50d70

# In GDB with pwndbg:
pwndbg> p system
$1 = {<text variable, no debug info>} 0x7f8b123a5d70 <system>

pwndbg> libc
libc base: 0x7f8b12355000

# Using one_gadget tool to find magic gadgets:
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
  
0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL`}
            </Typography>
          </Paper>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.1), border: `1px solid ${alpha("#ef4444", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
              <WarningIcon fontSize="small" /> Common Heap Exploitation Techniques
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              <strong>Use-After-Free:</strong> Access freed memory that's been reallocated<br />
              <strong>Double Free:</strong> Free same chunk twice → corrupt freelist<br />
              <strong>Heap Overflow:</strong> Overflow into adjacent chunk metadata<br />
              <strong>Tcache Poisoning:</strong> Corrupt tcache fd pointer for arbitrary write
            </Typography>
          </Box>
        </Paper>

        {/* ==================== SECTION 8: /PROC FILESYSTEM ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
          <Typography id="proc-filesystem-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#0ea5e9" }}>
            📁 8. The /proc Filesystem
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            A window into running processes and kernel internals
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            The /proc filesystem is a virtual filesystem that provides an interface to kernel data structures. 
            It doesn't exist on disk—it's generated on-the-fly by the kernel. For reverse engineers, /proc is 
            invaluable for inspecting running processes without attaching a debugger, bypassing some anti-debugging techniques.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
            Key /proc/[pid]/ Files
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { file: "maps", desc: "Memory mappings (addresses, permissions, files)", use: "Find loaded libraries, heap/stack locations" },
              { file: "mem", desc: "Process memory (raw access)", use: "Read/write memory without ptrace" },
              { file: "cmdline", desc: "Command line arguments", use: "See how process was invoked" },
              { file: "environ", desc: "Environment variables", use: "Find sensitive env vars, paths" },
              { file: "fd/", desc: "Open file descriptors", use: "See open files, sockets, pipes" },
              { file: "exe", desc: "Symlink to executable", use: "Find the actual binary path" },
              { file: "status", desc: "Process status info", use: "PID, state, memory usage, capabilities" },
              { file: "syscall", desc: "Current syscall info", use: "See what syscall is executing" },
              { file: "stack", desc: "Kernel stack trace", use: "Debug kernel-side issues" },
              { file: "cwd", desc: "Current working directory", use: "Find where process is running" },
              { file: "root", desc: "Root directory (chroot)", use: "Detect if containerized" },
              { file: "limits", desc: "Resource limits", use: "Check stack size, file limits" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.file}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#0ea5e9", 0.05), border: `1px solid ${alpha("#0ea5e9", 0.15)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: "#0ea5e9" }}>/proc/[pid]/{item.file}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>{item.desc}</Typography>
                  <Typography variant="caption" sx={{ color: "#10b981" }}>→ {item.use}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
            Reading Process Memory via /proc
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#0ea5e9", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`# Find a process
$ pgrep -f target_binary
12345

# View memory maps
$ cat /proc/12345/maps
555555554000-555555558000 r--p 00000000 08:01 123 /path/to/binary
555555558000-55555555c000 r-xp 00004000 08:01 123 /path/to/binary  ← .text
7ffff7dc0000-7ffff7de5000 r--p 00000000 08:01 456 /lib/libc.so.6
7ffff7de5000-7ffff7f3d000 r-xp 00025000 08:01 456 /lib/libc.so.6  ← libc code
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0   [stack]

# Read memory directly (requires same user or root)
$ xxd -s 0x555555558000 -l 64 /proc/12345/mem
555555558000: 4889 e7e8 0c00 0000 4889 c7e8 1100 0000  H.......H.......

# Dump specific section
$ dd if=/proc/12345/mem bs=1 skip=$((0x555555558000)) count=4096 2>/dev/null | xxd

# Python script to read process memory:
import os
pid = 12345
maps_file = open(f"/proc/{pid}/maps", 'r')
mem_file = open(f"/proc/{pid}/mem", 'rb', 0)

for line in maps_file:
    if 'r-xp' in line and '/bin/' in line:  # Find executable section
        start, end = line.split()[0].split('-')
        start, end = int(start, 16), int(end, 16)
        mem_file.seek(start)
        data = mem_file.read(end - start)
        print(f"Read {len(data)} bytes from {hex(start)}")`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
            System-Wide /proc Files
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { file: "/proc/sys/kernel/randomize_va_space", desc: "ASLR setting (0=off, 1=partial, 2=full)" },
              { file: "/proc/sys/kernel/yama/ptrace_scope", desc: "ptrace restrictions (0=permissive)" },
              { file: "/proc/kallsyms", desc: "Kernel symbol table (addresses + names)" },
              { file: "/proc/modules", desc: "Loaded kernel modules" },
              { file: "/proc/version", desc: "Kernel version string" },
              { file: "/proc/cpuinfo", desc: "CPU features (check for security features)" },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.file}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.1)}` }}>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: 600, color: "#0ea5e9" }}>{item.file}</Typography>
                  <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
              <TipsAndUpdatesIcon fontSize="small" /> Anti-Debugging Bypass
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Some anti-debugging checks read <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>/proc/self/status</code> looking 
              for "TracerPid: 0". You can bypass this by hooking the open/read syscalls or using 
              <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>LD_PRELOAD</code> to intercept fopen() on /proc files.
            </Typography>
          </Box>
        </Paper>

        {/* ==================== SECTION 9: CALLING CONVENTIONS ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
          <Typography id="calling-conventions-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#dc2626" }}>
            📋 9. x86-64 Calling Conventions
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            System V AMD64 ABI - how functions pass arguments
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            Understanding calling conventions is essential for reading disassembly. The System V AMD64 ABI is used on 
            Linux (and macOS, BSDs). It defines which registers hold arguments, how return values are passed, and 
            which registers must be preserved across function calls.
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#dc2626", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ color: "#dc2626", mb: 2, fontWeight: 700 }}>
              System V AMD64 ABI - Argument Passing
            </Typography>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`┌─────────────────────────────────────────────────────────────┐
│  INTEGER/POINTER ARGUMENTS (in order):                      │
│                                                             │
│    Arg 1 → RDI                                              │
│    Arg 2 → RSI                                              │
│    Arg 3 → RDX                                              │
│    Arg 4 → RCX                                              │
│    Arg 5 → R8                                               │
│    Arg 6 → R9                                               │
│    Arg 7+ → Stack (right to left, 8-byte aligned)           │
├─────────────────────────────────────────────────────────────┤
│  FLOATING POINT ARGUMENTS:                                  │
│                                                             │
│    XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7          │
├─────────────────────────────────────────────────────────────┤
│  RETURN VALUES:                                             │
│                                                             │
│    Integer/Pointer → RAX (and RDX for 128-bit)              │
│    Floating Point  → XMM0 (and XMM1 for complex)            │
└─────────────────────────────────────────────────────────────┘

Example: int func(int a, int b, int c, int d, int e, int f, int g);
                   RDI   RSI   RDX   RCX   R8    R9   [rsp+8]`}
            </Typography>
          </Paper>

          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#10b981", mb: 2 }}>Callee-Saved (Must Preserve)</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1 }}>
                  <strong>RBX, RBP, R12, R13, R14, R15</strong>
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  If a function uses these, it MUST save them on entry and restore on exit. 
                  Look for push/pop pairs in function prologues/epilogues.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444", mb: 2 }}>Caller-Saved (Can Be Clobbered)</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1 }}>
                  <strong>RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11</strong>
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  These may be destroyed by function calls. Caller must save them if needed 
                  after the call. RAX always holds return value.
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
            Function Prologue & Epilogue
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#dc2626", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`TYPICAL FUNCTION PROLOGUE:
─────────────────────────
func:
    push rbp            ; Save old frame pointer (callee-saved)
    mov rbp, rsp        ; Set up new frame pointer
    sub rsp, 0x20       ; Allocate local variables (32 bytes)
    push rbx            ; Save any callee-saved regs we'll use
    
    ; Function body here
    ; Arguments in: RDI, RSI, RDX, RCX, R8, R9
    ; Local vars at: [rbp-8], [rbp-16], etc.
    
TYPICAL FUNCTION EPILOGUE:
─────────────────────────
    pop rbx             ; Restore callee-saved registers
    mov rax, result     ; Set return value
    leave               ; Equivalent to: mov rsp, rbp; pop rbp
    ret                 ; Return to caller

LEAF FUNCTION (no calls, simplified):
─────────────────────────
fast_func:
    ; No prologue needed for simple leaf functions
    mov eax, edi        ; Use arguments directly
    add eax, esi
    ret                 ; Return immediately

STACK FRAME LAYOUT:
─────────────────────────
     High addresses
    ┌────────────────┐
    │  Arg 8+        │  [rbp+24]
    ├────────────────┤
    │  Arg 7         │  [rbp+16]  (7th+ args on stack)
    ├────────────────┤
    │  Return Addr   │  [rbp+8]   ← Pushed by CALL
    ├────────────────┤
    │  Saved RBP     │  [rbp]     ← Frame pointer points here
    ├────────────────┤
    │  Local var 1   │  [rbp-8]
    ├────────────────┤
    │  Local var 2   │  [rbp-16]
    ├────────────────┤
    │  Saved RBX     │  [rbp-24]
    └────────────────┘
     Low addresses (RSP)`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
            Syscall Calling Convention (Different!)
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`SYSCALL convention (kernel interface):
──────────────────────────────────────
  Syscall # → RAX
  Arg 1    → RDI
  Arg 2    → RSI  
  Arg 3    → RDX
  Arg 4    → R10  ← Different from function calls (not RCX!)
  Arg 5    → R8
  Arg 6    → R9
  
  Return   → RAX (negative = -errno)
  
  RCX and R11 are DESTROYED by syscall instruction!

Example: write(1, "Hello", 5)
  mov rax, 1      ; syscall number for write
  mov rdi, 1      ; fd = stdout
  lea rsi, [msg]  ; buffer pointer
  mov rdx, 5      ; count
  syscall`}
            </Typography>
          </Paper>
        </Paper>

        {/* ==================== SECTION 10: SIGNALS ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
          <Typography id="signals-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#22c55e" }}>
            ⚡ 10. Signals & Signal Handlers
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Asynchronous notifications and their exploitation potential
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            Signals are software interrupts sent to processes to notify them of events. Understanding signals 
            is crucial for RE because they're used for debugging (SIGTRAP), crash handling (SIGSEGV), and 
            can be vectors for exploitation through race conditions and signal handler vulnerabilities.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Important Signals for RE
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { num: "1", name: "SIGHUP", def: "Term", desc: "Hangup / config reload" },
              { num: "2", name: "SIGINT", def: "Term", desc: "Ctrl+C interrupt" },
              { num: "3", name: "SIGQUIT", def: "Core", desc: "Ctrl+\\ quit with core dump" },
              { num: "5", name: "SIGTRAP", def: "Core", desc: "Breakpoint/trace trap (debuggers!)" },
              { num: "6", name: "SIGABRT", def: "Core", desc: "abort() called" },
              { num: "9", name: "SIGKILL", def: "Term", desc: "Kill (cannot be caught!)" },
              { num: "11", name: "SIGSEGV", def: "Core", desc: "Segmentation fault" },
              { num: "13", name: "SIGPIPE", def: "Term", desc: "Broken pipe" },
              { num: "14", name: "SIGALRM", def: "Term", desc: "Alarm clock (timeouts)" },
              { num: "15", name: "SIGTERM", def: "Term", desc: "Termination request" },
              { num: "17", name: "SIGCHLD", def: "Ign", desc: "Child process status change" },
              { num: "19", name: "SIGSTOP", def: "Stop", desc: "Stop process (cannot be caught!)" },
            ].map((sig) => (
              <Grid item xs={6} sm={4} md={3} key={sig.num}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}`, height: "100%" }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                    <Chip label={sig.num} size="small" sx={{ bgcolor: "#22c55e", color: "white", fontWeight: 700, fontFamily: "monospace", height: 20 }} />
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", fontSize: "0.75rem" }}>{sig.name}</Typography>
                  </Box>
                  <Chip label={sig.def} size="small" sx={{ height: 16, fontSize: "0.6rem", mb: 0.5 }} />
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{sig.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Signal Handlers in Code
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#22c55e", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`// Simple signal handler
#include <signal.h>
#include <stdio.h>

void handler(int sig) {
    // WARNING: Only async-signal-safe functions allowed here!
    // printf is NOT safe (can deadlock), write() is safe
    write(1, "Caught signal!\\n", 15);
}

int main() {
    // Old-style (avoid)
    signal(SIGINT, handler);
    
    // Better: sigaction (more control)
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;  // Restart interrupted syscalls
    sigaction(SIGINT, &sa, NULL);
    
    while(1) { pause(); }  // Wait for signals
}

// In disassembly, look for:
// - sigaction / signal / sigprocmask calls
// - Signal handler addresses being registered
// - SA_SIGINFO flag (handler gets extra info)

// Anti-debugging via signals:
void anti_debug(int sig) {
    // If SIGTRAP handler is called, no debugger
    // (debugger would intercept it instead)
    still_clean = 1;
}
signal(SIGTRAP, anti_debug);
raise(SIGTRAP);  // Send signal to self
if (!still_clean) exit(1);  // Debugger caught it!`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Signal-Related Vulnerabilities
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { 
                name: "Signal Handler Race", 
                desc: "Handler modifies global state while main code reads it",
                example: "TOCTOU bugs when handler sets flag"
              },
              { 
                name: "Non-Reentrant Functions", 
                desc: "Calling unsafe functions (malloc, printf) in handler",
                example: "Heap corruption if malloc interrupted by handler calling malloc"
              },
              { 
                name: "SIGRETURN Exploitation", 
                desc: "Abuse sigreturn frame to set arbitrary registers",
                example: "SROP: Sigreturn-Oriented Programming"
              },
              { 
                name: "Double Handler", 
                desc: "Signal arrives while handler is running",
                example: "Stack frame corruption"
              },
            ].map((vuln) => (
              <Grid item xs={12} sm={6} key={vuln.name}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444" }}>{vuln.name}</Typography>
                  <Typography variant="body2" color="text.secondary">{vuln.desc}</Typography>
                  <Typography variant="caption" sx={{ fontStyle: "italic", color: "#f59e0b" }}>Ex: {vuln.example}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.1), border: `1px solid ${alpha("#8b5cf6", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
              <TipsAndUpdatesIcon fontSize="small" /> SROP (Sigreturn-Oriented Programming)
            </Typography>
            <Typography variant="body2" color="text.secondary">
              When a signal handler returns, the kernel calls <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>rt_sigreturn</code> to 
              restore registers from a stack frame. If you control the stack, you can craft a fake sigreturn frame 
              to set ALL registers (including RIP) to arbitrary values—a powerful exploitation primitive!
            </Typography>
          </Box>
        </Paper>

        {/* ==================== SECTION 11: PTRACE API ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#f97316", 0.2)}` }}>
          <Typography id="ptrace-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#f97316" }}>
            🔬 11. ptrace & Process Tracing
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            The syscall that makes debugging possible
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            ptrace is the system call underlying all Linux debuggers. It allows one process (tracer) to observe and 
            control another (tracee)—reading/writing memory, registers, and single-stepping. Understanding ptrace 
            is essential for both building debugging tools and defeating anti-debugging protection.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            ptrace Requests
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { req: "PTRACE_TRACEME", desc: "Allow parent to trace me", use: "Called by child after fork" },
              { req: "PTRACE_ATTACH", desc: "Attach to running process", use: "Attach debugger to PID" },
              { req: "PTRACE_SEIZE", desc: "Attach without stopping", use: "Modern attach method" },
              { req: "PTRACE_DETACH", desc: "Stop tracing", use: "Detach debugger cleanly" },
              { req: "PTRACE_PEEKTEXT", desc: "Read word from memory", use: "Read code/data" },
              { req: "PTRACE_POKETEXT", desc: "Write word to memory", use: "Patch code, set breakpoints" },
              { req: "PTRACE_GETREGS", desc: "Read all registers", use: "Inspect CPU state" },
              { req: "PTRACE_SETREGS", desc: "Write all registers", use: "Modify execution" },
              { req: "PTRACE_SINGLESTEP", desc: "Execute one instruction", use: "Step through code" },
              { req: "PTRACE_CONT", desc: "Continue execution", use: "Resume after stop" },
              { req: "PTRACE_SYSCALL", desc: "Stop at next syscall", use: "Syscall tracing" },
              { req: "PTRACE_GETSIGINFO", desc: "Get signal info", use: "Debug crashes" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.req}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", fontSize: "0.7rem", color: "#f97316" }}>{item.req}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem" }}>{item.desc}</Typography>
                  <Typography variant="caption" sx={{ color: "#10b981" }}>→ {item.use}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Simple Tracer Example
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#f97316", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.7rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    pid_t child = fork();
    
    if (child == 0) {
        // CHILD: Request to be traced, then exec target
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], argv[1], NULL);
    } else {
        // PARENT: The tracer/debugger
        int status;
        struct user_regs_struct regs;
        
        wait(&status);  // Wait for child to stop (after TRACEME)
        
        while (WIFSTOPPED(status)) {
            // Read registers
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            printf("RIP: 0x%llx, RAX: 0x%llx\\n", regs.rip, regs.rax);
            
            // Read instruction at RIP
            long data = ptrace(PTRACE_PEEKTEXT, child, regs.rip, NULL);
            printf("Instruction bytes: %016lx\\n", data);
            
            // Single step
            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            wait(&status);
        }
    }
    return 0;
}

// Setting a breakpoint (INT3 injection):
long orig = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
ptrace(PTRACE_POKETEXT, pid, addr, (orig & ~0xff) | 0xcc);  // 0xcc = INT3
// ... wait for SIGTRAP ...
ptrace(PTRACE_POKETEXT, pid, addr, orig);  // Restore original byte`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Anti-Debugging Techniques & Bypasses
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { 
                technique: "ptrace(PTRACE_TRACEME)", 
                how: "Process traces itself; only one tracer allowed",
                bypass: "Hook ptrace, set $rax=0 in GDB, patch call"
              },
              { 
                technique: "/proc/self/status TracerPid", 
                how: "Check if TracerPid != 0",
                bypass: "LD_PRELOAD hook, modify /proc output"
              },
              { 
                technique: "Timing checks", 
                how: "Measure execution time (debugging is slow)",
                bypass: "Patch time functions, skip checks"
              },
              { 
                technique: "INT3 scanning", 
                how: "Look for 0xCC bytes in own code",
                bypass: "Use hardware breakpoints instead"
              },
              { 
                technique: "SIGTRAP handler", 
                how: "Raise SIGTRAP; handler called = no debugger",
                bypass: "Intercept signal in GDB, don't pass to program"
              },
              { 
                technique: "Parent PID check", 
                how: "Check if parent is expected (not gdb)",
                bypass: "Set fake PPID, run under expected parent"
              },
            ].map((item) => (
              <Grid item xs={12} md={6} key={item.technique}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#1e293b", 0.5), border: `1px solid ${alpha("#f97316", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", fontFamily: "monospace", fontSize: "0.75rem" }}>{item.technique}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>{item.how}</Typography>
                  <Typography variant="caption" sx={{ color: "#10b981" }}><strong>Bypass:</strong> {item.bypass}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
              <TipsAndUpdatesIcon fontSize="small" /> Yama ptrace_scope
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Modern Linux restricts ptrace via <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>/proc/sys/kernel/yama/ptrace_scope</code>:
              0 = classic (any process), 1 = parent only, 2 = admin only, 3 = disabled.
              For CTFs/RE, you may need: <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4, color: "#e2e8f0" }}>echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope</code>
            </Typography>
          </Box>
        </Paper>

        {/* ==================== SECTION 12: KERNEL MODULES ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
          <Typography id="kernel-modules-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#8b5cf6" }}>
            🔧 12. Kernel Modules & Rootkits
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            LKM internals and how rootkits hide themselves
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            Linux Kernel Modules (LKMs) are pieces of code that can be loaded into the kernel at runtime. 
            They're used for device drivers, filesystems, and security modules—but also rootkits. 
            Understanding LKMs helps you analyze both legitimate drivers and malicious kernel-level threats.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Basic LKM Structure
          </Typography>
          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#8b5cf6", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.7rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`// hello.c - Minimal kernel module
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Researcher");
MODULE_DESCRIPTION("Demo LKM");

// Called when module is loaded (insmod)
static int __init hello_init(void) {
    printk(KERN_INFO "Hello from kernel!\\n");
    return 0;  // 0 = success
}

// Called when module is unloaded (rmmod)
static void __exit hello_exit(void) {
    printk(KERN_INFO "Goodbye from kernel!\\n");
}

module_init(hello_init);
module_exit(hello_exit);

// Makefile:
obj-m += hello.o
all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

// Build and load:
$ make
$ sudo insmod hello.ko
$ dmesg | tail -1
[12345.678] Hello from kernel!
$ lsmod | grep hello
hello     16384  0
$ sudo rmmod hello`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Common Rootkit Techniques
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { 
                name: "Syscall Table Hooking", 
                desc: "Replace syscall handler pointers to intercept all calls",
                indicator: "Modified sys_call_table entries"
              },
              { 
                name: "Function Hooking (ftrace)", 
                desc: "Use kernel tracing infrastructure to intercept functions",
                indicator: "Unexpected ftrace handlers"
              },
              { 
                name: "VFS Hooking", 
                desc: "Hook file operations (read, getdents) to hide files",
                indicator: "Files visible with ls but not find"
              },
              { 
                name: "Process Hiding", 
                desc: "Remove process from task list, hide from /proc",
                indicator: "PIDs missing from ps but using resources"
              },
              { 
                name: "Module Hiding", 
                desc: "Unlink from module list, hide from lsmod",
                indicator: "Compare /proc/modules with /sys/module/"
              },
              { 
                name: "Network Hiding", 
                desc: "Filter network connections from netstat",
                indicator: "ss shows connections that netstat doesn't"
              },
            ].map((tech) => (
              <Grid item xs={12} md={6} key={tech.name}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444" }}>{tech.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>{tech.desc}</Typography>
                  <Typography variant="caption" sx={{ color: "#f59e0b" }}>🔍 {tech.indicator}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Syscall Table Hooking Example
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#8b5cf6", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.65rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`// Simplified syscall hook (educational - modern kernels have protections)
#include <linux/kallsyms.h>

static unsigned long *sys_call_table;
static asmlinkage long (*original_kill)(pid_t pid, int sig);

// Our hooked version
asmlinkage long hooked_kill(pid_t pid, int sig) {
    // Hide process with magic PID
    if (pid == 31337) {
        printk(KERN_INFO "Hidden kill!\\n");
        return 0;
    }
    return original_kill(pid, sig);
}

// Finding syscall table (modern method):
sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");

// Disable write protection to modify table:
unsigned long cr0 = read_cr0();
write_cr0(cr0 & ~0x10000);  // Clear WP bit

// Hook!
original_kill = sys_call_table[__NR_kill];
sys_call_table[__NR_kill] = hooked_kill;

write_cr0(cr0);  // Restore WP

// Detection: Compare sys_call_table entries against System.map
// Or use: cat /proc/kallsyms | grep sys_kill
//         Should match sys_call_table[__NR_kill]`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Detection & Analysis Tools
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { name: "lsmod", desc: "List loaded modules" },
              { name: "modinfo", desc: "Show module info" },
              { name: "dmesg", desc: "Kernel message buffer" },
              { name: "/proc/kallsyms", desc: "Kernel symbol addresses" },
              { name: "/sys/module/", desc: "Module parameters" },
              { name: "Volatility", desc: "Memory forensics framework" },
              { name: "chkrootkit", desc: "Rootkit detection tool" },
              { name: "rkhunter", desc: "Rootkit hunter" },
            ].map((tool) => (
              <Grid item xs={6} sm={3} key={tool.name}>
                <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}`, textAlign: "center" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: "#8b5cf6" }}>{tool.name}</Typography>
                  <Typography variant="caption" color="text.secondary">{tool.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.1), border: `1px solid ${alpha("#ef4444", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
              <WarningIcon fontSize="small" /> Modern Kernel Protections
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Modern kernels have protections against LKM attacks: <strong>KASLR</strong> (randomizes kernel addresses), 
              <strong>SMEP/SMAP</strong> (prevents kernel from executing/accessing user memory), 
              <strong>module signing</strong> (only signed modules load), and <strong>lockdown mode</strong> (restricts root).
              Analyzing rootkits often requires disabling these or using memory forensics.
            </Typography>
          </Box>
        </Paper>

        {/* ==================== SECTION 13: RE TOOLS & WORKFLOWS ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
          <Typography id="analysis-tools-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#3b82f6" }}>
            🛠️ 13. Linux RE Tools & Workflows
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Building an effective analysis toolkit and methodology
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            Having the right tools and knowing how to use them together is what separates efficient analysts from 
            those who struggle. This section covers the essential Linux RE toolkit and practical workflows for 
            different analysis scenarios.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Command-Line Analysis Tools
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { name: "file", cmd: "file binary", desc: "Identify file type, architecture, linking" },
              { name: "strings", cmd: "strings -a binary", desc: "Extract printable strings (use -a for all sections)" },
              { name: "readelf", cmd: "readelf -a binary", desc: "Display all ELF information" },
              { name: "objdump", cmd: "objdump -d binary", desc: "Disassemble code sections" },
              { name: "nm", cmd: "nm -C binary", desc: "List symbols (demangle C++ with -C)" },
              { name: "ldd", cmd: "ldd binary", desc: "Show shared library dependencies" },
              { name: "checksec", cmd: "checksec --file=binary", desc: "Check security properties" },
              { name: "hexdump", cmd: "hexdump -C binary | head", desc: "Hex dump with ASCII" },
              { name: "xxd", cmd: "xxd binary | less", desc: "Better hex viewer" },
              { name: "objcopy", cmd: "objcopy --dump-section .text=out binary", desc: "Extract sections" },
              { name: "strip", cmd: "strip binary", desc: "Remove symbols (analyze before!)" },
              { name: "patchelf", cmd: "patchelf --set-interpreter ... binary", desc: "Modify ELF properties" },
            ].map((tool) => (
              <Grid item xs={12} sm={6} md={4} key={tool.name}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>{tool.name}</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#10b981", display: "block", mb: 0.5 }}>{tool.cmd}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem" }}>{tool.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Initial Triage Workflow
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#3b82f6", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`# STEP 1: Basic identification
$ file mystery_binary
mystery_binary: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

$ checksec --file=mystery_binary
RELRO: Partial | Canary: No | NX: Yes | PIE: No | RPATH: No | RUNPATH: No

# STEP 2: Get an overview of strings (often reveals functionality)
$ strings -a mystery_binary | grep -iE 'password|flag|http|socket|/bin'
$ strings -a mystery_binary | grep -E '^[A-Za-z0-9_]{4,}$' | head -50

# STEP 3: Check symbols and imports
$ nm -C mystery_binary 2>/dev/null || echo "Stripped!"
$ objdump -T mystery_binary | grep -E 'GLIBC|system|exec|socket|connect'

# STEP 4: Examine sections
$ readelf -S mystery_binary
$ readelf -p .rodata mystery_binary   # Read-only strings

# STEP 5: Look at entry point and main
$ readelf -h mystery_binary | grep Entry
$ objdump -d mystery_binary | grep -A 20 '<main>'

# STEP 6: Runtime analysis (in sandbox!)
$ strace ./mystery_binary 2>&1 | head -100
$ ltrace ./mystery_binary 2>&1 | head -100

# STEP 7: Open in Ghidra/IDA for deeper analysis`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Disassemblers & Decompilers
          </Typography>
          <Grid container spacing={3} sx={{ mb: 3 }}>
            {[
              { 
                name: "Ghidra", 
                type: "Free (NSA)", 
                color: "#ef4444",
                pros: ["Excellent decompiler", "Multi-platform", "Scriptable (Java/Python)", "Active development"],
                cons: ["Java-based (resource heavy)", "Learning curve"],
              },
              { 
                name: "IDA Pro", 
                type: "Commercial", 
                color: "#3b82f6",
                pros: ["Industry standard", "Best x86 support", "Huge plugin ecosystem", "Hex-Rays decompiler"],
                cons: ["Expensive", "Linux version less polished"],
              },
              { 
                name: "Binary Ninja", 
                type: "Commercial", 
                color: "#10b981",
                pros: ["Modern UI", "Fast", "Great API", "HLIL/MLIL IRs"],
                cons: ["Newer ecosystem", "Decompiler improving"],
              },
              { 
                name: "radare2/Cutter", 
                type: "Free & Open Source", 
                color: "#8b5cf6",
                pros: ["CLI powerhouse", "Cutter GUI", "Fully open source", "Lightweight"],
                cons: ["Steep CLI learning curve", "Decompiler via Ghidra/r2dec"],
              },
            ].map((tool) => (
              <Grid item xs={12} sm={6} key={tool.name}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(tool.color, 0.2)}`, height: "100%" }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: tool.color }}>{tool.name}</Typography>
                    <Chip label={tool.type} size="small" sx={{ bgcolor: alpha(tool.color, 0.1), color: tool.color, fontWeight: 600 }} />
                  </Box>
                  <Grid container spacing={1}>
                    <Grid item xs={6}>
                      <Typography variant="caption" sx={{ color: "#10b981", fontWeight: 700 }}>✓ Pros</Typography>
                      {tool.pros.map((p) => (
                        <Typography key={p} variant="body2" sx={{ fontSize: "0.75rem" }}>• {p}</Typography>
                      ))}
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" sx={{ color: "#ef4444", fontWeight: 700 }}>✗ Cons</Typography>
                      {tool.cons.map((c) => (
                        <Typography key={c} variant="body2" sx={{ fontSize: "0.75rem" }}>• {c}</Typography>
                      ))}
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
              <TipsAndUpdatesIcon fontSize="small" /> Tool Tip
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Start with <strong>command-line tools</strong> for quick triage, use <strong>Ghidra</strong> for deeper static analysis 
              (it's free and powerful), and <strong>GDB + pwndbg</strong> for dynamic analysis. This combo handles 95% of Linux RE tasks.
            </Typography>
          </Box>
        </Paper>

        {/* ==================== SECTION 14: EXPLOITATION PATTERNS ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
          <Typography id="exploitation-patterns-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#ef4444" }}>
            💥 14. Exploitation Patterns on Linux
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Common vulnerability classes and exploitation techniques
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            Understanding exploitation isn't just for attackers—it helps defenders understand what's possible and 
            reverse engineers understand how protections work. This section covers the fundamental patterns you'll 
            encounter in CTFs, security research, and real-world vulnerabilities.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            Exploitation Roadmap
          </Typography>
          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#ef4444", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`┌───────────────────────────────────────────────────────────────┐
│                    EXPLOITATION WORKFLOW                       │
└───────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   ┌─────────┐         ┌─────────────┐       ┌──────────┐
   │  FIND   │         │  CONTROL    │       │ EXECUTE  │
   │  BUG    │   ───▶  │  SOMETHING  │  ───▶ │  CODE    │
   └─────────┘         └─────────────┘       └──────────┘
   • Buffer overflow    • Return address      • Shellcode
   • Format string      • Function pointer    • ROP chain  
   • Use-after-free     • GOT entry           • ret2libc
   • Integer overflow   • vtable pointer      • one_gadget
   • Race condition     • __malloc_hook       • SROP

              Protected by:                Protected by:
              Stack canary                 NX/DEP
              ASLR                         CFI (rare)
              PIE                          RELRO`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            Common Vulnerability Classes
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { 
                name: "Stack Buffer Overflow", 
                desc: "Write past buffer → overwrite return address",
                example: "char buf[64]; gets(buf);",
                target: "Saved RIP on stack",
                bypass: "Need: No canary, know/leak addresses"
              },
              { 
                name: "Format String", 
                desc: "User controls format specifier → read/write memory",
                example: "printf(user_input);",
                target: "Stack values, GOT entries",
                bypass: "%p to leak, %n to write"
              },
              { 
                name: "Heap Overflow", 
                desc: "Overflow into adjacent heap chunk metadata",
                example: "char *p = malloc(32); strcpy(p, long_input);",
                target: "Chunk headers, freed chunk pointers",
                bypass: "Depends on allocator version"
              },
              { 
                name: "Use-After-Free", 
                desc: "Access memory after free → control reallocation",
                example: "free(ptr); ... ptr->func();",
                target: "Reallocated object's data",
                bypass: "Spray heap with controlled data"
              },
              { 
                name: "Integer Overflow", 
                desc: "Arithmetic wrap → undersized allocation",
                example: "malloc(count * size); // overflow!",
                target: "Allocation size → heap overflow",
                bypass: "Calculate wrapped value"
              },
              { 
                name: "Off-By-One", 
                desc: "Write one byte past buffer (often null)",
                example: "for(i=0; i<=len; i++) // should be <",
                target: "Least significant byte of saved RBP",
                bypass: "Frame pointer manipulation"
              },
            ].map((vuln) => (
              <Grid item xs={12} md={6} key={vuln.name}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 0.5 }}>{vuln.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{vuln.desc}</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: "#1e293b", px: 1, py: 0.5, borderRadius: 1, display: "block", mb: 1 }}>{vuln.example}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    <strong>Target:</strong> {vuln.target}<br />
                    <strong>Key:</strong> {vuln.bypass}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            ROP (Return-Oriented Programming)
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#ef4444", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.7rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`# ROP bypasses NX by chaining existing code "gadgets"
# Gadget = instruction(s) ending in RET

# Finding gadgets:
$ ROPgadget --binary ./vuln | grep "pop rdi"
0x00401234 : pop rdi ; ret                    # Set RDI (1st arg)

$ ROPgadget --binary ./vuln | grep "pop rsi"
0x00401238 : pop rsi ; pop r15 ; ret          # Set RSI (2nd arg, junk r15)

# Example: Call system("/bin/sh") via ROP

# Stack layout for ROP chain:
┌────────────────────────────┐
│  addr of "pop rdi; ret"    │  ← Return address lands here
├────────────────────────────┤
│  addr of "/bin/sh" string  │  ← Popped into RDI
├────────────────────────────┤
│  addr of system()          │  ← After ret, we jump here
└────────────────────────────┘

# Using pwntools:
from pwn import *
elf = ELF('./vuln')
rop = ROP(elf)
rop.call('system', [next(elf.search(b'/bin/sh'))])
print(rop.dump())

# ret2libc: Similar but use libc gadgets when binary is small
# Need to leak libc address first (ASLR), then calculate offsets`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            pwntools Quick Reference
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#10b981", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.7rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`from pwn import *

# Setup
context.binary = elf = ELF('./vuln')
context.log_level = 'debug'  # See all I/O

# Connect
p = process('./vuln')          # Local
# p = remote('host', port)     # Remote

# I/O
p.sendline(b'input')           # Send with newline
p.send(b'raw')                 # Send without newline
p.recvline()                   # Receive line
p.recvuntil(b'> ')             # Receive until marker
leak = p.recvline()            # Capture output

# Packing
p64(0xdeadbeef)                # Pack 64-bit little-endian
u64(leak.ljust(8, b'\\x00'))   # Unpack 64-bit

# Payloads
payload = flat([
    b'A' * 72,                 # Padding to return address
    elf.symbols['win'],        # Target address
])

# Shellcraft
shellcode = asm(shellcraft.sh())  # Generate /bin/sh shellcode

# ROP
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])  # Leak GOT
rop.call('main')                      # Return to main

# GDB
gdb.attach(p, '''
    break main
    continue
''')

p.interactive()  # Drop to interactive shell`}
            </Typography>
          </Paper>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.1), border: `1px solid ${alpha("#8b5cf6", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}>
              <TipsAndUpdatesIcon fontSize="small" /> Learning Path for Exploitation
            </Typography>
            <Typography variant="body2" color="text.secondary">
              1. Start with <strong>stack overflows</strong> (no protections) → 2. Add <strong>NX</strong>, learn <strong>ret2libc</strong> → 
              3. Add <strong>ASLR</strong>, learn <strong>info leaks</strong> → 4. Add <strong>canaries</strong>, learn <strong>format strings</strong> → 
              5. Move to <strong>heap exploitation</strong>. Each step builds on the previous!
            </Typography>
          </Box>
        </Paper>

        {/* ==================== SECTION 15: PRACTICE & CTF ==================== */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
          <Typography id="practice-ctf-content" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180, color: "#10b981" }}>
            🎯 15. Practice & CTF Challenges
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Hands-on resources to build real skills
          </Typography>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            Theory without practice is useless in RE. This section provides curated resources for hands-on learning, 
            from beginner-friendly wargames to advanced CTF challenges. The key is consistent practice—solve at least 
            one challenge per day when learning.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Wargames & Practice Platforms
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { name: "pwnable.kr", url: "pwnable.kr", level: "Beginner+", focus: "Pwn fundamentals", challenges: "~50" },
              { name: "pwnable.tw", url: "pwnable.tw", level: "Intermediate", focus: "Modern exploitation", challenges: "~40" },
              { name: "pwnable.xyz", url: "pwnable.xyz", level: "Intermediate", focus: "Heap exploitation", challenges: "~35" },
              { name: "OverTheWire", url: "overthewire.org", level: "Beginner", focus: "Bandit→Narnia→Behemoth", challenges: "100+" },
              { name: "ROP Emporium", url: "ropemporium.com", level: "Beginner+", focus: "ROP techniques only", challenges: "8" },
              { name: "Exploit Education", url: "exploit.education", level: "Beginner+", focus: "Phoenix/Protostar", challenges: "~60" },
              { name: "Nightmare", url: "guyinatuxedo.github.io", level: "All levels", focus: "CTF writeups + theory", challenges: "100+" },
              { name: "how2heap", url: "github.com/shellphish/how2heap", level: "Intermediate+", focus: "Heap techniques", challenges: "~30" },
            ].map((platform) => (
              <Grid item xs={12} sm={6} md={4} key={platform.name}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.15)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#10b981" }}>{platform.name}</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#3b82f6", display: "block" }}>{platform.url}</Typography>
                  <Box sx={{ display: "flex", gap: 0.5, mt: 1, flexWrap: "wrap" }}>
                    <Chip label={platform.level} size="small" sx={{ height: 18, fontSize: "0.6rem" }} />
                    <Chip label={platform.challenges} size="small" sx={{ height: 18, fontSize: "0.6rem", bgcolor: alpha("#10b981", 0.1) }} />
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 1, fontSize: "0.8rem" }}>{platform.focus}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Recommended Learning Order
          </Typography>
          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e293b", 0.95), border: `1px solid ${alpha("#10b981", 0.3)}` }}>
            <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#e2e8f0", whiteSpace: "pre-wrap", m: 0 }}>
{`WEEK 1-2: Foundations
├── OverTheWire Bandit (Linux basics)
├── picoCTF easy RE challenges
└── Nightmare: intro chapters

WEEK 3-4: Basic Exploitation  
├── ROP Emporium (all challenges)
├── Exploit Education Phoenix (stack levels)
└── pwnable.kr: fd, collision, bof, flag

WEEK 5-6: Return-Oriented Programming
├── pwnable.kr: passcode, random, input
├── ROP Emporium with ASLR enabled
└── Practice ret2libc manually

WEEK 7-8: Format Strings & Canaries
├── pwnable.kr: fsb, asm, memcpy  
├── Nightmare format string chapters
└── Build your own exploit tools

WEEK 9-12: Heap Exploitation
├── how2heap: all glibc 2.23 techniques
├── pwnable.tw: start, orw, calc
├── pwnable.xyz: sub, add, misalignment
└── Study tcache (modern glibc)

ONGOING: CTF Competitions
├── CTFtime.org for upcoming events
├── Archive: DEFCON, PlaidCTF, GoogleCTF
└── Join a team or compete solo`}
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Essential Reading & Resources
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { title: "Hacking: The Art of Exploitation", author: "Jon Erickson", type: "Book", desc: "Classic introduction to exploitation" },
              { title: "The Shellcoder's Handbook", author: "Various", type: "Book", desc: "Comprehensive shellcode/exploit reference" },
              { title: "Practical Binary Analysis", author: "Dennis Andriesse", type: "Book", desc: "Modern binary analysis techniques" },
              { title: "LiveOverflow YouTube", author: "LiveOverflow", type: "Video", desc: "Excellent CTF/RE tutorials" },
              { title: "0x00sec", author: "Community", type: "Forum", desc: "Security research community" },
              { title: "CTF 101", author: "OSIRIS Lab", type: "Guide", desc: "ctf101.org - CTF primer" },
            ].map((resource) => (
              <Grid item xs={12} sm={6} md={4} key={resource.title}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.15)}`, height: "100%" }}>
                  <Chip label={resource.type} size="small" sx={{ mb: 1, height: 18, fontSize: "0.6rem", fontWeight: 700 }} />
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{resource.title}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>by {resource.author}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, fontSize: "0.8rem" }}>{resource.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
              <TipsAndUpdatesIcon fontSize="small" /> The 30-Day Challenge
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Commit to solving <strong>one pwn challenge every day for 30 days</strong>. Start easy (pwnable.kr fd, bof) and 
              progress. Document your solutions. By day 30, you'll have built real intuition for vulnerability patterns and 
              be ready for live CTF competitions!
            </Typography>
          </Box>
        </Paper>

        {/* ==================== COMPLETION BANNER ==================== */}
        <Paper
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#10b981", 0.15)} 0%, ${alpha("#3b82f6", 0.15)} 100%)`,
            border: `2px solid ${alpha("#10b981", 0.3)}`,
            textAlign: "center",
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, color: "#10b981" }}>
            🎉 Congratulations!
          </Typography>
          <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
            You've completed the Linux Internals for RE guide
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 700, mx: "auto", lineHeight: 1.8, mb: 3 }}>
            You now have a solid foundation in Linux binary internals—from ELF format and memory layout to exploitation 
            techniques and practice resources. Remember: <strong>reading is not enough</strong>. Fire up a terminal, 
            grab a binary, and start analyzing!
          </Typography>
          <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap" }}>
            <Button
              variant="contained"
              startIcon={<SchoolIcon />}
              onClick={() => navigate("/learn")}
              sx={{ bgcolor: "#10b981", "&:hover": { bgcolor: "#059669" } }}
            >
              More Learning Resources
            </Button>
            <Button
              variant="outlined"
              startIcon={<ArrowBackIcon />}
              onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
              sx={{ borderColor: "#3b82f6", color: "#3b82f6" }}
            >
              Back to Top
            </Button>
          </Box>
        </Paper>

        {/* ==================== TOOLS YOU'LL USE ==================== */}
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🛠️ Tools You'll Learn to Use
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Essential tools for Linux reverse engineering
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            { name: "GDB", desc: "The GNU Debugger - your primary debugging tool", color: "#dc2626", category: "Debugger" },
            { name: "readelf", desc: "Examine ELF file headers and sections", color: "#3b82f6", category: "Analysis" },
            { name: "objdump", desc: "Disassemble and display object file information", color: "#8b5cf6", category: "Analysis" },
            { name: "nm", desc: "List symbols from object files", color: "#10b981", category: "Analysis" },
            { name: "strace", desc: "Trace system calls and signals", color: "#f59e0b", category: "Tracing" },
            { name: "ltrace", desc: "Trace library calls", color: "#ec4899", category: "Tracing" },
            { name: "Ghidra", desc: "NSA's reverse engineering suite", color: "#0ea5e9", category: "Disassembler" },
            { name: "radare2", desc: "Advanced CLI reverse engineering framework", color: "#6366f1", category: "Framework" },
            { name: "pwntools", desc: "Python CTF and exploit development library", color: "#22c55e", category: "Exploitation" },
            { name: "checksec", desc: "Check binary security properties", color: "#ef4444", category: "Security" },
            { name: "ROPgadget", desc: "Search for ROP gadgets in binaries", color: "#f97316", category: "Exploitation" },
            { name: "patchelf", desc: "Modify ELF executables", color: "#8b5cf6", category: "Patching" },
          ].map((tool) => (
            <Grid item xs={6} sm={4} md={3} key={tool.name}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: `1px solid ${alpha(tool.color, 0.2)}`,
                  height: "100%",
                  transition: "all 0.2s ease",
                  "&:hover": {
                    borderColor: tool.color,
                    transform: "translateY(-2px)",
                  },
                }}
              >
                <Chip
                  label={tool.category}
                  size="small"
                  sx={{
                    mb: 1,
                    height: 18,
                    fontSize: "0.6rem",
                    fontWeight: 700,
                    bgcolor: alpha(tool.color, 0.1),
                    color: tool.color,
                  }}
                />
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: tool.color }}>
                  {tool.name}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {tool.desc}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== LEARNING PATH ==================== */}
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🗺️ Recommended Learning Path
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          How to progress through the material effectively
        </Typography>

        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
          <Grid container spacing={3}>
            {[
              { phase: "Phase 1", title: "Foundations", topics: "ELF Format, Memory Layout, /proc filesystem", weeks: "1-2", color: "#3b82f6" },
              { phase: "Phase 2", title: "System Interface", topics: "System Calls, Calling Conventions, Signals", weeks: "3-4", color: "#8b5cf6" },
              { phase: "Phase 3", title: "Dynamic Aspects", topics: "Dynamic Linking, libc Internals", weeks: "5-6", color: "#10b981" },
              { phase: "Phase 4", title: "Practical Skills", topics: "Debugging, Tools, Binary Protections", weeks: "7-8", color: "#f59e0b" },
              { phase: "Phase 5", title: "Advanced Topics", topics: "ptrace, Kernel Modules, Exploitation", weeks: "9-12", color: "#ef4444" },
            ].map((phase, idx) => (
              <Grid item xs={12} key={phase.phase}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box
                    sx={{
                      width: 60,
                      height: 60,
                      borderRadius: "50%",
                      bgcolor: alpha(phase.color, 0.1),
                      border: `2px solid ${phase.color}`,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      flexShrink: 0,
                    }}
                  >
                    <Typography variant="h6" sx={{ fontWeight: 800, color: phase.color }}>
                      {idx + 1}
                    </Typography>
                  </Box>
                  <Box sx={{ flexGrow: 1 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        {phase.phase}: {phase.title}
                      </Typography>
                      <Chip
                        label={`Weeks ${phase.weeks}`}
                        size="small"
                        sx={{
                          height: 20,
                          fontSize: "0.65rem",
                          fontWeight: 600,
                          bgcolor: alpha(phase.color, 0.1),
                          color: phase.color,
                        }}
                      />
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      {phase.topics}
                    </Typography>
                  </Box>
                  {idx < 4 && (
                    <Box sx={{ display: { xs: "none", md: "block" } }}>
                      <Typography variant="h4" color="text.disabled">→</Typography>
                    </Box>
                  )}
                </Box>
                {idx < 4 && <Divider sx={{ mt: 2 }} />}
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== NEXT STEPS ==================== */}
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🚀 Where to Go From Here
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Continue your reverse engineering journey
        </Typography>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { title: "Buffer Overflow", desc: "Apply your knowledge to stack-based exploitation", path: "/learn/buffer-overflow", color: "#ef4444" },
            { title: "Ghidra Guide", desc: "Use a powerful disassembler with your new knowledge", path: "/learn/ghidra", color: "#dc2626" },
            { title: "Windows Internals", desc: "Compare with Windows RE techniques", path: "/learn/windows-internals", color: "#8b5cf6" },
            { title: "Debugging 101", desc: "Strengthen your debugging foundations", path: "/learn/debugging-101", color: "#3b82f6" },
          ].map((item) => (
            <Grid item xs={12} sm={6} key={item.title}>
              <Paper
                onClick={() => navigate(item.path)}
                sx={{
                  p: 3,
                  borderRadius: 3,
                  cursor: "pointer",
                  border: `1px solid ${alpha(item.color, 0.2)}`,
                  transition: "all 0.2s ease",
                  "&:hover": {
                    borderColor: item.color,
                    transform: "translateX(4px)",
                    boxShadow: `0 4px 16px ${alpha(item.color, 0.15)}`,
                  },
                }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>
                  {item.title} →
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {item.desc}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Back to Learning Hub Button */}
        <Box sx={{ display: "flex", justifyContent: "center", mt: 6 }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{
              px: 4,
              py: 1.5,
              borderRadius: 3,
              fontWeight: 700,
              background: `linear-gradient(135deg, #f97316, #3b82f6)`,
              "&:hover": {
                background: `linear-gradient(135deg, #ea580c, #2563eb)`,
              },
            }}
          >
            Back to Learning Hub
          </Button>
        </Box>

        {/* Floating Back to Top Button */}
        <Zoom in={useScrollTrigger({ disableHysteresis: true, threshold: 400 })}>
          <Fab
            color="primary"
            size="medium"
            onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
            sx={{
              position: "fixed",
              bottom: 24,
              right: 24,
              bgcolor: "#f97316",
              "&:hover": { bgcolor: "#ea580c" },
              zIndex: 1000,
            }}
          >
            <KeyboardArrowUpIcon />
          </Fab>
        </Zoom>

      </Container>
    </LearnPageLayout>
  );
}
