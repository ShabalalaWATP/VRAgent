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
import CodeIcon from "@mui/icons-material/Code";
import WarningIcon from "@mui/icons-material/Warning";
import WebIcon from "@mui/icons-material/Web";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import { useNavigate } from "react-router-dom";

interface XSSType {
  title: string;
  description: string;
  persistence: string;
  color: string;
}

const xssTypes: XSSType[] = [
  { title: "Reflected XSS", description: "Payload in URL/request, reflected back in response", persistence: "Non-persistent", color: "#f59e0b" },
  { title: "Stored XSS", description: "Payload saved in database, executes for all users", persistence: "Persistent", color: "#ef4444" },
  { title: "DOM-Based XSS", description: "Payload manipulates DOM directly via client-side JS", persistence: "Client-side", color: "#8b5cf6" },
];

const commonPayloads = [
  { payload: "<script>alert(1)</script>", context: "Basic test" },
  { payload: "<img src=x onerror=alert(1)>", context: "Event handler" },
  { payload: "<svg onload=alert(1)>", context: "SVG element" },
  { payload: "javascript:alert(1)", context: "URL scheme" },
  { payload: "'-alert(1)-'", context: "Attribute breakout" },
  { payload: "</script><script>alert(1)</script>", context: "Tag escape" },
];

const impactScenarios = [
  "Session hijacking (steal cookies)",
  "Keylogging user input",
  "Phishing via page modification",
  "Cryptocurrency mining",
  "Malware distribution",
  "Credential theft via fake login forms",
];

const preventionMethods = [
  "Context-aware output encoding (HTML, JS, URL, CSS)",
  "Content Security Policy (CSP) headers",
  "HttpOnly and Secure cookie flags",
  "Input validation (whitelist allowed chars)",
  "Use frameworks with auto-escaping (React, Angular)",
  "Sanitize HTML with DOMPurify or similar",
];

const dangerousSinks = [
  "innerHTML, outerHTML",
  "document.write()",
  "eval(), setTimeout(), setInterval()",
  "location.href, location.assign()",
  "jQuery .html(), .append()",
];

export default function XSSGuidePage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Cross-Site Scripting (XSS) Guide - Covers reflected, stored, and DOM-based XSS types. Lists common payloads, dangerous JavaScript sinks, impact scenarios, and prevention methods including CSP and output encoding.`;

  return (
    <LearnPageLayout pageTitle="Cross-Site Scripting (XSS)" pageContext={pageContext}>
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
                bgcolor: alpha("#f59e0b", 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <CodeIcon sx={{ fontSize: 36, color: "#f59e0b" }} />
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Cross-Site Scripting (XSS)
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Client-Side Code Injection
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Web Security" color="warning" size="small" />
            <Chip label="OWASP A03" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
            <Chip label="Client-Side" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
          </Box>
        </Box>

        {/* Overview */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <WebIcon color="warning" /> What is XSS?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other 
            users. The victim's browser executes the script in the context of the vulnerable site, enabling session 
            hijacking, data theft, and account takeover.
          </Typography>
        </Paper>

        {/* XSS Types */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 XSS Types</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {xssTypes.map((type) => (
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
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: type.color }}>
                    {type.title}
                  </Typography>
                  <Chip label={type.persistence} size="small" sx={{ fontSize: "0.65rem", height: 20 }} />
                </Box>
                <Typography variant="body2" color="text.secondary">
                  {type.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Common Payloads */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.05)}, ${alpha("#ef4444", 0.05)})`,
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <BugReportIcon sx={{ color: "#f59e0b" }} /> Common Payloads
          </Typography>
          <Grid container spacing={1}>
            {commonPayloads.map((p, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Box sx={{ p: 0.5, px: 1, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem", flexShrink: 0 }}>
                    {p.payload}
                  </Box>
                  <Typography variant="caption" color="text.secondary">{p.context}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Dangerous Sinks & Impact */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ color: "#8b5cf6" }} /> Dangerous Sinks (DOM XSS)
              </Typography>
              <List dense>
                {dangerousSinks.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2", fontFamily: "monospace", fontSize: "0.8rem" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: "#ef4444" }} /> Impact Scenarios
              </Typography>
              <List dense>
                {impactScenarios.map((s, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <WarningIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={s} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Prevention */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon sx={{ color: "#10b981" }} /> Prevention Methods
          </Typography>
          <Grid container spacing={1}>
            {preventionMethods.map((m, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                  <Typography variant="body2">{m}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Tip */}
        <Paper
          sx={{
            p: 2,
            mb: 4,
            borderRadius: 2,
            bgcolor: alpha("#3b82f6", 0.05),
            border: `1px solid ${alpha("#3b82f6", 0.2)}`,
            display: "flex",
            alignItems: "center",
            gap: 2,
          }}
        >
          <TipsAndUpdatesIcon sx={{ color: "#3b82f6" }} />
          <Typography variant="body2">
            <strong>CSP Tip:</strong> Start with <code>Content-Security-Policy: default-src 'self'</code> and gradually add trusted sources.
          </Typography>
        </Paper>

        {/* Related */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📚 Related Learning</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Command Injection →" clickable onClick={() => navigate("/learn/command-injection")} sx={{ fontWeight: 600 }} />
            <Chip label="SQL Injection →" clickable onClick={() => navigate("/learn/sql-injection")} sx={{ fontWeight: 600 }} />
            <Chip label="OWASP Top 10 →" clickable onClick={() => navigate("/learn/owasp")} sx={{ fontWeight: 600 }} />
          </Box>
        </Paper>
      </Container>
    </LearnPageLayout>
  );
}
