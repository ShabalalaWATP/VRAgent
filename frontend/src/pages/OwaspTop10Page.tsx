import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  IconButton,
  Chip,
  Grid,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Link,
  Alert,
  LinearProgress,
} from "@mui/material";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import LaunchIcon from "@mui/icons-material/Launch";
import WarningIcon from "@mui/icons-material/Warning";
import SecurityIcon from "@mui/icons-material/Security";

interface OwaspItem {
  id: string;
  rank: number;
  name: string;
  shortName: string;
  color: string;
  prevalence: number;
  description: string;
  impact: string;
  examples: string[];
  prevention: string[];
  cwes: { id: string; name: string }[];
  realWorldIncident: string;
}

const owaspTop10: OwaspItem[] = [
  {
    id: "A01",
    rank: 1,
    name: "Broken Access Control",
    shortName: "Access Control",
    color: "#dc2626",
    prevalence: 94,
    description: "Failures in enforcing restrictions on what authenticated users are allowed to do. Attackers exploit these flaws to access unauthorized functionality and/or data, such as accessing other users' accounts, viewing sensitive files, or modifying other users' data.",
    impact: "Attackers can act as users or administrators, create, access, update, or delete any record, or gain unauthorized access to data.",
    examples: [
      "Modifying URL parameters to access other users' data (IDOR)",
      "Elevation of privilege by modifying JWT tokens or cookies",
      "Force browsing to authenticated pages as unauthenticated user",
      "Accessing API endpoints with missing access controls",
      "CORS misconfiguration allowing unauthorized API access",
    ],
    prevention: [
      "Deny access by default (except for public resources)",
      "Implement access control mechanisms once and reuse throughout the application",
      "Model access controls should enforce record ownership",
      "Disable directory listing and ensure metadata/backup files aren't in web roots",
      "Log access control failures and alert admins on repeated failures",
      "Rate limit API and controller access to minimize automated attack damage",
    ],
    cwes: [
      { id: "CWE-200", name: "Exposure of Sensitive Information" },
      { id: "CWE-201", name: "Insertion of Sensitive Information Into Sent Data" },
      { id: "CWE-352", name: "Cross-Site Request Forgery (CSRF)" },
    ],
    realWorldIncident: "2019 Capital One breach: SSRF combined with overly permissive IAM roles exposed 100M+ customer records.",
  },
  {
    id: "A02",
    rank: 2,
    name: "Cryptographic Failures",
    shortName: "Crypto Failures",
    color: "#ea580c",
    prevalence: 89,
    description: "Failures related to cryptography (or lack thereof), which often lead to exposure of sensitive data. Previously known as 'Sensitive Data Exposure'. Includes data transmitted in clear text, weak cryptographic algorithms, and improper key management.",
    impact: "Exposure of sensitive data including passwords, credit card numbers, health records, personal information, and business secrets.",
    examples: [
      "Transmitting data in clear text (HTTP, SMTP, FTP)",
      "Using old or weak cryptographic algorithms (MD5, SHA1, DES)",
      "Using default, weak, or re-used cryptographic keys",
      "Not enforcing encryption with proper headers (HSTS)",
      "Improper certificate validation",
    ],
    prevention: [
      "Classify data processed, stored, or transmitted and identify which is sensitive",
      "Apply controls per classification, don't store sensitive data unnecessarily",
      "Encrypt all sensitive data at rest using strong algorithms (AES-256)",
      "Encrypt all data in transit with secure protocols (TLS 1.2+)",
      "Use authenticated encryption instead of just encryption",
      "Generate cryptographically strong random keys, store keys securely",
    ],
    cwes: [
      { id: "CWE-259", name: "Use of Hard-coded Password" },
      { id: "CWE-327", name: "Use of Broken or Risky Cryptographic Algorithm" },
      { id: "CWE-331", name: "Insufficient Entropy" },
    ],
    realWorldIncident: "2017 Equifax: Unencrypted data at rest meant 143M people's SSNs, birth dates, and addresses were exposed.",
  },
  {
    id: "A03",
    rank: 3,
    name: "Injection",
    shortName: "Injection",
    color: "#d97706",
    prevalence: 84,
    description: "User-supplied data is not validated, filtered, or sanitized by the application, allowing attackers to inject malicious code. Includes SQL, NoSQL, OS command, ORM, LDAP, and Expression Language injection.",
    impact: "Data loss, corruption, or disclosure to unauthorized parties. Loss of accountability. Denial of access. Complete host takeover.",
    examples: [
      "SQL injection: SELECT * FROM users WHERE id = '" + "user_input" + "'",
      "Command injection: system('ping ' + user_input)",
      "LDAP injection in authentication queries",
      "XPath injection for XML data queries",
      "Template injection (SSTI) in server-side templates",
    ],
    prevention: [
      "Use parameterized queries or prepared statements for all database access",
      "Use positive server-side input validation",
      "Escape special characters for interpreters",
      "Use LIMIT and other SQL controls to prevent mass disclosure",
      "Use safe APIs that provide parameterized interfaces",
    ],
    cwes: [
      { id: "CWE-79", name: "Cross-site Scripting (XSS)" },
      { id: "CWE-89", name: "SQL Injection" },
      { id: "CWE-73", name: "External Control of File Name or Path" },
    ],
    realWorldIncident: "2008 Heartland Payment Systems: SQL injection exposed 134M credit cards, largest payment card breach at the time.",
  },
  {
    id: "A04",
    rank: 4,
    name: "Insecure Design",
    shortName: "Insecure Design",
    color: "#ca8a04",
    prevalence: 78,
    description: "Focuses on risks related to design and architectural flaws. Calls for more use of threat modeling, secure design patterns, and reference architectures. A secure implementation cannot fix an insecure design.",
    impact: "Systemic vulnerabilities that cannot be fixed by better implementation. Requires architectural changes to remediate.",
    examples: [
      "No rate limiting on sensitive operations (account creation, password reset)",
      "Missing business logic validation (negative quantities, prices)",
      "Trust boundaries not properly defined",
      "Lack of segregation of duties",
      "Credential recovery mechanism reveals user existence",
    ],
    prevention: [
      "Establish and use a secure development lifecycle with security professionals",
      "Use threat modeling for critical authentication, access control, business logic",
      "Integrate security language and controls into user stories",
      "Write unit and integration tests to validate all critical flows",
      "Segregate tier layers on system and network level",
    ],
    cwes: [
      { id: "CWE-209", name: "Generation of Error Message Containing Sensitive Info" },
      { id: "CWE-256", name: "Plaintext Storage of a Password" },
      { id: "CWE-501", name: "Trust Boundary Violation" },
    ],
    realWorldIncident: "Twitter API design flaw allowed enumeration of all phone numbers linked to accounts (2019 vulnerability).",
  },
  {
    id: "A05",
    rank: 5,
    name: "Security Misconfiguration",
    shortName: "Misconfig",
    color: "#65a30d",
    prevalence: 71,
    description: "Application is vulnerable due to missing appropriate security hardening, improperly configured permissions, unnecessary features enabled, default accounts/passwords, overly informative error messages, or disabled security features.",
    impact: "Unauthorized access to systems or data, sometimes full system compromise. Often easy to detect and exploit.",
    examples: [
      "Default credentials not changed (admin/admin)",
      "Unnecessary features enabled (ports, services, pages, accounts)",
      "Error handling reveals stack traces to users",
      "Cloud storage buckets publicly accessible",
      "Security headers missing or misconfigured",
      "Directory listing enabled on web server",
    ],
    prevention: [
      "Repeatable hardening process making it fast to deploy secure environments",
      "Minimal platform without unnecessary features or frameworks",
      "Review and update configurations as part of patch management",
      "Segmented application architecture with secure separation",
      "Automated process to verify configuration effectiveness",
    ],
    cwes: [
      { id: "CWE-16", name: "Configuration" },
      { id: "CWE-611", name: "Improper Restriction of XML External Entity Reference" },
      { id: "CWE-1188", name: "Initialization with Hard-Coded Network Resource Configuration" },
    ],
    realWorldIncident: "2019 Facebook: 540M records exposed due to misconfigured third-party app storage on AWS.",
  },
  {
    id: "A06",
    rank: 6,
    name: "Vulnerable and Outdated Components",
    shortName: "Components",
    color: "#16a34a",
    prevalence: 67,
    description: "Using components (libraries, frameworks, software modules) with known vulnerabilities or that are unsupported/out of date. Includes operating systems, web servers, databases, APIs, and all components/libraries.",
    impact: "Can range from minimal impact to full server compromise and data breach, depending on the vulnerable component.",
    examples: [
      "Using libraries with known CVEs (Log4Shell in Log4j)",
      "Running outdated OS versions without security patches",
      "Using frameworks past end-of-life without updates",
      "Not scanning dependencies for vulnerabilities",
      "Failing to fix/upgrade underlying platform in a timely fashion",
    ],
    prevention: [
      "Remove unused dependencies, features, components, files, and documentation",
      "Continuously inventory component versions (SBOM)",
      "Only obtain components from official sources over secure links",
      "Monitor for unmaintained libraries without security patches",
      "Subscribe to security bulletins for components you use",
    ],
    cwes: [
      { id: "CWE-1104", name: "Use of Unmaintained Third Party Components" },
      { id: "CWE-937", name: "Using Components with Known Vulnerabilities" },
    ],
    realWorldIncident: "2017 Equifax: Failed to patch known Apache Struts vulnerability (CVE-2017-5638), leading to breach of 143M records.",
  },
  {
    id: "A07",
    rank: 7,
    name: "Identification and Authentication Failures",
    shortName: "Auth Failures",
    color: "#0891b2",
    prevalence: 62,
    description: "Confirmation of the user's identity, authentication, and session management is critical. Weaknesses can allow attackers to compromise passwords, keys, or session tokens, or exploit implementation flaws to assume other users' identities.",
    impact: "Account takeover, identity theft, unauthorized access to sensitive functions and data.",
    examples: [
      "Permitting brute force or credential stuffing attacks",
      "Using weak or well-known passwords (Password1, admin123)",
      "Using weak or ineffective credential recovery",
      "Exposing session ID in URL",
      "Not properly invalidating sessions on logout",
      "Not rotating session IDs after successful login",
    ],
    prevention: [
      "Implement multi-factor authentication (MFA)",
      "Do not deploy with default credentials",
      "Implement weak password checks against common password lists",
      "Align password policies with NIST 800-63 guidelines",
      "Harden against credential enumeration attacks",
      "Limit failed login attempts with exponential backoff",
    ],
    cwes: [
      { id: "CWE-287", name: "Improper Authentication" },
      { id: "CWE-297", name: "Improper Validation of Certificate with Host Mismatch" },
      { id: "CWE-384", name: "Session Fixation" },
    ],
    realWorldIncident: "2012 LinkedIn: 117M password hashes stolen due to unsalted SHA-1 hashing, later cracked and leaked.",
  },
  {
    id: "A08",
    rank: 8,
    name: "Software and Data Integrity Failures",
    shortName: "Integrity",
    color: "#2563eb",
    prevalence: 55,
    description: "Code and infrastructure that does not protect against integrity violations. Includes using untrusted plugins/libraries/modules, insecure CI/CD pipelines, and auto-update functionality without integrity verification.",
    impact: "Supply chain compromise, malicious updates, unauthorized code execution.",
    examples: [
      "Using CDNs or package managers without integrity verification (SRI)",
      "Insecure deserialization from untrusted sources",
      "CI/CD pipeline without proper access controls and verification",
      "Auto-update functionality without signed updates",
      "Object serialization used for state or communication",
    ],
    prevention: [
      "Use digital signatures to verify software/data from expected source",
      "Use software composition analysis tools",
      "Ensure CI/CD pipeline has proper segregation and access control",
      "Review code and config changes for malicious content",
      "Ensure unsigned or unencrypted serialized data isn't sent to untrusted clients",
    ],
    cwes: [
      { id: "CWE-829", name: "Inclusion of Functionality from Untrusted Control Sphere" },
      { id: "CWE-494", name: "Download of Code Without Integrity Check" },
      { id: "CWE-502", name: "Deserialization of Untrusted Data" },
    ],
    realWorldIncident: "2020 SolarWinds: Nation-state actors compromised build process, distributing malware to 18,000+ organizations.",
  },
  {
    id: "A09",
    rank: 9,
    name: "Security Logging and Monitoring Failures",
    shortName: "Logging",
    color: "#7c3aed",
    prevalence: 48,
    description: "Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response allows attackers to maintain persistence, pivot to more systems, and tamper with, extract, or destroy data.",
    impact: "Delayed or failed breach detection, inability to respond to incidents, no forensic evidence for investigation.",
    examples: [
      "Login, failed logins, and high-value transactions not logged",
      "Logs not monitored for suspicious activity",
      "Logs only stored locally",
      "Inappropriate alerting thresholds or no alerting",
      "Penetration testing doesn't trigger alerts",
    ],
    prevention: [
      "Log all login, access control, and server-side input validation failures",
      "Ensure logs are generated in format easily consumed by log management",
      "Ensure high-value transactions have audit trail with integrity controls",
      "Establish effective monitoring and alerting",
      "Establish or adopt incident response and recovery plan (NIST 800-61r2)",
    ],
    cwes: [
      { id: "CWE-778", name: "Insufficient Logging" },
      { id: "CWE-117", name: "Improper Output Neutralization for Logs" },
      { id: "CWE-223", name: "Omission of Security-relevant Information" },
    ],
    realWorldIncident: "2013 Target: Attackers in network for 2 weeks; security alerts were generated but not acted upon. 40M cards compromised.",
  },
  {
    id: "A10",
    rank: 10,
    name: "Server-Side Request Forgery (SSRF)",
    shortName: "SSRF",
    color: "#c026d3",
    prevalence: 43,
    description: "SSRF occurs when a web application fetches a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send crafted requests to unexpected destinations.",
    impact: "Internal service enumeration, reading internal files, accessing cloud metadata, pivoting to internal systems.",
    examples: [
      "Fetching URL from user input: fetch(user_url)",
      "Accessing cloud metadata (169.254.169.254)",
      "Port scanning internal network through vulnerable app",
      "Reading local files via file:// protocol",
      "Accessing internal admin interfaces",
    ],
    prevention: [
      "Segment remote resource access functionality in separate networks",
      "Enforce 'deny by default' firewall policies",
      "Sanitize and validate all client-supplied URLs",
      "Disable HTTP redirections",
      "Don't return raw responses to clients",
      "Use allowlists for URL schemas, ports, and destinations",
    ],
    cwes: [
      { id: "CWE-918", name: "Server-Side Request Forgery (SSRF)" },
    ],
    realWorldIncident: "2019 Capital One: SSRF in WAF allowed attacker to access AWS metadata and steal credentials, exposing 106M records.",
  },
];

export default function OwaspTop10Page() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [expandedItem, setExpandedItem] = useState<string | false>("A01");

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Button */}
      <IconButton onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
        <ArrowBackIcon />
      </IconButton>

      {/* Header */}
      <Box sx={{ mb: 5 }}>
        <Typography
          variant="h3"
          sx={{
            fontWeight: 800,
            mb: 2,
            background: `linear-gradient(135deg, #dc2626, #7c3aed)`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          🛡️ OWASP Top 10 (2021)
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 900 }}>
          The definitive awareness document for web application security, representing the most critical security risks to web applications.
        </Typography>
      </Box>

      {/* Overview */}
      <Paper sx={{ p: 4, mb: 5, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#dc2626", 0.05)}, ${alpha("#7c3aed", 0.05)})` }}>
        <Grid container spacing={4}>
          <Grid item xs={12} md={8}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
              What is the OWASP Top 10?
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
              The <strong>OWASP Top 10</strong> is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications, published by the Open Web Application Security Project (OWASP).
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
              The 2021 edition includes three new categories (A04, A08, A10), merges several previous categories, and is based on data from over 500,000 applications and APIs. It's the industry standard reference for prioritizing web security efforts.
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              <Chip label="2021 Edition" sx={{ bgcolor: alpha("#dc2626", 0.1), color: "#dc2626", fontWeight: 600 }} />
              <Chip label="10 Categories" variant="outlined" />
              <Chip label="500K+ Apps Analyzed" variant="outlined" />
              <Chip label="Industry Standard" variant="outlined" />
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <Alert severity="info" sx={{ mb: 2, borderRadius: 2 }}>
              <Typography variant="body2">
                <strong>💡 Pro Tip:</strong> Use OWASP Top 10 for prioritization, not as an exhaustive checklist. Many important vulnerabilities aren't in the Top 10.
              </Typography>
            </Alert>
            <Link
              href="https://owasp.org/Top10/"
              target="_blank"
              rel="noopener"
              sx={{ display: "flex", alignItems: "center", gap: 0.5 }}
            >
              Official OWASP Top 10 Site <LaunchIcon fontSize="small" />
            </Link>
          </Grid>
        </Grid>
      </Paper>

      {/* Risk Visualization */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
        📊 Prevalence Overview
      </Typography>
      <Paper sx={{ p: 3, mb: 5, borderRadius: 3 }}>
        <Grid container spacing={2}>
          {owaspTop10.map((item) => (
            <Grid item xs={12} key={item.id}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <Box sx={{ minWidth: 40, textAlign: "center" }}>
                  <Typography variant="h6" sx={{ fontWeight: 800, color: item.color }}>
                    #{item.rank}
                  </Typography>
                </Box>
                <Box sx={{ flex: 1 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      {item.name}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {item.prevalence}% of apps affected
                    </Typography>
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={item.prevalence}
                    sx={{
                      height: 8,
                      borderRadius: 4,
                      bgcolor: alpha(item.color, 0.1),
                      "& .MuiLinearProgress-bar": { bgcolor: item.color, borderRadius: 4 },
                    }}
                  />
                </Box>
              </Box>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Detailed Breakdown */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
        📋 Detailed Breakdown
      </Typography>
      {owaspTop10.map((item) => (
        <Accordion
          key={item.id}
          expanded={expandedItem === item.id}
          onChange={(_, expanded) => setExpandedItem(expanded ? item.id : false)}
          sx={{
            mb: 2,
            borderRadius: 2,
            "&:before": { display: "none" },
            border: `1px solid ${alpha(item.color, 0.2)}`,
            "&.Mui-expanded": { border: `2px solid ${item.color}` },
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{
              bgcolor: alpha(item.color, 0.05),
              borderRadius: "8px 8px 0 0",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
              <Chip
                label={item.id}
                size="small"
                sx={{ bgcolor: item.color, color: "white", fontWeight: 700, minWidth: 50 }}
              />
              <Box sx={{ flex: 1 }}>
                <Typography variant="h6" sx={{ fontWeight: 700 }}>
                  {item.name}
                </Typography>
              </Box>
              <Chip
                label={`${item.prevalence}%`}
                size="small"
                variant="outlined"
                sx={{ borderColor: item.color, color: item.color }}
              />
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ p: 4 }}>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              {item.description}
            </Typography>

            <Alert severity="error" sx={{ mb: 3, borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Impact</Typography>
              <Typography variant="body2">{item.impact}</Typography>
            </Alert>

            <Grid container spacing={4}>
              {/* Examples */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <WarningIcon fontSize="small" /> Common Examples
                  </Typography>
                  <List dense>
                    {item.examples.map((example, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <Typography variant="body2">•</Typography>
                        </ListItemIcon>
                        <ListItemText primary={example} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>

              {/* Prevention */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.15)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <SecurityIcon fontSize="small" /> Prevention Measures
                  </Typography>
                  <List dense>
                    {item.prevention.map((prev, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <Typography variant="body2" color="success.main">✓</Typography>
                        </ListItemIcon>
                        <ListItemText primary={prev} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            </Grid>

            <Divider sx={{ my: 3 }} />

            {/* CWEs and Incident */}
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>📌 Related CWEs</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                  {item.cwes.map((cwe) => (
                    <Link
                      key={cwe.id}
                      href={`https://cwe.mitre.org/data/definitions/${cwe.id.split("-")[1]}.html`}
                      target="_blank"
                      rel="noopener"
                      underline="none"
                    >
                      <Chip
                        label={`${cwe.id}: ${cwe.name}`}
                        size="small"
                        clickable
                        sx={{ fontSize: "0.75rem", bgcolor: alpha(item.color, 0.1), color: item.color }}
                      />
                    </Link>
                  ))}
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>🔥 Real-World Incident</Typography>
                <Typography variant="body2" color="text.secondary">
                  {item.realWorldIncident}
                </Typography>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>
      ))}

      {/* Resources */}
      <Paper sx={{ p: 4, mt: 4, borderRadius: 3, bgcolor: alpha(theme.palette.info.main, 0.05), border: `1px solid ${alpha(theme.palette.info.main, 0.2)}` }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          🔗 Additional Resources
        </Typography>
        <Grid container spacing={2}>
          {[
            { title: "OWASP Top 10 Official", url: "https://owasp.org/Top10/" },
            { title: "OWASP Testing Guide", url: "https://owasp.org/www-project-web-security-testing-guide/" },
            { title: "OWASP Cheat Sheet Series", url: "https://cheatsheetseries.owasp.org/" },
            { title: "OWASP ASVS", url: "https://owasp.org/www-project-application-security-verification-standard/" },
          ].map((resource) => (
            <Grid item xs={12} sm={6} md={3} key={resource.title}>
              <Link href={resource.url} target="_blank" rel="noopener" underline="none">
                <Paper
                  sx={{
                    p: 2,
                    textAlign: "center",
                    bgcolor: "background.paper",
                    transition: "all 0.2s",
                    "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) },
                  }}
                >
                  <Typography variant="body2" sx={{ fontWeight: 600, color: "primary.main", display: "flex", alignItems: "center", justifyContent: "center", gap: 0.5 }}>
                    {resource.title} <LaunchIcon fontSize="small" />
                  </Typography>
                </Paper>
              </Link>
            </Grid>
          ))}
        </Grid>
      </Paper>
    </Container>
  );
}
