import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Button,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  keyframes,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import LockIcon from "@mui/icons-material/Lock";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SecurityIcon from "@mui/icons-material/Security";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import CancelIcon from "@mui/icons-material/Cancel";
import InfoIcon from "@mui/icons-material/Info";
import BugReportIcon from "@mui/icons-material/BugReport";
import ShieldIcon from "@mui/icons-material/Shield";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import LinkIcon from "@mui/icons-material/Link";
import GppBadIcon from "@mui/icons-material/GppBad";
import GppGoodIcon from "@mui/icons-material/GppGood";
import ReportProblemIcon from "@mui/icons-material/ReportProblem";
import SpeedIcon from "@mui/icons-material/Speed";
import BuildIcon from "@mui/icons-material/Build";
import KeyIcon from "@mui/icons-material/Key";
import PublicIcon from "@mui/icons-material/Public";
import DnsIcon from "@mui/icons-material/Dns";
import SettingsIcon from "@mui/icons-material/Settings";
import HelpOutlineIcon from "@mui/icons-material/HelpOutline";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import DownloadIcon from "@mui/icons-material/Download";
import PsychologyIcon from "@mui/icons-material/Psychology";
import DataObjectIcon from "@mui/icons-material/DataObject";

// Animations
const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-8px); }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
`;

const lockPulse = keyframes`
  0% { transform: scale(1); }
  50% { transform: scale(1.1); }
  100% { transform: scale(1); }
`;

export default function SSLTLSGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();

  const pageContext = `This page covers SSL/TLS security analysis including:
- TLS protocol versions: TLS 1.3, 1.2, 1.1, 1.0 and SSL 3.0, 2.0 security status
- Known vulnerabilities: POODLE, BEAST, Heartbleed, CRIME, BREACH, DROWN, FREAK, Logjam
- Cipher suite analysis: AEAD ciphers, key exchange algorithms, encryption modes
- Certificate inspection: validity, chain verification, key strength
- Security headers and HSTS configuration
- Common misconfigurations and remediation steps
- Best practices for secure TLS deployment`;

  // SSL/TLS Protocol versions with security assessment
  const tlsVersions = [
    { version: "TLS 1.3", year: "2018", status: "secure", description: "Current gold standard. Faster handshake, forward secrecy by default, removed weak algorithms.", recommendation: "Preferred", color: "#10b981" },
    { version: "TLS 1.2", year: "2008", status: "secure", description: "Still secure with proper cipher configuration. Widely supported, requires careful cipher selection.", recommendation: "Acceptable", color: "#22c55e" },
    { version: "TLS 1.1", year: "2006", status: "deprecated", description: "Deprecated by RFC 8996 (2021). Lacks modern cipher suites, vulnerable to various attacks.", recommendation: "Disable", color: "#f59e0b" },
    { version: "TLS 1.0", year: "1999", status: "deprecated", description: "Deprecated, vulnerable to POODLE, BEAST. PCI DSS prohibited since June 2018.", recommendation: "Disable", color: "#f97316" },
    { version: "SSL 3.0", year: "1996", status: "insecure", description: "Critically vulnerable to POODLE. No safe cipher suite exists. Never use.", recommendation: "Disable", color: "#ef4444" },
    { version: "SSL 2.0", year: "1995", status: "insecure", description: "Fundamentally broken. Weak MAC, export ciphers, no protection against truncation.", recommendation: "Disable", color: "#dc2626" },
  ];

  // Known SSL/TLS vulnerabilities the scanner detects
  const knownVulnerabilities = [
    {
      name: "POODLE",
      fullName: "Padding Oracle On Downgraded Legacy Encryption",
      cve: "CVE-2014-3566",
      cvss: "3.4",
      severity: "Medium",
      description: "Exploits SSL 3.0's block cipher padding to decrypt HTTPS traffic byte-by-byte. Attacker forces protocol downgrade, then uses padding oracle to reveal plaintext.",
      affected: "SSL 3.0, TLS with CBC ciphers",
      mitigation: "Disable SSL 3.0, use TLS 1.2+ with AEAD ciphers (GCM)",
      year: "2014",
      color: "#ef4444",
    },
    {
      name: "BEAST",
      fullName: "Browser Exploit Against SSL/TLS",
      cve: "CVE-2011-3389",
      cvss: "4.3",
      severity: "Medium",
      description: "Chosen-plaintext attack against CBC ciphers in TLS 1.0. Exploits predictable IV to decrypt cookies. Requires MITM + JavaScript.",
      affected: "TLS 1.0 with CBC ciphers",
      mitigation: "Use TLS 1.2+ or RC4 (deprecated). Modern browsers mitigate via 1/n-1 split.",
      year: "2011",
      color: "#f59e0b",
    },
    {
      name: "CRIME",
      fullName: "Compression Ratio Info-leak Made Easy",
      cve: "CVE-2012-4929",
      cvss: "2.6",
      severity: "Low",
      description: "Exploits TLS compression to reveal secrets like session cookies. Attacker measures compressed size to infer plaintext content.",
      affected: "TLS with DEFLATE compression",
      mitigation: "Disable TLS-level compression. All modern browsers disabled it.",
      year: "2012",
      color: "#f59e0b",
    },
    {
      name: "BREACH",
      fullName: "Browser Reconnaissance & Exfiltration via Adaptive Compression of Hypertext",
      cve: "CVE-2013-3587",
      cvss: "2.6",
      severity: "Low",
      description: "Like CRIME but targets HTTP compression (gzip). Can extract CSRF tokens, session IDs from responses. Works even with TLS 1.3.",
      affected: "HTTP compression with secrets in responses",
      mitigation: "Disable HTTP compression, randomize secrets, separate secret domains",
      year: "2013",
      color: "#eab308",
    },
    {
      name: "Heartbleed",
      fullName: "OpenSSL TLS Heartbeat Extension Buffer Over-read",
      cve: "CVE-2014-0160",
      cvss: "7.5",
      severity: "High",
      description: "Buffer over-read in OpenSSL's heartbeat extension. Leaks up to 64KB of server memory per request—private keys, passwords, session data.",
      affected: "OpenSSL 1.0.1 - 1.0.1f",
      mitigation: "Upgrade OpenSSL to 1.0.1g+, revoke and reissue certificates, rotate credentials",
      year: "2014",
      color: "#dc2626",
    },
    {
      name: "FREAK",
      fullName: "Factoring RSA Export Keys",
      cve: "CVE-2015-0204",
      cvss: "4.3",
      severity: "Medium",
      description: "Forces downgrade to 512-bit 'export-grade' RSA. 512-bit RSA factored in ~7 hours on AWS. Affects 36% of HTTPS sites when discovered.",
      affected: "Servers supporting RSA_EXPORT ciphers",
      mitigation: "Disable export cipher suites. Modern browsers reject weak RSA.",
      year: "2015",
      color: "#f97316",
    },
    {
      name: "Logjam",
      fullName: "Diffie-Hellman Export Downgrade Attack",
      cve: "CVE-2015-4000",
      cvss: "4.3",
      severity: "Medium",
      description: "Similar to FREAK but for Diffie-Hellman. Forces 512-bit DH export parameters. Pre-computed lookup tables enable real-time decryption.",
      affected: "Servers supporting DHE_EXPORT ciphers",
      mitigation: "Disable export ciphers, use 2048-bit+ DH parameters, prefer ECDHE",
      year: "2015",
      color: "#f97316",
    },
    {
      name: "DROWN",
      fullName: "Decrypting RSA with Obsolete and Weakened eNcryption",
      cve: "CVE-2016-0800",
      cvss: "5.9",
      severity: "Medium",
      description: "Uses SSL 2.0 to attack TLS 1.2. Bleichenbacher oracle via SSL 2.0 decrypts modern TLS sessions. 33% of HTTPS servers vulnerable.",
      affected: "Servers with SSL 2.0 enabled (even if TLS is preferred)",
      mitigation: "Disable SSL 2.0 completely. Don't share keys with SSL 2.0 servers.",
      year: "2016",
      color: "#ef4444",
    },
    {
      name: "ROBOT",
      fullName: "Return Of Bleichenbacher's Oracle Threat",
      cve: "CVE-2017-13099",
      cvss: "5.9",
      severity: "Medium",
      description: "Revives 1998 Bleichenbacher attack against RSA key exchange. Timing differences reveal PKCS#1 padding validity, enabling decryption.",
      affected: "RSA key exchange implementations with timing leaks",
      mitigation: "Disable RSA key exchange, use ECDHE. Patch vulnerable implementations.",
      year: "2017",
      color: "#f59e0b",
    },
    {
      name: "Lucky13",
      fullName: "Lucky Thirteen: Breaking the TLS and DTLS Record Protocols",
      cve: "CVE-2013-0169",
      cvss: "2.2",
      severity: "Low",
      description: "Timing side-channel against CBC MAC-then-encrypt. Measures decryption time to determine padding validity. Practical on localhost/LAN.",
      affected: "TLS/DTLS with CBC cipher suites",
      mitigation: "Use AEAD ciphers (AES-GCM, ChaCha20-Poly1305). Implementations patched.",
      year: "2013",
      color: "#eab308",
    },
    {
      name: "Sweet32",
      fullName: "Sweet32: Birthday Attacks on 64-bit Block Ciphers in TLS and OpenVPN",
      cve: "CVE-2016-2183",
      cvss: "5.3",
      severity: "Medium",
      description: "Birthday attack on 64-bit block ciphers (3DES, Blowfish). After 32GB of data, collisions reveal XOR of plaintexts.",
      affected: "3DES, Blowfish, other 64-bit block ciphers",
      mitigation: "Disable 3DES and other 64-bit ciphers. Use AES-128/256.",
      year: "2016",
      color: "#f59e0b",
    },
    {
      name: "ROCA",
      fullName: "Return of Coppersmith's Attack",
      cve: "CVE-2017-15361",
      cvss: "5.9",
      severity: "Medium",
      description: "Weak RSA key generation in Infineon chips. Affected keys can be factored. Found in smartcards, TPMs, and HSMs.",
      affected: "RSA keys generated by vulnerable Infineon firmware",
      mitigation: "Regenerate affected RSA keys using secure RNG. Check keys with ROCA detection tool.",
      year: "2017",
      color: "#f97316",
    },
  ];

  // Certificate chain validation checks
  const chainValidationChecks = [
    { check: "Trusted Root CA", description: "Certificate chain terminates at a trusted root CA from Mozilla/NSS bundle", icon: <VerifiedUserIcon />, importance: "Critical" },
    { check: "Chain Completeness", description: "All intermediate certificates present—browsers can build complete chain to root", icon: <LinkIcon />, importance: "Critical" },
    { check: "Not Self-Signed", description: "Server certificate signed by recognized CA, not self-signed (except for internal use)", icon: <ShieldIcon />, importance: "High" },
    { check: "Valid Signatures", description: "Each certificate's signature valid, chain of trust unbroken", icon: <CheckCircleIcon />, importance: "Critical" },
    { check: "Not Expired", description: "All certificates in chain within validity period", icon: <ReportProblemIcon />, importance: "Critical" },
    { check: "Hostname Match", description: "Certificate CN or SAN matches the hostname being accessed", icon: <DnsIcon />, importance: "Critical" },
    { check: "Not Revoked", description: "Certificate not on CRL/OCSP revocation list (if checked)", icon: <GppBadIcon />, importance: "High" },
    { check: "Key Usage", description: "Certificate has appropriate key usage extensions for TLS", icon: <KeyIcon />, importance: "Medium" },
  ];

  // Cipher suite analysis categories
  const cipherCategories = [
    {
      category: "Key Exchange",
      secure: ["ECDHE", "DHE (2048-bit+)"],
      insecure: ["RSA", "DH (512-bit)", "EXPORT", "NULL"],
      why: "Perfect Forward Secrecy (PFS) ensures session keys can't be decrypted even if server key is compromised",
      color: "#3b82f6",
    },
    {
      category: "Authentication",
      secure: ["RSA (2048-bit+)", "ECDSA"],
      insecure: ["RSA (1024-bit)", "DSS", "NULL", "anon"],
      why: "Proves server identity, prevents MITM. Anonymous ciphers allow interception.",
      color: "#8b5cf6",
    },
    {
      category: "Encryption",
      secure: ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"],
      insecure: ["RC4", "3DES", "DES", "NULL", "EXPORT"],
      why: "AEAD modes (GCM, Poly1305) provide authenticated encryption, preventing tampering",
      color: "#10b981",
    },
    {
      category: "MAC/Hash",
      secure: ["SHA256", "SHA384", "AEAD"],
      insecure: ["MD5", "SHA1"],
      why: "Message authentication prevents tampering. SHA1/MD5 have known collision attacks.",
      color: "#f59e0b",
    },
  ];

  // AI exploitation analysis capabilities
  const aiExploitationFeatures = [
    {
      title: "Attack Scenario Generation",
      description: "Generates realistic attack scenarios based on detected vulnerabilities. Explains how an attacker would chain weaknesses to compromise the target.",
      icon: <GppBadIcon />,
      color: "#ef4444",
    },
    {
      title: "Tool Recommendations",
      description: "Recommends offensive security tools for each vulnerability: testssl.sh, sslscan, Nmap NSE scripts, OpenSSL commands, Metasploit modules.",
      icon: <BuildIcon />,
      color: "#f59e0b",
    },
    {
      title: "Exploitation Steps",
      description: "Step-by-step exploitation guidance from an offensive security perspective. Details prerequisites, commands, and expected outputs.",
      icon: <DataObjectIcon />,
      color: "#8b5cf6",
    },
    {
      title: "Proof of Concept",
      description: "Provides PoC code snippets and commands to demonstrate vulnerabilities. Useful for penetration test reports and validation.",
      icon: <BugReportIcon />,
      color: "#dc2626",
    },
    {
      title: "Real-World Impact",
      description: "Assesses business impact: what data could be stolen, what access gained, potential for lateral movement.",
      icon: <ReportProblemIcon />,
      color: "#f97316",
    },
    {
      title: "Evasion Techniques",
      description: "Discusses detection avoidance: how to test without triggering alerts, timing considerations, passive vs active scanning.",
      icon: <SecurityIcon />,
      color: "#6366f1",
    },
  ];

  // Trusted Root CAs checked
  const trustedCAs = [
    "DigiCert", "Let's Encrypt (ISRG)", "Sectigo (Comodo)", "GlobalSign", "GoDaddy",
    "Amazon Trust Services", "Google Trust Services", "Microsoft", "Entrust",
    "Buypass", "QuoVadis", "SSL.com", "IdenTrust", "Actalis", "Certum",
    "SwissSign", "T-Systems", "Camerfirma", "AC FNMT", "ANF AC"
  ];

  return (
    <LearnPageLayout pageTitle="SSL/TLS Security" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2, mb: 2 }}
        />
        <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 2 }}>
          <Box
            sx={{
              width: 80,
              height: 80,
              borderRadius: 3,
              background: `linear-gradient(135deg, #10b981 0%, #059669 100%)`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              animation: `${float} 3s ease-in-out infinite`,
              boxShadow: `0 10px 40px ${alpha("#10b981", 0.4)}`,
            }}
          >
            <LockIcon sx={{ fontSize: 45, color: "white", animation: `${lockPulse} 2s ease-in-out infinite` }} />
          </Box>
          <Box>
            <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
              SSL/TLS Security Guide
            </Typography>
            <Typography variant="subtitle1" color="text.secondary">
              Understand what VRAgent's SSL Scanner analyzes and why it matters
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <Chip label="Certificate Analysis" size="small" color="success" />
          <Chip label="12 CVE Checks" size="small" color="error" />
          <Chip label="Chain Validation" size="small" color="primary" />
          <Chip label="AI Exploitation" size="small" color="warning" />
        </Box>
      </Box>

      {/* Overview Card */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#10b981", 0.1)}, ${alpha("#059669", 0.05)})`,
          border: `1px solid ${alpha("#10b981", 0.2)}`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <InfoIcon sx={{ color: "#10b981", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            What Does the SSL/TLS Scanner Do?
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
          VRAgent's SSL/TLS Scanner performs comprehensive security analysis of HTTPS endpoints. It connects to targets, 
          negotiates TLS handshakes, and analyzes the cryptographic configuration for security weaknesses. The scanner checks:
        </Typography>
        <Grid container spacing={2}>
          {[
            { title: "Protocol Versions", desc: "Tests SSL 2.0/3.0, TLS 1.0/1.1/1.2/1.3 support", icon: <SettingsIcon /> },
            { title: "Cipher Suites", desc: "Evaluates all supported ciphers for weaknesses", icon: <KeyIcon /> },
            { title: "Certificate Chain", desc: "Validates trust chain to root CA", icon: <LinkIcon /> },
            { title: "Known Vulnerabilities", desc: "Tests for 12 documented CVEs", icon: <BugReportIcon /> },
            { title: "Key Strength", desc: "Assesses RSA/ECDSA key sizes", icon: <ShieldIcon /> },
            { title: "AI Exploitation", desc: "Generates attack scenarios with tools", icon: <PsychologyIcon /> },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.title}>
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                <Box sx={{ color: "#10b981", mt: 0.25 }}>{item.icon}</Box>
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                    {item.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {item.desc}
                  </Typography>
                </Box>
              </Box>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* TLS Versions */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <SettingsIcon sx={{ color: "#3b82f6", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Protocol Versions Analyzed
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          The scanner tests which SSL/TLS protocol versions your server supports. Here's what each version means:
        </Typography>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700 }}>Protocol</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Year</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Status</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Recommendation</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {tlsVersions.map((tls) => (
                <TableRow key={tls.version}>
                  <TableCell sx={{ fontWeight: 600 }}>{tls.version}</TableCell>
                  <TableCell>{tls.year}</TableCell>
                  <TableCell>
                    <Chip
                      label={tls.status.toUpperCase()}
                      size="small"
                      sx={{
                        bgcolor: alpha(tls.color, 0.1),
                        color: tls.color,
                        fontWeight: 600,
                      }}
                    />
                  </TableCell>
                  <TableCell sx={{ maxWidth: 300 }}>
                    <Typography variant="body2">{tls.description}</Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      icon={tls.status === "secure" ? <CheckCircleIcon /> : <CancelIcon />}
                      label={tls.recommendation}
                      size="small"
                      color={tls.status === "secure" ? "success" : "error"}
                      variant="outlined"
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        <Paper
          sx={{
            p: 2,
            mt: 3,
            borderRadius: 2,
            bgcolor: alpha("#10b981", 0.05),
            border: `1px solid ${alpha("#10b981", 0.2)}`,
          }}
        >
          <Typography variant="body2">
            <strong>✅ Best Practice:</strong> Enable only TLS 1.2 and TLS 1.3. Disable all SSL versions and TLS 1.0/1.1. 
            Configure TLS 1.3 as the preferred protocol for modern clients.
          </Typography>
        </Paper>
      </Paper>

      {/* Known Vulnerabilities */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <BugReportIcon sx={{ color: "#ef4444", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            12 Known Vulnerabilities Detected
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          The scanner actively tests for these documented SSL/TLS vulnerabilities, each with a CVE identifier:
        </Typography>
        <Grid container spacing={2}>
          {knownVulnerabilities.map((vuln) => (
            <Grid item xs={12} md={6} key={vuln.name}>
              <Accordion
                sx={{
                  border: `1px solid ${alpha(vuln.color, 0.2)}`,
                  borderRadius: "8px !important",
                  "&:before": { display: "none" },
                  mb: 1,
                }}
              >
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                    <Box
                      sx={{
                        width: 40,
                        height: 40,
                        borderRadius: 1,
                        bgcolor: alpha(vuln.color, 0.1),
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      <GppBadIcon sx={{ color: vuln.color }} />
                    </Box>
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        {vuln.name}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {vuln.cve} • CVSS {vuln.cvss} • {vuln.year}
                      </Typography>
                    </Box>
                    <Chip
                      label={vuln.severity}
                      size="small"
                      sx={{
                        bgcolor: alpha(vuln.color, 0.1),
                        color: vuln.color,
                        fontWeight: 600,
                      }}
                    />
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
                    {vuln.fullName}
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    {vuln.description}
                  </Typography>
                  <Divider sx={{ my: 2 }} />
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                    <Box>
                      <Typography variant="caption" sx={{ fontWeight: 600, color: "#ef4444" }}>
                        Affected:
                      </Typography>
                      <Typography variant="body2">{vuln.affected}</Typography>
                    </Box>
                    <Box>
                      <Typography variant="caption" sx={{ fontWeight: 600, color: "#10b981" }}>
                        Mitigation:
                      </Typography>
                      <Typography variant="body2">{vuln.mitigation}</Typography>
                    </Box>
                  </Box>
                </AccordionDetails>
              </Accordion>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Certificate Chain Validation */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <LinkIcon sx={{ color: "#8b5cf6", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Certificate Chain Validation
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          The scanner validates the entire certificate chain from your server's certificate to a trusted root CA:
        </Typography>
        <Grid container spacing={2}>
          {chainValidationChecks.map((check) => (
            <Grid item xs={12} sm={6} key={check.check}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
                  height: "100%",
                }}
              >
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                  <Box sx={{ color: "#8b5cf6", mt: 0.25 }}>{check.icon}</Box>
                  <Box>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                        {check.check}
                      </Typography>
                      <Chip
                        label={check.importance}
                        size="small"
                        sx={{
                          fontSize: "0.65rem",
                          height: 20,
                          bgcolor: check.importance === "Critical" ? alpha("#ef4444", 0.1) : alpha("#f59e0b", 0.1),
                          color: check.importance === "Critical" ? "#ef4444" : "#f59e0b",
                        }}
                      />
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      {check.description}
                    </Typography>
                  </Box>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Trusted Root CAs */}
        <Box sx={{ mt: 4 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
            Trusted Root CAs ({trustedCAs.length}+ Authorities)
          </Typography>
          <Paper
            sx={{
              p: 2,
              borderRadius: 2,
              bgcolor: alpha("#8b5cf6", 0.03),
            }}
          >
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {trustedCAs.map((ca) => (
                <Chip
                  key={ca}
                  label={ca}
                  size="small"
                  icon={<VerifiedUserIcon />}
                  sx={{
                    bgcolor: alpha("#8b5cf6", 0.1),
                    "& .MuiChip-icon": { color: "#8b5cf6" },
                  }}
                />
              ))}
            </Box>
          </Paper>
        </Box>
      </Paper>

      {/* Cipher Suite Analysis */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <KeyIcon sx={{ color: "#f59e0b", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Cipher Suite Analysis
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Cipher suites determine how encryption is performed. The scanner evaluates each component:
        </Typography>
        <Grid container spacing={3}>
          {cipherCategories.map((cat) => (
            <Grid item xs={12} md={6} key={cat.category}>
              <Card
                sx={{
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha(cat.color, 0.2)}`,
                  borderTop: `4px solid ${cat.color}`,
                }}
              >
                <CardContent>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                    {cat.category}
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <GppGoodIcon sx={{ color: "#10b981", fontSize: 18 }} />
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#10b981" }}>
                        Secure
                      </Typography>
                    </Box>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {cat.secure.map((s) => (
                        <Chip key={s} label={s} size="small" color="success" variant="outlined" />
                      ))}
                    </Box>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <GppBadIcon sx={{ color: "#ef4444", fontSize: 18 }} />
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#ef4444" }}>
                        Insecure
                      </Typography>
                    </Box>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {cat.insecure.map((i) => (
                        <Chip key={i} label={i} size="small" color="error" variant="outlined" />
                      ))}
                    </Box>
                  </Box>
                  <Divider sx={{ my: 2 }} />
                  <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                    <HelpOutlineIcon sx={{ color: cat.color, fontSize: 18, mt: 0.25 }} />
                    <Typography variant="body2" color="text.secondary">
                      {cat.why}
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
        <Paper
          sx={{
            p: 2,
            mt: 3,
            borderRadius: 2,
            bgcolor: alpha("#f59e0b", 0.05),
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
          }}
        >
          <Typography variant="body2">
            <strong>💡 Example Secure Suite:</strong>{" "}
            <code style={{ backgroundColor: alpha("#10b981", 0.1), padding: "2px 6px", borderRadius: 4 }}>
              TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            </code>{" "}
            = ECDHE (PFS key exchange) + RSA (authentication) + AES-256-GCM (authenticated encryption) + SHA384 (hash)
          </Typography>
        </Paper>
      </Paper>

      {/* AI Exploitation Analysis */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#ef4444", 0.05)}, ${alpha("#f59e0b", 0.05)})`,
          border: `1px solid ${alpha("#ef4444", 0.2)}`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <AutoAwesomeIcon sx={{ color: "#ef4444", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            AI Exploitation Analysis
          </Typography>
          <Chip label="Offensive Focus" size="small" color="error" />
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Unlike traditional scanners, VRAgent's AI generates offensive security analysis—helping penetration testers
          understand how to exploit findings:
        </Typography>
        <Grid container spacing={2}>
          {aiExploitationFeatures.map((feature) => (
            <Grid item xs={12} sm={6} md={4} key={feature.title}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  height: "100%",
                  border: `1px solid ${alpha(feature.color, 0.2)}`,
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1.5 }}>
                  <Box sx={{ color: feature.color }}>{feature.icon}</Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                    {feature.title}
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  {feature.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
        <Paper
          sx={{
            p: 2,
            mt: 3,
            borderRadius: 2,
            bgcolor: alpha("#ef4444", 0.05),
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
          }}
        >
          <Typography variant="body2">
            <strong>⚠️ Responsible Use:</strong> The AI exploitation analysis is designed for authorized penetration testing,
            red team engagements, and security research. Always obtain proper authorization before testing targets you don't own.
          </Typography>
        </Paper>
      </Paper>

      {/* Export Options */}
      <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <DownloadIcon sx={{ color: "#6366f1", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Export & Reporting
          </Typography>
        </Box>
        <Typography variant="body1" sx={{ mb: 3 }}>
          Generate professional reports from your SSL/TLS scan results:
        </Typography>
        <Grid container spacing={2}>
          {[
            { format: "Markdown", icon: "📝", desc: "Clean, readable format. Great for documentation, wikis, and GitHub.", color: "#10b981" },
            { format: "PDF", icon: "📄", desc: "Professional reports for clients and stakeholders. Print-ready.", color: "#ef4444" },
            { format: "Word (DOCX)", icon: "📃", desc: "Editable reports. Add custom findings, adjust formatting.", color: "#3b82f6" },
          ].map((exp) => (
            <Grid item xs={12} md={4} key={exp.format}>
              <Paper
                sx={{
                  p: 3,
                  borderRadius: 2,
                  textAlign: "center",
                  border: `1px solid ${alpha(exp.color, 0.2)}`,
                  borderTop: `4px solid ${exp.color}`,
                }}
              >
                <Typography variant="h3" sx={{ mb: 1 }}>{exp.icon}</Typography>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
                  {exp.format}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {exp.desc}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          All exports include: certificate details, protocol support, cipher analysis, vulnerability findings, 
          chain validation results, and AI exploitation analysis.
        </Typography>
      </Paper>

      {/* Tips & Best Practices */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#10b981", 0.1)}, ${alpha("#10b981", 0.05)})`,
          border: `1px solid ${alpha("#10b981", 0.2)}`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <TipsAndUpdatesIcon sx={{ color: "#10b981", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Remediation Best Practices
          </Typography>
        </Box>
        <Grid container spacing={2}>
          {[
            { tip: "Enable only TLS 1.2 and TLS 1.3. Disable SSL 2.0/3.0 and TLS 1.0/1.1 completely.", icon: <SettingsIcon /> },
            { tip: "Use AEAD cipher suites only: AES-GCM and ChaCha20-Poly1305. Disable CBC mode ciphers.", icon: <KeyIcon /> },
            { tip: "Require Perfect Forward Secrecy (PFS) with ECDHE key exchange. Disable static RSA.", icon: <ShieldIcon /> },
            { tip: "Use 2048-bit RSA or 256-bit ECDSA keys minimum. 4096-bit RSA for high-security applications.", icon: <LockIcon /> },
            { tip: "Install complete certificate chains. Include all intermediates, don't rely on browser caching.", icon: <LinkIcon /> },
            { tip: "Enable HSTS (HTTP Strict Transport Security) with includeSubdomains and a long max-age.", icon: <SecurityIcon /> },
            { tip: "Renew certificates before expiration. Automate with Let's Encrypt and certbot.", icon: <ReportProblemIcon /> },
            { tip: "Use Mozilla SSL Configuration Generator for server-specific recommendations.", icon: <BuildIcon /> },
            { tip: "Regularly scan with testssl.sh and VRAgent to catch configuration drift.", icon: <SpeedIcon /> },
            { tip: "Keep OpenSSL, nginx, Apache, and other TLS software updated to patch vulnerabilities.", icon: <VerifiedUserIcon /> },
          ].map((item, idx) => (
            <Grid item xs={12} md={6} key={idx}>
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                <Box sx={{ color: "#10b981", mt: 0.25 }}>{item.icon}</Box>
                <Typography variant="body2">{item.tip}</Typography>
              </Box>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* CTA Footer */}
      <Paper
        sx={{
          p: 4,
          borderRadius: 3,
          textAlign: "center",
          background: `linear-gradient(135deg, ${alpha("#10b981", 0.1)} 0%, ${alpha("#059669", 0.05)} 100%)`,
          border: `1px solid ${alpha("#10b981", 0.2)}`,
        }}
      >
        <LockIcon sx={{ fontSize: 48, color: "#10b981", mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          Ready to Analyze Your TLS Configuration?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
          Scan any HTTPS endpoint to get comprehensive security analysis, vulnerability detection, 
          and AI-powered exploitation insights!
        </Typography>
        <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap" }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<RocketLaunchIcon />}
            onClick={() => navigate("/network/ssl")}
            sx={{
              background: `linear-gradient(135deg, #10b981 0%, #059669 100%)`,
              px: 4,
              py: 1.5,
              fontWeight: 700,
              fontSize: "1rem",
              boxShadow: `0 4px 20px ${alpha("#10b981", 0.4)}`,
              "&:hover": {
                boxShadow: `0 6px 30px ${alpha("#10b981", 0.5)}`,
              },
            }}
          >
            Open SSL/TLS Scanner
          </Button>
          <Button
            variant="outlined"
            size="large"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{
              borderColor: "#10b981",
              color: "#10b981",
              px: 4,
              py: 1.5,
              fontWeight: 600,
              "&:hover": {
                borderColor: "#059669",
                bgcolor: alpha("#10b981", 0.05),
              },
            }}
          >
            Back to Learning Hub
          </Button>
        </Box>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
}
