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
  Tabs,
  Tab,
  Slider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  InputAdornment,
  Link,
  Divider,
  Alert,
  Card,
  CardContent,
} from "@mui/material";
import { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import LearnPageLayout from "../components/LearnPageLayout";
import SearchIcon from "@mui/icons-material/Search";
import LaunchIcon from "@mui/icons-material/Launch";

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index }: TabPanelProps) {
  return (
    <div hidden={value !== index}>
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

interface FamousCVE {
  id: string;
  name: string;
  year: number;
  cvss: number;
  epss: number;
  description: string;
  impact: string;
}

const famousCVEs: FamousCVE[] = [
  { id: "CVE-2021-44228", name: "Log4Shell", year: 2021, cvss: 10.0, epss: 0.976, description: "RCE in Apache Log4j via JNDI lookup", impact: "Millions of Java applications compromised worldwide" },
  { id: "CVE-2017-5638", name: "Apache Struts", year: 2017, cvss: 10.0, epss: 0.975, description: "RCE via Content-Type header manipulation", impact: "Equifax breach exposing 143M records" },
  { id: "CVE-2014-0160", name: "Heartbleed", year: 2014, cvss: 7.5, epss: 0.973, description: "Buffer over-read in OpenSSL TLS heartbeat", impact: "17% of SSL servers vulnerable at discovery" },
  { id: "CVE-2017-0144", name: "EternalBlue", year: 2017, cvss: 8.1, epss: 0.974, description: "SMBv1 RCE vulnerability in Windows", impact: "WannaCry ransomware infected 230K+ computers" },
  { id: "CVE-2021-26855", name: "ProxyLogon", year: 2021, cvss: 9.8, epss: 0.972, description: "SSRF in Microsoft Exchange Server", impact: "250,000+ Exchange servers compromised" },
  { id: "CVE-2019-19781", name: "Citrix ADC", year: 2019, cvss: 9.8, epss: 0.968, description: "Directory traversal leading to RCE", impact: "Thousands of Citrix servers compromised" },
  { id: "CVE-2020-1472", name: "Zerologon", year: 2020, cvss: 10.0, epss: 0.965, description: "Netlogon authentication bypass", impact: "Complete domain compromise in seconds" },
  { id: "CVE-2021-34527", name: "PrintNightmare", year: 2021, cvss: 8.8, epss: 0.962, description: "RCE in Windows Print Spooler", impact: "All Windows systems vulnerable" },
];

interface CWEEntry {
  id: string;
  name: string;
  category: string;
  description: string;
}

const topCWEs: CWEEntry[] = [
  { id: "CWE-79", name: "Cross-site Scripting (XSS)", category: "Injection", description: "Improper neutralization of input during web page generation" },
  { id: "CWE-89", name: "SQL Injection", category: "Injection", description: "Improper neutralization of special elements used in SQL commands" },
  { id: "CWE-20", name: "Improper Input Validation", category: "Input Validation", description: "Product does not validate or incorrectly validates input" },
  { id: "CWE-125", name: "Out-of-bounds Read", category: "Memory", description: "Product reads data past the end of intended buffer" },
  { id: "CWE-78", name: "OS Command Injection", category: "Injection", description: "Improper neutralization of special elements used in OS commands" },
  { id: "CWE-416", name: "Use After Free", category: "Memory", description: "Referencing memory after it has been freed" },
  { id: "CWE-22", name: "Path Traversal", category: "File System", description: "Improper limitation of pathname to restricted directory" },
  { id: "CWE-352", name: "Cross-Site Request Forgery", category: "Auth", description: "Web application does not verify request was intentionally sent" },
  { id: "CWE-287", name: "Improper Authentication", category: "Auth", description: "Actor claims identity but evidence is not validated" },
  { id: "CWE-476", name: "NULL Pointer Dereference", category: "Memory", description: "Application dereferences pointer expected to be valid but is NULL" },
  { id: "CWE-502", name: "Deserialization of Untrusted Data", category: "Injection", description: "Deserializing untrusted data without proper verification" },
  { id: "CWE-190", name: "Integer Overflow", category: "Numeric", description: "Calculation produces integer overflow or wraparound" },
];

export default function CveCweCvssPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [selectedTab, setSelectedTab] = useState(0);
  const [cvssScore, setCvssScore] = useState<number>(7.5);
  const [cweSearch, setCweSearch] = useState("");

  const filteredCWEs = useMemo(() => {
    if (!cweSearch.trim()) return topCWEs;
    const query = cweSearch.toLowerCase();
    return topCWEs.filter(
      (cwe) =>
        cwe.id.toLowerCase().includes(query) ||
        cwe.name.toLowerCase().includes(query) ||
        cwe.category.toLowerCase().includes(query)
    );
  }, [cweSearch]);

  const getCVSSSeverity = (score: number) => {
    if (score === 0) return { label: "None", color: "#6b7280" };
    if (score < 4) return { label: "Low", color: "#22c55e" };
    if (score < 7) return { label: "Medium", color: "#f59e0b" };
    if (score < 9) return { label: "High", color: "#ef4444" };
    return { label: "Critical", color: "#dc2626" };
  };

  const severity = getCVSSSeverity(cvssScore);

  const pageContext = `This page covers CVE/CWE/CVSS vulnerability classification systems. CVE (Common Vulnerabilities and Exposures) provides unique identifiers for security vulnerabilities. CWE (Common Weakness Enumeration) categorizes software weaknesses. CVSS (Common Vulnerability Scoring System) rates vulnerability severity. Current tab: ${selectedTab === 0 ? 'CVE' : selectedTab === 1 ? 'CWE' : 'CVSS'}. ${cweSearch ? `CWE search: ${cweSearch}.` : ''} CVSS calculator score: ${cvssScore} (${severity.label}).`;

  return (
    <LearnPageLayout pageTitle="CVE/CWE/CVSS Reference" pageContext={pageContext}>
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
            background: `linear-gradient(135deg, #f59e0b, #ef4444)`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          🎯 CVE, CWE, CVSS & EPSS
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 900 }}>
          Understanding vulnerability identification, classification, and scoring systems used across the security industry.
        </Typography>
      </Box>

      {/* Tabs */}
      <Paper sx={{ borderRadius: 3, mb: 4 }}>
        <Tabs
          value={selectedTab}
          onChange={(_, v) => setSelectedTab(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            borderBottom: 1,
            borderColor: "divider",
            "& .MuiTab-root": { fontWeight: 600, textTransform: "none", minHeight: 56 },
          }}
        >
          <Tab label="🔢 CVE" />
          <Tab label="📋 CWE" />
          <Tab label="📊 CVSS" />
          <Tab label="📈 EPSS" />
        </Tabs>

        {/* CVE Tab */}
        <TabPanel value={selectedTab} index={0}>
          <Box sx={{ px: 4, pb: 2 }}>
            <Grid container spacing={4}>
              <Grid item xs={12} md={7}>
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
                  Common Vulnerabilities and Exposures (CVE)
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
                  A <strong>CVE</strong> is a standardized identifier for a publicly disclosed cybersecurity vulnerability. Each CVE entry contains an identification number, description, and references. The CVE system enables organizations to share information about vulnerabilities using a common naming convention.
                </Typography>
                
                <Paper sx={{ p: 3, bgcolor: alpha(theme.palette.background.default, 0.5), borderRadius: 2, mb: 3 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>CVE ID Format</Typography>
                  <Box sx={{ fontFamily: "monospace", fontSize: "1.1rem", bgcolor: alpha(theme.palette.primary.main, 0.05), p: 2, borderRadius: 1 }}>
                    CVE-<span style={{ color: theme.palette.primary.main }}>YYYY</span>-<span style={{ color: theme.palette.secondary.main }}>NNNNN</span>
                  </Box>
                  <Box sx={{ mt: 2, display: "flex", gap: 3 }}>
                    <Typography variant="body2" color="text.secondary">
                      <strong style={{ color: theme.palette.primary.main }}>YYYY</strong>: Year assigned
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      <strong style={{ color: theme.palette.secondary.main }}>NNNNN</strong>: Sequence number (4-7 digits)
                    </Typography>
                  </Box>
                </Paper>

                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Key Points</Typography>
                <Box component="ul" sx={{ pl: 2, "& li": { mb: 1 } }}>
                  <li><Typography variant="body2">Maintained by MITRE Corporation, sponsored by CISA</Typography></li>
                  <li><Typography variant="body2">CVE Numbering Authorities (CNAs) can assign CVE IDs</Typography></li>
                  <li><Typography variant="body2">Used by vulnerability databases, scanners, and security tools</Typography></li>
                  <li><Typography variant="body2">NVD enriches CVE entries with CVSS scores and additional metadata</Typography></li>
                </Box>
              </Grid>
              <Grid item xs={12} md={5}>
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>🔥 Famous CVEs</Typography>
                  {famousCVEs.slice(0, 4).map((cve) => (
                    <Box key={cve.id} sx={{ mb: 2, pb: 2, borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`, "&:last-child": { mb: 0, pb: 0, borderBottom: "none" } }}>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                        <Link href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" underline="hover" sx={{ fontWeight: 700, fontSize: "0.9rem" }}>
                          {cve.id}
                        </Link>
                        <Chip label={`CVSS ${cve.cvss}`} size="small" sx={{ bgcolor: getCVSSSeverity(cve.cvss).color, color: "white", fontWeight: 700, fontSize: "0.7rem" }} />
                      </Box>
                      <Typography variant="body2" sx={{ fontWeight: 600, color: "primary.main" }}>{cve.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{cve.description}</Typography>
                    </Box>
                  ))}
                  <Link href="https://cve.mitre.org/" target="_blank" sx={{ display: "flex", alignItems: "center", gap: 0.5, mt: 2, fontSize: "0.875rem" }}>
                    Browse CVE Database <LaunchIcon fontSize="small" />
                  </Link>
                </Paper>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>

        {/* CWE Tab */}
        <TabPanel value={selectedTab} index={1}>
          <Box sx={{ px: 4, pb: 2 }}>
            <Grid container spacing={4}>
              <Grid item xs={12} md={7}>
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
                  Common Weakness Enumeration (CWE)
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
                  <strong>CWE</strong> is a category system for software security weaknesses. Unlike CVE (specific instances), CWE describes types of vulnerabilities. For example, CWE-89 covers all SQL Injection vulnerabilities, while a CVE identifies a specific SQL Injection in a specific product.
                </Typography>
                
                <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
                  <Typography variant="body2">
                    <strong>CVE vs CWE:</strong> A CVE is a specific vulnerability instance. A CWE is a category of vulnerability type. Many CVEs map to the same CWE.
                  </Typography>
                </Alert>

                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>CWE Hierarchy</Typography>
                <Box component="ul" sx={{ pl: 2, "& li": { mb: 1 } }}>
                  <li><Typography variant="body2"><strong>Views:</strong> Different perspectives (e.g., OWASP Top 10, CWE Top 25)</Typography></li>
                  <li><Typography variant="body2"><strong>Categories:</strong> Groupings of related weaknesses</Typography></li>
                  <li><Typography variant="body2"><strong>Weaknesses:</strong> Individual weakness types (Base, Variant, Composite)</Typography></li>
                </Box>
              </Grid>
              <Grid item xs={12} md={5}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Search CWEs..."
                  value={cweSearch}
                  onChange={(e) => setCweSearch(e.target.value)}
                  sx={{ mb: 2 }}
                  InputProps={{
                    startAdornment: <InputAdornment position="start"><SearchIcon color="action" /></InputAdornment>,
                  }}
                />
                <Paper sx={{ maxHeight: 350, overflow: "auto", borderRadius: 2 }}>
                  {filteredCWEs.map((cwe) => (
                    <Box
                      key={cwe.id}
                      sx={{ p: 2, borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`, "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.03) } }}
                    >
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 0.5 }}>
                        <Link href={`https://cwe.mitre.org/data/definitions/${cwe.id.split("-")[1]}.html`} target="_blank" underline="hover" sx={{ fontWeight: 700, fontSize: "0.85rem" }}>
                          {cwe.id}
                        </Link>
                        <Chip label={cwe.category} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                      </Box>
                      <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.5 }}>{cwe.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{cwe.description}</Typography>
                    </Box>
                  ))}
                </Paper>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>

        {/* CVSS Tab */}
        <TabPanel value={selectedTab} index={2}>
          <Box sx={{ px: 4, pb: 2 }}>
            <Grid container spacing={4}>
              <Grid item xs={12} md={7}>
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
                  Common Vulnerability Scoring System (CVSS)
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
                  <strong>CVSS</strong> is a standardized framework for rating the severity of security vulnerabilities. It provides a numerical score (0.0-10.0) that reflects a vulnerability's characteristics. CVSS v3.1 is the current standard, with v4.0 recently released.
                </Typography>

                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>CVSS Metric Groups</Typography>
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  {[
                    { name: "Base", desc: "Intrinsic characteristics (attack vector, complexity, impact)", color: "#3b82f6" },
                    { name: "Temporal", desc: "Current exploit state (exploit code maturity, remediation level)", color: "#8b5cf6" },
                    { name: "Environmental", desc: "Organization-specific factors (modified base metrics, requirements)", color: "#10b981" },
                  ].map((group) => (
                    <Grid item xs={12} key={group.name}>
                      <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha(group.color, 0.05), border: `1px solid ${alpha(group.color, 0.15)}` }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: group.color }}>{group.name} Score</Typography>
                        <Typography variant="body2" color="text.secondary">{group.desc}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>

                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Base Metrics</Typography>
                <Box component="ul" sx={{ pl: 2, "& li": { mb: 0.5 } }}>
                  <li><Typography variant="body2"><strong>Attack Vector (AV):</strong> Network, Adjacent, Local, Physical</Typography></li>
                  <li><Typography variant="body2"><strong>Attack Complexity (AC):</strong> Low, High</Typography></li>
                  <li><Typography variant="body2"><strong>Privileges Required (PR):</strong> None, Low, High</Typography></li>
                  <li><Typography variant="body2"><strong>User Interaction (UI):</strong> None, Required</Typography></li>
                  <li><Typography variant="body2"><strong>Scope (S):</strong> Unchanged, Changed</Typography></li>
                  <li><Typography variant="body2"><strong>Impact (C/I/A):</strong> None, Low, High (for each)</Typography></li>
                </Box>
              </Grid>
              <Grid item xs={12} md={5}>
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(severity.color, 0.05), border: `2px solid ${severity.color}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 3 }}>Interactive CVSS Scale</Typography>
                  
                  <Box sx={{ textAlign: "center", mb: 3 }}>
                    <Typography variant="h2" sx={{ fontWeight: 800, color: severity.color }}>
                      {cvssScore.toFixed(1)}
                    </Typography>
                    <Chip label={severity.label} sx={{ bgcolor: severity.color, color: "white", fontWeight: 700, mt: 1 }} />
                  </Box>

                  <Slider
                    value={cvssScore}
                    onChange={(_, v) => setCvssScore(v as number)}
                    min={0}
                    max={10}
                    step={0.1}
                    marks={[
                      { value: 0, label: "0" },
                      { value: 4, label: "4" },
                      { value: 7, label: "7" },
                      { value: 9, label: "9" },
                      { value: 10, label: "10" },
                    ]}
                    sx={{
                      color: severity.color,
                      "& .MuiSlider-mark": { bgcolor: alpha(theme.palette.text.primary, 0.2) },
                    }}
                  />

                  <Divider sx={{ my: 3 }} />

                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>Severity Ranges</Typography>
                  {[
                    { range: "0.0", label: "None", color: "#6b7280" },
                    { range: "0.1 - 3.9", label: "Low", color: "#22c55e" },
                    { range: "4.0 - 6.9", label: "Medium", color: "#f59e0b" },
                    { range: "7.0 - 8.9", label: "High", color: "#ef4444" },
                    { range: "9.0 - 10.0", label: "Critical", color: "#dc2626" },
                  ].map((s) => (
                    <Box key={s.label} sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                      <Box sx={{ width: 12, height: 12, borderRadius: "50%", bgcolor: s.color }} />
                      <Typography variant="body2" sx={{ flex: 1 }}>{s.label}</Typography>
                      <Typography variant="caption" color="text.secondary">{s.range}</Typography>
                    </Box>
                  ))}
                </Paper>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>

        {/* EPSS Tab */}
        <TabPanel value={selectedTab} index={3}>
          <Box sx={{ px: 4, pb: 2 }}>
            <Grid container spacing={4}>
              <Grid item xs={12} md={7}>
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
                  Exploit Prediction Scoring System (EPSS)
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
                  <strong>EPSS</strong> is a data-driven effort to estimate the probability that a vulnerability will be exploited in the wild. Unlike CVSS (which measures severity), EPSS measures likelihood of exploitation, helping prioritize which vulnerabilities to patch first.
                </Typography>

                <Alert severity="warning" sx={{ mb: 3, borderRadius: 2 }}>
                  <Typography variant="body2">
                    <strong>CVSS vs EPSS:</strong> A vulnerability might have a high CVSS score (severe if exploited) but low EPSS (unlikely to be exploited). Use both for prioritization - focus on high CVSS + high EPSS first.
                  </Typography>
                </Alert>

                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>How EPSS Works</Typography>
                <Box component="ul" sx={{ pl: 2, "& li": { mb: 1 } }}>
                  <li><Typography variant="body2">Uses machine learning on historical exploitation data</Typography></li>
                  <li><Typography variant="body2">Scores range from 0 (0%) to 1 (100%) probability</Typography></li>
                  <li><Typography variant="body2">Updated daily with new threat intelligence</Typography></li>
                  <li><Typography variant="body2">Considers factors like: CVE age, CVSS, vendor, exploit availability</Typography></li>
                </Box>

                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, mt: 3 }}>EPSS in Practice</Typography>
                <Typography variant="body2" color="text.secondary">
                  The top 10% of EPSS scores typically contain 50%+ of all exploited vulnerabilities. Patching vulnerabilities in the top EPSS percentiles first dramatically reduces risk more efficiently than patching by CVSS alone.
                </Typography>
              </Grid>
              <Grid item xs={12} md={5}>
                <Paper sx={{ p: 3, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Famous CVEs with EPSS Scores</Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700 }}>CVE</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>CVSS</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>EPSS</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {famousCVEs.map((cve) => (
                          <TableRow key={cve.id} hover>
                            <TableCell>
                              <Link href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" underline="hover" sx={{ fontSize: "0.8rem" }}>
                                {cve.name}
                              </Link>
                            </TableCell>
                            <TableCell>
                              <Chip label={cve.cvss} size="small" sx={{ bgcolor: getCVSSSeverity(cve.cvss).color, color: "white", fontWeight: 700, fontSize: "0.7rem", minWidth: 45 }} />
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" sx={{ fontWeight: 600, color: cve.epss > 0.9 ? "#dc2626" : cve.epss > 0.5 ? "#f59e0b" : "#10b981" }}>
                                {(cve.epss * 100).toFixed(1)}%
                              </Typography>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <Divider sx={{ my: 2 }} />
                  <Link href="https://www.first.org/epss/" target="_blank" sx={{ display: "flex", alignItems: "center", gap: 0.5, fontSize: "0.875rem" }}>
                    FIRST EPSS Calculator <LaunchIcon fontSize="small" />
                  </Link>
                </Paper>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>
      </Paper>

      {/* Quick Reference */}
      <Paper sx={{ p: 4, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          📖 Quick Reference
        </Typography>
        <Grid container spacing={3}>
          {[
            { title: "CVE", purpose: "Unique identifier for specific vulnerabilities", example: "CVE-2021-44228", url: "https://cve.mitre.org/", color: "#3b82f6" },
            { title: "CWE", purpose: "Category/type classification of weaknesses", example: "CWE-89 (SQL Injection)", url: "https://cwe.mitre.org/", color: "#8b5cf6" },
            { title: "CVSS", purpose: "Severity score (0-10) based on characteristics", example: "9.8 Critical", url: "https://www.first.org/cvss/", color: "#ef4444" },
            { title: "EPSS", purpose: "Probability of exploitation (0-100%)", example: "97.6% likely exploited", url: "https://www.first.org/epss/", color: "#10b981" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={3} key={item.title}>
              <Card sx={{ height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <CardContent>
                  <Typography variant="h6" sx={{ fontWeight: 800, color: item.color, mb: 1 }}>
                    {item.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {item.purpose}
                  </Typography>
                  <Chip label={item.example} size="small" sx={{ bgcolor: alpha(item.color, 0.1), color: item.color, fontSize: "0.7rem", mb: 2 }} />
                  <Box>
                    <Link href={item.url} target="_blank" sx={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: 0.5 }}>
                      Learn more <LaunchIcon sx={{ fontSize: 14 }} />
                    </Link>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Paper>
    </Container>
    </LearnPageLayout>
  );
}
