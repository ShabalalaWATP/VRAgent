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
  TextField,
  InputAdornment,
  Link,
  Card,
  CardContent,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from "@mui/material";
import { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SearchIcon from "@mui/icons-material/Search";
import LaunchIcon from "@mui/icons-material/Launch";
import {
  actorCategories,
  ctiMethodology,
  tlpLevels,
  admiraltyCode,
  biases,
  trackingMethods,
  pivotTechniques,
} from "../data/ctiData";

export default function CyberThreatIntelPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [selectedCategory, setSelectedCategory] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  const [tabValue, setTabValue] = useState(0);

  const filteredActors = useMemo(() => {
    if (!searchQuery.trim()) return actorCategories[selectedCategory].actors;
    const query = searchQuery.toLowerCase();
    return actorCategories[selectedCategory].actors.filter(
      (a) =>
        a.name.toLowerCase().includes(query) ||
        a.aliases.some((al) => al.toLowerCase().includes(query)) ||
        a.origin.toLowerCase().includes(query) ||
        a.description.toLowerCase().includes(query)
    );
  }, [selectedCategory, searchQuery]);

  const allActors = useMemo(() => {
    return actorCategories.flatMap((c) => c.actors);
  }, []);

  const globalSearch = useMemo(() => {
    if (!searchQuery.trim()) return [];
    const query = searchQuery.toLowerCase();
    return allActors.filter(
      (a) =>
        a.name.toLowerCase().includes(query) ||
        a.aliases.some((al) => al.toLowerCase().includes(query)) ||
        a.origin.toLowerCase().includes(query)
    );
  }, [searchQuery, allActors]);

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
            background: `linear-gradient(135deg, #dc2626, #f59e0b, #3b82f6)`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          🕵️ Cyber Threat Intelligence
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 900 }}>
          Understanding threat actors, attribution methods, and intelligence tradecraft for defensive and offensive security operations.
        </Typography>
      </Box>

      {/* Main Tabs */}
      <Tabs value={tabValue} onChange={(_, v) => setTabValue(v)} sx={{ mb: 4 }}>
        <Tab label="🎭 Threat Actors" />
        <Tab label="🔬 CTI Methodology" />
        <Tab label="📡 Tracking & Tools" />
      </Tabs>

      {/* TAB 0: Threat Actors */}
      {tabValue === 0 && (
        <>
          {/* Stats */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#dc2626", 0.05)}, ${alpha("#3b82f6", 0.05)})` }}>
            <Grid container spacing={3} justifyContent="center">
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "error.main" }}>{allActors.length}+</Typography>
                  <Typography variant="body2" color="text.secondary">Threat Actors</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "warning.main" }}>{actorCategories.length}</Typography>
                  <Typography variant="body2" color="text.secondary">Categories</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "info.main" }}>15+</Typography>
                  <Typography variant="body2" color="text.secondary">Nations</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "success.main" }}>2024</Typography>
                  <Typography variant="body2" color="text.secondary">Updated</Typography>
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* Search */}
          <TextField
            fullWidth
            size="small"
            placeholder="Search actors, aliases, origins..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            InputProps={{
              startAdornment: <InputAdornment position="start"><SearchIcon color="action" /></InputAdornment>,
            }}
            sx={{ mb: 3, maxWidth: 500 }}
          />

          {/* Global Search Results */}
          {searchQuery.trim() && globalSearch.length > 0 && (
            <Alert severity="info" sx={{ mb: 3 }}>
              Found {globalSearch.length} actors matching "{searchQuery}" across all categories
            </Alert>
          )}

          {/* Category Cards */}
          <Box sx={{ display: "flex", overflowX: "auto", gap: 1.5, mb: 4, pb: 2 }}>
            {actorCategories.map((cat, index) => (
              <Card
                key={cat.id}
                onClick={() => { setSelectedCategory(index); setSearchQuery(""); }}
                sx={{
                  minWidth: 130,
                  flexShrink: 0,
                  cursor: "pointer",
                  border: `2px solid ${selectedCategory === index ? cat.color : "transparent"}`,
                  bgcolor: selectedCategory === index ? alpha(cat.color, 0.1) : "background.paper",
                  transition: "all 0.2s",
                  "&:hover": { bgcolor: alpha(cat.color, 0.05), transform: "translateY(-2px)" },
                }}
              >
                <CardContent sx={{ textAlign: "center", p: 2, "&:last-child": { pb: 2 } }}>
                  <Typography variant="h5" sx={{ mb: 0.5 }}>{cat.icon}</Typography>
                  <Typography variant="caption" sx={{ fontWeight: 600, color: cat.color, display: "block", fontSize: "0.7rem" }}>
                    {cat.name.split(" ")[0]}
                  </Typography>
                  <Typography variant="caption" color="text.disabled" sx={{ fontSize: "0.65rem" }}>
                    {cat.actors.length} actors
                  </Typography>
                </CardContent>
              </Card>
            ))}
          </Box>

          {/* Selected Category Detail */}
          <Paper sx={{ mb: 4, borderRadius: 3, overflow: "hidden" }}>
            <Box sx={{ p: 3, bgcolor: alpha(actorCategories[selectedCategory].color, 0.05), borderBottom: `3px solid ${actorCategories[selectedCategory].color}` }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                <Typography variant="h4">{actorCategories[selectedCategory].icon}</Typography>
                <Typography variant="h5" sx={{ fontWeight: 700 }}>{actorCategories[selectedCategory].name}</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">{actorCategories[selectedCategory].description}</Typography>
            </Box>

            {/* Actor List */}
            <Box sx={{ p: 3 }}>
              {filteredActors.length === 0 ? (
                <Alert severity="info">No actors match your search.</Alert>
              ) : (
                <Grid container spacing={2}>
                  {filteredActors.map((actor) => (
                    <Grid item xs={12} md={6} key={actor.name}>
                      <Paper
                        sx={{
                          p: 2,
                          height: "100%",
                          border: `1px solid ${alpha(actorCategories[selectedCategory].color, 0.2)}`,
                          transition: "all 0.2s",
                          "&:hover": { borderColor: actorCategories[selectedCategory].color, bgcolor: alpha(actorCategories[selectedCategory].color, 0.02) },
                        }}
                      >
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{actor.name}</Typography>
                          <Chip label={actor.type} size="small" sx={{ fontSize: "0.65rem", bgcolor: alpha(actorCategories[selectedCategory].color, 0.1), color: actorCategories[selectedCategory].color }} />
                        </Box>
                        {actor.aliases.length > 0 && (
                          <Typography variant="caption" color="text.disabled" sx={{ display: "block", mb: 1 }}>
                            aka: {actor.aliases.slice(0, 3).join(", ")}{actor.aliases.length > 3 ? "..." : ""}
                          </Typography>
                        )}
                        <Box sx={{ display: "flex", gap: 0.5, mb: 1, flexWrap: "wrap" }}>
                          <Chip label={actor.origin} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                          {actor.targets.slice(0, 2).map((t) => (
                            <Chip key={t} label={t} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                          ))}
                        </Box>
                        <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem", lineHeight: 1.5 }}>
                          {actor.description}
                        </Typography>
                        {actor.notableCampaigns && (
                          <Box sx={{ mt: 1.5 }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, display: "block", fontSize: "0.7rem", color: "text.primary" }}>Notable Campaigns:</Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.7rem" }}>{actor.notableCampaigns.join(", ")}</Typography>
                          </Box>
                        )}
                        {actor.ttps && (
                          <Box sx={{ mt: 1 }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, display: "block", fontSize: "0.7rem", color: "text.primary" }}>Key TTPs:</Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.7rem" }}>{actor.ttps.join(", ")}</Typography>
                          </Box>
                        )}
                        {actor.tools && (
                          <Box sx={{ mt: 1 }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, display: "block", fontSize: "0.7rem", color: "text.primary" }}>Tools & Malware:</Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.7rem" }}>{actor.tools.join(", ")}</Typography>
                          </Box>
                        )}
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              )}
            </Box>
          </Paper>
        </>
      )}

      {/* TAB 1: CTI Methodology */}
      {tabValue === 1 && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🔬 CTI Methodology & Frameworks</Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            {ctiMethodology.map((section) => (
              <Grid item xs={12} md={6} key={section.title}>
                <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha(section.color, 0.2)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                    <Typography variant="h4">{section.icon}</Typography>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>{section.title}</Typography>
                  </Box>
                  {section.steps.map((step, i) => (
                    <Box key={i} sx={{ display: "flex", gap: 1.5, mb: 1.5 }}>
                      <Typography variant="body2" sx={{ color: section.color, fontWeight: 700, minWidth: 20 }}>{i + 1}.</Typography>
                      <Typography variant="body2" color="text.secondary">{step}</Typography>
                    </Box>
                  ))}
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Diamond Model */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>💎 Diamond Model of Intrusion Analysis</Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Box sx={{ textAlign: "center", mb: 3 }}>
                  <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
                    Four core features connected by relationships:
                  </Typography>
                  <Box sx={{ display: "flex", justifyContent: "center", gap: 3, flexWrap: "wrap" }}>
                    {[
                      { label: "Adversary", color: "#ef4444", desc: "Threat actor" },
                      { label: "Infrastructure", color: "#f59e0b", desc: "C2, domains, IPs" },
                      { label: "Capability", color: "#3b82f6", desc: "Tools, malware" },
                      { label: "Victim", color: "#10b981", desc: "Target org/system" },
                    ].map((node) => (
                      <Box key={node.label} sx={{ textAlign: "center" }}>
                        <Box sx={{ width: 80, height: 80, borderRadius: 2, bgcolor: alpha(node.color, 0.1), border: `2px solid ${node.color}`, display: "flex", alignItems: "center", justifyContent: "center", mb: 1 }}>
                          <Typography variant="body2" sx={{ fontWeight: 700, color: node.color }}>{node.label}</Typography>
                        </Box>
                        <Typography variant="caption" color="text.secondary">{node.desc}</Typography>
                      </Box>
                    ))}
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Meta-Features</Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {[
                    "Timestamp - When activity occurred",
                    "Phase - Kill chain stage",
                    "Result - Success/failure",
                    "Direction - Adversary→Victim or bidirectional",
                    "Methodology - How capability was deployed",
                    "Resources - What adversary needed",
                  ].map((meta) => (
                    <Typography key={meta} variant="body2" color="text.secondary">• {meta}</Typography>
                  ))}
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* STIX/TAXII */}
          <Paper sx={{ p: 4, borderRadius: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📋 STIX & TAXII Standards</Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>STIX (Structured Threat Information eXpression)</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Standardized language for describing cyber threat information:
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {["Attack Pattern", "Campaign", "Course of Action", "Identity", "Indicator", "Intrusion Set", "Malware", "Observed Data", "Report", "Threat Actor", "Tool", "Vulnerability"].map((obj) => (
                    <Chip key={obj} label={obj} size="small" sx={{ fontSize: "0.65rem" }} />
                  ))}
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>TAXII (Trusted Automated eXchange of Intelligence Information)</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Transport protocol for exchanging STIX data:
                </Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {[
                    "Collections - Sets of CTI objects",
                    "Channels - Publish/subscribe feeds",
                    "API Roots - Service endpoints",
                  ].map((item) => (
                    <Typography key={item} variant="body2" color="text.secondary">• {item}</Typography>
                  ))}
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* TLP & Biases */}
          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🚦 Traffic Light Protocol (TLP)</Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                  {tlpLevels.map((tlp) => (
                    <Box key={tlp.level} sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Chip label={tlp.level} size="small" sx={{ bgcolor: tlp.color, color: tlp.level === "TLP:CLEAR" ? "black" : "white", fontWeight: 700, minWidth: 100 }} />
                      <Typography variant="caption" color="text.secondary">{tlp.desc}</Typography>
                    </Box>
                  ))}
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🧠 Cognitive Biases in Analysis</Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                  {biases.map((bias) => (
                    <Box key={bias.name}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "error.main" }}>{bias.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{bias.desc}</Typography>
                    </Box>
                  ))}
                </Box>
              </Paper>
            </Grid>
          </Grid>

          {/* Admiralty Code */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>⚓ Admiralty Code (Source Reliability & Credibility)</Typography>
            <Grid container spacing={4}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "primary.main" }}>Source Reliability</Typography>
                <TableContainer component={Paper} variant="outlined">
                  <Table size="small">
                    <TableBody>
                      {admiraltyCode.reliability.map((item) => (
                        <TableRow key={item.grade}>
                          <TableCell sx={{ fontWeight: 700, width: 50, textAlign: "center", bgcolor: alpha(theme.palette.primary.main, 0.1) }}>{item.grade}</TableCell>
                          <TableCell>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.label}</Typography>
                            <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "secondary.main" }}>Information Credibility</Typography>
                <TableContainer component={Paper} variant="outlined">
                  <Table size="small">
                    <TableBody>
                      {admiraltyCode.credibility.map((item) => (
                        <TableRow key={item.grade}>
                          <TableCell sx={{ fontWeight: 700, width: 50, textAlign: "center", bgcolor: alpha(theme.palette.secondary.main, 0.1) }}>{item.grade}</TableCell>
                          <TableCell>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.label}</Typography>
                            <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>
            </Grid>
          </Paper>
        </>
      )}

      {/* TAB 2: Tracking & Tools */}
      {tabValue === 2 && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📡 Tracking Methods & Tools</Typography>

          {/* Tracking Methods Table */}
          <TableContainer component={Paper} sx={{ mb: 4, borderRadius: 3 }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Method</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Tools</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {trackingMethods.map((row) => (
                  <TableRow key={row.method}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.method}</TableCell>
                    <TableCell>{row.description}</TableCell>
                    <TableCell>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {row.tools.split(", ").map((tool) => (
                          <Chip key={tool} label={tool} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                        ))}
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {/* Pivot Searching */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🔍 Pivot Searching Techniques</Typography>
            <Grid container spacing={2}>
              {pivotTechniques.map((tech) => (
                <Grid item xs={12} sm={6} md={4} key={tech.name}>
                  <Box sx={{ p: 2, border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main", mb: 1 }}>{tech.name}</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {tech.pivots.map((p) => (
                        <Chip key={p} label={p} size="small" sx={{ fontSize: "0.65rem" }} />
                      ))}
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Key Platforms */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🛠️ CTI Platforms & Resources</Typography>
          <Grid container spacing={2}>
            {[
              { name: "MISP", url: "https://www.misp-project.org/", desc: "Open source threat intelligence platform" },
              { name: "OpenCTI", url: "https://www.opencti.io/", desc: "Open cyber threat intelligence platform" },
              { name: "MITRE ATT&CK", url: "https://attack.mitre.org/", desc: "Adversary TTPs knowledge base" },
              { name: "VirusTotal", url: "https://www.virustotal.com/", desc: "Malware and URL analysis" },
              { name: "Shodan", url: "https://www.shodan.io/", desc: "Internet-connected device search" },
              { name: "Censys", url: "https://censys.io/", desc: "Internet-wide scanning and data" },
              { name: "URLhaus", url: "https://urlhaus.abuse.ch/", desc: "Malicious URL tracking" },
              { name: "MalwareBazaar", url: "https://bazaar.abuse.ch/", desc: "Malware sample sharing" },
              { name: "AlienVault OTX", url: "https://otx.alienvault.com/", desc: "Open threat exchange" },
              { name: "Recorded Future", url: "https://www.recordedfuture.com/", desc: "Commercial threat intelligence" },
              { name: "Mandiant", url: "https://www.mandiant.com/", desc: "Threat research and IR" },
              { name: "CrowdStrike Falcon", url: "https://www.crowdstrike.com/", desc: "Threat intelligence and EDR" },
            ].map((platform) => (
              <Grid item xs={12} sm={6} md={4} key={platform.name}>
                <Link href={platform.url} target="_blank" rel="noopener" underline="none">
                  <Paper sx={{ p: 2, height: "100%", transition: "all 0.2s", "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) } }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main" }}>{platform.name}</Typography>
                      <LaunchIcon fontSize="small" color="action" sx={{ fontSize: 14 }} />
                    </Box>
                    <Typography variant="caption" color="text.secondary">{platform.desc}</Typography>
                  </Paper>
                </Link>
              </Grid>
            ))}
          </Grid>

          {/* Government Resources */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 3 }}>🏛️ Government CTI Resources</Typography>
          <Grid container spacing={2}>
            {[
              { name: "CISA Known Exploited Vulnerabilities", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", country: "🇺🇸" },
              { name: "FBI IC3", url: "https://www.ic3.gov/", country: "🇺🇸" },
              { name: "NCSC UK Advisories", url: "https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports", country: "🇬🇧" },
              { name: "ANSSI France", url: "https://www.cert.ssi.gouv.fr/", country: "🇫🇷" },
              { name: "BSI Germany", url: "https://www.bsi.bund.de/", country: "🇩🇪" },
              { name: "ACSC Australia", url: "https://www.cyber.gov.au/", country: "🇦🇺" },
            ].map((resource) => (
              <Grid item xs={12} sm={6} md={4} key={resource.name}>
                <Link href={resource.url} target="_blank" rel="noopener" underline="none">
                  <Paper sx={{ p: 2, transition: "all 0.2s", "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) } }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Typography variant="body1">{resource.country}</Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{resource.name}</Typography>
                      <LaunchIcon fontSize="small" color="action" sx={{ fontSize: 14, ml: "auto" }} />
                    </Box>
                  </Paper>
                </Link>
              </Grid>
            ))}
          </Grid>
        </>
      )}
    </Container>
  );
}
