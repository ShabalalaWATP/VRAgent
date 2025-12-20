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
  LinearProgress,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from "@mui/material";
import { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SearchIcon from "@mui/icons-material/Search";
import LaunchIcon from "@mui/icons-material/Launch";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import TrendingDownIcon from "@mui/icons-material/TrendingDown";
import TrendingFlatIcon from "@mui/icons-material/TrendingFlat";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import SecurityIcon from "@mui/icons-material/Security";
import LearnPageLayout from "../components/LearnPageLayout";

// Page context for AI chat
const pageContext = `This is a comprehensive Cyber Threat Intelligence (CTI) page covering:

1. Threat Actors Database:
- Nation-State APT groups (APT28, APT29, Lazarus Group, APT41, Hafnium, etc.)
- Ransomware Groups (LockBit, BlackCat/ALPHV, Cl0p, Wizard Spider, etc.)
- Cybercrime Organizations (FIN7, Evil Corp, Scattered Spider)
- Hacktivists and their campaigns
- Actor profiles with TTPs, tools, targets, and notable campaigns

2. CTI Methodology & Frameworks:
- Intelligence Cycle (Direction, Collection, Processing, Analysis, Dissemination)
- Diamond Model of Intrusion Analysis
- Attribution Confidence Levels
- STIX & TAXII Standards
- Traffic Light Protocol (TLP)
- Admiralty Code for source reliability
- Cognitive Biases in Analysis
- Analysis Techniques (ACH, Link Analysis, etc.)

3. IOCs & MITRE ATT&CK:
- Indicator of Compromise types (Hashes, IPs, Domains, URLs, etc.)
- MITRE ATT&CK Tactics and Techniques
- Common Malware Families
- Pyramid of Pain concept

4. Threat Landscape (2024-2025):
- Current threat trends and statistics
- Emerging threats (AI-powered attacks, supply chain, identity attacks)
- Geopolitical cyber context (Ukraine, China-Taiwan, Middle East, DPRK)

5. Tracking & Tools:
- Tracking methods and pivot techniques
- Intelligence sources (free and commercial)
- Government CTI resources

6. Defensive Intelligence:
- Defensive recommendations by actor type
- Detection priority matrix
- Incident response quick reference
- Threat hunting hypotheses`;
import {
  actorCategories,
  ctiMethodology,
  tlpLevels,
  admiraltyCode,
  biases,
  trackingMethods,
  pivotTechniques,
  iocTypes,
  mitreTactics,
  intelligenceSources,
  analysisTechniques,
  threatLandscape,
  attributionConfidence,
  malwareFamilies,
  defensiveRecommendations,
  reportTemplates,
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
    <LearnPageLayout pageTitle="Cyber Threat Intelligence" pageContext={pageContext}>
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
      <Tabs value={tabValue} onChange={(_, v) => setTabValue(v)} sx={{ mb: 4 }} variant="scrollable" scrollButtons="auto">
        <Tab label="🎭 Threat Actors" />
        <Tab label="🔬 CTI Methodology" />
        <Tab label="📊 IOCs & MITRE" />
        <Tab label="🌐 Threat Landscape" />
        <Tab label="📡 Tracking & Tools" />
        <Tab label="🛡️ Defensive Intel" />
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
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "success.main" }}>2025</Typography>
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
                        {/* Header with name, type, and status */}
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{actor.name}</Typography>
                            {actor.active !== undefined && (
                              <Chip 
                                label={actor.active ? "Active" : "Inactive"} 
                                size="small" 
                                sx={{ 
                                  fontSize: "0.55rem", 
                                  height: 18,
                                  bgcolor: actor.active ? alpha("#10b981", 0.15) : alpha("#6b7280", 0.15),
                                  color: actor.active ? "#10b981" : "#6b7280",
                                  fontWeight: 700
                                }} 
                              />
                            )}
                          </Box>
                          <Chip label={actor.type} size="small" sx={{ fontSize: "0.65rem", bgcolor: alpha(actorCategories[selectedCategory].color, 0.1), color: actorCategories[selectedCategory].color }} />
                        </Box>

                        {/* Aliases */}
                        {actor.aliases.length > 0 && (
                          <Typography variant="caption" color="text.disabled" sx={{ display: "block", mb: 1 }}>
                            aka: {actor.aliases.slice(0, 4).join(", ")}{actor.aliases.length > 4 ? ` (+${actor.aliases.length - 4} more)` : ""}
                          </Typography>
                        )}

                        {/* Origin, First Seen, Targets */}
                        <Box sx={{ display: "flex", gap: 0.5, mb: 1, flexWrap: "wrap", alignItems: "center" }}>
                          <Chip label={actor.origin} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                          {actor.firstSeen && (
                            <Chip 
                              label={`Since ${actor.firstSeen}`} 
                              size="small" 
                              sx={{ 
                                fontSize: "0.6rem", 
                                height: 20, 
                                bgcolor: alpha("#8b5cf6", 0.1),
                                color: "#8b5cf6",
                                fontWeight: 600
                              }} 
                            />
                          )}
                          {actor.targets.slice(0, 2).map((t) => (
                            <Chip key={t} label={t} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                          ))}
                          {actor.targets.length > 2 && (
                            <Typography variant="caption" color="text.disabled" sx={{ fontSize: "0.6rem" }}>
                              +{actor.targets.length - 2} more
                            </Typography>
                          )}
                        </Box>

                        {/* Description */}
                        <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem", lineHeight: 1.5, mb: 1.5 }}>
                          {actor.description}
                        </Typography>

                        {/* Notable Campaigns */}
                        {actor.notableCampaigns && actor.notableCampaigns.length > 0 && (
                          <Box sx={{ mt: 1, p: 1, bgcolor: alpha("#ef4444", 0.05), borderRadius: 1, borderLeft: `3px solid #ef4444` }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, display: "block", fontSize: "0.7rem", color: "#ef4444", mb: 0.5 }}>
                              🎯 Notable Campaigns
                            </Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.7rem" }}>
                              {actor.notableCampaigns.join(" • ")}
                            </Typography>
                          </Box>
                        )}

                        {/* TTPs */}
                        {actor.ttps && actor.ttps.length > 0 && (
                          <Box sx={{ mt: 1, p: 1, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 1, borderLeft: `3px solid #f59e0b` }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, display: "block", fontSize: "0.7rem", color: "#f59e0b", mb: 0.5 }}>
                              ⚔️ Key TTPs
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                              {actor.ttps.slice(0, 6).map((ttp, i) => (
                                <Chip 
                                  key={i} 
                                  label={ttp} 
                                  size="small" 
                                  sx={{ 
                                    fontSize: "0.6rem", 
                                    height: 18,
                                    bgcolor: alpha("#f59e0b", 0.1)
                                  }} 
                                />
                              ))}
                              {actor.ttps.length > 6 && (
                                <Typography variant="caption" color="text.disabled" sx={{ fontSize: "0.6rem", alignSelf: "center" }}>
                                  +{actor.ttps.length - 6} more
                                </Typography>
                              )}
                            </Box>
                          </Box>
                        )}

                        {/* Tools & Malware */}
                        {actor.tools && actor.tools.length > 0 && (
                          <Box sx={{ mt: 1, p: 1, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 1, borderLeft: `3px solid #3b82f6` }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, display: "block", fontSize: "0.7rem", color: "#3b82f6", mb: 0.5 }}>
                              🛠️ Tools & Malware
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                              {actor.tools.slice(0, 6).map((tool, i) => (
                                <Chip 
                                  key={i} 
                                  label={tool} 
                                  size="small" 
                                  variant="outlined"
                                  sx={{ 
                                    fontSize: "0.6rem", 
                                    height: 18,
                                    borderColor: alpha("#3b82f6", 0.3)
                                  }} 
                                />
                              ))}
                              {actor.tools.length > 6 && (
                                <Typography variant="caption" color="text.disabled" sx={{ fontSize: "0.6rem", alignSelf: "center" }}>
                                  +{actor.tools.length - 6} more
                                </Typography>
                              )}
                            </Box>
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

          {/* Attribution Confidence */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 Attribution Confidence Levels</Typography>
            <Grid container spacing={3}>
              {attributionConfidence.map((level) => (
                <Grid item xs={12} sm={6} md={3} key={level.level}>
                  <Paper 
                    variant="outlined" 
                    sx={{ 
                      p: 2, 
                      height: "100%",
                      borderColor: level.color,
                      borderWidth: 2,
                      bgcolor: alpha(level.color, 0.05)
                    }}
                  >
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: level.color, mb: 0.5 }}>
                      {level.level}
                    </Typography>
                    <Typography variant="h5" sx={{ fontWeight: 800, mb: 1 }}>{level.percentage}</Typography>
                    <Divider sx={{ my: 1.5 }} />
                    {level.indicators.map((ind, i) => (
                      <Typography key={i} variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>
                        • {ind}
                      </Typography>
                    ))}
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* STIX/TAXII */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
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

          {/* Analysis Techniques */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🔍 Analysis Techniques</Typography>
          {analysisTechniques.map((technique) => (
            <Accordion key={technique.name} sx={{ mb: 1, borderRadius: 2, "&:before": { display: "none" } }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{technique.name}</Typography>
                  <Chip 
                    label={technique.difficulty} 
                    size="small" 
                    sx={{ 
                      ml: "auto", 
                      mr: 2,
                      bgcolor: technique.difficulty === "Advanced" ? alpha("#ef4444", 0.1) : 
                               technique.difficulty === "Intermediate" ? alpha("#f59e0b", 0.1) : alpha("#10b981", 0.1),
                      color: technique.difficulty === "Advanced" ? "#ef4444" : 
                             technique.difficulty === "Intermediate" ? "#f59e0b" : "#10b981"
                    }} 
                  />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{technique.description}</Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Steps:</Typography>
                    {technique.steps.map((step, i) => (
                      <Typography key={i} variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                        {i + 1}. {step}
                      </Typography>
                    ))}
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Tools:</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {technique.tools.map((tool) => (
                        <Chip key={tool} label={tool} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                      ))}
                    </Box>
                  </Grid>
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}
        </>
      )}

      {/* TAB 2: IOCs & MITRE */}
      {tabValue === 2 && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📊 Indicators of Compromise (IOCs)</Typography>
          
          {/* IOC Types */}
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {iocTypes.map((ioc) => (
              <Grid item xs={12} sm={6} md={4} key={ioc.name}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Typography variant="h5">{ioc.icon}</Typography>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{ioc.name}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5, fontSize: "0.8rem" }}>
                    {ioc.description}
                  </Typography>
                  <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>Detection Methods:</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {ioc.detectionMethods.map((method) => (
                      <Chip key={method} label={method} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* MITRE ATT&CK Tactics */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>⚔️ MITRE ATT&CK Tactics</Typography>
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              The MITRE ATT&CK framework provides a comprehensive matrix of adversary tactics and techniques based on real-world observations.
            </Typography>
            <Grid container spacing={1}>
              {mitreTactics.map((tactic) => (
                <Grid item xs={6} sm={4} md={3} key={tactic.id}>
                  <Tooltip title={tactic.description} arrow>
                    <Paper 
                      sx={{ 
                        p: 1.5, 
                        textAlign: "center", 
                        cursor: "pointer",
                        border: `2px solid ${tactic.color}`,
                        bgcolor: alpha(tactic.color, 0.05),
                        transition: "all 0.2s",
                        "&:hover": { bgcolor: alpha(tactic.color, 0.15), transform: "translateY(-2px)" }
                      }}
                    >
                      <Typography variant="caption" sx={{ fontWeight: 700, color: tactic.color, display: "block" }}>
                        {tactic.id}
                      </Typography>
                      <Typography variant="body2" sx={{ fontWeight: 600, fontSize: "0.75rem" }}>
                        {tactic.name}
                      </Typography>
                      <Typography variant="caption" color="text.disabled">
                        {tactic.techniques} techniques
                      </Typography>
                    </Paper>
                  </Tooltip>
                </Grid>
              ))}
            </Grid>
            <Box sx={{ mt: 3, textAlign: "center" }}>
              <Link href="https://attack.mitre.org/" target="_blank" rel="noopener">
                <Chip 
                  label="Explore Full MITRE ATT&CK Matrix →" 
                  clickable 
                  color="primary" 
                  sx={{ fontWeight: 600 }}
                />
              </Link>
            </Box>
          </Paper>

          {/* Common Malware Families */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🦠 Common Malware Families</Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {malwareFamilies.map((malware) => (
              <Grid item xs={12} md={6} key={malware.name}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{malware.name}</Typography>
                    <Chip label={malware.type} size="small" color="error" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5, fontSize: "0.8rem" }}>
                    {malware.description}
                  </Typography>
                  <Box sx={{ mb: 1 }}>
                    <Typography variant="caption" sx={{ fontWeight: 700 }}>Capabilities: </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {malware.capabilities.join(", ")}
                    </Typography>
                  </Box>
                  <Box sx={{ mb: 1 }}>
                    <Typography variant="caption" sx={{ fontWeight: 700 }}>Used By: </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {malware.usedBy.join(", ")}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" sx={{ fontWeight: 700 }}>Detection: </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                      {malware.detection.map((d) => (
                        <Chip key={d} label={d} size="small" sx={{ fontSize: "0.6rem", height: 18 }} />
                      ))}
                    </Box>
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Pyramid of Pain Visual */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📐 Pyramid of Pain</Typography>
          <Paper sx={{ p: 4, borderRadius: 3 }}>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3, textAlign: "center" }}>
              The higher up the pyramid, the more painful for adversaries to change these indicators.
            </Typography>
            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 1 }}>
              {[
                { level: "TTPs", pain: "Tough!", color: "#ef4444", width: "30%", desc: "Behaviors and patterns - hardest to change" },
                { level: "Tools", pain: "Challenging", color: "#f97316", width: "45%", desc: "Custom malware and exploit kits" },
                { level: "Network/Host Artifacts", pain: "Annoying", color: "#f59e0b", width: "55%", desc: "User-agents, registry keys, C2 patterns" },
                { level: "Domain Names", pain: "Simple", color: "#eab308", width: "65%", desc: "Attacker-controlled domains" },
                { level: "IP Addresses", pain: "Easy", color: "#84cc16", width: "75%", desc: "C2 servers and proxies" },
                { level: "Hash Values", pain: "Trivial", color: "#22c55e", width: "85%", desc: "File hashes - easily changed" },
              ].map((item) => (
                <Tooltip key={item.level} title={item.desc} arrow placement="right">
                  <Paper 
                    sx={{ 
                      width: item.width, 
                      py: 1.5, 
                      px: 2,
                      bgcolor: alpha(item.color, 0.1), 
                      border: `2px solid ${item.color}`,
                      textAlign: "center",
                      cursor: "help"
                    }}
                  >
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>
                      {item.level}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">{item.pain}</Typography>
                  </Paper>
                </Tooltip>
              ))}
            </Box>
          </Paper>
        </>
      )}

      {/* TAB 3: Threat Landscape */}
      {tabValue === 3 && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🌐 2024-2025 Threat Landscape</Typography>
          
          {/* Threat Trends */}
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {threatLandscape.map((threat) => (
              <Grid item xs={12} sm={6} md={4} key={threat.category}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{threat.category}</Typography>
                    <Chip 
                      icon={
                        threat.trend === "increasing" ? <TrendingUpIcon sx={{ fontSize: 16 }} /> :
                        threat.trend === "decreasing" ? <TrendingDownIcon sx={{ fontSize: 16 }} /> :
                        <TrendingFlatIcon sx={{ fontSize: 16 }} />
                      }
                      label={threat.trend}
                      size="small"
                      sx={{ 
                        bgcolor: threat.trend === "increasing" ? alpha("#ef4444", 0.1) :
                                 threat.trend === "decreasing" ? alpha("#10b981", 0.1) : alpha("#f59e0b", 0.1),
                        color: threat.trend === "increasing" ? "#ef4444" :
                               threat.trend === "decreasing" ? "#10b981" : "#f59e0b",
                        "& .MuiChip-icon": { 
                          color: threat.trend === "increasing" ? "#ef4444" :
                                 threat.trend === "decreasing" ? "#10b981" : "#f59e0b"
                        }
                      }}
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5, fontSize: "0.8rem" }}>
                    {threat.description}
                  </Typography>
                  <Divider sx={{ my: 1 }} />
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                    {threat.keyStats.map((stat, i) => (
                      <Typography key={i} variant="caption" color="text.secondary">
                        • {stat}
                      </Typography>
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Key Statistics */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#dc2626", 0.05)}, ${alpha("#3b82f6", 0.05)})` }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📈 Key Statistics (2024)</Typography>
            <Grid container spacing={3}>
              {[
                { stat: "$9.5T", label: "Global cybercrime cost", color: "#ef4444" },
                { stat: "277", label: "Days avg breach detection", color: "#f59e0b" },
                { stat: "$4.88M", label: "Average data breach cost", color: "#3b82f6" },
                { stat: "3,205", label: "Data breaches reported", color: "#10b981" },
                { stat: "24B+", label: "Credentials exposed", color: "#8b5cf6" },
                { stat: "560K", label: "New malware daily", color: "#ec4899" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.label}>
                  <Box sx={{ textAlign: "center" }}>
                    <Typography variant="h4" sx={{ fontWeight: 800, color: item.color }}>{item.stat}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.label}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Emerging Threats */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>⚠️ Emerging Threats to Watch</Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { 
                title: "AI-Powered Attacks", 
                description: "LLMs generating phishing content, deepfakes for fraud, and automated vulnerability discovery",
                icon: "🤖",
                severity: "High"
              },
              { 
                title: "Quantum Computing Threats", 
                description: "Harvest-now-decrypt-later attacks, urgency for post-quantum cryptography adoption",
                icon: "⚛️",
                severity: "Medium"
              },
              { 
                title: "Supply Chain Compromise", 
                description: "Targeting open source dependencies, build pipelines, and software update mechanisms",
                icon: "📦",
                severity: "Critical"
              },
              { 
                title: "Identity Infrastructure Attacks", 
                description: "Targeting Azure AD/Entra, Okta, and identity providers for widespread access",
                icon: "🆔",
                severity: "Critical"
              },
              { 
                title: "Edge & IoT Exploitation", 
                description: "Compromising routers, VPN appliances, and IoT devices for initial access and botnets",
                icon: "📡",
                severity: "High"
              },
              { 
                title: "Cloud-Native Threats", 
                description: "Kubernetes attacks, serverless function abuse, and cloud IAM exploitation",
                icon: "☁️",
                severity: "High"
              },
            ].map((threat) => (
              <Grid item xs={12} sm={6} md={4} key={threat.title}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Typography variant="h5">{threat.icon}</Typography>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{threat.title}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1, fontSize: "0.8rem" }}>
                    {threat.description}
                  </Typography>
                  <Chip 
                    label={`Severity: ${threat.severity}`} 
                    size="small"
                    sx={{ 
                      bgcolor: threat.severity === "Critical" ? alpha("#ef4444", 0.1) :
                               threat.severity === "High" ? alpha("#f59e0b", 0.1) : alpha("#3b82f6", 0.1),
                      color: threat.severity === "Critical" ? "#ef4444" :
                             threat.severity === "High" ? "#f59e0b" : "#3b82f6",
                      fontSize: "0.65rem"
                    }}
                  />
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Geopolitical Context */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🌍 Geopolitical Cyber Context</Typography>
          <Paper sx={{ p: 3, borderRadius: 3 }}>
            <Grid container spacing={3}>
              {[
                { region: "🇺🇦 Ukraine Conflict", impact: "Ongoing Russian destructive operations, hacktivism on both sides, spillover risks to NATO" },
                { region: "🇨🇳 China-Taiwan", impact: "Pre-positioning in critical infrastructure, IP theft acceleration, telecom targeting (Salt Typhoon)" },
                { region: "🇮🇷 Middle East", impact: "Israel-Iran cyber escalation, attacks on water/energy infrastructure, CyberAv3ngers" },
                { region: "🇰🇵 DPRK Sanctions", impact: "Cryptocurrency theft for regime funding, IT worker fraud schemes, Lazarus evolution" },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.region}>
                  <Box sx={{ display: "flex", gap: 2 }}>
                    <Typography variant="h6">{item.region.split(" ")[0]}</Typography>
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.region.split(" ").slice(1).join(" ")}</Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem" }}>{item.impact}</Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </>
      )}

      {/* TAB 4: Tracking & Tools */}
      {tabValue === 4 && (
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

          {/* Intelligence Sources */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📚 Intelligence Sources Database</Typography>
          
          {/* Free Sources */}
          <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `2px solid ${alpha("#10b981", 0.3)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
              <Chip label="FREE" size="small" sx={{ bgcolor: "#10b981", color: "white", fontWeight: 700 }} />
              <Typography variant="h6" sx={{ fontWeight: 700 }}>Open Source & Free Tools</Typography>
            </Box>
            <Grid container spacing={2}>
              {intelligenceSources.filter(s => s.free).map((source) => (
                <Grid item xs={12} sm={6} md={4} key={source.name}>
                  <Link href={source.url} target="_blank" rel="noopener" underline="none">
                    <Paper 
                      variant="outlined"
                      sx={{ 
                        p: 1.5, 
                        height: "100%", 
                        transition: "all 0.2s", 
                        "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05), borderColor: "primary.main" } 
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main" }}>{source.name}</Typography>
                        <LaunchIcon fontSize="small" color="action" sx={{ fontSize: 12, ml: "auto" }} />
                      </Box>
                      <Chip label={source.category} size="small" sx={{ fontSize: "0.6rem", height: 18, mb: 0.5 }} />
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", fontSize: "0.7rem" }}>
                        {source.description}
                      </Typography>
                    </Paper>
                  </Link>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Commercial Sources */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `2px solid ${alpha("#f59e0b", 0.3)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
              <Chip label="COMMERCIAL" size="small" sx={{ bgcolor: "#f59e0b", color: "white", fontWeight: 700 }} />
              <Typography variant="h6" sx={{ fontWeight: 700 }}>Commercial Platforms</Typography>
            </Box>
            <Grid container spacing={2}>
              {intelligenceSources.filter(s => !s.free).map((source) => (
                <Grid item xs={12} sm={6} md={4} key={source.name}>
                  <Link href={source.url} target="_blank" rel="noopener" underline="none">
                    <Paper 
                      variant="outlined"
                      sx={{ 
                        p: 1.5, 
                        height: "100%", 
                        transition: "all 0.2s", 
                        "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05), borderColor: "primary.main" } 
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main" }}>{source.name}</Typography>
                        <LaunchIcon fontSize="small" color="action" sx={{ fontSize: 12, ml: "auto" }} />
                      </Box>
                      <Chip label={source.category} size="small" sx={{ fontSize: "0.6rem", height: 18, mb: 0.5 }} />
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", fontSize: "0.7rem" }}>
                        {source.description}
                      </Typography>
                    </Paper>
                  </Link>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Government Resources */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🏛️ Government CTI Resources</Typography>
          <Grid container spacing={2}>
            {[
              { name: "CISA Known Exploited Vulnerabilities", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", country: "🇺🇸" },
              { name: "FBI IC3", url: "https://www.ic3.gov/", country: "🇺🇸" },
              { name: "NCSC UK Advisories", url: "https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports", country: "🇬🇧" },
              { name: "ANSSI France", url: "https://www.cert.ssi.gouv.fr/", country: "🇫🇷" },
              { name: "BSI Germany", url: "https://www.bsi.bund.de/", country: "🇩🇪" },
              { name: "ACSC Australia", url: "https://www.cyber.gov.au/", country: "🇦🇺" },
              { name: "CCCS Canada", url: "https://www.cyber.gc.ca/", country: "🇨🇦" },
              { name: "JPCERT Japan", url: "https://www.jpcert.or.jp/english/", country: "🇯🇵" },
              { name: "ENISA Europe", url: "https://www.enisa.europa.eu/", country: "🇪🇺" },
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

      {/* TAB 5: Defensive Intel */}
      {tabValue === 5 && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🛡️ Defensive Intelligence & Recommendations</Typography>

          {/* Defensive Recommendations by Actor Type */}
          <Grid container spacing={3} sx={{ mb: 4 }}>
            {Object.entries(defensiveRecommendations).map(([actorType, data]) => (
              <Grid item xs={12} md={6} key={actorType}>
                <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                    <Typography variant="h5">
                      {actorType === "nation-state" ? "🏛️" : 
                       actorType === "ransomware" ? "💀" : 
                       actorType === "hacktivist" ? "✊" : "💰"}
                    </Typography>
                    <Box>
                      <Typography variant="h6" sx={{ fontWeight: 700, textTransform: "capitalize" }}>
                        {actorType.replace("-", " ")} Defense
                      </Typography>
                      <Chip 
                        label={`Priority: ${data.priority}`} 
                        size="small"
                        sx={{ 
                          bgcolor: data.priority === "Critical" ? alpha("#ef4444", 0.1) :
                                   data.priority === "High" ? alpha("#f59e0b", 0.1) : alpha("#3b82f6", 0.1),
                          color: data.priority === "Critical" ? "#ef4444" :
                                 data.priority === "High" ? "#f59e0b" : "#3b82f6",
                          fontSize: "0.7rem"
                        }}
                      />
                    </Box>
                  </Box>
                  <List dense>
                    {data.recommendations.map((rec, i) => (
                      <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "success.main" }} />
                        </ListItemIcon>
                        <ListItemText 
                          primary={rec} 
                          primaryTypographyProps={{ variant: "body2", fontSize: "0.8rem" }} 
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Report Templates */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📝 Intelligence Report Templates</Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {Object.values(reportTemplates).map((template) => (
              <Grid item xs={12} md={6} key={template.name}>
                <Paper sx={{ p: 2, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>{template.name}</Typography>
                  <Box sx={{ display: "flex", gap: 1, mb: 1.5 }}>
                    <Chip label={template.audience} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                    <Chip label={template.frequency} size="small" sx={{ fontSize: "0.65rem", bgcolor: alpha("#3b82f6", 0.1) }} />
                  </Box>
                  <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>Sections:</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {template.sections.map((section, i) => (
                      <Typography key={i} variant="caption" color="text.secondary">
                        {i + 1}. {section}{i < template.sections.length - 1 ? " •" : ""}
                      </Typography>
                    ))}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Quick Reference: Detection Priorities */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🎯 Detection Priority Matrix</Typography>
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
            <Grid container spacing={2}>
              {[
                { category: "Initial Access", techniques: ["Phishing", "Valid Accounts", "Exploit Public-Facing App", "External Remote Services"], priority: "Critical" },
                { category: "Execution", techniques: ["PowerShell", "Windows Command Shell", "Scheduled Task", "User Execution"], priority: "High" },
                { category: "Persistence", techniques: ["Registry Run Keys", "Scheduled Task", "Account Creation", "Web Shell"], priority: "Critical" },
                { category: "Defense Evasion", techniques: ["Process Injection", "Masquerading", "Indicator Removal", "Obfuscated Files"], priority: "High" },
                { category: "Credential Access", techniques: ["LSASS Memory", "Kerberoasting", "Brute Force", "Credentials from Stores"], priority: "Critical" },
                { category: "Lateral Movement", techniques: ["Remote Services", "SMB/Admin Shares", "Remote Desktop", "Pass-the-Hash"], priority: "Critical" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.category}>
                  <Box sx={{ p: 2, border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.category}</Typography>
                      <Chip 
                        label={item.priority} 
                        size="small"
                        sx={{ 
                          bgcolor: item.priority === "Critical" ? alpha("#ef4444", 0.1) : alpha("#f59e0b", 0.1),
                          color: item.priority === "Critical" ? "#ef4444" : "#f59e0b",
                          fontSize: "0.65rem"
                        }}
                      />
                    </Box>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {item.techniques.map((tech) => (
                        <Chip key={tech} label={tech} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                      ))}
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Incident Response Quick Reference */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🚨 Incident Response Quick Reference</Typography>
          <Grid container spacing={2}>
            {[
              { 
                phase: "1. Preparation", 
                icon: "📋",
                tasks: ["IR plan documented", "Contact lists updated", "Playbooks ready", "Tools deployed", "Backups verified"],
                color: "#3b82f6"
              },
              { 
                phase: "2. Identification", 
                icon: "🔍",
                tasks: ["Alert triage", "Scope assessment", "IOC extraction", "Timeline building", "Severity classification"],
                color: "#8b5cf6"
              },
              { 
                phase: "3. Containment", 
                icon: "🔒",
                tasks: ["Network isolation", "Account disable", "Block IOCs", "Preserve evidence", "Communication plan"],
                color: "#f59e0b"
              },
              { 
                phase: "4. Eradication", 
                icon: "🗑️",
                tasks: ["Malware removal", "Persistence cleanup", "Patch vulnerabilities", "Credential reset", "Verify removal"],
                color: "#ef4444"
              },
              { 
                phase: "5. Recovery", 
                icon: "🔄",
                tasks: ["System restoration", "Service validation", "Monitoring increase", "User communication", "Staged return"],
                color: "#10b981"
              },
              { 
                phase: "6. Lessons Learned", 
                icon: "📚",
                tasks: ["Incident report", "Detection gaps", "Process improvements", "Training needs", "Control updates"],
                color: "#6366f1"
              },
            ].map((phase) => (
              <Grid item xs={12} sm={6} md={4} key={phase.phase}>
                <Paper 
                  sx={{ 
                    p: 2, 
                    height: "100%", 
                    borderRadius: 2,
                    borderTop: `4px solid ${phase.color}`
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
                    <Typography variant="h5">{phase.icon}</Typography>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: phase.color }}>{phase.phase}</Typography>
                  </Box>
                  {phase.tasks.map((task, i) => (
                    <Typography key={i} variant="body2" color="text.secondary" sx={{ mb: 0.5, fontSize: "0.8rem" }}>
                      • {task}
                    </Typography>
                  ))}
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Threat Hunting Hypotheses */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 3 }}>🎣 Threat Hunting Hypothesis Examples</Typography>
          <Paper sx={{ p: 3, borderRadius: 3 }}>
            <Grid container spacing={2}>
              {[
                { hypothesis: "Attackers are using LOLBins for defense evasion", query: "Search for unusual parent-child process relationships with native Windows binaries" },
                { hypothesis: "Compromised credentials are being used for lateral movement", query: "Look for authentication anomalies, impossible travel, and service account usage" },
                { hypothesis: "Data staging occurring before exfiltration", query: "Monitor for large file creations, compression, and unusual network destinations" },
                { hypothesis: "Persistence mechanisms exist from prior compromise", query: "Audit scheduled tasks, services, registry run keys, and startup folders" },
                { hypothesis: "Web shells deployed on internet-facing servers", query: "Search for suspicious file modifications in web directories and anomalous web server process spawning" },
                { hypothesis: "Attackers maintaining C2 via DNS tunneling", query: "Analyze DNS query volumes, TXT record requests, and unusual subdomain patterns" },
              ].map((item, i) => (
                <Grid item xs={12} md={6} key={i}>
                  <Box sx={{ p: 2, bgcolor: alpha(theme.palette.primary.main, 0.02), borderRadius: 2, border: "1px solid", borderColor: "divider" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main", mb: 0.5 }}>
                      Hypothesis: {item.hypothesis}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem" }}>
                      <strong>Hunt:</strong> {item.query}
                    </Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </>
      )}
    </Container>
    </LearnPageLayout>
  );
}
