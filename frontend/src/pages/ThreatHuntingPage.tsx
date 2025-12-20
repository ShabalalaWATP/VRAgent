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
import TravelExploreIcon from "@mui/icons-material/TravelExplore";
import PsychologyIcon from "@mui/icons-material/Psychology";
import SourceIcon from "@mui/icons-material/Source";
import TrackChangesIcon from "@mui/icons-material/TrackChanges";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import WarningIcon from "@mui/icons-material/Warning";
import { useNavigate } from "react-router-dom";

interface HuntingPhase {
  title: string;
  description: string;
  color: string;
}

const huntingPhases: HuntingPhase[] = [
  { title: "Hypothesis", description: "Form a theory about potential attacker activity based on intel or patterns", color: "#8b5cf6" },
  { title: "Data Collection", description: "Identify and gather relevant data sources for investigation", color: "#3b82f6" },
  { title: "Investigation", description: "Query data, analyze patterns, look for anomalies", color: "#f59e0b" },
  { title: "Findings", description: "Document discoveries, IOCs, and evidence of compromise", color: "#ef4444" },
  { title: "Response", description: "Escalate to IR, create detections, share intelligence", color: "#10b981" },
];

const dataSources = [
  "EDR telemetry (process, file, network)",
  "SIEM logs (auth, firewall, DNS)",
  "Network traffic (NetFlow, PCAP)",
  "Cloud audit logs (AWS, Azure, GCP)",
  "Threat intelligence feeds",
  "Active Directory / authentication logs",
];

const huntIdeas = [
  { hunt: "Persistence mechanisms", technique: "T1547, T1053, T1136" },
  { hunt: "Living off the land binaries", technique: "T1218, T1059" },
  { hunt: "Credential access attempts", technique: "T1003, T1558" },
  { hunt: "Lateral movement indicators", technique: "T1021, T1570" },
  { hunt: "Data staging / exfiltration", technique: "T1074, T1041" },
  { hunt: "C2 beaconing patterns", technique: "T1071, T1573" },
];

const frameworks = [
  { name: "MITRE ATT&CK", use: "Map TTPs, identify coverage gaps" },
  { name: "Pyramid of Pain", use: "Prioritize high-value indicators" },
  { name: "PEAK Framework", use: "Structured hypothesis hunting" },
  { name: "Cyber Kill Chain", use: "Track intrusion progression" },
];

const huntTypes = [
  {
    title: "Intel-Driven",
    description: "Pivot from reports, IOCs, or TTPs relevant to your sector.",
    color: "#6366f1",
  },
  {
    title: "Anomaly-Driven",
    description: "Find deviations from baselines (new parents, rare binaries).",
    color: "#f59e0b",
  },
  {
    title: "Threat-Informed",
    description: "Map known adversary behaviors to your telemetry.",
    color: "#ef4444",
  },
  {
    title: "Model-Driven",
    description: "Use statistical or heuristic models to surface signals.",
    color: "#3b82f6",
  },
];

const hypothesisSources = [
  "Threat intel reports and recent campaigns",
  "Recent incidents and post-mortem gaps",
  "Purple team exercises and red team findings",
  "New infrastructure or SaaS rollouts",
  "Critical business workflows (finance, HR, prod)",
];

const analysisTechniques = [
  "Stacking: sort by frequency to find rare events",
  "Temporal analysis: bursts, beaconing, off-hours activity",
  "Parent-child process analysis and command line parsing",
  "Peer grouping: compare users or hosts against similar peers",
  "Graph pivots: link IPs, users, hosts, and hashes",
  "Entropy or string analysis for encoded payloads",
];

const baselineChecklist = [
  "Define normal activity windows per team or system",
  "Capture top binaries, parent processes, and destinations",
  "Segment baselines by role (admins vs. standard users)",
  "Refresh baselines after major deployments",
  "Record known-good automation and scheduled jobs",
];

const huntOutputs = [
  "New detections (rules, queries, playbooks)",
  "Validated IOCs or TTPs with context",
  "Gaps in telemetry or logging coverage",
  "Hardening recommendations and configuration fixes",
  "Escalations to incident response with evidence",
];

const huntMetrics = [
  "Mean time to validate a hypothesis",
  "Percent of hypotheses converted to detections",
  "Telemetry coverage vs. ATT&CK techniques",
  "False positive rate of new detections",
  "Time from hunt finding to remediation",
];

const huntCardTemplate = [
  "Hypothesis and reasoning",
  "Data sources required",
  "Queries and pivots to run",
  "Expected vs. suspicious signals",
  "Decision points and escalation criteria",
  "Outcome and follow-up actions",
];

const commonPitfalls = [
  "Hunting without a scoped hypothesis or success criteria",
  "Ignoring data quality issues (missing fields, time drift)",
  "Not validating findings with additional sources",
  "Failing to convert findings into detections",
  "Skipping documentation because no threat was found",
];

export default function ThreatHuntingPage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Threat Hunting Fundamentals Guide - Covers proactive threat hunting methodology including hypothesis formation, data collection, investigation, findings documentation, and response. Includes hunt types, hypothesis sources, analysis techniques, baselining, hunt card templates, outputs, metrics, data sources, hunt ideas mapped to MITRE ATT&CK techniques, and frameworks (ATT&CK, Pyramid of Pain, PEAK, Cyber Kill Chain).`;

  return (
    <LearnPageLayout pageTitle="Threat Hunting Fundamentals" pageContext={pageContext}>
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
                bgcolor: alpha("#8b5cf6", 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <TravelExploreIcon sx={{ fontSize: 36, color: "#8b5cf6" }} />
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Threat Hunting Fundamentals
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Proactive adversary detection
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Blue Team" color="primary" size="small" />
            <Chip label="Hunting" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
            <Chip label="ATT&CK" size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
          </Box>
        </Box>

        {/* Overview */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TravelExploreIcon color="primary" /> What is Threat Hunting?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            Threat hunting is the proactive search for adversaries that have evaded existing security controls. 
            Unlike reactive alert-driven detection, hunters form hypotheses about attacker behavior and actively 
            search for evidence. It assumes breach and looks for what automated tools miss.
          </Typography>
        </Paper>

        {/* Hypothesis Sources */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.04) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <LightbulbIcon sx={{ color: "#8b5cf6" }} /> Hypothesis Sources
          </Typography>
          <List dense>
            {hypothesisSources.map((source, i) => (
              <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                </ListItemIcon>
                <ListItemText primary={source} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Hunting Process */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🔄 Hunting Process</Typography>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 4 }}>
          {huntingPhases.map((phase, i) => (
            <React.Fragment key={phase.title}>
              <Paper
                sx={{
                  px: 2,
                  py: 1.5,
                  borderRadius: 2,
                  border: `1px solid ${alpha(phase.color, 0.3)}`,
                  bgcolor: alpha(phase.color, 0.05),
                  display: "flex",
                  alignItems: "center",
                  gap: 1,
                }}
              >
                <Box
                  sx={{
                    width: 24,
                    height: 24,
                    borderRadius: "50%",
                    bgcolor: phase.color,
                    color: "#fff",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: "0.75rem",
                    fontWeight: 700,
                  }}
                >
                  {i + 1}
                </Box>
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, lineHeight: 1.2 }}>{phase.title}</Typography>
                  <Typography variant="caption" color="text.secondary">{phase.description}</Typography>
                </Box>
              </Paper>
            </React.Fragment>
          ))}
        </Box>

        {/* Hunt Types */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>?? Hunt Types</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {huntTypes.map((hunt) => (
            <Grid item xs={12} sm={6} md={3} key={hunt.title}>
              <Paper
                sx={{
                  p: 2,
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha(hunt.color, 0.2)}`,
                  "&:hover": { borderColor: hunt.color },
                }}
              >
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: hunt.color, mb: 1 }}>
                  {hunt.title}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {hunt.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Data Sources & Hunt Ideas */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SourceIcon sx={{ color: "#3b82f6" }} /> Data Sources
              </Typography>
              <List dense>
                {dataSources.map((ds, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={ds} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <TrackChangesIcon sx={{ color: "#ef4444" }} /> Hunt Ideas (ATT&CK)
              </Typography>
              <List dense>
                {huntIdeas.map((h, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={h.hunt}
                      secondary={h.technique}
                      primaryTypographyProps={{ variant: "body2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption", sx: { fontFamily: "monospace" } }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Baseline and Analysis */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SourceIcon sx={{ color: "#10b981" }} /> Baseline Checklist
              </Typography>
              <List dense>
                {baselineChecklist.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
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
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#f59e0b", 0.04) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <PsychologyIcon sx={{ color: "#f59e0b" }} /> Analysis Techniques
              </Typography>
              <List dense>
                {analysisTechniques.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Hunt Card Template */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.04) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon sx={{ color: "#3b82f6" }} /> Hunt Card Template
          </Typography>
          <List dense>
            {huntCardTemplate.map((item, i) => (
              <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                </ListItemIcon>
                <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Frameworks */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.05)}, ${alpha("#6366f1", 0.05)})`,
            border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <PsychologyIcon sx={{ color: "#8b5cf6" }} /> Hunting Frameworks
          </Typography>
          <Grid container spacing={2}>
            {frameworks.map((f) => (
              <Grid item xs={12} sm={6} key={f.name}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                  <CheckCircleIcon sx={{ fontSize: 18, color: "#8b5cf6", mt: 0.3 }} />
                  <Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{f.name}</Typography>
                    <Typography variant="caption" color="text.secondary">{f.use}</Typography>
                  </Box>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Outputs and Metrics */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#6366f1", 0.04) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <TrackChangesIcon sx={{ color: "#6366f1" }} /> Hunt Outputs
              </Typography>
              <List dense>
                {huntOutputs.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#6366f1" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#10b981", 0.04) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <TrackChangesIcon sx={{ color: "#10b981" }} /> Metrics to Track
              </Typography>
              <List dense>
                {huntMetrics.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Common Pitfalls */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon sx={{ color: "#ef4444" }} /> Common Pitfalls
          </Typography>
          <List dense>
            {commonPitfalls.map((item, i) => (
              <ListItem key={i} sx={{ py: 0.5 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <WarningIcon sx={{ fontSize: 16, color: "#ef4444" }} />
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
            bgcolor: alpha("#10b981", 0.05),
            border: `1px solid ${alpha("#10b981", 0.2)}`,
            display: "flex",
            alignItems: "center",
            gap: 2,
          }}
        >
          <TipsAndUpdatesIcon sx={{ color: "#10b981" }} />
          <Typography variant="body2">
            <strong>Tip:</strong> Start with high-confidence TTPs relevant to your industry. Document everything—even negative results improve future hunts.
          </Typography>
        </Paper>

        {/* Related */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📚 Related Learning</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="SIEM Fundamentals →" clickable onClick={() => navigate("/learn/siem")} sx={{ fontWeight: 600 }} />
            <Chip label="SOC Workflow →" clickable onClick={() => navigate("/learn/soc-workflow")} sx={{ fontWeight: 600 }} />
            <Chip label="Incident Response →" clickable onClick={() => navigate("/learn/incident-response")} sx={{ fontWeight: 600 }} />
          </Box>
        </Paper>
      </Container>
    </LearnPageLayout>
  );
}
