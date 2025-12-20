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
import SupportAgentIcon from "@mui/icons-material/SupportAgent";
import PlaylistAddCheckIcon from "@mui/icons-material/PlaylistAddCheck";
import PriorityHighIcon from "@mui/icons-material/PriorityHigh";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import AssignmentIcon from "@mui/icons-material/Assignment";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ArrowForwardIcon from "@mui/icons-material/ArrowForward";
import SourceIcon from "@mui/icons-material/Source";
import TrackChangesIcon from "@mui/icons-material/TrackChanges";
import { useNavigate } from "react-router-dom";

interface WorkflowStep {
  step: string;
  title: string;
  description: string;
  color: string;
}

const workflowSteps: WorkflowStep[] = [
  { step: "1", title: "Alert Triage", description: "Review incoming alerts, assess severity, filter noise", color: "#ef4444" },
  { step: "2", title: "Initial Analysis", description: "Gather context, check IOCs, review logs, identify scope", color: "#f59e0b" },
  { step: "3", title: "Enrichment", description: "Query threat intel, correlate data, identify affected assets", color: "#8b5cf6" },
  { step: "4", title: "Determination", description: "True positive, false positive, or needs escalation?", color: "#3b82f6" },
  { step: "5", title: "Response/Escalation", description: "Contain threat, escalate to Tier 2/3, or close as FP", color: "#10b981" },
  { step: "6", title: "Documentation", description: "Record findings, update ticket, contribute to knowledge base", color: "#6366f1" },
];

const tierResponsibilities = [
  { tier: "Tier 1", focus: "Alert monitoring, initial triage, basic investigation, escalation" },
  { tier: "Tier 2", focus: "Deep-dive analysis, threat hunting, incident handling, tool tuning" },
  { tier: "Tier 3", focus: "Advanced forensics, malware analysis, threat intel, architecture" },
];

const bestPractices = [
  "Always document your investigation steps",
  "Don't close alerts without understanding root cause",
  "Build runbooks for common alert types",
  "Communicate clearly during shift handoffs",
  "Track metrics: MTTD, MTTR, FP rates",
  "Take breaks—alert fatigue is real",
];

const commonTools = [
  "SIEM (Splunk, Sentinel, Elastic)",
  "EDR (CrowdStrike, Defender, SentinelOne)",
  "Threat Intel (VirusTotal, MISP, OTX)",
  "Ticketing (Jira, ServiceNow)",
  "SOAR (Phantom, XSOAR, Shuffle)",
];

const triageQuestions = [
  "What detection rule fired and why?",
  "Is the user/host expected for this activity?",
  "Is there corroborating telemetry (EDR, DNS, proxy)?",
  "Is this a known benign tool or scheduled task?",
  "What is the likely impact if true positive?",
];

const alertCategories = [
  { name: "Malware", color: "#ef4444" },
  { name: "Phishing", color: "#f59e0b" },
  { name: "Credential Abuse", color: "#8b5cf6" },
  { name: "Lateral Movement", color: "#3b82f6" },
  { name: "Data Exfiltration", color: "#10b981" },
  { name: "Cloud Misconfig", color: "#6366f1" },
];

const enrichmentSources = [
  "Asset inventory/CMDB (owner, criticality)",
  "EDR process tree and command line",
  "DNS/proxy logs and domain reputation",
  "Threat intel lookups (hash, IP, domain)",
  "GeoIP/ASN context for external IPs",
  "Authentication logs and prior failures",
];

const investigationChecklist = [
  "Identify affected users/hosts and timeframe",
  "Build process tree and parent-child chain",
  "Review network connections and destinations",
  "Check for persistence or privilege escalation",
  "Search for similar activity across the environment",
];

const escalationCriteria = [
  "Confirmed credential compromise or data access",
  "Lateral movement beyond initial host",
  "Privileged or service accounts involved",
  "Malware with C2 or exfiltration indicators",
  "Critical or regulated assets impacted",
];

const containmentActions = [
  "Isolate host via EDR",
  "Disable/reset affected accounts",
  "Block hashes/domains/IPs",
  "Quarantine email or attachments",
  "Revoke tokens/keys and rotate secrets",
];

const documentationFields = [
  "Alert ID and detection rule",
  "Timeline of events and evidence",
  "Scope: users, hosts, and assets",
  "Actions taken and approvals",
  "Final disposition and severity",
];

const shiftHandoffChecklist = [
  "Open investigations with status and next steps",
  "High-priority alerts pending review",
  "Temporary blocks or containment actions",
  "Known false positives or noisy rules",
  "Upcoming changes or maintenance windows",
];

const socMetrics = [
  "MTTD, MTTR, and dwell time",
  "Alert volume by severity and source",
  "False positive rate by rule",
  "Coverage mapped to ATT&CK techniques",
  "SLA compliance for triage and response",
];

const commonPitfalls = [
  "Closing alerts without validation",
  "Relying on a single data source",
  "Skipping asset or user context",
  "Delaying escalation on high-risk signals",
  "No post-incident detection tuning",
];

const alertLifecycle = [
  { status: "New", detail: "Alert created and queued for triage." },
  { status: "In Progress", detail: "Analyst actively investigating." },
  { status: "Pending", detail: "Waiting on info or system owner." },
  { status: "Escalated", detail: "Handed to Tier 2/IR for action." },
  { status: "Resolved", detail: "Mitigation completed or verified." },
  { status: "Closed", detail: "Documentation finished and archived." },
];

const severityGuidance = [
  { level: "Critical", action: "Immediate triage and containment", example: "Active C2 or confirmed exfiltration" },
  { level: "High", action: "Triage within hours", example: "Privileged account compromise indicators" },
  { level: "Medium", action: "Same-day review", example: "Suspicious process with weak corroboration" },
  { level: "Low", action: "Batch and tune", example: "Noisy rule or benign automation" },
];

const slaTargets = [
  "Critical: triage in 15 minutes, response within 1 hour",
  "High: triage in 1 hour, response within 4 hours",
  "Medium: triage in 1 business day",
  "Low: review during backlog tuning",
];

const playbookElements = [
  "Trigger conditions and rule references",
  "Required logs and enrichment sources",
  "Decision tree for FP/TP/escalation",
  "Containment actions and approvals",
  "Post-incident tuning tasks",
];

const evidenceArtifacts = [
  "Timeline of events with timestamps",
  "Query results and screenshots",
  "Process tree and command line",
  "Network connections and destinations",
  "Hash and file metadata",
];

const communicationTips = [
  "Lead with facts, then impact, then recommendations",
  "Use clear severity language and avoid jargon",
  "Flag assumptions or gaps explicitly",
  "Share next steps with owners and due dates",
  "Confirm handoff acceptance in writing",
];

const analystSkills = [
  "SIEM query fluency and filtering",
  "EDR triage and process tree analysis",
  "Basic networking and DNS understanding",
  "Scripting for automation or log parsing",
  "Clear incident documentation",
];

const shiftRoutine = [
  "Review backlog and high-severity alerts",
  "Check new intel or blocked indicators",
  "Validate rule health and noisy detections",
  "Update tickets and communicate handoff",
];

export default function SOCWorkflowPage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `SOC Analyst Workflow Guide - Covers the Security Operations Center analyst workflow including alert triage, initial analysis, enrichment, determination, response/escalation, and documentation. Includes triage questions, alert categories, enrichment sources, investigation checklists, escalation criteria, containment actions, documentation fields, shift handoff steps, SOC metrics, best practices, tier responsibilities (Tier 1-3), and common tools used in security operations.`;

  return (
    <LearnPageLayout pageTitle="SOC Analyst Workflow" pageContext={pageContext}>
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
                bgcolor: alpha("#10b981", 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <SupportAgentIcon sx={{ fontSize: 36, color: "#10b981" }} />
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                SOC Analyst Workflow
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Security Operations Center processes
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Blue Team" color="primary" size="small" />
            <Chip label="SOC" size="small" sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981" }} />
            <Chip label="Operations" size="small" sx={{ bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6" }} />
          </Box>
        </Box>

        {/* Overview */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SupportAgentIcon color="primary" /> Overview
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            SOC analysts are the front line of defense, monitoring security alerts 24/7, investigating potential 
            incidents, and responding to threats. A structured workflow ensures consistent, thorough analysis 
            and helps teams scale while maintaining quality.
          </Typography>
        </Paper>

        {/* Workflow Steps */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🔄 Investigation Workflow</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {workflowSteps.map((ws, i) => (
            <Grid item xs={12} sm={6} md={4} key={ws.step}>
              <Paper
                sx={{
                  p: 2,
                  height: "100%",
                  borderRadius: 2,
                  border: `1px solid ${alpha(ws.color, 0.2)}`,
                  "&:hover": { borderColor: ws.color },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <Box
                    sx={{
                      width: 28,
                      height: 28,
                      borderRadius: "50%",
                      bgcolor: ws.color,
                      color: "#fff",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontWeight: 700,
                      fontSize: "0.85rem",
                    }}
                  >
                    {ws.step}
                  </Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    {ws.title}
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  {ws.description}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Triage Questions */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <PriorityHighIcon sx={{ color: "#ef4444" }} /> Triage Questions
          </Typography>
          <List dense>
            {triageQuestions.map((q, i) => (
              <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                </ListItemIcon>
                <ListItemText primary={q} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Alert Categories */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <AssignmentIcon sx={{ color: "#3b82f6" }} /> Common Alert Categories
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {alertCategories.map((cat) => (
              <Chip
                key={cat.name}
                label={cat.name}
                size="small"
                sx={{ bgcolor: alpha(cat.color, 0.12), color: cat.color, fontWeight: 600 }}
              />
            ))}
          </Box>
        </Paper>

        {/* Tier Responsibilities */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.05)}, ${alpha("#6366f1", 0.05)})`,
            border: `1px solid ${alpha("#3b82f6", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SwapHorizIcon sx={{ color: "#3b82f6" }} /> SOC Tier Responsibilities
          </Typography>
          {tierResponsibilities.map((t) => (
            <Box key={t.tier} sx={{ display: "flex", alignItems: "flex-start", gap: 1.5, mb: 1.5 }}>
              <Chip label={t.tier} size="small" sx={{ fontWeight: 700, minWidth: 60 }} />
              <Typography variant="body2" color="text.secondary">{t.focus}</Typography>
            </Box>
          ))}
        </Paper>

        {/* Enrichment and Investigation */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SourceIcon sx={{ color: "#8b5cf6" }} /> Enrichment Sources
              </Typography>
              <List dense>
                {enrichmentSources.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
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
                <PlaylistAddCheckIcon sx={{ color: "#f59e0b" }} /> Investigation Checklist
              </Typography>
              <List dense>
                {investigationChecklist.map((item, i) => (
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

        {/* Escalation and Containment */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <PriorityHighIcon sx={{ color: "#ef4444" }} /> Escalation Criteria
              </Typography>
              <List dense>
                {escalationCriteria.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <AssignmentIcon sx={{ color: "#10b981" }} /> Containment Actions
              </Typography>
              <List dense>
                {containmentActions.map((item, i) => (
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

        {/* Documentation and Handoff */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#6366f1", 0.04) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <AssignmentIcon sx={{ color: "#6366f1" }} /> Documentation Fields
              </Typography>
              <List dense>
                {documentationFields.map((item, i) => (
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
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#3b82f6", 0.04) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SwapHorizIcon sx={{ color: "#3b82f6" }} /> Shift Handoff Checklist
              </Typography>
              <List dense>
                {shiftHandoffChecklist.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Best Practices & Tools side by side */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <PlaylistAddCheckIcon sx={{ color: "#10b981" }} /> Best Practices
              </Typography>
              <List dense>
                {bestPractices.map((bp, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={bp} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <AssignmentIcon sx={{ color: "#8b5cf6" }} /> Common Tools
              </Typography>
              <List dense>
                {commonTools.map((tool, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={tool} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Metrics and Pitfalls */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <TrackChangesIcon sx={{ color: "#8b5cf6" }} /> SOC Metrics to Track
              </Typography>
              <List dense>
                {socMetrics.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
                <WarningIcon sx={{ color: "#ef4444" }} /> Common Pitfalls
              </Typography>
              <List dense>
                {commonPitfalls.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
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

        {/* Alert Lifecycle */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <ArrowForwardIcon sx={{ color: "#3b82f6" }} /> Alert Lifecycle
          </Typography>
          <Grid container spacing={2}>
            {alertLifecycle.map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.status}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                    {item.status}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {item.detail}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Severity and SLA Guidance */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <PriorityHighIcon sx={{ color: "#ef4444" }} /> Severity Guidance
              </Typography>
              <List dense>
                {severityGuidance.map((item) => (
                  <ListItem key={item.level} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={`${item.level}: ${item.action}`}
                      secondary={item.example}
                      primaryTypographyProps={{ variant: "body2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <PlaylistAddCheckIcon sx={{ color: "#10b981" }} /> SLA Targets
              </Typography>
              <List dense>
                {slaTargets.map((item, i) => (
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

        {/* Playbooks and Evidence */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#6366f1", 0.04) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <AssignmentIcon sx={{ color: "#6366f1" }} /> Playbook Elements
              </Typography>
              <List dense>
                {playbookElements.map((item, i) => (
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
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#3b82f6", 0.04) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <AssignmentIcon sx={{ color: "#3b82f6" }} /> Evidence Artifacts
              </Typography>
              <List dense>
                {evidenceArtifacts.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Communication and Skills */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#f59e0b", 0.05) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SwapHorizIcon sx={{ color: "#f59e0b" }} /> Communication Tips
              </Typography>
              <List dense>
                {communicationTips.map((item, i) => (
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
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.04) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <SupportAgentIcon sx={{ color: "#8b5cf6" }} /> Core Analyst Skills
              </Typography>
              <List dense>
                {analystSkills.map((item, i) => (
                  <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Shift Routine */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SupportAgentIcon sx={{ color: "#10b981" }} /> Daily Shift Routine
          </Typography>
          <List dense>
            {shiftRoutine.map((item, i) => (
              <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                </ListItemIcon>
                <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Warning */}
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
          <WarningIcon sx={{ color: "#f59e0b" }} />
          <Typography variant="body2">
            <strong>Burnout Warning:</strong> SOC work is demanding. Rotate shifts, take breaks, and support your team.
          </Typography>
        </Paper>

        {/* Related */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📚 Related Learning</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="SIEM Fundamentals →" clickable onClick={() => navigate("/learn/siem")} sx={{ fontWeight: 600 }} />
            <Chip label="Threat Hunting →" clickable onClick={() => navigate("/learn/threat-hunting")} sx={{ fontWeight: 600 }} />
            <Chip label="Incident Response →" clickable onClick={() => navigate("/learn/incident-response")} sx={{ fontWeight: 600 }} />
          </Box>
        </Paper>
      </Container>
    </LearnPageLayout>
  );
}
