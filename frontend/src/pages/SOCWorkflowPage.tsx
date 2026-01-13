import React, { useEffect, useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Typography,
  Paper,
  Chip,
  Button,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Drawer,
  Fab,
  IconButton,
  Tooltip,
  Divider,
  LinearProgress,
  alpha,
  useTheme,
  useMediaQuery,
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
import QuizIcon from "@mui/icons-material/Quiz";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import { Link, useNavigate } from "react-router-dom";

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

const telemetrySources = [
  {
    source: "Endpoint telemetry",
    signals: ["Process creation and command line", "File and registry writes", "Module loads and driver activity"],
    questions: ["What is the parent process?", "Is the binary signed or known?", "Any persistence or privilege changes?"],
    color: "#10b981",
  },
  {
    source: "Identity and authentication",
    signals: ["Login failures and successes", "MFA prompts and denials", "Privilege or group changes"],
    questions: ["Is the location expected?", "Is the user high risk or privileged?", "Is there impossible travel?"],
    color: "#3b82f6",
  },
  {
    source: "Network and proxy",
    signals: ["DNS queries and responses", "Proxy URLs and user agents", "Firewall flows and TLS SNI"],
    questions: ["Is the destination newly seen?", "Is there beaconing or staging?", "Is the ASN suspicious?"],
    color: "#f59e0b",
  },
  {
    source: "Email and collaboration",
    signals: ["Inbound attachments and URLs", "Mailbox rules and forwarding", "OAuth consent grants"],
    questions: ["Is the sender spoofed?", "Did the user click or open?", "Are there rule changes?"],
    color: "#8b5cf6",
  },
  {
    source: "Cloud and SaaS",
    signals: ["IAM role changes", "Key creation and token use", "Storage access patterns"],
    questions: ["Is activity from trusted IPs?", "Are keys newly created?", "Are downloads unusual?"],
    color: "#6366f1",
  },
  {
    source: "Asset and vulnerability data",
    signals: ["Asset criticality", "Exposure and internet facing status", "Known vulnerabilities"],
    questions: ["Is this a crown jewel asset?", "Is there a matching CVE?", "Who owns this system?"],
    color: "#ef4444",
  },
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

const dispositionGuidance = [
  {
    label: "True Positive",
    criteria: "Evidence confirms malicious intent or impact.",
    action: "Contain, escalate to IR, and open an incident.",
    color: "#ef4444",
  },
  {
    label: "False Positive",
    criteria: "Detection triggered by benign behavior or bad logic.",
    action: "Document reasoning, tune detection, and close.",
    color: "#10b981",
  },
  {
    label: "Benign Positive",
    criteria: "Suspicious action but approved or expected activity.",
    action: "Validate approval, document, and consider allowlist.",
    color: "#3b82f6",
  },
  {
    label: "Needs More Data",
    criteria: "Signals are incomplete or conflicting.",
    action: "Collect additional logs and keep in progress.",
    color: "#f59e0b",
  },
];

const escalationCriteria = [
  "Confirmed credential compromise or data access",
  "Lateral movement beyond initial host",
  "Privileged or service accounts involved",
  "Malware with C2 or exfiltration indicators",
  "Critical or regulated assets impacted",
];

const escalationPacket = [
  "Short summary and current severity rationale",
  "Timeline with key evidence and timestamps",
  "Affected users, hosts, and asset criticality",
  "Containment already performed or approvals needed",
  "Open questions and requested actions",
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

// Example SIEM queries for common scenarios
const exampleSiemQueries = [
  {
    scenario: "Failed Login Spike",
    query: `index=auth event_type=failed_login | stats count by user, src_ip | where count > 5`,
    purpose: "Identify brute force or credential stuffing attempts",
  },
  {
    scenario: "Suspicious PowerShell",
    query: `index=edr process_name=powershell.exe (command_line=*-enc* OR command_line=*bypass*)`,
    purpose: "Detect encoded or execution policy bypass activity",
  },
  {
    scenario: "Large Outbound Transfer",
    query: `index=proxy bytes_out > 50000000 | stats sum(bytes_out) by src_ip, dest_domain`,
    purpose: "Identify potential data exfiltration",
  },
  {
    scenario: "Rare Parent-Child Process",
    query: `index=edr | rare parent_process, process_name limit=20`,
    purpose: "Find unusual process relationships",
  },
];

// Real-world triage scenarios
const triageScenarios = [
  {
    alert: "Mimikatz detected on workstation",
    steps: ["Isolate host immediately", "Check for lateral movement", "Review auth logs for credential use", "Escalate to IR"],
    outcome: "True Positive - Active compromise",
  },
  {
    alert: "PowerShell encoded command execution",
    steps: ["Decode the command", "Check parent process (email client?)", "Review user context", "Search for similar activity"],
    outcome: "May be TP (attack) or FP (admin script)",
  },
  {
    alert: "Multiple failed logins followed by success",
    steps: ["Check source IP reputation", "Verify user traveled or VPN used", "Look for post-auth anomalies"],
    outcome: "FP if legitimate travel, TP if stolen creds",
  },
];

const alertTypePlaybooks = [
  {
    type: "Phishing",
    focus: "Email and identity abuse",
    checks: [
      "Inspect headers, sender domain, and spoofing signals",
      "Review URL reputation and redirect chain",
      "Confirm user click or attachment open",
      "Search for similar messages across the org",
      "Check for mailbox rule or OAuth changes",
    ],
    color: "#f59e0b",
  },
  {
    type: "Malware",
    focus: "Endpoint execution and persistence",
    checks: [
      "Validate hash reputation and file origin",
      "Build process tree and parent relationship",
      "Check for persistence mechanisms",
      "Review outbound connections and C2 indicators",
      "Scope similar activity across hosts",
    ],
    color: "#ef4444",
  },
  {
    type: "Credential Abuse",
    focus: "Suspicious auth behavior",
    checks: [
      "Check source IP, ASN, and geo context",
      "Look for failed logins followed by success",
      "Review MFA prompts and token use",
      "Identify privileged or service accounts",
      "Hunt for post-auth anomalies",
    ],
    color: "#8b5cf6",
  },
  {
    type: "Lateral Movement",
    focus: "Movement between hosts",
    checks: [
      "Identify remote execution tools used",
      "Review admin share and RDP activity",
      "Check for new services or scheduled tasks",
      "Confirm credential reuse or theft indicators",
      "Contain spread and escalate quickly",
    ],
    color: "#3b82f6",
  },
  {
    type: "Data Exfiltration",
    focus: "Large or unusual data transfer",
    checks: [
      "Review data volume and destination",
      "Check for new cloud storage or file share use",
      "Correlate with user behavior and working hours",
      "Look for compression or staging activity",
      "Escalate if regulated data is involved",
    ],
    color: "#10b981",
  },
];

// Detection tuning tips
const tuningTips = [
  "Whitelist known admin tools with specific hash and path conditions",
  "Add user/group exceptions only after validation, not to silence alerts",
  "Track FP rates per rule and tune the noisiest 10%",
  "Document every tuning change with rationale",
  "Re-enable suppressed rules periodically to check for changes",
];

const detectionFeedbackLoop = [
  { step: "Observe", detail: "Capture alert outcomes, FP rates, and analyst notes." },
  { step: "Tune", detail: "Adjust logic, thresholds, and exception criteria." },
  { step: "Validate", detail: "Replay test data or run controlled scenarios." },
  { step: "Deploy", detail: "Release updates with change notes and ownership." },
  { step: "Measure", detail: "Track coverage, latency, and true positive rate." },
];

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#10b981";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "What does SOC stand for?",
    options: [
      "Security Operations Center",
      "Secure Online Console",
      "System Operations Console",
      "Security Orchestration Cloud",
    ],
    correctAnswer: 0,
    explanation: "SOC stands for Security Operations Center.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "The SOC workflow primarily ensures:",
    options: [
      "Password rotation schedules",
      "Consistent triage and response to alerts",
      "Only compliance reporting",
      "Replacing firewalls",
    ],
    correctAnswer: 1,
    explanation: "A defined workflow keeps investigations consistent and repeatable.",
  },
  {
    id: 3,
    topic: "Workflow",
    question: "Which step comes first in the SOC workflow?",
    options: ["Initial analysis", "Alert triage", "Containment", "Documentation"],
    correctAnswer: 1,
    explanation: "Alert triage is the first step before deeper analysis.",
  },
  {
    id: 4,
    topic: "Triage",
    question: "The main goal of triage is to:",
    options: ["Patch systems", "Assess severity and filter noise", "Create malware", "Disable logging"],
    correctAnswer: 1,
    explanation: "Triage filters noise and prioritizes real risk.",
  },
  {
    id: 5,
    topic: "Analysis",
    question: "Initial analysis typically includes:",
    options: [
      "Only closing alerts",
      "Gathering context and reviewing logs or IOCs",
      "Formatting disks",
      "Ignoring user activity",
    ],
    correctAnswer: 1,
    explanation: "Analysts gather context and review evidence before deciding next steps.",
  },
  {
    id: 6,
    topic: "Enrichment",
    question: "Enrichment commonly uses:",
    options: ["Threat intel and asset context", "Only CPU stats", "Wallpaper settings", "Compiler flags"],
    correctAnswer: 0,
    explanation: "Enrichment adds context from intel and asset data.",
  },
  {
    id: 7,
    topic: "Determination",
    question: "The determination step decides whether an alert is:",
    options: [
      "A patch candidate",
      "True positive, false positive, or needs escalation",
      "A network upgrade",
      "A software license issue",
    ],
    correctAnswer: 1,
    explanation: "Determination classifies the alert outcome.",
  },
  {
    id: 8,
    topic: "Response",
    question: "Response or escalation typically includes:",
    options: [
      "Containment or escalation to Tier 2 or IR",
      "Disabling all alerts",
      "Only reporting",
      "File backups",
    ],
    correctAnswer: 0,
    explanation: "The response step contains threats or escalates for deeper handling.",
  },
  {
    id: 9,
    topic: "Documentation",
    question: "Documentation should:",
    options: ["Record findings and actions in the ticket", "Delete evidence", "Stop logging", "Change DNS"],
    correctAnswer: 0,
    explanation: "Documentation preserves evidence and decisions for audit and handoff.",
  },
  {
    id: 10,
    topic: "Roles",
    question: "Tier 1 analysts mainly focus on:",
    options: [
      "Monitoring and initial triage",
      "Advanced malware reverse engineering",
      "Network architecture design",
      "Risk auditing",
    ],
    correctAnswer: 0,
    explanation: "Tier 1 handles alert intake, triage, and escalation.",
  },
  {
    id: 11,
    topic: "Roles",
    question: "Tier 2 analysts typically handle:",
    options: [
      "Deep-dive investigations and containment",
      "Only password resets",
      "Only compliance reporting",
      "Physical security",
    ],
    correctAnswer: 0,
    explanation: "Tier 2 performs deeper analysis and advanced triage.",
  },
  {
    id: 12,
    topic: "Roles",
    question: "Tier 3 responsibilities often include:",
    options: [
      "Advanced forensics and threat intel",
      "Initial alert triage",
      "Ticket routing",
      "Data entry",
    ],
    correctAnswer: 0,
    explanation: "Tier 3 handles complex investigations and specialized analysis.",
  },
  {
    id: 13,
    topic: "Tools",
    question: "A SIEM is primarily used for:",
    options: ["Log search and correlation", "User training", "Device charging", "Code compilation"],
    correctAnswer: 0,
    explanation: "SIEMs aggregate and correlate security logs.",
  },
  {
    id: 14,
    topic: "Tools",
    question: "EDR tools are used for:",
    options: ["Endpoint telemetry and isolation", "Network cabling", "Email marketing", "Asset procurement"],
    correctAnswer: 0,
    explanation: "EDR provides endpoint visibility and containment capabilities.",
  },
  {
    id: 15,
    topic: "Tools",
    question: "SOAR platforms help teams:",
    options: ["Automate response workflows", "Encrypt disks", "Replace SIEM", "Disable alerts"],
    correctAnswer: 0,
    explanation: "SOAR automates and orchestrates response tasks.",
  },
  {
    id: 16,
    topic: "Tools",
    question: "Ticketing systems are used to:",
    options: ["Track investigations and handoffs", "Run antivirus scans", "Block IPs", "Collect PCAP"],
    correctAnswer: 0,
    explanation: "Tickets capture evidence, actions, and status.",
  },
  {
    id: 17,
    topic: "Threat Intel",
    question: "Which is a threat intelligence source?",
    options: ["MISP or VirusTotal", "Spreadsheet macros", "Wallpaper images", "Keyboard drivers"],
    correctAnswer: 0,
    explanation: "MISP and VirusTotal provide threat intelligence data.",
  },
  {
    id: 18,
    topic: "Triage",
    question: "Which question helps validate legitimacy during triage?",
    options: [
      "What is the printer model?",
      "What is the user wallpaper?",
      "Is the user or host expected for this activity?",
      "Which font is installed?",
    ],
    correctAnswer: 2,
    explanation: "User and host context helps identify suspicious activity.",
  },
  {
    id: 19,
    topic: "Context",
    question: "Asset criticality helps determine:",
    options: ["Severity and escalation priority", "Mouse speed", "Battery health", "CPU fan curves"],
    correctAnswer: 0,
    explanation: "Critical assets drive prioritization and response urgency.",
  },
  {
    id: 20,
    topic: "Alerts",
    question: "Which is a common alert category?",
    options: ["Phishing", "Patch Tuesday", "Disk cleanup", "UI bug"],
    correctAnswer: 0,
    explanation: "Phishing is a common SOC alert category.",
  },
  {
    id: 21,
    topic: "Escalation",
    question: "Which is a valid escalation criterion?",
    options: ["Privileged accounts involved", "Low disk space", "User forgot password", "Printer offline"],
    correctAnswer: 0,
    explanation: "Privileged account involvement raises risk and requires escalation.",
  },
  {
    id: 22,
    topic: "Containment",
    question: "Which is a common containment action?",
    options: ["Isolate host via EDR", "Rename shared folder", "Upgrade monitor", "Change wallpaper"],
    correctAnswer: 0,
    explanation: "Isolation limits threat spread and reduces impact.",
  },
  {
    id: 23,
    topic: "Documentation",
    question: "Good documentation includes:",
    options: ["Timeline of events and evidence", "Only ticket ID", "Only analyst name", "No timestamps"],
    correctAnswer: 0,
    explanation: "Detailed evidence and timelines are critical for investigations.",
  },
  {
    id: 24,
    topic: "Handoff",
    question: "Shift handoff should include:",
    options: ["Open investigations and next steps", "Personal notes only", "No status details", "Only closed cases"],
    correctAnswer: 0,
    explanation: "Handoffs must capture active work and pending actions.",
  },
  {
    id: 25,
    topic: "Metrics",
    question: "MTTD stands for:",
    options: ["Mean Time to Detect", "Monthly Trend Tracking Dashboard", "Message Trace Data", "Managed Threat Tuning Data"],
    correctAnswer: 0,
    explanation: "MTTD measures detection speed.",
  },
  {
    id: 26,
    topic: "Metrics",
    question: "MTTR stands for:",
    options: ["Mean Time to Restore", "Mean Time to Respond", "Monthly Triage Rate", "Mitigation Task Ratio"],
    correctAnswer: 1,
    explanation: "MTTR measures response speed.",
  },
  {
    id: 27,
    topic: "Metrics",
    question: "False positive rate measures:",
    options: ["Percent of alerts that are not real incidents", "CPU usage", "Disk capacity", "Network speed"],
    correctAnswer: 0,
    explanation: "A high false positive rate indicates noisy detections.",
  },
  {
    id: 28,
    topic: "Metrics",
    question: "ATT&CK coverage mapping helps teams:",
    options: ["Disable alerts", "Reduce storage", "Identify detection gaps", "Ignore telemetry"],
    correctAnswer: 2,
    explanation: "Mapping detections to ATT&CK reveals gaps.",
  },
  {
    id: 29,
    topic: "Lifecycle",
    question: "An alert in the 'New' state is:",
    options: ["Created and queued for triage", "Closed and archived", "Containment done", "Escalated already"],
    correctAnswer: 0,
    explanation: "New alerts are awaiting initial triage.",
  },
  {
    id: 30,
    topic: "Lifecycle",
    question: "An alert in the 'Escalated' state is:",
    options: ["Resolved and closed", "Handed to Tier 2 or IR", "Ignored permanently", "Only logged"],
    correctAnswer: 1,
    explanation: "Escalated alerts are transferred for deeper handling.",
  },
  {
    id: 31,
    topic: "Severity",
    question: "Critical severity usually requires:",
    options: ["Immediate triage and containment", "Backlog review", "Ignore until later", "Weekly review"],
    correctAnswer: 0,
    explanation: "Critical issues demand immediate action.",
  },
  {
    id: 32,
    topic: "Severity",
    question: "Low severity alerts are often:",
    options: ["Immediate containment", "Batch reviewed and tuned", "Always ignored", "Escalated to Tier 3"],
    correctAnswer: 1,
    explanation: "Low severity alerts are typically batched and tuned.",
  },
  {
    id: 33,
    topic: "SLA",
    question: "SLA stands for:",
    options: ["Service Level Agreement", "System Log Archive", "Security Logic Algorithm", "Severity Level Assignment"],
    correctAnswer: 0,
    explanation: "SLAs define expected response timelines.",
  },
  {
    id: 34,
    topic: "SLA",
    question: "A sample SLA for critical alerts is:",
    options: [
      "Triage in 24 hours, response next week",
      "Triage in 8 hours, response in 24 hours",
      "Triage in 15 minutes, response within 1 hour",
      "Triage when convenient",
    ],
    correctAnswer: 2,
    explanation: "Critical alerts require the fastest triage and response times.",
  },
  {
    id: 35,
    topic: "Playbooks",
    question: "A playbook typically includes:",
    options: ["Decision tree and containment actions", "Only a title", "Only a severity level", "Only a ticket ID"],
    correctAnswer: 0,
    explanation: "Playbooks document steps, decisions, and actions.",
  },
  {
    id: 36,
    topic: "Evidence",
    question: "Which is a common evidence artifact?",
    options: ["Process tree and command line", "Wallpaper theme", "Monitor model", "Keyboard layout"],
    correctAnswer: 0,
    explanation: "Process trees and command lines are key investigation artifacts.",
  },
  {
    id: 37,
    topic: "Communication",
    question: "A good communication tip is to:",
    options: [
      "Lead with facts, then impact, then recommendations",
      "Use jargon without context",
      "Hide assumptions",
      "Avoid timelines",
    ],
    correctAnswer: 0,
    explanation: "Clear, structured communication improves stakeholder alignment.",
  },
  {
    id: 38,
    topic: "Skills",
    question: "A core analyst skill is:",
    options: ["SIEM query fluency", "Graphic design", "Sales training", "Hardware repair"],
    correctAnswer: 0,
    explanation: "Analysts must query and filter logs efficiently.",
  },
  {
    id: 39,
    topic: "Shift Routine",
    question: "A daily shift routine should include:",
    options: ["Review backlog and high-severity alerts", "Ignore new intel", "Disable detections", "Skip handoff"],
    correctAnswer: 0,
    explanation: "Reviewing backlog and high-severity alerts keeps risk in check.",
  },
  {
    id: 40,
    topic: "Pitfalls",
    question: "A common pitfall is:",
    options: ["Relying on a single data source", "Corroborating evidence", "Documenting findings", "Using enrichment"],
    correctAnswer: 0,
    explanation: "Single-source investigations can miss key context.",
  },
  {
    id: 41,
    topic: "Pitfalls",
    question: "Another common pitfall is:",
    options: ["Closing alerts without validation", "Using triage questions", "Updating runbooks", "Sharing handoffs"],
    correctAnswer: 0,
    explanation: "Alerts should not be closed without proper validation.",
  },
  {
    id: 42,
    topic: "Operations",
    question: "Alert fatigue is often caused by:",
    options: ["Too many noisy alerts", "Too few alerts", "Perfect detections", "No logs"],
    correctAnswer: 0,
    explanation: "Excessive low-quality alerts exhaust analysts.",
  },
  {
    id: 43,
    topic: "Triage",
    question: "During triage, analysts should check:",
    options: ["Corroborating telemetry such as EDR, DNS, or proxy logs", "Only the alert title", "Wallpaper settings", "Monitor resolution"],
    correctAnswer: 0,
    explanation: "Cross-source evidence strengthens confidence in findings.",
  },
  {
    id: 44,
    topic: "Enrichment",
    question: "An enrichment source example is:",
    options: ["DNS or proxy logs and domain reputation", "Screen brightness", "CPU fan speed", "Keyboard shortcuts"],
    correctAnswer: 0,
    explanation: "Enrichment uses additional sources to add context.",
  },
  {
    id: 45,
    topic: "Containment",
    question: "For credential compromise, a common containment action is:",
    options: ["Disable or reset affected accounts", "Change wallpapers", "Reinstall fonts", "Ignore the alert"],
    correctAnswer: 0,
    explanation: "Account reset or disablement stops attacker access.",
  },
  {
    id: 46,
    topic: "Escalation",
    question: "Escalation is required when:",
    options: ["Lateral movement extends beyond the initial host", "A low-risk alert appears", "A user changes a password", "A service restarts"],
    correctAnswer: 0,
    explanation: "Lateral movement indicates broader compromise.",
  },
  {
    id: 47,
    topic: "Documentation",
    question: "Case documentation should include:",
    options: ["Actions taken and approvals", "Only the ticket ID", "Only the analyst name", "No timestamps"],
    correctAnswer: 0,
    explanation: "Actions and approvals are essential for audit trails.",
  },
  {
    id: 48,
    topic: "Handoff",
    question: "Handoffs should note:",
    options: ["Temporary blocks or containment actions", "Only closed cases", "No next steps", "Only screenshots"],
    correctAnswer: 0,
    explanation: "Pending blocks and actions must be visible to the next shift.",
  },
  {
    id: 49,
    topic: "Analysis",
    question: "Initial analysis should review:",
    options: ["Detection rule logic and scope", "Only keyboard settings", "Only user wallpaper", "Only system uptime"],
    correctAnswer: 0,
    explanation: "Understanding the detection rule clarifies why the alert fired.",
  },
  {
    id: 50,
    topic: "Determination",
    question: "Determination results in:",
    options: ["True positive, false positive, or needs escalation", "Only a status color", "Only a ticket number", "Only a summary line"],
    correctAnswer: 0,
    explanation: "Determination classifies the alert outcome and next steps.",
  },
  {
    id: 51,
    topic: "Playbooks",
    question: "Runbooks and playbooks help by:",
    options: ["Providing consistent response steps", "Hiding evidence", "Disabling logging", "Replacing analysts"],
    correctAnswer: 0,
    explanation: "Playbooks standardize response and reduce errors.",
  },
  {
    id: 52,
    topic: "Tuning",
    question: "Post-incident tuning is used to:",
    options: ["Reduce noise and improve detections", "Delete logs", "Disable alerts", "Avoid documentation"],
    correctAnswer: 0,
    explanation: "Tuning refines detections based on lessons learned.",
  },
  {
    id: 53,
    topic: "Severity",
    question: "Severity should consider:",
    options: ["Business impact and confidence", "Monitor size", "Keyboard layout", "Printer brand"],
    correctAnswer: 0,
    explanation: "Severity should reflect business impact and evidence strength.",
  },
  {
    id: 54,
    topic: "Context",
    question: "Asset criticality influences:",
    options: ["Escalation priority", "Screen brightness", "Mouse speed", "Keyboard settings"],
    correctAnswer: 0,
    explanation: "Critical assets raise the urgency of response.",
  },
  {
    id: 55,
    topic: "Enrichment",
    question: "GeoIP enrichment helps analysts:",
    options: ["Spot unusual countries or ASNs", "Update device drivers", "Change desktop themes", "Adjust CPU voltage"],
    correctAnswer: 0,
    explanation: "GeoIP reveals suspicious locations or networks.",
  },
  {
    id: 56,
    topic: "Alerts",
    question: "A malware alert usually indicates:",
    options: ["Malicious code execution", "Normal system updates", "Printer issues", "User training"],
    correctAnswer: 0,
    explanation: "Malware alerts often signal malicious code activity.",
  },
  {
    id: 57,
    topic: "Alerts",
    question: "Phishing alerts often involve:",
    options: ["Suspicious emails or links", "Hardware failures", "CPU throttling", "Disk defragmentation"],
    correctAnswer: 0,
    explanation: "Phishing commonly arrives via email or messaging links.",
  },
  {
    id: 58,
    topic: "Alerts",
    question: "Credential abuse indicators include:",
    options: ["Repeated failed logins or impossible travel", "Wallpaper changes", "Printer usage", "Screen lock events"],
    correctAnswer: 0,
    explanation: "Repeated failures or impossible travel are classic signals.",
  },
  {
    id: 59,
    topic: "Alerts",
    question: "Lateral movement indicators often include:",
    options: ["Remote service logons or PsExec activity", "Normal patching", "User training", "Desktop shortcuts"],
    correctAnswer: 0,
    explanation: "Remote service use can indicate lateral movement.",
  },
  {
    id: 60,
    topic: "Alerts",
    question: "Data exfiltration indicators include:",
    options: ["Large outbound transfers", "Routine backups", "Software updates", "Printer jobs"],
    correctAnswer: 0,
    explanation: "Large outbound transfers can signal data theft.",
  },
  {
    id: 61,
    topic: "Alerts",
    question: "A cloud misconfiguration alert might be:",
    options: ["A public storage bucket", "A battery warning", "A monitor issue", "A keyboard layout change"],
    correctAnswer: 0,
    explanation: "Public cloud storage exposure is a common misconfiguration.",
  },
  {
    id: 62,
    topic: "Triage",
    question: "Triage should avoid:",
    options: ["Closing without evidence", "Gathering context", "Checking logs", "Corroborating telemetry"],
    correctAnswer: 0,
    explanation: "Closing without evidence increases risk of missed incidents.",
  },
  {
    id: 63,
    topic: "Documentation",
    question: "Analysts should document even when:",
    options: ["The alert is a false positive", "The alert is obvious", "The system is idle", "The user is offline"],
    correctAnswer: 0,
    explanation: "Documentation supports auditing and future tuning.",
  },
  {
    id: 64,
    topic: "Handoff",
    question: "Handoff acceptance should be:",
    options: ["Confirmed in writing", "Assumed automatically", "Skipped for speed", "Only verbal"],
    correctAnswer: 0,
    explanation: "Written confirmation reduces missed ownership.",
  },
  {
    id: 65,
    topic: "Investigation",
    question: "An investigation checklist should include:",
    options: ["Build process tree and timeline", "Change wallpaper", "Upgrade drivers", "Uninstall browsers"],
    correctAnswer: 0,
    explanation: "Process trees and timelines are core investigation steps.",
  },
  {
    id: 66,
    topic: "Evidence",
    question: "Maintaining evidence integrity requires:",
    options: ["Preserving data without tampering", "Deleting logs", "Sharing credentials", "Ignoring timestamps"],
    correctAnswer: 0,
    explanation: "Integrity ensures evidence is trustworthy.",
  },
  {
    id: 67,
    topic: "SLA",
    question: "SLA compliance is measured by:",
    options: ["Time to triage and response", "Disk space", "Email volume", "Number of desktops"],
    correctAnswer: 0,
    explanation: "SLA performance tracks timeliness of triage and response.",
  },
  {
    id: 68,
    topic: "Tools",
    question: "A common ticketing tool is:",
    options: ["Jira or ServiceNow", "Paint", "Calculator", "Notepad"],
    correctAnswer: 0,
    explanation: "Jira and ServiceNow are widely used for case management.",
  },
  {
    id: 69,
    topic: "Containment",
    question: "A containment action for a malicious domain is:",
    options: ["Block at DNS or proxy", "Change wallpaper", "Reboot printers", "Update fonts"],
    correctAnswer: 0,
    explanation: "Blocking at DNS or proxy stops traffic to the domain.",
  },
  {
    id: 70,
    topic: "Escalation",
    question: "Escalation is required when:",
    options: ["Regulated or critical assets are impacted", "A laptop battery is low", "A user logs out", "A patch is applied"],
    correctAnswer: 0,
    explanation: "Regulated assets raise risk and require escalation.",
  },
  {
    id: 71,
    topic: "Best Practices",
    question: "A best practice for SOC teams is to:",
    options: ["Build runbooks for common alerts", "Avoid documentation", "Ignore noisy rules", "Disable all alerts"],
    correctAnswer: 0,
    explanation: "Runbooks improve consistency and reduce mistakes.",
  },
  {
    id: 72,
    topic: "Communication",
    question: "Another communication tip is to:",
    options: ["Flag assumptions or gaps explicitly", "Hide uncertainty", "Avoid next steps", "Use vague language"],
    correctAnswer: 0,
    explanation: "Clear assumptions help stakeholders assess risk.",
  },
  {
    id: 73,
    topic: "Skills",
    question: "A core analyst skill includes:",
    options: ["Basic networking and DNS understanding", "Video editing", "Graphic design", "Sales forecasting"],
    correctAnswer: 0,
    explanation: "Networking fundamentals are essential for investigations.",
  },
  {
    id: 74,
    topic: "Metrics",
    question: "SOC metrics often include:",
    options: ["Alert volume by severity and source", "Monitor brightness", "Mouse DPI", "Laptop temperature"],
    correctAnswer: 0,
    explanation: "Alert volume by severity shows workload trends.",
  },
  {
    id: 75,
    topic: "Wellness",
    question: "The burnout warning suggests teams should:",
    options: ["Rotate shifts and take breaks", "Work longer hours", "Skip handoffs", "Ignore fatigue"],
    correctAnswer: 0,
    explanation: "Rotating shifts and breaks helps prevent burnout.",
  },
];

export default function SOCWorkflowPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const accent = "#8b5cf6";

  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const pageContext = `SOC Analyst Workflow Guide - Covers the Security Operations Center analyst workflow including alert triage, initial analysis, enrichment, determination, response/escalation, and documentation. Includes triage questions, alert categories, core telemetry sources, enrichment sources, investigation checklists, disposition rubric, escalation criteria, escalation packet checklists, containment actions, documentation fields, shift handoff steps, SOC metrics, best practices, tier responsibilities (Tier 1-3), common tools, alert-type playbooks, and a detection feedback loop.`;

  const sectionNavItems = [
    { id: "intro", label: "Overview", icon: <SupportAgentIcon /> },
    { id: "workflow", label: "Workflow", icon: <PlaylistAddCheckIcon /> },
    { id: "telemetry", label: "Telemetry", icon: <SourceIcon /> },
    { id: "disposition", label: "Disposition", icon: <AssignmentIcon /> },
    { id: "escalation", label: "Escalation", icon: <PriorityHighIcon /> },
    { id: "documentation", label: "Documentation", icon: <AssignmentIcon /> },
    { id: "best-practices", label: "Best Practices", icon: <CheckCircleIcon /> },
    { id: "metrics", label: "Metrics & Pitfalls", icon: <TrackChangesIcon /> },
    { id: "lifecycle", label: "Alert Lifecycle", icon: <ArrowForwardIcon /> },
    { id: "playbooks", label: "Playbooks", icon: <AssignmentIcon /> },
    { id: "siem-queries", label: "SIEM Queries", icon: <SourceIcon /> },
    { id: "triage-scenarios", label: "Scenarios", icon: <WarningIcon /> },
    { id: "tuning", label: "Tuning", icon: <TrackChangesIcon /> },
    { id: "feedback-loop", label: "Feedback Loop", icon: <SwapHorizIcon /> },
    { id: "related", label: "Related", icon: <ListAltIcon /> },
    { id: "quiz", label: "Quiz", icon: <QuizIcon /> },
  ];

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setNavDrawerOpen(false);
    }
  };

  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map((item) => item.id);
      let currentSection = "";

      for (const sectionId of sections) {
        const element = document.getElementById(sectionId);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 150) {
            currentSection = sectionId;
          }
        }
      }
      setActiveSection(currentSection);
    };

    window.addEventListener("scroll", handleScroll);
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });

  const currentIndex = sectionNavItems.findIndex((item) => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / sectionNavItems.length) * 100 : 0;

  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        width: 220,
        flexShrink: 0,
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        borderRadius: 3,
        border: `1px solid ${alpha(accent, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha(accent, 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography
          variant="subtitle2"
          sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}
        >
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              Progress
            </Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
              {Math.round(progressPercent)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: accent,
                borderRadius: 3,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1.5,
                mb: 0.25,
                py: 0.5,
                cursor: "pointer",
                bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha(accent, 0.08),
                },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem" }}>{item.icon}</ListItemIcon>
              <ListItemText
                primary={
                  <Typography
                    variant="caption"
                    sx={{
                      fontWeight: activeSection === item.id ? 700 : 500,
                      color: activeSection === item.id ? accent : "text.secondary",
                      fontSize: "0.75rem",
                    }}
                  >
                    {item.label}
                  </Typography>
                }
              />
            </ListItem>
          ))}
        </List>
      </Box>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="SOC Analyst Workflow" pageContext={pageContext}>
      {/* Floating Navigation Button - Mobile Only */}
      <Tooltip title="Navigate Sections" placement="left">
        <Fab
          color="primary"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: 90,
            right: 24,
            zIndex: 1000,
            bgcolor: accent,
            "&:hover": { bgcolor: "#7c3aed" },
            boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
            display: { xs: "flex", lg: "none" },
          }}
        >
          <ListAltIcon />
        </Fab>
      </Tooltip>

      {/* Scroll to Top Button - Mobile Only */}
      <Tooltip title="Scroll to Top" placement="left">
        <Fab
          size="small"
          onClick={scrollToTop}
          sx={{
            position: "fixed",
            bottom: 32,
            right: 28,
            zIndex: 1000,
            bgcolor: alpha(accent, 0.15),
            color: accent,
            "&:hover": { bgcolor: alpha(accent, 0.25) },
            display: { xs: "flex", lg: "none" },
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      </Tooltip>

      {/* Navigation Drawer - Mobile */}
      <Drawer
        anchor="right"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: {
            width: isMobile ? "85%" : 320,
            bgcolor: theme.palette.background.paper,
            backgroundImage: "none",
          },
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <ListAltIcon sx={{ color: accent }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>

          <Divider sx={{ mb: 2 }} />

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                Progress
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
                {Math.round(progressPercent)}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(accent, 0.1),
                "& .MuiLinearProgress-bar": {
                  bgcolor: accent,
                  borderRadius: 3,
                },
              }}
            />
          </Box>

          {/* Navigation List */}
          <List dense sx={{ mx: -1 }}>
            {sectionNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                  "&:hover": {
                    bgcolor: alpha(accent, 0.1),
                  },
                  transition: "all 0.2s ease",
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, fontSize: "1.1rem" }}>{item.icon}</ListItemIcon>
                <ListItemText
                  primary={
                    <Typography
                      variant="body2"
                      sx={{
                        fontWeight: activeSection === item.id ? 700 : 500,
                        color: activeSection === item.id ? accent : "text.primary",
                      }}
                    >
                      {item.label}
                    </Typography>
                  }
                />
                {activeSection === item.id && (
                  <Chip
                    label="Current"
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: "0.65rem",
                      bgcolor: alpha(accent, 0.2),
                      color: accent,
                    }}
                  />
                )}
              </ListItem>
            ))}
          </List>

          <Divider sx={{ my: 2 }} />

          {/* Quick Actions */}
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={scrollToTop}
              startIcon={<KeyboardArrowUpIcon />}
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

        <Box sx={{ flex: 1, minWidth: 0 }}>
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
                label="Learning Hub"
                size="small"
                clickable
                onClick={() => navigate("/learn")}
                sx={{
                  fontWeight: 700,
                  fontSize: "0.75rem",
                  bgcolor: alpha(accent, 0.1),
                  color: accent,
                  "&:hover": {
                    bgcolor: alpha(accent, 0.2),
                  },
                }}
              />
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.secondary" }}>
                Quick Navigation
              </Typography>
            </Box>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {[
                { label: "Overview", id: "intro" },
                { label: "Workflow", id: "workflow" },
                { label: "Telemetry", id: "telemetry" },
                { label: "Disposition", id: "disposition" },
                { label: "Escalation", id: "escalation" },
                { label: "Playbooks", id: "playbooks" },
                { label: "Queries", id: "siem-queries" },
                { label: "Scenarios", id: "triage-scenarios" },
                { label: "Quiz", id: "quiz" },
              ].map((nav) => (
                <Chip
                  key={nav.id}
                  label={nav.label}
                  size="small"
                  clickable
                  onClick={() => scrollToSection(nav.id)}
                  sx={{
                    fontWeight: 600,
                    fontSize: "0.75rem",
                    "&:hover": {
                      bgcolor: alpha(accent, 0.15),
                      color: accent,
                    },
                  }}
                />
              ))}
            </Box>
          </Paper>

        {/* Overview */}
        <Paper
          id="intro"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            scrollMarginTop: 180,
          }}
        >
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
        <Typography id="workflow" variant="h5" sx={{ fontWeight: 700, mb: 3, scrollMarginTop: 180 }}>
          Investigation Workflow
        </Typography>
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

        {/* Core Telemetry Sources */}
        <Typography id="telemetry" variant="h5" sx={{ fontWeight: 700, mb: 3, scrollMarginTop: 180 }}>
          Core Telemetry Sources
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {telemetrySources.map((source) => (
            <Grid item xs={12} md={6} key={source.source}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, border: `1px solid ${alpha(source.color, 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: source.color, mb: 1 }}>
                  {source.source}
                </Typography>
                <Typography variant="caption" sx={{ fontWeight: 700, color: alpha(source.color, 0.9), letterSpacing: 0.6 }}>
                  SIGNALS
                </Typography>
                <List dense sx={{ mb: 1 }}>
                  {source.signals.map((signal) => (
                    <ListItem key={signal} sx={{ py: 0, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 20 }}>
                        <CheckCircleIcon sx={{ fontSize: 14, color: source.color }} />
                      </ListItemIcon>
                      <ListItemText primary={signal} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
                <Typography variant="caption" sx={{ fontWeight: 700, color: alpha(source.color, 0.9), letterSpacing: 0.6 }}>
                  QUESTIONS TO ASK
                </Typography>
                <List dense>
                  {source.questions.map((question) => (
                    <ListItem key={question} sx={{ py: 0, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 20 }}>
                        <CheckCircleIcon sx={{ fontSize: 14, color: source.color }} />
                      </ListItemIcon>
                      <ListItemText primary={question} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          ))}
        </Grid>

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

        {/* Determination Guidance */}
        <Typography id="disposition" variant="h5" sx={{ fontWeight: 700, mb: 3, scrollMarginTop: 180 }}>
          Alert Disposition Rubric
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {dispositionGuidance.map((item) => (
            <Grid item xs={12} md={6} key={item.label}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.05) }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>
                  {item.label}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {item.criteria}
                </Typography>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  Action: {item.action}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Escalation and Containment */}
        <Typography id="escalation" variant="h5" sx={{ fontWeight: 700, mb: 3, scrollMarginTop: 180 }}>
          Escalation & Containment
        </Typography>
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

        {/* Escalation Packet */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#ef4444", 0.02) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <PriorityHighIcon sx={{ color: "#ef4444" }} /> Escalation Packet Checklist
          </Typography>
          <List dense>
            {escalationPacket.map((item, i) => (
              <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                </ListItemIcon>
                <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Documentation and Handoff */}
        <Typography id="documentation" variant="h5" sx={{ fontWeight: 700, mb: 3, scrollMarginTop: 180 }}>
          Documentation & Handoff
        </Typography>
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
        <Typography id="best-practices" variant="h5" sx={{ fontWeight: 700, mb: 3, scrollMarginTop: 180 }}>
          Best Practices & Tools
        </Typography>
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
        <Typography id="metrics" variant="h5" sx={{ fontWeight: 700, mb: 3, scrollMarginTop: 180 }}>
          Metrics & Pitfalls
        </Typography>
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
        <Typography id="lifecycle" variant="h5" sx={{ fontWeight: 700, mb: 3, scrollMarginTop: 180 }}>
          Alert Lifecycle
        </Typography>
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
        <Typography id="severity-sla" variant="h5" sx={{ fontWeight: 700, mb: 3, scrollMarginTop: 180 }}>
          Severity & SLA Guidance
        </Typography>
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
        <Typography id="playbooks" variant="h5" sx={{ fontWeight: 700, mb: 3, scrollMarginTop: 180 }}>
          Playbooks & Evidence
        </Typography>
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

        {/* Example SIEM Queries */}
        <Typography id="siem-queries" variant="h5" sx={{ fontWeight: 700, mb: 3, scrollMarginTop: 180 }}>
          Example SIEM Queries
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {exampleSiemQueries.map((q, i) => (
            <Grid item xs={12} md={6} key={i}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 0.5 }}>{q.scenario}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>{q.purpose}</Typography>
                <Box sx={{ p: 1.5, bgcolor: alpha("#000", 0.03), borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem", overflowX: "auto" }}>
                  {q.query}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Alert Type Playbooks */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>Alert Type Quick Playbooks</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {alertTypePlaybooks.map((playbook) => (
            <Grid item xs={12} md={4} key={playbook.type}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, border: `1px solid ${alpha(playbook.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: playbook.color, mb: 0.5 }}>
                  {playbook.type}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                  {playbook.focus}
                </Typography>
                <List dense>
                  {playbook.checks.map((check) => (
                    <ListItem key={check} sx={{ py: 0, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 20 }}>
                        <CheckCircleIcon sx={{ fontSize: 12, color: playbook.color }} />
                      </ListItemIcon>
                      <ListItemText primary={check} primaryTypographyProps={{ variant: "caption" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Triage Scenarios */}
        <Typography id="triage-scenarios" variant="h5" sx={{ fontWeight: 700, mb: 3, scrollMarginTop: 180 }}>
          Real-World Triage Scenarios
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {triageScenarios.map((s, i) => (
            <Grid item xs={12} md={4} key={i}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>{s.alert}</Typography>
                <List dense disablePadding sx={{ mb: 1.5 }}>
                  {s.steps.map((step, j) => (
                    <ListItem key={j} sx={{ py: 0, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 20 }}>
                        <CheckCircleIcon sx={{ fontSize: 12, color: "#8b5cf6" }} />
                      </ListItemIcon>
                      <ListItemText primary={step} primaryTypographyProps={{ variant: "caption" }} />
                    </ListItem>
                  ))}
                </List>
                <Chip label={s.outcome} size="small" sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981", fontSize: "0.7rem" }} />
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Detection Tuning Tips */}
        <Paper
          id="tuning"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#f59e0b", 0.03),
            scrollMarginTop: 180,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TrackChangesIcon sx={{ color: "#f59e0b" }} /> Detection Tuning Tips
          </Typography>
          <List dense>
            {tuningTips.map((item, i) => (
              <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                <ListItemIcon sx={{ minWidth: 28 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                </ListItemIcon>
                <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Detection Feedback Loop */}
        <Paper
          id="feedback-loop"
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#3b82f6", 0.03),
            scrollMarginTop: 180,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TrackChangesIcon sx={{ color: "#3b82f6" }} /> Detection Engineering Feedback Loop
          </Typography>
          <Grid container spacing={2}>
            {detectionFeedbackLoop.map((item, index) => (
              <Grid item xs={12} sm={6} md={4} key={item.step}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                    {index + 1}. {item.step}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {item.detail}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
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
        <Paper
          id="related"
          sx={{
            p: 3,
            borderRadius: 3,
            bgcolor: alpha(theme.palette.primary.main, 0.03),
            scrollMarginTop: 180,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📚 Related Learning</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="SIEM Fundamentals →" clickable onClick={() => navigate("/learn/siem")} sx={{ fontWeight: 600 }} />
            <Chip label="Threat Hunting →" clickable onClick={() => navigate("/learn/threat-hunting")} sx={{ fontWeight: 600 }} />
            <Chip label="Incident Response →" clickable onClick={() => navigate("/learn/incident-response")} sx={{ fontWeight: 600 }} />
          </Box>
        </Paper>

        <Paper
          id="quiz"
          sx={{
            mt: 4,
            p: 4,
            borderRadius: 3,
            border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`,
            scrollMarginTop: 180,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
            Knowledge Check
          </Typography>
          <QuizSection
            questions={quizQuestions}
            accentColor={QUIZ_ACCENT_COLOR}
            title="SOC Analyst Workflow Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
        </Paper>

          {/* Footer Navigation */}
          <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
            <Button
              variant="outlined"
              size="large"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{
                borderRadius: 2,
                px: 4,
                py: 1.5,
                fontWeight: 600,
                borderColor: alpha(accent, 0.3),
                color: accent,
                "&:hover": {
                  borderColor: accent,
                  bgcolor: alpha(accent, 0.05),
                },
              }}
            >
              Return to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
