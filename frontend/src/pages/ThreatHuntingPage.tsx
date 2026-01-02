import React from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
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
import QuizIcon from "@mui/icons-material/Quiz";
import { Link, useNavigate } from "react-router-dom";

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

const QUIZ_ACCENT_COLOR = "#8b5cf6";
const QUIZ_QUESTION_COUNT = 10;

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "Threat hunting is best described as:",
    options: [
      "Proactive search for adversaries that evaded controls",
      "Reactive alert triage only",
      "Patch management",
      "Vulnerability scanning",
    ],
    correctAnswer: 0,
    explanation: "Threat hunting assumes breach and searches for evidence proactively.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "Hunting is typically driven by:",
    options: ["A hypothesis", "A random query", "Only vendor alerts", "Compliance checklists"],
    correctAnswer: 0,
    explanation: "A hypothesis focuses the hunt on likely attacker behavior.",
  },
  {
    id: 3,
    topic: "Process",
    question: "The first phase of the hunting process is usually:",
    options: ["Hypothesis", "Findings", "Response", "Containment"],
    correctAnswer: 0,
    explanation: "Hunting starts by forming a hypothesis.",
  },
  {
    id: 4,
    topic: "Data Sources",
    question: "Which is a common hunting data source?",
    options: ["EDR telemetry", "BIOS settings", "Printer queues", "Game logs"],
    correctAnswer: 0,
    explanation: "EDR provides process, file, and network telemetry.",
  },
  {
    id: 5,
    topic: "Frameworks",
    question: "MITRE ATT&CK is used to:",
    options: ["Map adversary tactics and techniques", "Encrypt logs", "Patch systems", "Block all traffic"],
    correctAnswer: 0,
    explanation: "ATT&CK catalogs adversary behaviors for mapping and coverage.",
  },
  {
    id: 6,
    topic: "Frameworks",
    question: "The Pyramid of Pain helps prioritize:",
    options: ["Indicators that are harder for attackers to change", "Disk usage", "Patch schedules", "Cloud costs"],
    correctAnswer: 0,
    explanation: "Higher-level indicators like TTPs are harder to change.",
  },
  {
    id: 7,
    topic: "Frameworks",
    question: "The Cyber Kill Chain is used to:",
    options: ["Track stages of an intrusion", "Encrypt data", "Replace IDS", "Store keys"],
    correctAnswer: 0,
    explanation: "Kill Chain models adversary progression stages.",
  },
  {
    id: 8,
    topic: "Hunt Types",
    question: "Intel-driven hunts start from:",
    options: ["Threat intelligence or reports", "Random baselines", "Only dashboards", "Compliance requirements"],
    correctAnswer: 0,
    explanation: "Intel-driven hunts pivot from known campaigns or IOCs.",
  },
  {
    id: 9,
    topic: "Hunt Types",
    question: "Anomaly-driven hunts focus on:",
    options: ["Deviations from baselines", "Only signatures", "Only admin tools", "Only malware hashes"],
    correctAnswer: 0,
    explanation: "Anomaly hunts look for rare or unusual behavior.",
  },
  {
    id: 10,
    topic: "Hunt Types",
    question: "Threat-informed hunting uses:",
    options: ["Adversary TTPs", "Random queries", "Only antivirus alerts", "User surveys"],
    correctAnswer: 0,
    explanation: "Threat-informed hunts map known adversary behaviors.",
  },
  {
    id: 11,
    topic: "Hunt Types",
    question: "Model-driven hunts use:",
    options: ["Statistical or heuristic models", "Only blocklists", "Only IP allowlists", "Only IDS"],
    correctAnswer: 0,
    explanation: "Models can surface weak signals not caught by rules.",
  },
  {
    id: 12,
    topic: "Baselines",
    question: "A baseline is:",
    options: ["Normal activity profile", "A patch list", "A firewall rule", "A password policy"],
    correctAnswer: 0,
    explanation: "Baselines define expected behavior for comparison.",
  },
  {
    id: 13,
    topic: "Baselines",
    question: "Baselines should be refreshed:",
    options: ["After major changes", "Only once", "Never", "Only during incidents"],
    correctAnswer: 0,
    explanation: "Deployments and changes can shift normal behavior.",
  },
  {
    id: 14,
    topic: "Analysis",
    question: "Stacking analysis means:",
    options: ["Sorting by frequency to find rare events", "Encrypting logs", "Deleting duplicates", "Running malware"],
    correctAnswer: 0,
    explanation: "Stacking surfaces rare or unusual values.",
  },
  {
    id: 15,
    topic: "Analysis",
    question: "Temporal analysis is useful for:",
    options: ["Detecting beaconing or off-hours activity", "Increasing log size", "Changing passwords", "Resetting tokens"],
    correctAnswer: 0,
    explanation: "Time patterns reveal periodic or anomalous behavior.",
  },
  {
    id: 16,
    topic: "Analysis",
    question: "Parent-child process analysis helps detect:",
    options: ["Suspicious process lineage", "Disk failures", "DNS propagation", "User training"],
    correctAnswer: 0,
    explanation: "Unusual parent-child chains often indicate abuse.",
  },
  {
    id: 17,
    topic: "Analysis",
    question: "Peer grouping compares:",
    options: ["Users or hosts against similar peers", "Only admins", "Only servers", "Only desktops"],
    correctAnswer: 0,
    explanation: "Peer grouping highlights outliers within similar groups.",
  },
  {
    id: 18,
    topic: "Analysis",
    question: "Graph pivots are used to:",
    options: ["Link users, hosts, IPs, and hashes", "Compress logs", "Disable alerts", "Rotate keys"],
    correctAnswer: 0,
    explanation: "Graph pivots connect related entities for investigation.",
  },
  {
    id: 19,
    topic: "Outputs",
    question: "A strong hunt output is:",
    options: ["New detections or rules", "A larger dashboard", "More false positives", "No documentation"],
    correctAnswer: 0,
    explanation: "Hunts should produce detections or improvements.",
  },
  {
    id: 20,
    topic: "Outputs",
    question: "Hunt findings should be:",
    options: ["Documented with evidence", "Kept informal", "Deleted after review", "Only verbal"],
    correctAnswer: 0,
    explanation: "Documentation supports response and future hunts.",
  },
  {
    id: 21,
    topic: "Metrics",
    question: "A useful hunting metric is:",
    options: ["Percent of hypotheses converted to detections", "Number of keyboards", "Printer uptime", "Wallpaper changes"],
    correctAnswer: 0,
    explanation: "Conversion rate shows impact of hunts.",
  },
  {
    id: 22,
    topic: "Metrics",
    question: "Mean time to validate a hypothesis measures:",
    options: ["Hunt efficiency", "Patch speed", "Password strength", "Log retention"],
    correctAnswer: 0,
    explanation: "Shorter validation times indicate efficient workflows.",
  },
  {
    id: 23,
    topic: "Pitfalls",
    question: "A common hunting pitfall is:",
    options: ["Skipping documentation", "Using hypotheses", "Validating findings", "Building baselines"],
    correctAnswer: 0,
    explanation: "Documentation is required even when no threats are found.",
  },
  {
    id: 24,
    topic: "Pitfalls",
    question: "Ignoring data quality issues can lead to:",
    options: ["False conclusions", "Stronger detections", "More coverage", "Less noise"],
    correctAnswer: 0,
    explanation: "Missing fields and time drift can mislead hunts.",
  },
  {
    id: 25,
    topic: "Threats",
    question: "Living off the land refers to:",
    options: ["Abusing built-in tools", "Using only malware", "External pentests", "Hardware attacks"],
    correctAnswer: 0,
    explanation: "Attackers use legitimate tools to blend in.",
  },
  {
    id: 26,
    topic: "Threats",
    question: "Lateral movement is:",
    options: ["Moving between systems in a network", "Updating patches", "Changing passwords", "Blocking ports"],
    correctAnswer: 0,
    explanation: "Lateral movement spreads access across hosts.",
  },
  {
    id: 27,
    topic: "Threats",
    question: "Credential access often targets:",
    options: ["Password hashes or tickets", "DNS zones", "Hardware inventory", "User training"],
    correctAnswer: 0,
    explanation: "Credential access seeks secrets and authentication material.",
  },
  {
    id: 28,
    topic: "Threats",
    question: "Data staging refers to:",
    options: ["Collecting data before exfiltration", "Applying patches", "Creating baselines", "Resetting logs"],
    correctAnswer: 0,
    explanation: "Attackers often aggregate data before exfil.",
  },
  {
    id: 29,
    topic: "Threats",
    question: "C2 beaconing is identified by:",
    options: ["Regular periodic network traffic", "Random printer usage", "Patch downloads", "User logouts"],
    correctAnswer: 0,
    explanation: "Beacons often have periodic timing patterns.",
  },
  {
    id: 30,
    topic: "ATT&CK",
    question: "A MITRE technique ID looks like:",
    options: ["T1059", "CVE-2023-1234", "RFC1918", "ISO-27001"],
    correctAnswer: 0,
    explanation: "ATT&CK techniques are labeled T####.",
  },
  {
    id: 31,
    topic: "IOCs",
    question: "IOC stands for:",
    options: ["Indicator of Compromise", "Internal Operations Checklist", "Input Output Cache", "Incident Order Code"],
    correctAnswer: 0,
    explanation: "IOCs are indicators of compromise.",
  },
  {
    id: 32,
    topic: "TTPs",
    question: "TTP stands for:",
    options: ["Tactics, Techniques, and Procedures", "Tools, Tokens, and Policies", "Trends, Threats, and Plans", "Tests, Targets, and Proofs"],
    correctAnswer: 0,
    explanation: "TTPs describe how adversaries operate.",
  },
  {
    id: 33,
    topic: "Pyramid",
    question: "The hardest indicator for an attacker to change is:",
    options: ["TTPs", "File hashes", "IP addresses", "Domain names"],
    correctAnswer: 0,
    explanation: "TTPs are most painful for attackers to change.",
  },
  {
    id: 34,
    topic: "Hunt Cards",
    question: "A hunt card should include:",
    options: ["Hypothesis and data sources", "Only a title", "Only a metric", "Only a ticket ID"],
    correctAnswer: 0,
    explanation: "Hunt cards document scope, data, and outcomes.",
  },
  {
    id: 35,
    topic: "Process",
    question: "After investigation, the next phase is:",
    options: ["Findings", "Hypothesis", "Baseline", "Change control"],
    correctAnswer: 0,
    explanation: "Findings document evidence discovered.",
  },
  {
    id: 36,
    topic: "Process",
    question: "Response in hunting typically means:",
    options: ["Escalate to IR and create detections", "Ignore results", "Disable logging", "Delete data"],
    correctAnswer: 0,
    explanation: "Response turns findings into action and detections.",
  },
  {
    id: 37,
    topic: "Sources",
    question: "Threat intel reports are useful for:",
    options: ["Generating hypotheses", "Replacing logging", "Disabling alerts", "Avoiding baselines"],
    correctAnswer: 0,
    explanation: "Threat intel informs what to hunt for.",
  },
  {
    id: 38,
    topic: "Sources",
    question: "Post-incident reviews can provide:",
    options: ["Hunting hypotheses and gaps", "Only compliance data", "Only asset lists", "Only patch notes"],
    correctAnswer: 0,
    explanation: "Incidents reveal gaps and patterns to hunt.",
  },
  {
    id: 39,
    topic: "Sources",
    question: "Red team exercises help by:",
    options: ["Identifying detection gaps", "Replacing SIEM", "Removing alerts", "Avoiding documentation"],
    correctAnswer: 0,
    explanation: "Red team activity reveals gaps in visibility.",
  },
  {
    id: 40,
    topic: "Analysis",
    question: "Rare parent-child process pairs often indicate:",
    options: ["Abuse of LOLBins", "Normal admin tasks", "Routine patching", "User training"],
    correctAnswer: 0,
    explanation: "Unusual lineage can indicate living-off-the-land.",
  },
  {
    id: 41,
    topic: "Analysis",
    question: "Command line analysis helps detect:",
    options: ["Encoded or suspicious arguments", "CPU overheating", "Disk failures", "Browser versions"],
    correctAnswer: 0,
    explanation: "Command lines can reveal obfuscation or abuse.",
  },
  {
    id: 42,
    topic: "Analysis",
    question: "Off-hours logins are:",
    options: ["Potential anomalies to investigate", "Always benign", "Always blocked", "Irrelevant"],
    correctAnswer: 0,
    explanation: "Off-hours activity can indicate suspicious access.",
  },
  {
    id: 43,
    topic: "Analysis",
    question: "Beaconing often shows:",
    options: ["Consistent periodic connections", "Only one-time spikes", "No network traffic", "Random crashes"],
    correctAnswer: 0,
    explanation: "C2 traffic often appears periodic.",
  },
  {
    id: 44,
    topic: "Outputs",
    question: "A key hunt output is:",
    options: ["Telemetry gap identification", "A new logo", "Fewer logs", "Lower retention"],
    correctAnswer: 0,
    explanation: "Hunts can reveal missing data sources.",
  },
  {
    id: 45,
    topic: "Outputs",
    question: "Another valuable output is:",
    options: ["Hardening recommendations", "More dashboards", "Fewer queries", "Larger tickets"],
    correctAnswer: 0,
    explanation: "Hunts should improve security posture.",
  },
  {
    id: 46,
    topic: "Metrics",
    question: "False positive rate should:",
    options: ["Be tracked and reduced", "Be ignored", "Be maximized", "Be constant"],
    correctAnswer: 0,
    explanation: "Reducing false positives improves signal quality.",
  },
  {
    id: 47,
    topic: "Metrics",
    question: "Telemetry coverage vs ATT&CK helps:",
    options: ["Identify coverage gaps", "Disable controls", "Hide detections", "Reduce logging"],
    correctAnswer: 0,
    explanation: "Mapping shows which techniques lack visibility.",
  },
  {
    id: 48,
    topic: "Baselines",
    question: "Baselines should be segmented by:",
    options: ["Role or system type", "Random selection", "Only servers", "Only users"],
    correctAnswer: 0,
    explanation: "Different roles have different normal behavior.",
  },
  {
    id: 49,
    topic: "Fundamentals",
    question: "Threat hunting assumes:",
    options: ["Breach is possible or present", "No threats exist", "Only malware matters", "Only alerts matter"],
    correctAnswer: 0,
    explanation: "Hunting assumes threats may be present.",
  },
  {
    id: 50,
    topic: "Process",
    question: "Findings should include:",
    options: ["Evidence and context", "Only a guess", "Only screenshots", "No timestamps"],
    correctAnswer: 0,
    explanation: "Evidence supports escalation and response.",
  },
  {
    id: 51,
    topic: "Hunt Types",
    question: "Threat-informed hunts often start with:",
    options: ["Known adversary behaviors", "Printer logs", "Random errors", "Backup jobs"],
    correctAnswer: 0,
    explanation: "Threat-informed hunts map behaviors to telemetry.",
  },
  {
    id: 52,
    topic: "Sources",
    question: "New SaaS rollouts can introduce:",
    options: ["New hypotheses and data sources", "No new risk", "Fewer logs", "No telemetry"],
    correctAnswer: 0,
    explanation: "New systems introduce new attack surface and telemetry.",
  },
  {
    id: 53,
    topic: "Data Sources",
    question: "NetFlow and PCAP are examples of:",
    options: ["Network telemetry", "Endpoint EDR", "Email gateways", "Asset inventory"],
    correctAnswer: 0,
    explanation: "NetFlow and PCAP provide network visibility.",
  },
  {
    id: 54,
    topic: "Data Sources",
    question: "Cloud audit logs help detect:",
    options: ["Configuration and access changes", "Printer usage", "User passwords", "Disk wear"],
    correctAnswer: 0,
    explanation: "Cloud logs show API calls and configuration changes.",
  },
  {
    id: 55,
    topic: "Analysis",
    question: "Entropy analysis can indicate:",
    options: ["Encoded or obfuscated payloads", "User training", "Patch levels", "DNS latency"],
    correctAnswer: 0,
    explanation: "High entropy often signals encoding or encryption.",
  },
  {
    id: 56,
    topic: "Analysis",
    question: "Hunt queries should be:",
    options: ["Iterative and refined", "One and done", "Copied blindly", "Hidden"],
    correctAnswer: 0,
    explanation: "Hunts improve through iterative refinement.",
  },
  {
    id: 57,
    topic: "Outputs",
    question: "Hunt outputs should be shared with:",
    options: ["Detection engineering and IR", "Only the hunter", "Only HR", "Only vendors"],
    correctAnswer: 0,
    explanation: "Sharing improves detection and response.",
  },
  {
    id: 58,
    topic: "Pitfalls",
    question: "Hunting without a scoped hypothesis leads to:",
    options: ["Unfocused results", "Better detections", "Less noise", "Faster response"],
    correctAnswer: 0,
    explanation: "Scope and success criteria are critical.",
  },
  {
    id: 59,
    topic: "Process",
    question: "A hunt should end with:",
    options: ["Documented outcomes and follow-ups", "Deleted notes", "No reporting", "Only dashboards"],
    correctAnswer: 0,
    explanation: "Outcomes and actions should be recorded.",
  },
  {
    id: 60,
    topic: "Frameworks",
    question: "PEAK is a framework for:",
    options: ["Structured hypothesis hunting", "Patch management", "Encryption", "Asset tracking"],
    correctAnswer: 0,
    explanation: "PEAK guides structured threat hunting.",
  },
  {
    id: 61,
    topic: "Frameworks",
    question: "The Pyramid of Pain prioritizes:",
    options: ["Higher impact indicators", "Longer passwords", "More dashboards", "More alerts"],
    correctAnswer: 0,
    explanation: "Higher levels are more disruptive to adversaries.",
  },
  {
    id: 62,
    topic: "Metrics",
    question: "Time from hunt finding to remediation measures:",
    options: ["Response efficiency", "Patch complexity", "User satisfaction", "Disk usage"],
    correctAnswer: 0,
    explanation: "It indicates how quickly findings are addressed.",
  },
  {
    id: 63,
    topic: "Threats",
    question: "Credential dumping maps to ATT&CK technique:",
    options: ["T1003", "T1041", "T1071", "T1105"],
    correctAnswer: 0,
    explanation: "T1003 covers OS credential dumping.",
  },
  {
    id: 64,
    topic: "Threats",
    question: "Scheduled task persistence maps to:",
    options: ["T1053", "T1021", "T1566", "T1047"],
    correctAnswer: 0,
    explanation: "T1053 covers scheduled task/job persistence.",
  },
  {
    id: 65,
    topic: "Threats",
    question: "Living off the land binaries map to:",
    options: ["T1218", "T1041", "T1190", "T1105"],
    correctAnswer: 0,
    explanation: "T1218 covers signed binary proxy execution.",
  },
  {
    id: 66,
    topic: "Threats",
    question: "C2 over web protocols maps to:",
    options: ["T1071", "T1027", "T1082", "T1112"],
    correctAnswer: 0,
    explanation: "T1071 covers application layer protocols.",
  },
  {
    id: 67,
    topic: "Hunt Cards",
    question: "Expected vs. suspicious signals help:",
    options: ["Define decision points", "Hide findings", "Avoid analysis", "Skip validation"],
    correctAnswer: 0,
    explanation: "Clear expectations guide investigation decisions.",
  },
  {
    id: 68,
    topic: "Data Sources",
    question: "SIEM logs are most useful for:",
    options: ["Aggregated security events", "Rendering UI", "Running backups", "Compiling code"],
    correctAnswer: 0,
    explanation: "SIEMs aggregate and correlate security logs.",
  },
  {
    id: 69,
    topic: "Analysis",
    question: "Beaconing detection often uses:",
    options: ["Regular interval analysis", "File hashes only", "User training", "Static allowlists"],
    correctAnswer: 0,
    explanation: "Periodic intervals suggest beaconing.",
  },
  {
    id: 70,
    topic: "Data Quality",
    question: "Time drift across sources can cause:",
    options: ["Misaligned timelines", "Better detection", "Fewer logs", "Faster queries"],
    correctAnswer: 0,
    explanation: "Clock drift disrupts event correlation.",
  },
  {
    id: 71,
    topic: "Outputs",
    question: "A validated IOC should include:",
    options: ["Context and source", "Only a hash", "No timestamps", "No evidence"],
    correctAnswer: 0,
    explanation: "Context makes indicators actionable.",
  },
  {
    id: 72,
    topic: "Fundamentals",
    question: "Hunting differs from detection because it is:",
    options: ["Proactive and exploratory", "Automated and reactive", "Only signature-based", "Vendor-driven"],
    correctAnswer: 0,
    explanation: "Hunting explores beyond existing detections.",
  },
  {
    id: 73,
    topic: "Process",
    question: "After response, teams should:",
    options: ["Update detections and share intel", "Delete data", "Stop logging", "Ignore findings"],
    correctAnswer: 0,
    explanation: "Sharing and improving detections closes the loop.",
  },
  {
    id: 74,
    topic: "Baselines",
    question: "Segmenting baselines by role helps:",
    options: ["Reduce false positives", "Increase noise", "Hide anomalies", "Remove telemetry"],
    correctAnswer: 0,
    explanation: "Role-specific baselines improve accuracy.",
  },
  {
    id: 75,
    topic: "Pitfalls",
    question: "Failing to validate findings can lead to:",
    options: ["False positives and wasted effort", "Better detections", "Higher coverage", "Improved baselines"],
    correctAnswer: 0,
    explanation: "Validation is required before escalation.",
  },
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

        <Paper
          id="quiz-section"
          sx={{
            mt: 4,
            p: 4,
            borderRadius: 3,
            border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
            Knowledge Check
          </Typography>
          <QuizSection
            questions={quizQuestions}
            accentColor={QUIZ_ACCENT_COLOR}
            title="Threat Hunting Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
        </Paper>

        {/* Bottom Navigation */}
        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
          >
            Back to Learning Hub
          </Button>
        </Box>
      </Container>
    </LearnPageLayout>
  );
}
