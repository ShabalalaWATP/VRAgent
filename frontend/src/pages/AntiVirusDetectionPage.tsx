import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
  Typography,
  Paper,
  Tabs,
  Tab,
  Chip,
  Button,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import SecurityIcon from "@mui/icons-material/Security";
import ShieldIcon from "@mui/icons-material/Shield";
import BugReportIcon from "@mui/icons-material/BugReport";
import SearchIcon from "@mui/icons-material/Search";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import { useNavigate } from "react-router-dom";

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

const CodeBlock: React.FC<{ code: string; language?: string }> = ({
  code,
  language = "bash",
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper
      sx={{
        p: 2,
        bgcolor: "#121424",
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: "1px solid rgba(34, 197, 94, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#22c55e", color: "#0b1020" }} />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: "#e2e8f0" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          overflow: "auto",
          fontFamily: "monospace",
          fontSize: "0.85rem",
          color: "#e2e8f0",
          pt: 2,
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const AntiVirusDetectionPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `This page covers antivirus detection fundamentals for beginners. Topics include detection methods (signature-based, heuristic rules, behavior monitoring, reputation and cloud), understanding common alert types, detection signals and artifacts, and platform-specific checks for Windows Defender, Linux ClamAV, and macOS XProtect/Gatekeeper. The page covers telemetry sources, evidence capture, false positive handling, triage workflows, and when to escalate incidents. Key concepts include signatures, heuristics, behavior analysis, quarantine, and false positives/negatives.`;

  const beginnerObjectives = [
    "Explain what antivirus detection is in plain language.",
    "List the main detection methods: signatures, heuristics, behavior, and reputation.",
    "Identify the basic signals AV engines look for.",
    "Run safe, read-only status checks on a lab system.",
    "Write a short detection note with evidence and next steps.",
  ];
  const beginnerTerms = [
    { term: "Signature", desc: "A known pattern that matches previously identified malware." },
    { term: "Heuristic", desc: "A rule that looks for suspicious traits instead of exact matches." },
    { term: "Behavior", desc: "Actions at runtime such as injection, persistence, or credential access." },
    { term: "Quarantine", desc: "Isolating a file so it cannot run." },
    { term: "False positive", desc: "A safe file flagged as malicious." },
    { term: "False negative", desc: "A malicious file that is not detected." },
  ];

  const detectionMethods = [
    {
      title: "Signature-based",
      desc: "Matches known file patterns, hashes, or byte sequences.",
      strength: "Fast and accurate for known threats.",
      gap: "Misses new or modified malware.",
    },
    {
      title: "Heuristic rules",
      desc: "Flags suspicious structures or behaviors based on rules.",
      strength: "Good for new variants.",
      gap: "Can create false positives.",
    },
    {
      title: "Behavior monitoring",
      desc: "Watches runtime actions like process injection or registry changes.",
      strength: "Catches fileless or obfuscated threats.",
      gap: "Requires good telemetry and tuning.",
    },
    {
      title: "Reputation and cloud",
      desc: "Checks file reputation, prevalence, and cloud verdicts.",
      strength: "Fast response to emerging threats.",
      gap: "May not work offline or for new internal tools.",
    },
  ];
  const detectionPipeline = [
    "File appears on disk or is created by a process.",
    "AV scans the file against signatures and heuristics.",
    "If enabled, behavior monitoring watches what the process does.",
    "Cloud reputation checks determine if the file is known or new.",
    "Alert is generated with details for investigation.",
  ];
  const commonAlertTypes = [
    "Malware detected (known signature match).",
    "Suspicious behavior (script or macro abuse).",
    "PUA/PUA.PS (potentially unwanted application).",
    "Exploit behavior blocked (memory or injection attempts).",
    "Policy violation (blocked by allowlist or application control).",
  ];
  const beginnerQuestions = [
    "What file triggered the alert and where is it located?",
    "Which process launched it and which user ran it?",
    "Is the file signed and from a trusted vendor?",
    "Has this file appeared on other systems?",
    "What changed right before the alert (downloads, updates, email)?",
  ];
  const falsePositiveChecklist = [
    "Verify the file hash and vendor signature.",
    "Check the file origin (download source, internal build).",
    "See if the alert repeats after reboot or removal.",
    "Confirm if other security tools alert on the same file.",
    "If safe, add allowlist with approval and document why.",
  ];

  const signals = [
    "Unexpected child processes (office app spawning script engine).",
    "Executable running from user temp or downloads.",
    "Repeated registry or scheduled task changes.",
    "Suspicious network destinations or spikes in outbound traffic.",
    "Unsigned binaries or mismatched file hashes.",
  ];
  const telemetrySources = [
    "Process creation logs (with command line and parent).",
    "File creation and modification events.",
    "Security and application logs.",
    "Network connection logs (destination and ports).",
    "AV engine logs and quarantine events.",
  ];

  const artifacts = [
    "File path and hash (SHA-256)",
    "Command line arguments",
    "Parent process and process tree",
    "User account and logon session",
    "Timestamp and host context",
  ];
  const simpleScenario = [
    "User opens an email attachment.",
    "The attachment drops a new executable into the Downloads folder.",
    "AV flags the file based on signature and blocks execution.",
    "Analyst captures the hash, path, and user details.",
    "Incident response validates and checks if any other hosts saw it.",
  ];

  return (
    <LearnPageLayout pageTitle="Antivirus Detection" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="lg">
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2, color: "grey.400" }}>
          Back to Learn Hub
        </Button>

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <ShieldIcon sx={{ fontSize: 42, color: "#22c55e" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #22c55e 0%, #14b8a6 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Antivirus Detection
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          Antivirus detection is how security tools spot malware and risky activity on devices and servers.
        </Typography>
        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            In simple terms, antivirus tools are like security guards for your computer. They look at files and
            programs and try to decide if something is safe or risky. They do this by comparing files to known
            bad patterns, watching how programs behave, and checking reputation data.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            This page is a beginner-friendly guide to detection basics, safe checks you can run in a lab, and how
            to document what you find without disrupting systems.
          </Typography>
        </Paper>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<BugReportIcon />} label="Signatures" size="small" />
          <Chip icon={<SearchIcon />} label="Behavior" size="small" />
          <Chip icon={<SecurityIcon />} label="Reputation" size="small" />
          <Chip icon={<WarningIcon />} label="False Positives" size="small" />
        </Box>

        <Paper sx={{ bgcolor: "#111424", borderRadius: 2 }}>
          <Tabs
            value={tabValue}
            onChange={(_, v) => setTabValue(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              borderBottom: "1px solid rgba(255,255,255,0.08)",
              "& .MuiTab-root": { color: "grey.400" },
              "& .Mui-selected": { color: "#22c55e" },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Overview" />
            <Tab icon={<BugReportIcon />} label="Detection Methods" />
            <Tab icon={<ShieldIcon />} label="Signals and Artifacts" />
            <Tab icon={<SearchIcon />} label="Platform Checks" />
            <Tab icon={<WarningIcon />} label="Triage and Response" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 1 }}>
                  Beginner Objectives
                </Typography>
                <List dense>
                  {beginnerObjectives.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Quick Glossary
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Term</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Meaning</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {beginnerTerms.map((item) => (
                        <TableRow key={item.term}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.term}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Why Detection Matters
                </Typography>
                <List dense>
                  {[
                    "Endpoints are the first place malware appears.",
                    "Detection helps stop threats before they spread.",
                    "Good telemetry makes investigations faster and clearer.",
                    "Early alerts reduce downtime and data loss.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Basic Detection Flow
                </Typography>
                <List dense>
                  {detectionPipeline.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <TableContainer sx={{ mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: "#22c55e" }}>Method</TableCell>
                      <TableCell sx={{ color: "#22c55e" }}>What it does</TableCell>
                      <TableCell sx={{ color: "#22c55e" }}>Strength</TableCell>
                      <TableCell sx={{ color: "#22c55e" }}>Limit</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {detectionMethods.map((item) => (
                      <TableRow key={item.title}>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.title}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.strength}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.gap}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 1 }}>
                  Simple Example
                </Typography>
                <List dense>
                  {simpleScenario.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">False Positives and False Negatives</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "False positives happen when a safe file is flagged as malicious.",
                      "False negatives happen when malware is missed or allowed.",
                      "Use allowlists and tuning to reduce noise without lowering coverage.",
                      "Always validate alerts with additional evidence before taking action.",
                    ].map((item) => (
                      <ListItem key={item}>
                        <ListItemIcon>
                          <CheckCircleIcon color="warning" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 1 }}>
                  Common Detection Signals
                </Typography>
                <List dense>
                  {signals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 1 }}>
                  Common Alert Types
                </Typography>
                <List dense>
                  {commonAlertTypes.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Telemetry Sources to Check
                </Typography>
                <List dense>
                  {telemetrySources.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Evidence to Capture
                </Typography>
                <List dense>
                  {artifacts.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Windows Defender (Safe Checks)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="powershell"
                    code={`# Check Defender status
Get-MpComputerStatus

# View configuration (read-only)
Get-MpPreference

# Update signatures (safe on lab systems)
Update-MpSignature

# Run a quick scan (lab only)
Start-MpScan -ScanType QuickScan`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Linux (ClamAV Basics)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    code={`# Check ClamAV version
clamscan --version

# Scan a lab folder only
clamscan -r /path/to/lab-samples

# Update signatures (if configured)
freshclam`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">macOS (Basic Visibility)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    code={`# Check XProtect status (built-in protection)
defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString

# Gatekeeper status
spctl --status

# List system extensions (read-only)
systemextensionsctl list`}
                  />
                </AccordionDetails>
              </Accordion>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 1 }}>
                  Safe Baseline Checks
                </Typography>
                <List dense>
                  {[
                    "Confirm AV is enabled and signatures are current.",
                    "Check quarantine history for recent detections.",
                    "Validate scanning schedule and exclusions.",
                    "Record the tool version and last update time.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 1 }}>
                  Triage Workflow (Beginner Friendly)
                </Typography>
                <List dense>
                  {[
                    "Confirm alert details (host, user, process, file path).",
                    "Collect evidence: hash, command line, parent process.",
                    "Check if the file is known and signed by a trusted vendor.",
                    "Contain if needed: isolate host or stop the process.",
                    "Escalate to incident response with clear notes.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 1 }}>
                  Beginner Questions
                </Typography>
                <List dense>
                  {beginnerQuestions.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#22c55e", mb: 1 }}>
                  False Positive Checklist
                </Typography>
                <List dense>
                  {falsePositiveChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  When to Escalate
                </Typography>
                <List dense>
                  {[
                    "Multiple hosts showing the same alert.",
                    "Suspicious network connections or data exfiltration.",
                    "System files or privileged accounts involved.",
                    "Repeated detections after cleaning.",
                    "Any detection on production servers.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon sx={{ color: "#f59e0b" }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>
        </Paper>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#22c55e", color: "#22c55e" }}
          >
            Back to Learn Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default AntiVirusDetectionPage;
