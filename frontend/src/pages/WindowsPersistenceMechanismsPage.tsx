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
import AutorenewIcon from "@mui/icons-material/Autorenew";
import StorageIcon from "@mui/icons-material/Storage";
import BuildIcon from "@mui/icons-material/Build";
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
  language = "powershell",
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
        border: "1px solid rgba(59, 130, 246, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#3b82f6", color: "#0b1020" }} />
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

const WindowsPersistenceMechanismsPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `This page covers Windows persistence mechanisms used by attackers to maintain access after initial compromise. Categories include Registry Run Keys, Scheduled Tasks, Services, Startup Folders, WMI Event Subscriptions, Winlogon and LSA, Logon Scripts and GPO, and AppInit/DLL Search Order hijacking. Common locations covered: HKCU/HKLM Run keys, Task Scheduler Library, Windows Services, Startup folders, WMI EventFilter/Consumer, Winlogon shell/userinit, and AppInit_DLLs. The page includes detection signals, useful Windows Event IDs (4688, 4697, 4698, 7045, Sysmon 1/13), hardening checklists, safe enumeration commands, and beginner lab exercises.`;

  const objectives = [
    "Explain persistence in plain language and why it matters.",
    "List the most common Windows persistence locations.",
    "Safely enumerate persistence artifacts in a lab.",
    "Recognize basic detection signals and logs.",
    "Document findings with clear evidence and fixes.",
  ];
  const beginnerPath = [
    "1) Read the glossary so the terms make sense.",
    "2) Identify the main persistence categories (Run keys, services, tasks).",
    "3) Run the safe commands and save outputs to a notes file.",
    "4) Pick one artifact and explain why it is expected or suspicious.",
    "5) Write a short recommendation or detection idea.",
  ];
  const misconceptions = [
    {
      myth: "Persistence always means malware is installed.",
      reality: "Attackers can use legitimate Windows features to stay resident.",
    },
    {
      myth: "Disabling one tool stops persistence.",
      reality: "There are many persistence methods, so layered controls matter.",
    },
    {
      myth: "If it is in the registry, it is malicious.",
      reality: "Most Run keys are legitimate; context and location matter.",
    },
  ];

  const glossary = [
    { term: "Persistence", desc: "How an attacker stays on a system after initial access." },
    { term: "Run key", desc: "Registry locations that launch programs at user logon." },
    { term: "Service", desc: "Background process that starts with Windows or on demand." },
    { term: "Scheduled task", desc: "A job that runs on a schedule or trigger." },
    { term: "Startup folder", desc: "Folder that launches shortcuts at login." },
    { term: "WMI event", desc: "Automation trigger that can run scripts on events." },
  ];

  const persistenceCategories = [
    {
      title: "Registry Run Keys",
      desc: "Programs configured to start when a user logs in.",
      examples: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    },
    {
      title: "Scheduled Tasks",
      desc: "Jobs that run at logon, startup, or on a timer.",
      examples: "Task Scheduler library",
    },
    {
      title: "Services",
      desc: "Background services that start with Windows.",
      examples: "Service Control Manager",
    },
    {
      title: "Startup Folders",
      desc: "Shortcuts or scripts that run at logon.",
      examples: "Startup folder (All Users or User)",
    },
    {
      title: "WMI Event Subscriptions",
      desc: "Event-based triggers that run scripts or commands.",
      examples: "Permanent event subscriptions",
    },
    {
      title: "Winlogon and LSA",
      desc: "Authentication and logon components that can be extended.",
      examples: "Winlogon notify, LSA providers",
    },
    {
      title: "Logon Scripts and GPO",
      desc: "Scripts configured by policy or local settings at logon.",
      examples: "User logon scripts, Group Policy",
    },
    {
      title: "AppInit and DLL Search Order",
      desc: "DLL loading behavior that can run code in trusted processes.",
      examples: "AppInit_DLLs, hijacked DLL names",
    },
  ];

  const commonLocations = [
    {
      location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      purpose: "Run at current user logon",
      signal: "New entries pointing to user-writable paths",
    },
    {
      location: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      purpose: "Run at system logon",
      signal: "Unsigned binaries in system-wide keys",
    },
    {
      location: "HKLM\\System\\CurrentControlSet\\Services",
      purpose: "Windows services",
      signal: "New services with odd display names or paths",
    },
    {
      location: "Task Scheduler Library",
      purpose: "Scheduled tasks",
      signal: "Tasks created by non-admin users",
    },
    {
      location: "Startup Folders",
      purpose: "Logon startup shortcuts",
      signal: "Shortcuts pointing to temp directories",
    },
    {
      location: "WMI\\EventFilter / Consumer",
      purpose: "WMI persistence",
      signal: "Filters and consumers created recently",
    },
    {
      location: "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
      purpose: "Winlogon extensions",
      signal: "Unexpected shell or userinit values",
    },
    {
      location: "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
      purpose: "AppInit DLL loading",
      signal: "Non-Microsoft DLLs in AppInit",
    },
  ];

  const detectionSignals = [
    "New scheduled task with an unusual name or trigger.",
    "Service binary stored in a user profile or temp folder.",
    "Run key entry pointing to a script in Downloads.",
    "WMI subscriptions created by standard user accounts.",
    "Startup shortcuts with non-standard targets.",
    "Winlogon shell or userinit values modified.",
    "AppInit_DLLs populated with non-standard DLLs.",
    "Logon scripts added outside of admin change windows.",
  ];

  const evidenceChecklist = [
    "Full path to the binary or script",
    "Registry key and value name (if applicable)",
    "Task or service name and creation time",
    "Parent process and user account",
    "File hash and signature status",
  ];
  const hardeningChecklist = [
    "Enable process creation logging with command-line capture.",
    "Use application control (AppLocker or WDAC) for high-risk binaries.",
    "Review scheduled tasks and services for least privilege.",
    "Limit local admin usage and monitor privileged group changes.",
    "Harden PowerShell with constrained language where possible.",
  ];
  const eventIds = [
    "4688 - Process creation (Security log)",
    "4697 - Service installed (Security log)",
    "4698 - Scheduled task created (Security log)",
    "4699 - Scheduled task deleted (Security log)",
    "7045 - Service created (System log)",
    "13 - Registry value set (Sysmon)",
    "1 - Process creation (Sysmon)",
  ];
  const reportTemplate = `Host: <name>  Date: <utc>
Artifact type: <Run key / Task / Service / WMI>
Location: <path or registry key>
Value or name: <value>
Binary path: <path>
Signature: <signed/unsigned>
Observed by: <command used>
Why it matters: <risk or policy note>
Recommendation: <remove, restrict, allowlist, monitor>`;

  return (
    <LearnPageLayout pageTitle="Windows Persistence Mechanisms" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="lg">
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2, color: "grey.400" }}>
          Back to Learn Hub
        </Button>

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <AutorenewIcon sx={{ fontSize: 42, color: "#3b82f6" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #3b82f6 0%, #60a5fa 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Windows Persistence Mechanisms
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          Persistence is how attackers make sure they can get back into a system after the first compromise.
        </Typography>
        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            In simple terms, persistence means "staying put." If someone gains access to a Windows machine, they may
            add a task, service, or registry entry so their code runs again after reboot or logon. This page shows
            the common places those settings live and how to safely check them in a lab.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
            Think of persistence like leaving a key under the doormat. It is not always obvious, and sometimes it
            uses normal Windows features. Learning where those features are configured helps you spot risks quickly.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            You will learn the main persistence locations, how to list them safely, and what signals to watch for.
            Everything here focuses on read-only inspection and documentation.
          </Typography>
        </Paper>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<SecurityIcon />} label="Registry" size="small" />
          <Chip icon={<StorageIcon />} label="Services" size="small" />
          <Chip icon={<SearchIcon />} label="Scheduled Tasks" size="small" />
          <Chip icon={<BuildIcon />} label="Detection" size="small" />
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
              "& .Mui-selected": { color: "#3b82f6" },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Overview" />
            <Tab icon={<StorageIcon />} label="Categories" />
            <Tab icon={<SearchIcon />} label="Common Locations" />
            <Tab icon={<BuildIcon />} label="Detection and Logs" />
            <Tab icon={<WarningIcon />} label="Beginner Lab" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Learning Objectives
                </Typography>
                <List dense>
                  {objectives.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Beginner Path
                </Typography>
                <List dense>
                  {beginnerPath.map((item) => (
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
                      {glossary.map((item) => (
                        <TableRow key={item.term}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.term}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Common Misconceptions
                </Typography>
                <Grid container spacing={2}>
                  {misconceptions.map((item) => (
                    <Grid item xs={12} md={4} key={item.myth}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: "#0b1020",
                          borderRadius: 2,
                          border: "1px solid rgba(59,130,246,0.3)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1 }}>
                          Myth
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>
                          {item.myth}
                        </Typography>
                        <Typography variant="subtitle2" sx={{ color: "#a5b4fc", mb: 0.5 }}>
                          Reality
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>
                          {item.reality}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Why Persistence Matters
                </Typography>
                <List dense>
                  {[
                    "It lets attackers survive reboots and user logouts.",
                    "It is a common step after initial access.",
                    "It often relies on legitimate Windows features.",
                    "Detection depends on knowing where to look.",
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
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Grid container spacing={2}>
                {persistenceCategories.map((item) => (
                  <Grid item xs={12} md={6} key={item.title}>
                    <Paper
                      sx={{
                        p: 2,
                        bgcolor: "#0c0f1c",
                        borderRadius: 2,
                        border: "1px solid rgba(59,130,246,0.2)",
                        height: "100%",
                      }}
                    >
                      <Typography variant="subtitle1" sx={{ color: "#e2e8f0", fontWeight: 600 }}>
                        {item.title}
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                        {item.desc}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "grey.500" }}>
                        Example: {item.examples}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <TableContainer sx={{ mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: "#3b82f6" }}>Location</TableCell>
                      <TableCell sx={{ color: "#3b82f6" }}>Purpose</TableCell>
                      <TableCell sx={{ color: "#3b82f6" }}>Red Flag Signal</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {commonLocations.map((item) => (
                      <TableRow key={item.location}>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.location}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.purpose}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.signal}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Safe Enumeration Commands</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    code={`# Registry Run keys
reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

# Scheduled tasks (read-only)
schtasks /query /fo LIST /v
Get-ScheduledTask | Select-Object TaskName, TaskPath, State

# Services (read-only)
sc query type= service state= all
Get-Service | Select-Object Name, Status, StartType

# Startup folders (read-only)
dir "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
dir "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"

# WMI subscriptions (read-only)
Get-WmiObject -Namespace root\\subscription -Class __EventFilter
Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer`}
                    language="powershell"
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Command Cheat Sheet</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#3b82f6" }}>Command</TableCell>
                          <TableCell sx={{ color: "#3b82f6" }}>What it tells you</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["reg query ...\\Run", "Lists programs that run at user logon."],
                          ["schtasks /query", "Shows scheduled tasks and triggers."],
                          ["sc query", "Lists services and their status."],
                          ["dir Startup", "Shows startup shortcuts or scripts."],
                          ["Get-WmiObject root\\subscription", "Finds WMI persistence artifacts."],
                        ].map(([cmd, desc]) => (
                          <TableRow key={cmd}>
                            <TableCell sx={{ color: "grey.200", fontFamily: "monospace" }}>{cmd}</TableCell>
                            <TableCell sx={{ color: "grey.400" }}>{desc}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Detection Signals
                </Typography>
                <List dense>
                  {detectionSignals.map((item) => (
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
                  Useful Windows Event IDs
                </Typography>
                <List dense>
                  {eventIds.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Hardening Checklist
                </Typography>
                <List dense>
                  {hardeningChecklist.map((item) => (
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
                  Evidence Checklist
                </Typography>
                <List dense>
                  {evidenceChecklist.map((item) => (
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
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Beginner Lab Walkthrough (Read-only)
                </Typography>
                <List dense>
                  {[
                    "Use a Windows lab VM or test system you own.",
                    "Run the safe enumeration commands and save outputs.",
                    "Pick one task, one service, and one run key entry to document.",
                    "Check file paths and signatures for each item.",
                    "Write a short report with screenshots and recommendations.",
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

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Report Template</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock language="text" code={reportTemplate} />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>
        </Paper>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#3b82f6", color: "#3b82f6" }}
          >
            Back to Learn Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default WindowsPersistenceMechanismsPage;
