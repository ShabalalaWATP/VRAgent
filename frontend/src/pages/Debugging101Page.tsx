import React, { useState } from "react";
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
  Alert,
  AlertTitle,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import ShieldIcon from "@mui/icons-material/Shield";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SearchIcon from "@mui/icons-material/Search";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import MemoryIcon from "@mui/icons-material/Memory";
import TuneIcon from "@mui/icons-material/Tune";
import { useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";

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
        bgcolor: "#101626",
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

const Debugging101Page: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const objectives = [
    "Explain what a debugger is and why it is useful.",
    "Teach core debugging concepts: breakpoints, stepping, and inspection.",
    "Show a repeatable workflow for finding bugs.",
    "Introduce memory, stack, and register basics.",
    "Provide safe, beginner-friendly practice steps.",
  ];
  const beginnerPath = [
    "1) Read the beginner explanation and glossary.",
    "2) Learn how breakpoints and stepping work.",
    "3) Practice inspecting variables, stack, and registers.",
    "4) Use the workflow checklist for a sample bug.",
    "5) Record findings and verify the fix.",
  ];
  const keyIdeas = [
    "A debugger pauses a program so you can see what it is doing.",
    "Breakpoints let you stop at exact lines or functions.",
    "Stepping moves through code one instruction or line at a time.",
    "Inspecting variables and memory reveals the real state, not guesses.",
  ];
  const glossary = [
    { term: "Breakpoint", desc: "A stop point in code where execution pauses." },
    { term: "Step over", desc: "Run the current line without entering a function." },
    { term: "Step into", desc: "Enter a function call to debug inside it." },
    { term: "Stack", desc: "Memory used for function calls and local variables." },
    { term: "Register", desc: "Small, fast CPU storage for current operations." },
    { term: "Watchpoint", desc: "Pause when a variable or memory address changes." },
  ];
  const misconceptions = [
    {
      myth: "Debuggers are only for experts.",
      reality: "Basic debugging is a beginner skill that saves hours.",
    },
    {
      myth: "Print statements are always enough.",
      reality: "Debuggers show real state without code changes.",
    },
    {
      myth: "Debugging is just stepping line by line.",
      reality: "Good debugging is a workflow: reproduce, isolate, verify.",
    },
  ];
  const mindsetHabits = [
    "Observe before changing anything. The first state is often the most honest.",
    "Work backward from the symptom to the first wrong value.",
    "Change one thing at a time so you can trust the result.",
    "Write down what you expected and what you saw.",
    "If stuck, reduce the input or shorten the path.",
  ];
  const reproducibilityTips = [
    "Record exact inputs, flags, and environment variables.",
    "Control randomness with fixed seeds or deterministic data.",
    "Use smaller datasets to shorten the path.",
    "Keep the binary and source version in sync.",
    "Confirm the bug still exists after each change.",
  ];
  const bugTypeMap = [
    {
      type: "Logic error",
      signals: "Wrong output, failed assertions",
      approach: "Trace decisions and invariants",
    },
    {
      type: "State corruption",
      signals: "Values flip or drift",
      approach: "Watchpoints, compare before/after",
    },
    {
      type: "Boundary error",
      signals: "Crashes or off-by-one results",
      approach: "Check indexes and sizes",
    },
    {
      type: "Timing issue",
      signals: "Flaky or order-dependent behavior",
      approach: "Trace ordering and add delays",
    },
    {
      type: "Configuration",
      signals: "Works on one machine only",
      approach: "Diff env vars, versions, flags",
    },
  ];
  const signalNoiseTips = [
    "Look for the first error or warning, not the last.",
    "Align logs with debugger steps using timestamps.",
    "Prefer debugger state over printed output.",
    "Ignore unrelated warnings until the main failure is fixed.",
  ];

  const howDebuggingWorks = [
    "The debugger attaches to a program and can pause execution.",
    "It reads memory and CPU registers to show current state.",
    "Breakpoints stop execution at specific places.",
    "Stepping runs code in small controlled steps.",
    "You can inspect or change values to test hypotheses.",
  ];
  const workflow = [
    "Reproduce the bug reliably with a known input.",
    "Set a breakpoint near the suspected area.",
    "Step through and watch how values change.",
    "Identify the first point where state goes wrong.",
    "Fix the bug and verify with the same steps.",
  ];
  const hypothesisLoop = [
    "Observe: describe the wrong behavior precisely.",
    "Hypothesize: name one change that would explain it.",
    "Test: set a breakpoint or watchpoint for that change.",
    "Learn: adjust the hypothesis and repeat.",
  ];
  const minimalReproChecklist = [
    "Single failing input captured.",
    "Steps reduced to the minimum path.",
    "Only one variable changes at a time.",
    "External dependencies fixed or mocked.",
    "Repro steps written so someone else can follow.",
  ];
  const buildSettings = [
    "Use debug symbols to map code to lines.",
    "Disable heavy optimizations while learning the bug.",
    "Generate source maps for web apps.",
    "Match the binary to the source version you are debugging.",
  ];
  const loggingVsDebugger = [
    {
      choice: "Logging",
      bestFor: "Production issues, long flows",
      tradeoff: "Requires code changes, can miss timing",
    },
    {
      choice: "Debugger",
      bestFor: "Local repro, deep inspection",
      tradeoff: "Halts execution, needs access",
    },
    {
      choice: "Tracing/Profiling",
      bestFor: "Performance or ordering",
      tradeoff: "Extra setup and overhead",
    },
  ];
  const commonEntryPoints = [
    "Crash reports or stack traces.",
    "Failing tests or assertions.",
    "Unexpected output or wrong calculations.",
    "Performance problems or infinite loops.",
  ];
  const toolsByPlatform = [
    { platform: "Windows", tools: "WinDbg, Visual Studio Debugger" },
    { platform: "Linux", tools: "GDB, LLDB" },
    { platform: "macOS", tools: "LLDB, Xcode Debugger" },
  ];

  const breakpointTypes = [
    {
      type: "Line breakpoint",
      use: "Stop at a specific line in source code.",
      tip: "Start near where the bug first appears.",
    },
    {
      type: "Function breakpoint",
      use: "Stop when a function is called.",
      tip: "Useful when you do not know the exact line.",
    },
    {
      type: "Conditional breakpoint",
      use: "Stop only when a condition is true.",
      tip: "Great for loops or large input sets.",
    },
    {
      type: "Watchpoint",
      use: "Stop when a variable or memory changes.",
      tip: "Use for unexpected mutations.",
    },
  ];
  const steppingModes = [
    {
      mode: "Step over",
      meaning: "Run the current line but do not enter functions.",
      when: "Use to move quickly through known-good code.",
    },
    {
      mode: "Step into",
      meaning: "Enter the function called on this line.",
      when: "Use to inspect a function in detail.",
    },
    {
      mode: "Step out",
      meaning: "Run until the current function returns.",
      when: "Use to exit a function after confirming it is fine.",
    },
  ];
  const breakpointStrategies = [
    "Place the first breakpoint at the symptom, then move backward.",
    "Break on function entry when you are unsure where a value changes.",
    "Use conditional breakpoints to stop only on the bad case.",
    "Use temporary breakpoints once a path is confirmed.",
  ];
  const watchpointTips = [
    "Watch a variable when it changes in unexpected places.",
    "Use data breakpoints for a specific memory address.",
    "Capture the call stack to find the writer.",
  ];

  const memoryBasics = [
    "The stack stores return addresses and local variables.",
    "The heap stores dynamically allocated objects.",
    "Registers hold current CPU state and function parameters.",
    "Reading memory shows what values truly exist at runtime.",
  ];
  const registerHints = [
    "Instruction pointer shows where the CPU is executing.",
    "Stack pointer shows the current top of the stack.",
    "Base pointer helps locate local variables.",
  ];
  const stackFrameTips = [
    "The top frame is where execution is paused.",
    "Older frames show how you got there.",
    "Inspect arguments and locals before stepping.",
    "Corrupted stacks often show missing or odd frames.",
  ];
  const memoryAreas = [
    { area: "Stack", lifetime: "Per function call", risk: "Out-of-scope access" },
    { area: "Heap", lifetime: "Manual or GC-managed", risk: "Leaks, use-after-free" },
    { area: "Globals", lifetime: "Program lifetime", risk: "Hidden shared state" },
  ];
  const commonMemoryBugs = [
    "Off-by-one index errors.",
    "Use-after-free or stale references.",
    "Null or invalid pointer dereferences.",
    "Buffer overflows from unchecked lengths.",
  ];
  const memoryRedFlags = [
    "Values changing without a code path.",
    "Length or size fields that are negative or huge.",
    "Pointers that do not align with expected ranges.",
    "Local variables with garbage values.",
  ];
  const pitfalls = [
    "Chasing symptoms instead of the first incorrect value.",
    "Stepping too far without taking notes.",
    "Changing code or inputs while debugging (non-repeatable).",
    "Ignoring the possibility of uninitialized data.",
    "Not checking boundary conditions in loops.",
  ];

  const detectionSignals = [
    "Consistent crashes at the same location.",
    "Stack traces that point to input handling.",
    "Sudden value changes after a specific call.",
    "Variables that are null or unexpected types.",
  ];
  const telemetrySources = [
    "Crash dumps and stack traces.",
    "Application logs around failure points.",
    "Test logs and assertion outputs.",
    "Performance profiles for slow paths.",
  ];
  const crashArtifacts = [
    "Crash or core dump file.",
    "Exact error message and stack trace.",
    "Input that triggered the failure.",
    "Version/build hash and config flags.",
  ];
  const triageQuestions = [
    "Is the bug reproducible on another machine?",
    "Did it start after a specific change or release?",
    "Is the issue data-specific or time-specific?",
    "Is the failure deterministic or flaky?",
  ];
  const rootCauseChecklist = [
    "First incorrect value or decision identified.",
    "Reason for the incorrect state understood.",
    "Fix removes the repro and no new regressions.",
    "Tests cover the failing case.",
  ];
  const triageSteps = [
    "Confirm the exact input that triggers the bug.",
    "Capture the stack trace and error message.",
    "Reproduce under the debugger.",
    "Verify which line first shows a wrong value.",
    "Fix and re-run the same steps to confirm.",
  ];

  const preventionChecklist = [
    "Add tests for edge cases and boundary values.",
    "Use assertions to catch invalid state early.",
    "Log critical inputs and outputs for key steps.",
    "Validate input sizes and types.",
    "Keep functions small and focused.",
  ];
  const safePractices = [
    "Use a local or staging environment for debugging.",
    "Avoid debugging with real user data.",
    "Record steps as you go to make fixes repeatable.",
    "Turn off debug logs before releasing to production.",
  ];
  const practiceExercises = [
    "Off-by-one loop bug in a small array function.",
    "Null pointer crash in a simple parser.",
    "Incorrect branch in a calculator function.",
    "Performance stall in a naive search algorithm.",
  ];
  const reportChecklist = [
    "Bug summary and steps to reproduce.",
    "Root cause in one sentence.",
    "Fix summary and risk assessment.",
    "Verification steps and results.",
  ];
  const validationLadder = [
    "Re-run the exact repro steps.",
    "Run the targeted test suite.",
    "Run broader regression tests if available.",
    "Confirm logs show the expected state.",
  ];

  const gdbBasics = `# GDB basics
gdb ./app
break main
run
next
step
info locals
bt`;
  const lldbBasics = `# LLDB basics
lldb ./app
breakpoint set --name main
run
next
step
frame variable
bt`;
  const winDbgBasics = `# WinDbg basics
.symfix; .reload
bp main
g
t
p
r
kb`;
  const notesTemplate = `# Debugging notes
Bug: <short description>
Repro steps:
1.
2.

Expected vs actual:
- Expected:
- Actual:

First wrong value:
Location:
Evidence:

Fix idea:
Validation steps:
`;
  const conditionalBreakpointExample = `# Conditional breakpoints
# Stop when userId is invalid
break validateUser if userId <= 0

# Stop when loop index reaches the boundary
break processItems if i == items.size - 1`;

  const labSteps = [
    "Pick a small sample app with a known bug.",
    "Set a breakpoint before the bug appears.",
    "Step through and watch variables change.",
    "Inspect stack and registers when behavior changes.",
    "Fix the bug and verify the same steps.",
  ];
  const verificationChecklist = [
    "Bug is reproducible before the fix.",
    "Debugger shows correct state after the fix.",
    "Tests pass for the affected path.",
    "No new errors introduced by the change.",
  ];
  const safeBoundaries = [
    "Only debug software you own or have permission to test.",
    "Do not attach debuggers to production services.",
    "Do not handle sensitive data in a debugger session.",
    "Focus on diagnosis and verification, not exploitation.",
  ];

  const pageContext = `This page covers debugging fundamentals including debugger concepts, breakpoints, memory inspection, call stacks, and common debugging tools. Topics include reproducible workflows, hypothesis-driven debugging, build symbols, logging vs debugging tradeoffs, and safe practice routines.`;

  return (
    <LearnPageLayout pageTitle="Debugging 101" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="lg">
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2, color: "grey.400" }}>
          Back to Learn Hub
        </Button>

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <BugReportIcon sx={{ fontSize: 42, color: "#3b82f6" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #3b82f6 0%, #38bdf8 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Debugging 101
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          A beginner-friendly guide to finding bugs with confidence.
        </Typography>

        <Alert severity="info" sx={{ mb: 3 }}>
          <AlertTitle>Beginner Friendly</AlertTitle>
          This page focuses on safe, practical debugging skills you can use in any codebase.
        </Alert>

        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            Debugging is the practice of finding out why software behaves differently than expected. A debugger
            lets you pause a program, look inside it, and step through its logic. Instead of guessing, you can
            see the real values in memory, the exact line being executed, and the call stack that led there.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            Think of a debugger like a "pause and inspect" button for software. You can stop at a line, inspect
            variables, and move forward one step at a time. This is especially powerful when a bug only appears
            after many steps or under specific inputs.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            Debugging is not about stepping randomly. The best debuggers use a simple workflow: reproduce the bug,
            isolate the first wrong value, test a hypothesis, and verify the fix. The goal is to learn what the
            program is truly doing, not what we hope it is doing.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            This guide explains core debugging concepts, common tools, and a safe practice workflow for beginners.
          </Typography>
        </Paper>

        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<BugReportIcon />} label="Breakpoints" size="small" />
          <Chip icon={<SearchIcon />} label="Stepping" size="small" />
          <Chip icon={<MemoryIcon />} label="Memory" size="small" />
          <Chip icon={<ShieldIcon />} label="Safe Workflow" size="small" />
        </Box>

        <Paper sx={{ bgcolor: "#111826", borderRadius: 2 }}>
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
            <Tab icon={<TuneIcon />} label="Workflow" />
            <Tab icon={<CodeIcon />} label="Breakpoints" />
            <Tab icon={<MemoryIcon />} label="Memory & Registers" />
            <Tab icon={<SearchIcon />} label="Detection" />
            <Tab icon={<BuildIcon />} label="Safe Lab" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
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

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
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

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Key Ideas
                </Typography>
                <List dense>
                  {keyIdeas.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Quick Glossary
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Term</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Meaning</TableCell>
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

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Debugging Mindset
                </Typography>
                <List dense>
                  {mindsetHabits.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Repro Tips
                </Typography>
                <List dense>
                  {reproducibilityTips.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <SearchIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Bug Types Quick Map
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Type</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Signals</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Approach</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {bugTypeMap.map((item) => (
                        <TableRow key={item.type}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.type}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.signals}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.approach}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Signal vs Noise
                </Typography>
                <List dense>
                  {signalNoiseTips.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
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
                          border: "1px solid rgba(59, 130, 246, 0.25)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1 }}>
                          Myth
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>
                          {item.myth}
                        </Typography>
                        <Typography variant="subtitle2" sx={{ color: "#38bdf8", mb: 0.5 }}>
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
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  How Debugging Works
                </Typography>
                <List dense>
                  {howDebuggingWorks.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Debugging Workflow
                </Typography>
                <List dense>
                  {workflow.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Hypothesis Loop
                </Typography>
                <List dense>
                  {hypothesisLoop.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Minimum Repro Checklist
                </Typography>
                <List dense>
                  {minimalReproChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Build Settings That Matter
                </Typography>
                <List dense>
                  {buildSettings.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <BuildIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Logging vs Debugger
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Approach</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Best For</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Tradeoffs</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {loggingVsDebugger.map((item) => (
                        <TableRow key={item.choice}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.choice}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.bestFor}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.tradeoff}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Debug Notes Template
                </Typography>
                <CodeBlock code={notesTemplate} language="text" />
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Common Entry Points
                </Typography>
                <List dense>
                  {commonEntryPoints.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <SearchIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Debugger Tools by Platform
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Platform</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Tools</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {toolsByPlatform.map((item) => (
                        <TableRow key={item.platform}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.platform}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.tools}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Breakpoint Types
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Type</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Use</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Tip</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {breakpointTypes.map((item) => (
                        <TableRow key={item.type}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.type}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.use}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.tip}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Stepping Modes
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Mode</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Meaning</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>When to Use</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {steppingModes.map((item) => (
                        <TableRow key={item.mode}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.mode}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.meaning}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.when}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Breakpoint Strategy
                </Typography>
                <List dense>
                  {breakpointStrategies.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Conditional Examples
                </Typography>
                <CodeBlock code={conditionalBreakpointExample} language="text" />
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Watchpoints and Data Breakpoints
                </Typography>
                <List dense>
                  {watchpointTips.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <SearchIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Common Debugger Commands
                </Typography>
                <Accordion sx={{ bgcolor: "#0f1422", borderRadius: 2, mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle1">GDB</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <CodeBlock code={gdbBasics} language="bash" />
                  </AccordionDetails>
                </Accordion>
                <Accordion sx={{ bgcolor: "#0f1422", borderRadius: 2, mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle1">LLDB</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <CodeBlock code={lldbBasics} language="bash" />
                  </AccordionDetails>
                </Accordion>
                <Accordion sx={{ bgcolor: "#0f1422", borderRadius: 2 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle1">WinDbg</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <CodeBlock code={winDbgBasics} language="text" />
                  </AccordionDetails>
                </Accordion>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Memory Basics
                </Typography>
                <List dense>
                  {memoryBasics.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Register Hints
                </Typography>
                <List dense>
                  {registerHints.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Stack Frames in Practice
                </Typography>
                <List dense>
                  {stackFrameTips.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Memory Areas
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#38bdf8" }}>Area</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Lifetime</TableCell>
                        <TableCell sx={{ color: "#38bdf8" }}>Common Risk</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {memoryAreas.map((item) => (
                        <TableRow key={item.area}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.area}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.lifetime}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.risk}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Common Memory Bugs
                </Typography>
                <List dense>
                  {commonMemoryBugs.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Memory Red Flags
                </Typography>
                <List dense>
                  {memoryRedFlags.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Common Pitfalls
                </Typography>
                <List dense>
                  {pitfalls.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon color="warning" fontSize="small" />
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
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
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

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Telemetry Sources
                </Typography>
                <List dense>
                  {telemetrySources.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Crash Artifacts to Capture
                </Typography>
                <List dense>
                  {crashArtifacts.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Triage Questions
                </Typography>
                <List dense>
                  {triageQuestions.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <SearchIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Root Cause Checklist
                </Typography>
                <List dense>
                  {rootCauseChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Quick Triage Steps
                </Typography>
                <List dense>
                  {triageSteps.map((item) => (
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

          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Safe Lab Walkthrough
                </Typography>
                <List dense>
                  {labSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Practice Exercises
                </Typography>
                <List dense>
                  {practiceExercises.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Prevention Checklist
                </Typography>
                <List dense>
                  {preventionChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Safe Debugging Practices
                </Typography>
                <List dense>
                  {safePractices.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <ShieldIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Verification Checklist
                </Typography>
                <List dense>
                  {verificationChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Validation Ladder
                </Typography>
                <List dense>
                  {validationLadder.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#38bdf8", mb: 1 }}>
                  Debugging Report Checklist
                </Typography>
                <List dense>
                  {reportChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0f1422", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Safe Boundaries
                </Typography>
                <List dense>
                  {safeBoundaries.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon color="warning" fontSize="small" />
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

export default Debugging101Page;
