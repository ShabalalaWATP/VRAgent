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
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import ShieldIcon from "@mui/icons-material/Shield";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SearchIcon from "@mui/icons-material/Search";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import LockIcon from "@mui/icons-material/Lock";
import StorageIcon from "@mui/icons-material/Storage";
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

const DeserializationAttacksPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const objectives = [
    "Explain deserialization in plain language.",
    "Show why untrusted data is dangerous to load as objects.",
    "Identify common entry points and risky formats.",
    "Recognize detection signals and triage steps.",
    "Apply prevention patterns and safe alternatives.",
  ];
  const beginnerPath = [
    "1) Read the beginner explanation and glossary.",
    "2) Learn how serialization and deserialization work.",
    "3) Review common formats and risk hotspots.",
    "4) Study abuse patterns and detection signals.",
    "5) Apply the prevention checklist and safe code examples.",
  ];
  const keyIdeas = [
    "Deserialization turns data back into objects or code structures.",
    "If the data is untrusted, the object graph can be dangerous.",
    "The safest fix is to avoid native deserialization of untrusted data.",
    "If you must deserialize, validate, restrict, and verify integrity.",
  ];
  const glossary = [
    { term: "Serialization", desc: "Converting objects into bytes or text for storage or transport." },
    { term: "Deserialization", desc: "Rebuilding objects from serialized data." },
    { term: "Object graph", desc: "A connected set of objects created from data." },
    { term: "Integrity", desc: "Proof that data has not been changed in transit." },
    { term: "Schema", desc: "A contract that defines allowed fields and types." },
    { term: "Gadget", desc: "A class or method that can be abused during deserialization." },
  ];
  const misconceptions = [
    {
      myth: "Deserialization is safe if the payload is base64.",
      reality: "Encoding does not make untrusted data safe.",
    },
    {
      myth: "Only Java apps have deserialization issues.",
      reality: "Many languages and formats can be abused.",
    },
    {
      myth: "Signing tokens always prevents abuse.",
      reality: "Signatures help integrity, but logic issues can remain.",
    },
  ];

  const howItWorks = [
    "A system serializes an object into bytes or text.",
    "The data is stored or transmitted (cookies, caches, APIs).",
    "Later, the system deserializes it back into objects.",
    "If the data is untrusted, it can create dangerous objects.",
    "That object graph may trigger code paths the app never expected.",
  ];
  const trustBoundaries = [
    "User-controlled cookies or session tokens.",
    "API bodies that accept complex objects.",
    "Message queues or caches with shared access.",
    "File uploads or imports containing serialized content.",
    "Internal services that trust upstream data without validation.",
  ];
  const entryPoints = [
    "Session state stored in cookies or headers.",
    "RPC or message queue payloads.",
    "Signed or encrypted tokens that embed objects.",
    "Export and import features (backups, configs).",
    "Webhooks or integration endpoints.",
  ];
  const featureHotspots = [
    "Single sign-on or session middleware.",
    "Background job systems that consume queued objects.",
    "Caching layers that store object blobs.",
    "Admin tools for backup and restore.",
    "SDKs that deserialize request bodies automatically.",
  ];

  const riskyFormats = [
    {
      format: "Java serialization",
      languages: "Java",
      risk: "ObjectInputStream can rebuild dangerous object graphs.",
      safer: "JSON or protobuf with schema validation.",
    },
    {
      format: ".NET BinaryFormatter",
      languages: "C# / .NET",
      risk: "BinaryFormatter is unsafe for untrusted input.",
      safer: "System.Text.Json or protobuf.",
    },
    {
      format: "PHP serialize",
      languages: "PHP",
      risk: "Unserialize can invoke magic methods.",
      safer: "JSON with strict validation.",
    },
    {
      format: "Python pickle",
      languages: "Python",
      risk: "Pickle can execute code during load.",
      safer: "JSON with schema, msgpack with types.",
    },
    {
      format: "YAML load",
      languages: "Many",
      risk: "Unsafe loaders can instantiate objects.",
      safer: "Safe loaders or JSON.",
    },
    {
      format: "XML object mapping",
      languages: "Many",
      risk: "Type mapping can instantiate unexpected classes.",
      safer: "Restricted XML parsing or JSON.",
    },
  ];

  const abusePatterns = [
    {
      title: "Dangerous object graphs",
      description: "Untrusted data creates objects that trigger unexpected code paths.",
      impact: "Remote code execution or privilege escalation in worst cases.",
      signals: "Unexpected class names or method calls in logs.",
      defense: "Avoid native deserialization; allowlist types.",
    },
    {
      title: "Data tampering",
      description: "Object fields are changed to bypass business rules.",
      impact: "Authorization bypass, price changes, or role escalation.",
      signals: "Inconsistent state changes or invalid transitions.",
      defense: "Validate fields and enforce server-side checks.",
    },
    {
      title: "Type confusion",
      description: "Input is treated as a different object type than expected.",
      impact: "Logic bypass or hidden code paths executed.",
      signals: "Type casting errors or unusual exceptions.",
      defense: "Use strict schemas and typed deserializers.",
    },
    {
      title: "Resource exhaustion",
      description: "Deep or massive object graphs consume memory or CPU.",
      impact: "Denial of service or degraded performance.",
      signals: "High memory use, long parse times, timeouts.",
      defense: "Limit size, depth, and complexity.",
    },
    {
      title: "Replay or downgrade",
      description: "Old or stale objects are accepted as valid.",
      impact: "Bypass of newer validation or business rules.",
      signals: "Old version fields reappearing in requests.",
      defense: "Version objects and enforce expiration.",
    },
  ];

  const detectionSignals = [
    "Deserialization exceptions or stack traces.",
    "Unexpected class or type names in logs.",
    "Large or deeply nested payloads.",
    "Spikes in parsing time or memory usage.",
    "Requests that bypass normal validation paths.",
  ];
  const telemetrySources = [
    "Application logs and exception traces.",
    "APM metrics for parsing time and memory.",
    "WAF or API gateway logs for payload size anomalies.",
    "Audit logs for authorization changes.",
    "Dependency scanning reports for risky serializers.",
  ];
  const errorSignatures = [
    { system: "Java", examples: "InvalidClassException, StreamCorruptedException" },
    { system: ".NET", examples: "SerializationException, BinaryFormatter warnings" },
    { system: "PHP", examples: "unserialize() error, __wakeup() warnings" },
    { system: "Python", examples: "pickle.UnpicklingError" },
    { system: "Generic", examples: "Unexpected type, cannot cast, schema violation" },
  ];
  const baselineMetrics = [
    {
      metric: "Deserialization error rate",
      normal: "Low and stable by endpoint.",
      investigate: "Sudden spikes or new error types.",
    },
    {
      metric: "Payload size",
      normal: "Consistent within typical bounds.",
      investigate: "Large payloads or rapid growth.",
    },
    {
      metric: "Parse time",
      normal: "Small and predictable.",
      investigate: "Long parse times or timeouts.",
    },
  ];
  const triageSteps = [
    "Identify the endpoint and serializer involved.",
    "Check if the data is trusted or user-controlled.",
    "Review logs for type names and error patterns.",
    "Inspect payload size and nesting depth.",
    "Validate whether integrity checks are enforced.",
  ];
  const responseSteps = [
    "Disable or restrict the vulnerable deserialization path.",
    "Switch to a safe format or strict schema validation.",
    "Rotate signing keys if tampering is suspected.",
    "Add limits on size and depth immediately.",
    "Write regression tests for serialized inputs.",
  ];

  const preventionChecklist = [
    "Avoid native deserialization of untrusted data.",
    "Use safe formats like JSON with schema validation.",
    "Allowlist expected types and block everything else.",
    "Limit payload size, nesting depth, and object count.",
    "Verify integrity with signatures before parsing.",
    "Keep serializers and dependencies updated.",
    "Run services with least privilege.",
  ];
  const defenseInDepth = [
    "Use separate services to handle untrusted inputs.",
    "Enable detailed logging for deserialization errors.",
    "Monitor outbound network connections from app servers.",
    "Apply WAF rules for excessive payload sizes.",
    "Perform code reviews for any serializer usage.",
  ];
  const safeAlternatives = [
    {
      format: "JSON + schema",
      benefit: "Simple, explicit, and easy to validate.",
      note: "Use strict schemas and reject unknown fields.",
    },
    {
      format: "Protobuf",
      benefit: "Typed and efficient binary format.",
      note: "Avoid dynamic type resolution.",
    },
    {
      format: "MessagePack",
      benefit: "Compact with structured types.",
      note: "Use schema or strict mapping.",
    },
  ];

  const unsafeExample = `// Insecure: native deserialization of untrusted input
const data = request.body;
const obj = deserializeBinary(data);`;
  const safeExample = `// Safer: parse JSON and validate schema
const data = JSON.parse(request.body);
validateSchema(data, orderSchema);
processOrder(data);`;
  const integrityExample = `// Verify integrity before any parsing
if (!verifySignature(payload, publicKey)) {
  throw new Error("Invalid signature");
}
const data = JSON.parse(payload);`;

  const codeReviewChecklist = [
    "Find all deserialization libraries in the codebase.",
    "Confirm whether input is trusted or user-controlled.",
    "Check for allowlists and schema validation.",
    "Verify size and depth limits.",
    "Ensure integrity checks happen before parsing.",
  ];
  const codeReviewCommands = `# Search for risky serializers
rg -n "ObjectInputStream|BinaryFormatter|unserialize\\(|pickle\\.loads|yaml\\.load" src

# Search for custom deserialization helpers
rg -n "deserialize|unmarshal|fromBytes|fromString" src`;

  const labSteps = [
    "Identify any deserialization usage in a demo app.",
    "Classify which inputs are untrusted.",
    "Add schema validation and allowlists.",
    "Add size and depth limits to parsers.",
    "Record baseline parse time and error rates.",
  ];
  const verificationChecklist = [
    "No native deserialization on untrusted inputs.",
    "Schemas are enforced and unknown fields rejected.",
    "Integrity checks occur before parsing.",
    "Payload size and depth limits are configured.",
    "Logging captures deserialization failures.",
  ];
  const safeBoundaries = [
    "Only test in a lab or with written authorization.",
    "Avoid using real user data in tests.",
    "Do not attempt exploitation on production systems.",
    "Focus on detection and prevention steps.",
  ];

  const pageContext = `This page covers deserialization vulnerabilities and attacks across different programming languages including Java, PHP, Python, and .NET. Topics include insecure deserialization, gadget chains, remote code execution, exploitation techniques, and secure coding practices.`;

  return (
    <LearnPageLayout pageTitle="Deserialization Attacks" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="lg">
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 2, color: "grey.400" }}>
          Back to Learn Hub
        </Button>

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <AccountTreeIcon sx={{ fontSize: 42, color: "#3b82f6" }} />
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
            Deserialization Attacks
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          A beginner-friendly deep dive into why unsafe deserialization is risky and how to defend against it.
        </Typography>

        <Alert severity="warning" sx={{ mb: 3 }}>
          <AlertTitle>Defensive Learning Only</AlertTitle>
          This page focuses on prevention, detection, and safe engineering. Use it only for authorized testing.
        </Alert>

        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0f1422", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            Deserialization is the process of taking data and turning it back into objects. Many systems serialize
            objects into text or bytes so they can be stored in a cache, sent over the network, or saved in a file.
            When that data comes back, the system deserializes it to rebuild the original object graph.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            The danger is that deserialization can create objects that carry behavior, not just data. If an attacker
            can control the serialized input, they can influence what objects get created and how they are built.
            This can lead to surprising behavior, security bypasses, or even code execution in the worst cases.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            A beginner way to think about it: imagine sending a sealed box of instructions instead of a simple data
            form. If your system opens the box and follows the instructions automatically, a malicious box could
            trick it into doing unsafe things. Safe systems treat incoming data as plain data, not executable objects.
          </Typography>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            The safest fix is to avoid native deserialization for untrusted inputs and use strict formats like JSON
            with schema validation. If deserialization is required, you must restrict types, validate inputs, and
            verify integrity before parsing.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            This guide explains the concept, where it appears in real systems, how to detect it, and how to prevent it
            with practical checklists and safe examples.
          </Typography>
        </Paper>

        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<AccountTreeIcon />} label="Object Graphs" size="small" />
          <Chip icon={<StorageIcon />} label="Serialization" size="small" />
          <Chip icon={<SearchIcon />} label="Detection" size="small" />
          <Chip icon={<ShieldIcon />} label="Prevention" size="small" />
          <Chip icon={<CodeIcon />} label="Safe Parsing" size="small" />
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
            <Tab icon={<TuneIcon />} label="How It Works" />
            <Tab icon={<AccountTreeIcon />} label="Abuse Patterns" />
            <Tab icon={<SearchIcon />} label="Detection" />
            <Tab icon={<ShieldIcon />} label="Prevention" />
            <Tab icon={<BuildIcon />} label="Safe Lab" />
          </Tabs>

          {/* Tab 0: Overview */}
          <TabPanel value={tabValue} index={0}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    <SecurityIcon sx={{ mr: 1, verticalAlign: "middle", color: "#3b82f6" }} />
                    Learning Objectives
                  </Typography>
                  <List dense>
                    {objectives.map((obj, i) => (
                      <ListItem key={i}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
                        <ListItemText primary={obj} sx={{ color: "grey.300" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    <BugReportIcon sx={{ mr: 1, verticalAlign: "middle", color: "#f59e0b" }} />
                    Beginner Path
                  </Typography>
                  <List dense>
                    {beginnerPath.map((step, i) => (
                      <ListItem key={i}>
                        <ListItemText primary={step} sx={{ color: "grey.300" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    Key Ideas
                  </Typography>
                  <List dense>
                    {keyIdeas.map((idea, i) => (
                      <ListItem key={i}>
                        <ListItemIcon><LockIcon sx={{ color: "#3b82f6" }} /></ListItemIcon>
                        <ListItemText primary={idea} sx={{ color: "grey.300" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12}>
                <Accordion sx={{ bgcolor: "#151c2c" }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                    <Typography sx={{ color: "#fff", fontWeight: 600 }}>Glossary</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Term</TableCell>
                            <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Definition</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {glossary.map((g, i) => (
                            <TableRow key={i}>
                              <TableCell sx={{ color: "#3b82f6", fontWeight: 600 }}>{g.term}</TableCell>
                              <TableCell sx={{ color: "grey.300" }}>{g.desc}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Tab 1: How It Works */}
          <TabPanel value={tabValue} index={1}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    Serialization Flow
                  </Typography>
                  <List dense>
                    {howItWorks.map((step, i) => (
                      <ListItem key={i}>
                        <ListItemIcon><Chip label={i + 1} size="small" /></ListItemIcon>
                        <ListItemText primary={step} sx={{ color: "grey.300" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    Trust Boundaries
                  </Typography>
                  <List dense>
                    {trustBoundaries.map((b, i) => (
                      <ListItem key={i}>
                        <ListItemIcon><WarningIcon sx={{ color: "#f59e0b" }} /></ListItemIcon>
                        <ListItemText primary={b} sx={{ color: "grey.300" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    Risky Formats
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Format</TableCell>
                          <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Languages</TableCell>
                          <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Risk</TableCell>
                          <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Safer Alternative</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {riskyFormats.map((f, i) => (
                          <TableRow key={i}>
                            <TableCell sx={{ color: "#ef4444", fontWeight: 600 }}>{f.format}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{f.languages}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{f.risk}</TableCell>
                            <TableCell sx={{ color: "#22c55e" }}>{f.safer}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Tab 2: Abuse Patterns */}
          <TabPanel value={tabValue} index={2}>
            <Grid container spacing={2}>
              {abusePatterns.map((pattern, i) => (
                <Grid item xs={12} md={6} key={i}>
                  <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 1 }}>
                      {pattern.title}
                    </Typography>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 1 }}>{pattern.description}</Typography>
                    <Typography variant="body2" sx={{ color: "#ef4444", mb: 1 }}><strong>Impact:</strong> {pattern.impact}</Typography>
                    <Typography variant="body2" sx={{ color: "#f59e0b", mb: 1 }}><strong>Signals:</strong> {pattern.signals}</Typography>
                    <Typography variant="body2" sx={{ color: "#22c55e" }}><strong>Defense:</strong> {pattern.defense}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </TabPanel>

          {/* Tab 3: Detection */}
          <TabPanel value={tabValue} index={3}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    Detection Signals
                  </Typography>
                  <List dense>
                    {detectionSignals.map((s, i) => (
                      <ListItem key={i}>
                        <ListItemIcon><SearchIcon sx={{ color: "#3b82f6" }} /></ListItemIcon>
                        <ListItemText primary={s} sx={{ color: "grey.300" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    Triage Steps
                  </Typography>
                  <List dense>
                    {triageSteps.map((s, i) => (
                      <ListItem key={i}>
                        <ListItemIcon><Chip label={i + 1} size="small" /></ListItemIcon>
                        <ListItemText primary={s} sx={{ color: "grey.300" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    Error Signatures by System
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>System</TableCell>
                          <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Example Errors</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {errorSignatures.map((e, i) => (
                          <TableRow key={i}>
                            <TableCell sx={{ color: "#3b82f6", fontWeight: 600 }}>{e.system}</TableCell>
                            <TableCell sx={{ color: "grey.300", fontFamily: "monospace" }}>{e.examples}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Tab 4: Prevention */}
          <TabPanel value={tabValue} index={4}>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    <ShieldIcon sx={{ mr: 1, verticalAlign: "middle", color: "#22c55e" }} />
                    Prevention Checklist
                  </Typography>
                  <List dense>
                    {preventionChecklist.map((item, i) => (
                      <ListItem key={i}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
                        <ListItemText primary={item} sx={{ color: "grey.300" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    Safe Alternatives
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Format</TableCell>
                          <TableCell sx={{ color: "grey.400", fontWeight: 600 }}>Benefit</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {safeAlternatives.map((a, i) => (
                          <TableRow key={i}>
                            <TableCell sx={{ color: "#22c55e", fontWeight: 600 }}>{a.format}</TableCell>
                            <TableCell sx={{ color: "grey.300" }}>{a.benefit}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
              </Grid>
              <Grid item xs={12}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>Code Examples</Typography>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>❌ Unsafe</Typography>
                  <CodeBlock code={unsafeExample} language="javascript" />
                  <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 1, mt: 2 }}>✅ Safe</Typography>
                  <CodeBlock code={safeExample} language="javascript" />
                  <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1, mt: 2 }}>✅ With Integrity Check</Typography>
                  <CodeBlock code={integrityExample} language="javascript" />
                </Paper>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Tab 5: Safe Lab */}
          <TabPanel value={tabValue} index={5}>
            <Alert severity="info" sx={{ mb: 3 }}>
              <AlertTitle>Safe Practice</AlertTitle>
              Follow these steps only in authorized lab environments. Focus on detection and prevention.
            </Alert>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    Lab Steps
                  </Typography>
                  <List dense>
                    {labSteps.map((step, i) => (
                      <ListItem key={i}>
                        <ListItemIcon><Chip label={i + 1} size="small" /></ListItemIcon>
                        <ListItemText primary={step} sx={{ color: "grey.300" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    Verification Checklist
                  </Typography>
                  <List dense>
                    {verificationChecklist.map((item, i) => (
                      <ListItem key={i}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
                        <ListItemText primary={item} sx={{ color: "grey.300" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12}>
                <Paper sx={{ p: 2, bgcolor: "#151c2c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#fff", mb: 2 }}>
                    Code Review Commands
                  </Typography>
                  <CodeBlock code={codeReviewCommands} language="bash" />
                </Paper>
              </Grid>
              <Grid item xs={12}>
                <Paper sx={{ p: 2, bgcolor: "#1a1a2e", border: "1px solid #ef4444", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: "#ef4444", mb: 2 }}>
                    <WarningIcon sx={{ mr: 1, verticalAlign: "middle" }} />
                    Safe Boundaries
                  </Typography>
                  <List dense>
                    {safeBoundaries.map((b, i) => (
                      <ListItem key={i}>
                        <ListItemIcon><WarningIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
                        <ListItemText primary={b} sx={{ color: "grey.300" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </TabPanel>
        </Paper>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default DeserializationAttacksPage;