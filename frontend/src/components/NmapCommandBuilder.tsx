import React, { useState, useMemo } from "react";
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  IconButton,
  Chip,
  Collapse,
  Tooltip,
  alpha,
  Divider,
  useTheme,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  FormControlLabel,
  Checkbox,
  Grid,
  ToggleButton,
  ToggleButtonGroup,
  Slider,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from "@mui/material";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CheckIcon from "@mui/icons-material/Check";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import TerminalIcon from "@mui/icons-material/Terminal";
import BuildIcon from "@mui/icons-material/Build";
import SpeedIcon from "@mui/icons-material/Speed";
import SecurityIcon from "@mui/icons-material/Security";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import SettingsIcon from "@mui/icons-material/Settings";
import OutputIcon from "@mui/icons-material/Output";
import BugReportIcon from "@mui/icons-material/BugReport";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import RefreshIcon from "@mui/icons-material/Refresh";

interface ScanType {
  value: string;
  label: string;
  flag: string;
  description: string;
  requiresRoot: boolean;
  category: "tcp" | "udp" | "other";
}

const SCAN_TYPES: ScanType[] = [
  { value: "syn", label: "SYN Scan (Stealth)", flag: "-sS", description: "Fast, stealthy half-open scan. Default for root users.", requiresRoot: true, category: "tcp" },
  { value: "connect", label: "TCP Connect", flag: "-sT", description: "Full TCP connection. No root required but slower and logged.", requiresRoot: false, category: "tcp" },
  { value: "ack", label: "ACK Scan", flag: "-sA", description: "Detect firewall rules. Cannot determine open ports.", requiresRoot: true, category: "tcp" },
  { value: "window", label: "Window Scan", flag: "-sW", description: "Like ACK but can detect open ports on some systems.", requiresRoot: true, category: "tcp" },
  { value: "maimon", label: "Maimon Scan", flag: "-sM", description: "FIN/ACK probe. Works on some BSD systems.", requiresRoot: true, category: "tcp" },
  { value: "null", label: "NULL Scan", flag: "-sN", description: "No flags set. Stealthy but unreliable on Windows.", requiresRoot: true, category: "tcp" },
  { value: "fin", label: "FIN Scan", flag: "-sF", description: "Only FIN flag. Stealthy against non-Windows.", requiresRoot: true, category: "tcp" },
  { value: "xmas", label: "Xmas Scan", flag: "-sX", description: "FIN, PSH, URG flags. Stealthy against non-Windows.", requiresRoot: true, category: "tcp" },
  { value: "udp", label: "UDP Scan", flag: "-sU", description: "Scan UDP ports. Slow but essential for DNS, SNMP, etc.", requiresRoot: true, category: "udp" },
  { value: "idle", label: "Idle/Zombie Scan", flag: "-sI", description: "Extremely stealthy using zombie host.", requiresRoot: true, category: "other" },
  { value: "ping", label: "Ping Scan (No Port)", flag: "-sn", description: "Host discovery only, no port scan.", requiresRoot: false, category: "other" },
  { value: "protocol", label: "IP Protocol Scan", flag: "-sO", description: "Determine supported IP protocols.", requiresRoot: true, category: "other" },
];

const TIMING_TEMPLATES = [
  { value: 0, label: "T0 - Paranoid", description: "IDS evasion, very slow (5 min between probes)" },
  { value: 1, label: "T1 - Sneaky", description: "IDS evasion, slow (15 sec between probes)" },
  { value: 2, label: "T2 - Polite", description: "Less bandwidth, slow (0.4 sec between probes)" },
  { value: 3, label: "T3 - Normal", description: "Default timing" },
  { value: 4, label: "T4 - Aggressive", description: "Fast scan, assumes reliable network" },
  { value: 5, label: "T5 - Insane", description: "Very fast, may miss ports or overwhelm network" },
];

const NSE_SCRIPT_CATEGORIES = [
  { value: "default", label: "Default Scripts", flag: "-sC", description: "Safe, useful scripts" },
  { value: "vuln", label: "Vulnerability", flag: "--script=vuln", description: "Check for known vulnerabilities" },
  { value: "safe", label: "Safe", flag: "--script=safe", description: "Non-intrusive scripts" },
  { value: "auth", label: "Authentication", flag: "--script=auth", description: "Authentication bypass attempts" },
  { value: "discovery", label: "Discovery", flag: "--script=discovery", description: "Additional host/service info" },
  { value: "brute", label: "Brute Force", flag: "--script=brute", description: "Credential brute forcing" },
  { value: "exploit", label: "Exploit", flag: "--script=exploit", description: "Active exploitation (DANGEROUS)" },
];

const OUTPUT_FORMATS = [
  { value: "normal", label: "Normal (-oN)", flag: "-oN", ext: ".txt" },
  { value: "xml", label: "XML (-oX)", flag: "-oX", ext: ".xml" },
  { value: "grepable", label: "Grepable (-oG)", flag: "-oG", ext: ".gnmap" },
  { value: "all", label: "All Formats (-oA)", flag: "-oA", ext: "" },
];

const NmapCommandBuilder: React.FC = () => {
  const theme = useTheme();
  const accentColor = "#f59e0b"; // Nmap orange
  
  const [isExpanded, setIsExpanded] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState(false);
  
  // Scan options
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("syn");
  const [portSpec, setPortSpec] = useState<"default" | "all" | "top" | "custom">("default");
  const [customPorts, setCustomPorts] = useState("");
  const [topPorts, setTopPorts] = useState(100);
  const [timing, setTiming] = useState(4);
  
  // Detection options
  const [serviceVersion, setServiceVersion] = useState(false);
  const [osDetection, setOsDetection] = useState(false);
  const [aggressiveScan, setAggressiveScan] = useState(false);
  const [traceroute, setTraceroute] = useState(false);
  
  // Script options
  const [selectedScripts, setSelectedScripts] = useState<string[]>([]);
  const [customScript, setCustomScript] = useState("");
  
  // Host discovery
  const [skipPing, setSkipPing] = useState(false);
  const [hostDiscovery, setHostDiscovery] = useState<string[]>([]);
  
  // Evasion options
  const [fragmentPackets, setFragmentPackets] = useState(false);
  const [decoys, setDecoys] = useState(false);
  const [decoyCount, setDecoyCount] = useState(5);
  const [sourcePort, setSourcePort] = useState("");
  const [spoofMac, setSpoofMac] = useState(false);
  
  // Output options
  const [verbosity, setVerbosity] = useState(0);
  const [openOnly, setOpenOnly] = useState(false);
  const [outputFormat, setOutputFormat] = useState("");
  const [outputFile, setOutputFile] = useState("scan_results");
  
  // Build the command
  const generatedCommand = useMemo(() => {
    const parts: string[] = ["nmap"];
    
    // Scan type
    const selectedScan = SCAN_TYPES.find(s => s.value === scanType);
    if (selectedScan && selectedScan.flag !== "-sS") { // -sS is default for root
      parts.push(selectedScan.flag);
    }
    
    // Aggressive scan overrides individual options
    if (aggressiveScan) {
      parts.push("-A");
    } else {
      // Service version detection
      if (serviceVersion) parts.push("-sV");
      // OS detection
      if (osDetection) parts.push("-O");
      // Traceroute
      if (traceroute) parts.push("--traceroute");
    }
    
    // Port specification
    switch (portSpec) {
      case "all":
        parts.push("-p-");
        break;
      case "top":
        parts.push(`--top-ports ${topPorts}`);
        break;
      case "custom":
        if (customPorts) parts.push(`-p ${customPorts}`);
        break;
      // default: nmap uses top 1000
    }
    
    // Timing
    parts.push(`-T${timing}`);
    
    // Host discovery
    if (skipPing) {
      parts.push("-Pn");
    } else if (hostDiscovery.length > 0) {
      hostDiscovery.forEach(h => parts.push(h));
    }
    
    // Scripts
    if (selectedScripts.includes("default")) {
      parts.push("-sC");
    }
    selectedScripts.filter(s => s !== "default").forEach(script => {
      const scriptDef = NSE_SCRIPT_CATEGORIES.find(c => c.value === script);
      if (scriptDef) parts.push(scriptDef.flag);
    });
    if (customScript) {
      parts.push(`--script="${customScript}"`);
    }
    
    // Evasion
    if (fragmentPackets) parts.push("-f");
    if (decoys) parts.push(`-D RND:${decoyCount}`);
    if (sourcePort) parts.push(`-g ${sourcePort}`);
    if (spoofMac) parts.push("--spoof-mac 0");
    
    // Output options
    if (verbosity === 1) parts.push("-v");
    if (verbosity === 2) parts.push("-vv");
    if (openOnly) parts.push("--open");
    
    if (outputFormat && outputFile) {
      const format = OUTPUT_FORMATS.find(f => f.value === outputFormat);
      if (format) {
        parts.push(`${format.flag} ${outputFile}${format.ext}`);
      }
    }
    
    // Target (always at the end)
    parts.push(target || "<target>");
    
    return parts.join(" ");
  }, [
    scanType, portSpec, customPorts, topPorts, timing,
    serviceVersion, osDetection, aggressiveScan, traceroute,
    selectedScripts, customScript, skipPing, hostDiscovery,
    fragmentPackets, decoys, decoyCount, sourcePort, spoofMac,
    verbosity, openOnly, outputFormat, outputFile, target
  ]);
  
  const selectedScanInfo = SCAN_TYPES.find(s => s.value === scanType);
  
  const copyToClipboard = () => {
    navigator.clipboard.writeText(generatedCommand);
    setCopiedCommand(true);
    setTimeout(() => setCopiedCommand(false), 2000);
  };
  
  const resetAll = () => {
    setTarget("");
    setScanType("syn");
    setPortSpec("default");
    setCustomPorts("");
    setTopPorts(100);
    setTiming(4);
    setServiceVersion(false);
    setOsDetection(false);
    setAggressiveScan(false);
    setTraceroute(false);
    setSelectedScripts([]);
    setCustomScript("");
    setSkipPing(false);
    setHostDiscovery([]);
    setFragmentPackets(false);
    setDecoys(false);
    setDecoyCount(5);
    setSourcePort("");
    setSpoofMac(false);
    setVerbosity(0);
    setOpenOnly(false);
    setOutputFormat("");
    setOutputFile("scan_results");
  };
  
  const handleScriptToggle = (script: string) => {
    setSelectedScripts(prev => 
      prev.includes(script) 
        ? prev.filter(s => s !== script)
        : [...prev, script]
    );
  };

  return (
    <Paper
      elevation={0}
      sx={{
        border: `1px solid ${alpha(accentColor, 0.3)}`,
        borderRadius: 2,
        overflow: "hidden",
        mb: 3,
        bgcolor: alpha(accentColor, 0.02),
      }}
    >
      {/* Header */}
      <Box
        onClick={() => setIsExpanded(!isExpanded)}
        sx={{
          display: "flex",
          alignItems: "center",
          gap: 1.5,
          p: 2,
          cursor: "pointer",
          bgcolor: alpha(accentColor, 0.05),
          borderBottom: isExpanded ? `1px solid ${alpha(accentColor, 0.2)}` : "none",
          "&:hover": {
            bgcolor: alpha(accentColor, 0.08),
          },
          transition: "background-color 0.2s",
        }}
      >
        <Box
          sx={{
            width: 36,
            height: 36,
            borderRadius: "50%",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            bgcolor: alpha(accentColor, 0.15),
            color: accentColor,
          }}
        >
          <BuildIcon sx={{ fontSize: 20 }} />
        </Box>
        <Box sx={{ flex: 1 }}>
          <Typography variant="subtitle2" fontWeight={700} sx={{ color: accentColor }}>
            🔧 Nmap Command Builder
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Build custom Nmap scan commands with a visual interface
          </Typography>
        </Box>
        <Chip
          icon={<TerminalIcon sx={{ fontSize: 14 }} />}
          label="Interactive"
          size="small"
          sx={{
            bgcolor: alpha(accentColor, 0.1),
            color: accentColor,
            fontWeight: 600,
            fontSize: "0.7rem",
          }}
        />
        <IconButton size="small" sx={{ color: accentColor }}>
          {isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        </IconButton>
      </Box>

      {/* Content */}
      <Collapse in={isExpanded}>
        <Box sx={{ p: 2 }}>
          {/* Generated Command Display */}
          <Box sx={{ mb: 3 }}>
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
              <Typography variant="subtitle2" fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                <TerminalIcon sx={{ fontSize: 16, color: accentColor }} />
                Generated Command
              </Typography>
              <Box sx={{ display: "flex", gap: 1 }}>
                <Tooltip title="Reset all options">
                  <IconButton size="small" onClick={resetAll}>
                    <RefreshIcon sx={{ fontSize: 16 }} />
                  </IconButton>
                </Tooltip>
                <Tooltip title={copiedCommand ? "Copied!" : "Copy command"}>
                  <IconButton
                    size="small"
                    onClick={copyToClipboard}
                    sx={{ color: copiedCommand ? "#22c55e" : "inherit" }}
                  >
                    {copiedCommand ? <CheckIcon sx={{ fontSize: 16 }} /> : <ContentCopyIcon sx={{ fontSize: 16 }} />}
                  </IconButton>
                </Tooltip>
              </Box>
            </Box>
            <Box
              component="pre"
              sx={{
                fontFamily: "monospace",
                fontSize: "0.9rem",
                p: 2,
                borderRadius: 2,
                bgcolor: theme.palette.mode === "dark" ? "#1e1e1e" : "#f5f5f5",
                border: `2px solid ${alpha(accentColor, 0.3)}`,
                overflowX: "auto",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                m: 0,
                color: accentColor,
              }}
            >
              {generatedCommand}
            </Box>
            {selectedScanInfo?.requiresRoot && (
              <Alert severity="warning" sx={{ mt: 1, borderRadius: 1 }} icon={<SecurityIcon />}>
                <Typography variant="caption">
                  {selectedScanInfo.label} requires root/administrator privileges
                </Typography>
              </Alert>
            )}
          </Box>

          {/* Target Input */}
          <TextField
            fullWidth
            size="small"
            label="Target (IP, hostname, range, or CIDR)"
            placeholder="192.168.1.1, scanme.nmap.org, 192.168.1.0/24, 10.0.0.1-50"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            sx={{ mb: 3 }}
          />

          {/* Scan Type Selection */}
          <Accordion defaultExpanded sx={{ mb: 2, bgcolor: "transparent", boxShadow: "none", border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <NetworkCheckIcon sx={{ color: accentColor, fontSize: 20 }} />
                <Typography variant="subtitle2" fontWeight={600}>Scan Type</Typography>
                <Chip label={selectedScanInfo?.label || ""} size="small" sx={{ ml: 1, bgcolor: alpha(accentColor, 0.1) }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={1}>
                {SCAN_TYPES.map((scan) => (
                  <Grid item xs={12} sm={6} md={4} key={scan.value}>
                    <Paper
                      elevation={0}
                      onClick={() => setScanType(scan.value)}
                      sx={{
                        p: 1.5,
                        cursor: "pointer",
                        border: `1px solid ${scanType === scan.value ? accentColor : alpha(theme.palette.divider, 0.5)}`,
                        bgcolor: scanType === scan.value ? alpha(accentColor, 0.1) : "transparent",
                        borderRadius: 1,
                        "&:hover": { bgcolor: alpha(accentColor, 0.05) },
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Typography variant="body2" fontWeight={600}>{scan.label}</Typography>
                        {scan.requiresRoot && (
                          <Chip label="root" size="small" sx={{ height: 16, fontSize: "0.6rem", bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
                        )}
                      </Box>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
                        <code style={{ fontSize: "0.7rem", color: accentColor }}>{scan.flag}</code> - {scan.description}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>

          {/* Port Specification */}
          <Accordion sx={{ mb: 2, bgcolor: "transparent", boxShadow: "none", border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <SettingsIcon sx={{ color: accentColor, fontSize: 20 }} />
                <Typography variant="subtitle2" fontWeight={600}>Port Specification</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <ToggleButtonGroup
                value={portSpec}
                exclusive
                onChange={(_, val) => val && setPortSpec(val)}
                size="small"
                sx={{ mb: 2 }}
              >
                <ToggleButton value="default">Default (Top 1000)</ToggleButton>
                <ToggleButton value="all">All Ports (-p-)</ToggleButton>
                <ToggleButton value="top">Top N Ports</ToggleButton>
                <ToggleButton value="custom">Custom</ToggleButton>
              </ToggleButtonGroup>
              
              {portSpec === "top" && (
                <Box sx={{ px: 2 }}>
                  <Typography variant="caption" gutterBottom>Top {topPorts} ports</Typography>
                  <Slider
                    value={topPorts}
                    onChange={(_, val) => setTopPorts(val as number)}
                    min={10}
                    max={1000}
                    step={10}
                    marks={[
                      { value: 10, label: "10" },
                      { value: 100, label: "100" },
                      { value: 500, label: "500" },
                      { value: 1000, label: "1000" },
                    ]}
                  />
                </Box>
              )}
              
              {portSpec === "custom" && (
                <TextField
                  fullWidth
                  size="small"
                  label="Custom Ports"
                  placeholder="22,80,443,8080 or 1-1024 or U:53,T:22,80"
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                  helperText="Examples: 22,80,443 | 1-1024 | 80,443,8000-9000 | U:53,T:22,80"
                />
              )}
            </AccordionDetails>
          </Accordion>

          {/* Timing & Performance */}
          <Accordion sx={{ mb: 2, bgcolor: "transparent", boxShadow: "none", border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <SpeedIcon sx={{ color: accentColor, fontSize: 20 }} />
                <Typography variant="subtitle2" fontWeight={600}>Timing & Performance</Typography>
                <Chip label={`T${timing}`} size="small" sx={{ ml: 1, bgcolor: alpha(accentColor, 0.1) }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Box sx={{ px: 2 }}>
                <Slider
                  value={timing}
                  onChange={(_, val) => setTiming(val as number)}
                  min={0}
                  max={5}
                  step={1}
                  marks={TIMING_TEMPLATES.map(t => ({ value: t.value, label: `T${t.value}` }))}
                />
                <Box sx={{ mt: 2, p: 1.5, bgcolor: alpha(accentColor, 0.05), borderRadius: 1 }}>
                  <Typography variant="body2" fontWeight={600}>
                    {TIMING_TEMPLATES[timing].label}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {TIMING_TEMPLATES[timing].description}
                  </Typography>
                </Box>
              </Box>
            </AccordionDetails>
          </Accordion>

          {/* Service & OS Detection */}
          <Accordion sx={{ mb: 2, bgcolor: "transparent", boxShadow: "none", border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: accentColor, fontSize: 20 }} />
                <Typography variant="subtitle2" fontWeight={600}>Service & OS Detection</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={aggressiveScan}
                        onChange={(e) => {
                          setAggressiveScan(e.target.checked);
                          if (e.target.checked) {
                            setServiceVersion(false);
                            setOsDetection(false);
                            setTraceroute(false);
                          }
                        }}
                        sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2" fontWeight={600}>Aggressive Scan (-A)</Typography>
                        <Typography variant="caption" color="text.secondary">
                          Enables OS detection, version detection, script scanning, and traceroute
                        </Typography>
                      </Box>
                    }
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={serviceVersion}
                        onChange={(e) => setServiceVersion(e.target.checked)}
                        disabled={aggressiveScan}
                        sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">Version Detection (-sV)</Typography>
                        <Typography variant="caption" color="text.secondary">Probe services for version info</Typography>
                      </Box>
                    }
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={osDetection}
                        onChange={(e) => setOsDetection(e.target.checked)}
                        disabled={aggressiveScan}
                        sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">OS Detection (-O)</Typography>
                        <Typography variant="caption" color="text.secondary">Detect operating system</Typography>
                      </Box>
                    }
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={traceroute}
                        onChange={(e) => setTraceroute(e.target.checked)}
                        disabled={aggressiveScan}
                        sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">Traceroute (--traceroute)</Typography>
                        <Typography variant="caption" color="text.secondary">Trace hop path to host</Typography>
                      </Box>
                    }
                  />
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          {/* NSE Scripts */}
          <Accordion sx={{ mb: 2, bgcolor: "transparent", boxShadow: "none", border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon sx={{ color: accentColor, fontSize: 20 }} />
                <Typography variant="subtitle2" fontWeight={600}>NSE Scripts</Typography>
                {selectedScripts.length > 0 && (
                  <Chip label={selectedScripts.length} size="small" sx={{ ml: 1, bgcolor: alpha(accentColor, 0.1) }} />
                )}
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={1} sx={{ mb: 2 }}>
                {NSE_SCRIPT_CATEGORIES.map((script) => (
                  <Grid item xs={12} sm={6} md={4} key={script.value}>
                    <Paper
                      elevation={0}
                      onClick={() => handleScriptToggle(script.value)}
                      sx={{
                        p: 1.5,
                        cursor: "pointer",
                        border: `1px solid ${selectedScripts.includes(script.value) ? accentColor : alpha(theme.palette.divider, 0.5)}`,
                        bgcolor: selectedScripts.includes(script.value) ? alpha(accentColor, 0.1) : "transparent",
                        borderRadius: 1,
                        "&:hover": { bgcolor: alpha(accentColor, 0.05) },
                      }}
                    >
                      <Typography variant="body2" fontWeight={600}>{script.label}</Typography>
                      <Typography variant="caption" color="text.secondary">{script.description}</Typography>
                      {script.value === "exploit" && (
                        <Chip label="DANGEROUS" size="small" sx={{ ml: 1, height: 16, fontSize: "0.6rem", bgcolor: alpha("#ef4444", 0.2), color: "#ef4444" }} />
                      )}
                    </Paper>
                  </Grid>
                ))}
              </Grid>
              <TextField
                fullWidth
                size="small"
                label="Custom Script"
                placeholder="http-vuln-*, smb-vuln-ms17-010, ssl-heartbleed"
                value={customScript}
                onChange={(e) => setCustomScript(e.target.value)}
                helperText="Enter specific script names or wildcards"
              />
            </AccordionDetails>
          </Accordion>

          {/* Evasion & Stealth */}
          <Accordion sx={{ mb: 2, bgcolor: "transparent", boxShadow: "none", border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <VisibilityOffIcon sx={{ color: accentColor, fontSize: 20 }} />
                <Typography variant="subtitle2" fontWeight={600}>Evasion & Stealth</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={skipPing}
                        onChange={(e) => setSkipPing(e.target.checked)}
                        sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">Skip Host Discovery (-Pn)</Typography>
                        <Typography variant="caption" color="text.secondary">Treat all hosts as online</Typography>
                      </Box>
                    }
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={fragmentPackets}
                        onChange={(e) => setFragmentPackets(e.target.checked)}
                        sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">Fragment Packets (-f)</Typography>
                        <Typography variant="caption" color="text.secondary">Split packets to evade filters</Typography>
                      </Box>
                    }
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={decoys}
                        onChange={(e) => setDecoys(e.target.checked)}
                        sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">Use Decoys (-D RND:{decoyCount})</Typography>
                        <Typography variant="caption" color="text.secondary">Hide among random fake IPs</Typography>
                      </Box>
                    }
                  />
                </Grid>
                {decoys && (
                  <Grid item xs={12} sm={6}>
                    <TextField
                      size="small"
                      type="number"
                      label="Number of Decoys"
                      value={decoyCount}
                      onChange={(e) => setDecoyCount(parseInt(e.target.value) || 5)}
                      inputProps={{ min: 1, max: 20 }}
                    />
                  </Grid>
                )}
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={spoofMac}
                        onChange={(e) => setSpoofMac(e.target.checked)}
                        sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">Spoof MAC (--spoof-mac 0)</Typography>
                        <Typography variant="caption" color="text.secondary">Randomize MAC address</Typography>
                      </Box>
                    }
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    size="small"
                    label="Source Port (-g)"
                    placeholder="53, 80, 443"
                    value={sourcePort}
                    onChange={(e) => setSourcePort(e.target.value)}
                    helperText="Use trusted port (e.g., 53 for DNS)"
                  />
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          {/* Output Options */}
          <Accordion sx={{ mb: 2, bgcolor: "transparent", boxShadow: "none", border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <OutputIcon sx={{ color: accentColor, fontSize: 20 }} />
                <Typography variant="subtitle2" fontWeight={600}>Output Options</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Verbosity</InputLabel>
                    <Select
                      value={verbosity}
                      label="Verbosity"
                      onChange={(e) => setVerbosity(e.target.value as number)}
                    >
                      <MenuItem value={0}>Normal</MenuItem>
                      <MenuItem value={1}>Verbose (-v)</MenuItem>
                      <MenuItem value={2}>Very Verbose (-vv)</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={openOnly}
                        onChange={(e) => setOpenOnly(e.target.checked)}
                        sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">Open Ports Only (--open)</Typography>
                        <Typography variant="caption" color="text.secondary">Hide closed/filtered ports</Typography>
                      </Box>
                    }
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Output Format</InputLabel>
                    <Select
                      value={outputFormat}
                      label="Output Format"
                      onChange={(e) => setOutputFormat(e.target.value)}
                    >
                      <MenuItem value="">None (stdout only)</MenuItem>
                      {OUTPUT_FORMATS.map(f => (
                        <MenuItem key={f.value} value={f.value}>{f.label}</MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
                {outputFormat && (
                  <Grid item xs={12} sm={6}>
                    <TextField
                      fullWidth
                      size="small"
                      label="Output Filename"
                      value={outputFile}
                      onChange={(e) => setOutputFile(e.target.value)}
                      helperText={`Will save as ${outputFile}${OUTPUT_FORMATS.find(f => f.value === outputFormat)?.ext || ""}`}
                    />
                  </Grid>
                )}
              </Grid>
            </AccordionDetails>
          </Accordion>

          {/* Quick Presets */}
          <Divider sx={{ my: 2 }} />
          <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1.5, display: "flex", alignItems: "center", gap: 0.5 }}>
            ⚡ Quick Presets
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {[
              { label: "Quick Scan", action: () => { setScanType("syn"); setTiming(4); setPortSpec("default"); } },
              { label: "Full Scan", action: () => { setScanType("syn"); setTiming(4); setPortSpec("all"); setServiceVersion(true); } },
              { label: "Aggressive", action: () => { setScanType("syn"); setTiming(4); setAggressiveScan(true); } },
              { label: "Stealth", action: () => { setScanType("syn"); setTiming(2); setFragmentPackets(true); } },
              { label: "Vuln Scan", action: () => { setScanType("syn"); setServiceVersion(true); setSelectedScripts(["vuln"]); } },
              { label: "UDP Scan", action: () => { setScanType("udp"); setPortSpec("top"); setTopPorts(100); } },
              { label: "Host Discovery", action: () => { setScanType("ping"); } },
            ].map((preset) => (
              <Chip
                key={preset.label}
                label={preset.label}
                onClick={() => { resetAll(); preset.action(); }}
                sx={{
                  cursor: "pointer",
                  bgcolor: alpha(accentColor, 0.1),
                  "&:hover": { bgcolor: alpha(accentColor, 0.2) },
                }}
              />
            ))}
          </Box>
        </Box>
      </Collapse>
    </Paper>
  );
};

export default NmapCommandBuilder;
