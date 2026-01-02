/**
 * ReverseEngineeringHub - Interactive Reverse Engineering Analysis Page
 *
 * Provides tools for:
 * - Binary Analysis (EXE, ELF, DLL) - Extract strings, imports, metadata
 * - APK Analysis - Android app analysis with permission/security checks
 * - Docker Inspector - Inspect image layers, secrets, and attack vectors
 */

import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  Box,
  Container,
  Typography,
  Card,
  CardContent,
  Grid,
  Button,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  LinearProgress,
  alpha,
  useTheme,
  Divider,
  TextField,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  FormControlLabel,
  FormControl,
  Select,
  Switch,
  Slider,
  FormGroup,
  Breadcrumbs,
  Link as MuiLink,
  Autocomplete,
  Menu,
  MenuItem,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  InputLabel,
  Collapse,
} from "@mui/material";
import { Link, useSearchParams, useNavigate } from "react-router-dom";
import {
  CloudUpload as UploadIcon,
  Memory as BinaryIcon,
  Android as ApkIcon,
  Storage as DockerIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckIcon,
  Code as CodeIcon,
  VpnKey as SecretIcon,
  Functions as FunctionIcon,
  Layers as LayersIcon,
  SmartToy as AiIcon,
  Refresh as RefreshIcon,
  Home as HomeIcon,
  Hub as HubIcon,
  BugReport as BugIcon,
  BugReport as BugReportIcon,
  Lock as LockIcon,
  Shield as ShieldIcon,
  Info as InfoIcon,
  Search as SearchIcon,
  Save as SaveIcon,
  History as HistoryIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Share as ShareIcon,
  NavigateBefore as PrevIcon,
  NavigateNext as NextIcon,
  FirstPage as FirstPageIcon,
  LastPage as LastPageIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  AccountTree as ArchitectureIcon,
  Assessment as ReportIcon,
  InsertLink as LinkIcon,
  Folder as StorageIcon,
  Folder as FolderIcon,
  InsertDriveFile as InsertDriveFileIcon,
  ContentCopy as CopyIcon,
  Download as DownloadIcon,
  TrackChanges as TargetIcon,
  Description as DocIcon,
  PictureAsPdf as PdfIcon,
  Article as ArticleIcon,
  TextSnippet as WordIcon,
  Person as PersonIcon,
  Email as EmailIcon,
  Phone as PhoneIcon,
  Key as KeyIcon,
  AutoAwesome as AutoAwesomeIcon,
  Map as MapIcon,
  Terminal as TerminalIcon,
  Memory as MemoryIcon,
  AccessTime as AccessTimeIcon,
  Close as CloseIcon,
  ArrowBack as ArrowBackIcon,
} from "@mui/icons-material";
import {
  reverseEngineeringClient,
  type ReverseEngineeringStatus,
  type BinaryAnalysisResult,
  type ApkAnalysisResult,
  type ApkCertificate,
  type DockerAnalysisResult,
  type DockerImageInfo,
  type REReportSummary,
  type SaveREReportRequest,
  type DataFlowAnalysisResult,
  type JadxDecompilationResult,
  type AIVulnScanResult,
  type UnifiedApkScanProgress,
  type UnifiedApkScanResult,
  type UnifiedApkScanPhase,
  type UnifiedBinaryScanProgress,
  type AttackSurfaceMapResult,
  type EnhancedSecurityResult,
  type VulnerabilityHuntResult,
  type VulnerabilityFinding,
} from "../api/client";
import { MermaidDiagram } from "../components/MermaidDiagram";
import ShareToConversationDialog from "../components/social/ShareToConversationDialog";

// Advanced APK Analysis Components
import { JadxDecompiler, ManifestVisualizer, AttackSurfaceMap, ObfuscationAnalyzer } from "../components/ApkAdvancedAnalysis";

// Advanced Binary Analysis Components
import { EntropyVisualizer } from "../components/BinaryAdvancedAnalysis";
import { UnifiedBinaryResults } from "../components/UnifiedBinaryResults";

// AI Chat Panel and Guided Walkthrough
import ApkChatPanel from "../components/ApkChatPanel";
import GuidedWalkthrough from "../components/GuidedWalkthrough";
import LearnPageLayout from "../components/LearnPageLayout";

// Page context for AI chat
const pageContext = `This is the Reverse Engineering Hub page covering:
- Binary Analysis (EXE, ELF, DLL) - Extract strings, imports, metadata, entropy visualization
- APK Analysis - Android app analysis with permission/security checks, JADX decompilation, manifest analysis
- Docker Inspector - Layer inventory, secrets detection, and risk insights
- Ghidra integration for decompilation and function analysis
- AI-powered security scanning and vulnerability detection
- Attack surface mapping and obfuscation analysis
- Hex viewing and data flow analysis
Topics include: IDA Pro, Ghidra, radare2, x64dbg, debugging, disassembly, decompilation, malware analysis, reverse engineering techniques, binary exploitation, and mobile security testing.`;

// Severity colors
const getSeverityColor = (severity: string): string => {
  switch (severity.toLowerCase()) {
    case "critical":
      return "#dc2626";
    case "high":
      return "#ea580c";
    case "medium":
      return "#ca8a04";
    case "low":
      return "#16a34a";
    case "advisory":
      return "#3b82f6"; // Blue for advisory/informational hardening suggestions
    case "info":
      return "#6b7280";
    default:
      return "#6b7280";
  }
};

// Format seconds to human-readable time
const formatTimeSeconds = (seconds: number): string => {
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  } else if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    const secs = Math.round(seconds % 60);
    return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
  } else {
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  }
};

// Tab panel component
interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`re-tabpanel-${index}`}
      aria-labelledby={`re-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

// File drop zone component
interface FileDropZoneProps {
  accept: string;
  onFileSelect: (file: File) => void;
  label: string;
  description: string;
  icon: React.ReactNode;
  disabled?: boolean;
}

function FileDropZone({
  accept,
  onFileSelect,
  label,
  description,
  icon,
  disabled = false,
}: FileDropZoneProps) {
  const theme = useTheme();
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    if (!disabled) setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (disabled) return;

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      onFileSelect(files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      onFileSelect(e.target.files[0]);
    }
  };

  return (
    <Box
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      sx={{
        border: `2px dashed ${isDragging ? theme.palette.primary.main : theme.palette.divider}`,
        borderRadius: 2,
        p: 4,
        textAlign: "center",
        cursor: disabled ? "not-allowed" : "pointer",
        transition: "all 0.2s",
        bgcolor: isDragging
          ? alpha(theme.palette.primary.main, 0.1)
          : "transparent",
        opacity: disabled ? 0.5 : 1,
        "&:hover": disabled
          ? {}
          : {
              borderColor: theme.palette.primary.main,
              bgcolor: alpha(theme.palette.primary.main, 0.05),
            },
      }}
      component="label"
    >
      <input
        type="file"
        accept={accept}
        onChange={handleFileChange}
        hidden
        disabled={disabled}
      />
      <Box sx={{ color: theme.palette.primary.main, mb: 2 }}>{icon}</Box>
      <Typography variant="h6" gutterBottom>
        {label}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {description}
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
        Drag & drop or click to browse
      </Typography>
    </Box>
  );
}

// ============================================================================
// Unified APK Scanner Component with Progress Stepper
// ============================================================================

const SCAN_PHASE_ICONS: Record<string, React.ReactNode> = {
  manifest: <ApkIcon />,
  secrets: <SecretIcon />,
  jadx: <CodeIcon />,
  code_scan: <SecurityIcon />,
  sensitive_data: <PersonIcon />,
  cve_lookup: <WarningIcon />,
  vuln_hunt: <BugReportIcon />,
  verification: <CheckIcon />,
  ai_analysis: <AiIcon />,
  advanced_analysis: <ArchitectureIcon />,
  ai_reports: <ReportIcon />,
};

const SCAN_PHASE_LABELS: Record<string, string> = {
  manifest: "📋 Manifest Analysis",
  secrets: "🔑 Secret Detection",
  jadx: "☕ JADX Decompilation",
  code_scan: "🔍 Code Security Scan",
  sensitive_data: "🔐 Sensitive Data Discovery",
  cve_lookup: "🛡️ CVE Database Lookup",
  vuln_hunt: "🐛 AI Vulnerability Hunt",
  verification: "✅ AI Finding Verification",
  ai_analysis: "🧠 AI Deep Analysis",
  advanced_analysis: "🏗️ Advanced Analysis",
  ai_reports: "📝 AI Report Generation",
};

const BINARY_SCAN_PHASE_ICONS: Record<string, React.ReactNode> = {
  static: <BinaryIcon />,
  ghidra: <CodeIcon />,
  ghidra_ai: <AiIcon />,
  ai_summary: <SecurityIcon />,
  pattern_scan: <SearchIcon />,
  cve_lookup: <WarningIcon />,
  sensitive_scan: <SecretIcon />,
  vuln_hunt: <BugReportIcon />,
  ai_verification: <CheckIcon />,
  advanced_analysis: <ArchitectureIcon />,
  attack_surface: <MapIcon />,
  dynamic_scripts: <TerminalIcon />,
  emulation: <MemoryIcon />,
  ai_reports: <ReportIcon />,
};

const BINARY_SCAN_PHASE_LABELS: Record<string, string> = {
  static: "📊 Static Analysis",
  ghidra: "🔬 Ghidra Decompilation",
  ghidra_ai: "🧠 Ghidra AI Summaries",
  ai_summary: "✨ AI Security Summary",
  pattern_scan: "🔍 Pattern Vulnerability Scan",
  cve_lookup: "🛡️ CVE Database Lookup",
  sensitive_scan: "🔑 Sensitive Data Discovery",
  vuln_hunt: "🐛 AI Vulnerability Hunt",
  ai_verification: "✅ AI Findings Verification",
  advanced_analysis: "🏗️ Advanced Analysis",
  attack_surface: "🗺️ Attack Surface Mapping",
  dynamic_scripts: "⚡ Dynamic Analysis Scripts",
  emulation: "🎮 Emulation Analysis",
  ai_reports: "📝 AI Report Generation",
};

interface UnifiedApkScannerProps {
  apkFile: File | null;
  onFileSelect: (file: File | null) => void;
  onScanComplete: (result: UnifiedApkScanResult) => void;
  onJadxSessionReady: (sessionId: string) => void;
}

function UnifiedApkScanner({ 
  apkFile, 
  onFileSelect, 
  onScanComplete,
  onJadxSessionReady,
}: UnifiedApkScannerProps) {
  const theme = useTheme();
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<UnifiedApkScanProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<{ abort: () => void } | null>(null);
  
  // Vuln Hunt Options - enabled by default with increased limits
  const [includeVulnHunt, setIncludeVulnHunt] = useState(true);
  const [vulnHuntMaxPasses, setVulnHuntMaxPasses] = useState(5);
  const [vulnHuntMaxTargets, setVulnHuntMaxTargets] = useState(50);
  const [vulnHuntExpanded, setVulnHuntExpanded] = useState(false);
  
  const startScan = useCallback(() => {
    if (!apkFile) return;
    
    setIsScanning(true);
    setError(null);
    setProgress(null);
    
    const controller = reverseEngineeringClient.runUnifiedApkScan(
      apkFile,
      // onProgress
      (prog) => {
        setProgress(prog);
      },
      // onResult
      (result) => {
        if (result.jadx_session_id) {
          onJadxSessionReady(result.jadx_session_id);
        }
        onScanComplete(result);
        setIsScanning(false);
      },
      // onError
      (err) => {
        setError(err);
        setIsScanning(false);
      },
      // onDone
      () => {
        setIsScanning(false);
      },
      // Options
      {
        includeVulnHunt,
        vulnHuntMaxPasses,
        vulnHuntMaxTargets,
      }
    );
    
    abortRef.current = controller;
  }, [apkFile, onScanComplete, onJadxSessionReady, includeVulnHunt, vulnHuntMaxPasses, vulnHuntMaxTargets]);
  
  const cancelScan = useCallback(() => {
    abortRef.current?.abort();
    setIsScanning(false);
    setProgress(null);
  }, []);
  
  // Get active step index
  const getActiveStep = () => {
    if (!progress) return -1;
    return progress.phases.findIndex(p => p.status === "in_progress");
  };
  
  const activeStep = getActiveStep();
  
  return (
    <Box>
      {/* File Selection */}
      {!isScanning && !progress && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={5}>
            <FileDropZone
              accept=".apk,.aab"
              onFileSelect={(f) => {
                onFileSelect(f);
                setError(null);
              }}
              label="Upload APK"
              description="Android APK or AAB files up to 500MB"
              icon={<ApkIcon sx={{ fontSize: 48 }} />}
              disabled={isScanning}
            />
          </Grid>
          <Grid item xs={12} md={7}>
            {apkFile ? (
              <Paper sx={{ p: 3, height: "100%" }}>
                <Alert severity="info" sx={{ mb: 2 }}>
                  <strong>{apkFile.name}</strong> ({(apkFile.size / (1024 * 1024)).toFixed(1)} MB)
                </Alert>
                
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  This comprehensive scan will:
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon><ApkIcon color="primary" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Extract manifest, permissions & components" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><SecretIcon color="warning" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Scan for hardcoded secrets, API keys & URLs" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><CodeIcon color="secondary" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Decompile DEX to Java source code (JADX)" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><AiIcon color="info" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Generate AI-powered functionality & security reports" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><ArchitectureIcon color="success" fontSize="small" /></ListItemIcon>
                    <ListItemText primary="Create visual architecture diagram" />
                  </ListItem>
                </List>
                
                {/* AI Vulnerability Hunt Option */}
                <Box sx={{ mt: 2, p: 2, bgcolor: alpha(theme.palette.error.main, 0.05), borderRadius: 1, border: '1px solid', borderColor: alpha(theme.palette.error.main, 0.2) }}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={includeVulnHunt}
                        onChange={(e) => setIncludeVulnHunt(e.target.checked)}
                        color="error"
                      />
                    }
                    label={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                        <BugReportIcon fontSize="small" color="error" />
                        <Typography variant="body2" fontWeight="medium">AI Vulnerability Hunt</Typography>
                        <Chip label="Multi-Pass" size="small" color="error" variant="outlined" sx={{ fontSize: '0.6rem', height: 18, ml: 0.5 }} />
                      </Box>
                    }
                  />
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', ml: 5.5 }}>
                    Deep AI-guided vulnerability hunting with iterative analysis passes
                  </Typography>
                  
                  {includeVulnHunt && (
                    <Box sx={{ mt: 1, ml: 2 }}>
                      <Typography 
                        variant="caption" 
                        color="text.secondary" 
                        sx={{ 
                          cursor: 'pointer', 
                          display: 'flex', 
                          alignItems: 'center',
                          '&:hover': { color: 'primary.main' }
                        }}
                        onClick={() => setVulnHuntExpanded(!vulnHuntExpanded)}
                      >
                        {vulnHuntExpanded ? '▼' : '▶'} Advanced settings
                      </Typography>
                      {vulnHuntExpanded && (
                        <Box sx={{ mt: 1, pl: 1.5 }}>
                          <Typography variant="caption" color="text.secondary">
                            Max passes: {vulnHuntMaxPasses}
                          </Typography>
                          <Slider
                            value={vulnHuntMaxPasses}
                            onChange={(_, value) => setVulnHuntMaxPasses(value as number)}
                            min={2}
                            max={8}
                            step={1}
                            marks
                            size="small"
                            sx={{ mt: 0.5 }}
                          />
                          <Typography variant="caption" color="text.secondary">
                            Targets per pass: {vulnHuntMaxTargets}
                          </Typography>
                          <Slider
                            value={vulnHuntMaxTargets}
                            onChange={(_, value) => setVulnHuntMaxTargets(value as number)}
                            min={10}
                            max={100}
                            step={10}
                            size="small"
                            sx={{ mt: 0.5 }}
                          />
                        </Box>
                      )}
                    </Box>
                  )}
                </Box>
                
                <Alert severity="warning" sx={{ mt: 2, mb: 2 }}>
                  <Typography variant="body2">
                    ⏱️ This comprehensive scan may take <strong>{includeVulnHunt ? '5-10' : '2-5'} minutes</strong> depending on APK size.
                  </Typography>
                </Alert>
                
                <Button
                  variant="contained"
                  size="large"
                  fullWidth
                  onClick={startScan}
                  startIcon={<PlayIcon />}
                  sx={{
                    py: 1.5,
                    background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                  }}
                >
                  Start Full Analysis
                </Button>
                
                <Button
                  variant="text"
                  size="small"
                  fullWidth
                  onClick={() => onFileSelect(null)}
                  sx={{ mt: 1 }}
                >
                  Choose Different File
                </Button>
              </Paper>
            ) : (
              <Box sx={{ 
                height: "100%", 
                display: "flex", 
                flexDirection: "column", 
                alignItems: "center", 
                justifyContent: "center",
                textAlign: "center",
                p: 4,
                bgcolor: alpha(theme.palette.background.paper, 0.5),
                borderRadius: 2,
              }}>
                <ApkIcon sx={{ fontSize: 64, opacity: 0.3, mb: 2 }} />
                <Typography variant="h6" color="text.secondary">
                  Upload an Android APK to analyze
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  One comprehensive scan covering permissions, secrets, decompilation, and AI analysis
                </Typography>
              </Box>
            )}
          </Grid>
        </Grid>
      )}
      
      {/* Scanning Progress */}
      {isScanning && progress && (
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
            <Box>
              <Typography variant="h6">
                🔍 Analyzing: {apkFile?.name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {progress.message}
              </Typography>
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Typography variant="h4" color="primary">
                {progress.overall_progress}%
              </Typography>
              <Button
                variant="outlined"
                color="error"
                size="small"
                onClick={cancelScan}
                startIcon={<StopIcon />}
              >
                Cancel
              </Button>
            </Box>
          </Box>
          
          {/* Overall Progress Bar */}
          <LinearProgress 
            variant="determinate" 
            value={progress.overall_progress} 
            sx={{ 
              height: 8, 
              borderRadius: 4, 
              mb: 3,
              "& .MuiLinearProgress-bar": {
                background: `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
              }
            }} 
          />
          
          {/* Phase Stepper */}
          <Stepper activeStep={activeStep} orientation="vertical">
            {progress.phases.map((phase, index) => (
              <Step key={phase.id} completed={phase.status === "completed"}>
                <StepLabel
                  error={phase.status === "error"}
                  StepIconComponent={() => (
                    <Box
                      sx={{
                        width: 36,
                        height: 36,
                        borderRadius: "50%",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        bgcolor: phase.status === "completed"
                          ? theme.palette.success.main
                          : phase.status === "in_progress"
                          ? theme.palette.primary.main
                          : phase.status === "error"
                          ? theme.palette.error.main
                          : alpha(theme.palette.action.disabled, 0.3),
                        color: phase.status === "pending" ? "text.disabled" : "white",
                        transition: "all 0.3s",
                      }}
                    >
                      {phase.status === "completed" ? (
                        <CheckIcon sx={{ fontSize: 20 }} />
                      ) : phase.status === "in_progress" ? (
                        <CircularProgress size={20} color="inherit" />
                      ) : phase.status === "error" ? (
                        <ErrorIcon sx={{ fontSize: 20 }} />
                      ) : SCAN_PHASE_ICONS[phase.id] ? (
                        React.cloneElement(SCAN_PHASE_ICONS[phase.id] as React.ReactElement, { sx: { fontSize: 18 } })
                      ) : (
                        <SecurityIcon sx={{ fontSize: 18 }} />
                      )}
                    </Box>
                  )}
                >
                  <Typography fontWeight={phase.status === "in_progress" ? 700 : 500}>
                    {SCAN_PHASE_LABELS[phase.id] || phase.label}
                  </Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary">
                    {phase.description}
                  </Typography>
                  {phase.status === "in_progress" && (
                    <>
                      <LinearProgress 
                        variant={phase.progress > 0 ? "determinate" : "indeterminate"}
                        value={phase.progress || 0}
                        sx={{ 
                          mt: 1.5,
                          borderRadius: 1,
                          height: 6,
                          "& .MuiLinearProgress-bar": {
                            background: `linear-gradient(90deg, ${theme.palette.primary.light}, ${theme.palette.primary.main})`,
                          }
                        }} 
                      />
                      {phase.details && (
                        <Typography 
                          variant="caption" 
                          color="info.main" 
                          sx={{ 
                            mt: 0.5, 
                            display: "block",
                            fontStyle: "italic",
                            animation: "pulse 2s infinite",
                            "@keyframes pulse": {
                              "0%, 100%": { opacity: 1 },
                              "50%": { opacity: 0.6 },
                            }
                          }}
                        >
                          ⏳ {phase.details}
                        </Typography>
                      )}
                    </>
                  )}
                  {phase.status === "completed" && phase.details && (
                    <Typography variant="caption" color="success.main" sx={{ mt: 0.5, display: "block" }}>
                      ✓ {phase.details}
                    </Typography>
                  )}
                  {phase.status === "error" && phase.details && (
                    <Typography variant="caption" color="error" sx={{ mt: 0.5, display: "block" }}>
                      ✗ {phase.details}
                    </Typography>
                  )}
                </StepContent>
              </Step>
            ))}
          </Stepper>
        </Paper>
      )}
      
      {/* Initial Loading State - When scan starts but no progress yet */}
      {isScanning && !progress && (
        <Paper sx={{ p: 4, textAlign: "center" }}>
          <CircularProgress size={60} sx={{ mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            🚀 Starting Comprehensive APK Analysis...
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Uploading <strong>{apkFile?.name}</strong> and initializing scan
          </Typography>
          <Alert severity="info" sx={{ maxWidth: 500, mx: "auto" }}>
            This may take a moment for large APK files. Progress will appear shortly.
          </Alert>
          <Button
            variant="outlined"
            color="error"
            size="small"
            onClick={cancelScan}
            startIcon={<StopIcon />}
            sx={{ mt: 2 }}
          >
            Cancel
          </Button>
        </Paper>
      )}
      
      {/* Error Display */}
      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mt: 2 }}>
          {error}
        </Alert>
      )}
    </Box>
  );
}

// ============================================================================
// Decompiled Code Security Findings Component
// ============================================================================

interface DecompiledCodeFindingsAccordionProps {
  findings: Array<{
    scanner: string;
    category: string;
    severity: string;
    title: string;
    description: string;
    class_name: string;
    file_path: string;
    line_number: number;
    code_snippet: string;
    context_before: string;
    context_after: string;
    exploitation: string;
    remediation: string;
    cwe_id?: string;
    confidence: string;
  }>;
  summary?: {
    total_findings: number;
    by_severity: Record<string, number>;
    by_scanner: Record<string, number>;
    by_category: Record<string, number>;
    files_scanned: number;
  };
  jadxSessionId?: string;
}

// ===== SENSITIVE DATA FINDINGS SECTION COMPONENT =====
// Dedicated section for AI-verified passwords, API keys, emails, phone numbers, PII
function SensitiveDataFindingsSection({ result }: { result: ApkAnalysisResult | UnifiedApkScanResult }) {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(true);
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [showFiltered, setShowFiltered] = useState(false);
  
  const sensitiveData = (result as any).sensitive_data_findings;
  
  // Don't render if no sensitive data findings
  if (!sensitiveData?.findings || sensitiveData.findings.length === 0) {
    return null;
  }
  
  const findings = sensitiveData.findings;
  const filteredOut = sensitiveData.filtered_out || [];
  const summary = sensitiveData.summary || {};
  const stats = sensitiveData.scan_stats || {};
  
  const categoryIcons: Record<string, React.ReactNode> = {
    password: <LockIcon fontSize="small" />,
    api_key: <SecretIcon fontSize="small" />,
    username: <PersonIcon fontSize="small" />,
    email: <EmailIcon fontSize="small" />,
    phone: <PhoneIcon fontSize="small" />,
    personal_name: <PersonIcon fontSize="small" />,
    private_key: <KeyIcon fontSize="small" />,
    database_url: <StorageIcon fontSize="small" />,
  };
  
  const categoryLabels: Record<string, string> = {
    password: "Passwords",
    api_key: "API Keys",
    username: "Usernames",
    email: "Email Addresses",
    phone: "Phone Numbers",
    personal_name: "Personal Names",
    private_key: "Private Keys",
    database_url: "Database URLs",
  };
  
  const riskColors: Record<string, "error" | "warning" | "info" | "success"> = {
    critical: "error",
    high: "error",
    medium: "warning",
    low: "info",
    none: "success",
  };
  
  const categories = [...new Set(findings.map((f: any) => f.category))];
  
  const filteredFindings = findings.filter((f: any) => {
    if (categoryFilter !== "all" && f.category !== categoryFilter) return false;
    if (riskFilter !== "all" && f.ai_verification?.risk_level !== riskFilter) return false;
    return true;
  });
  
  // Sort by risk level
  const riskOrder = ["critical", "high", "medium", "low", "none"];
  const sortedFindings = [...filteredFindings].sort((a: any, b: any) => {
    const aRisk = a.ai_verification?.risk_level || "medium";
    const bRisk = b.ai_verification?.risk_level || "medium";
    return riskOrder.indexOf(aRisk) - riskOrder.indexOf(bRisk);
  });
  
  const criticalCount = summary.by_risk?.critical || 0;
  const highCount = summary.by_risk?.high || 0;
  
  return (
    <Paper 
      sx={{ 
        p: 0, 
        mb: 3, 
        border: `2px solid ${alpha(theme.palette.error.main, 0.3)}`,
        overflow: "hidden"
      }}
    >
      {/* Header */}
      <Box 
        sx={{ 
          p: 2, 
          bgcolor: alpha(theme.palette.error.main, 0.08),
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between"
        }}
        onClick={() => setExpanded(!expanded)}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <PersonIcon color="error" />
            <Typography variant="h6" fontWeight={600}>
              🔐 Sensitive Data Discovery
            </Typography>
          </Box>
          <Chip 
            label={`${findings.length} findings`} 
            size="small" 
            color="error" 
          />
          {criticalCount > 0 && (
            <Chip 
              label={`${criticalCount} Critical`} 
              size="small" 
              color="error" 
              variant="filled"
            />
          )}
          {highCount > 0 && (
            <Chip 
              label={`${highCount} High Risk`} 
              size="small" 
              color="warning" 
            />
          )}
          <Chip 
            label="AI Verified" 
            size="small" 
            icon={<AutoAwesomeIcon />}
            sx={{ bgcolor: alpha(theme.palette.info.main, 0.1) }}
          />
        </Box>
        {expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
      </Box>
      
      <Collapse in={expanded}>
        {/* Summary Stats */}
        <Box sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), borderBottom: `1px solid ${theme.palette.divider}` }}>
          <Grid container spacing={2}>
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">Files Scanned</Typography>
              <Typography variant="h6">{stats.files_scanned?.toLocaleString() || 0}</Typography>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">Raw Matches</Typography>
              <Typography variant="h6">{stats.raw_matches?.toLocaleString() || 0}</Typography>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">AI Verified</Typography>
              <Typography variant="h6" color="success.main">{stats.verified || 0}</Typography>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">False Positives Filtered</Typography>
              <Typography variant="h6" color="text.secondary">{stats.filtered || 0}</Typography>
            </Grid>
          </Grid>
          
          {/* Category breakdown */}
          <Box sx={{ mt: 2 }}>
            <Typography variant="caption" color="text.secondary" gutterBottom display="block">By Category:</Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {Object.entries(summary.by_category || {}).map(([cat, count]: [string, any]) => (
                <Chip
                  key={cat}
                  icon={categoryIcons[cat] as any}
                  label={`${categoryLabels[cat] || cat}: ${count}`}
                  size="small"
                  variant={categoryFilter === cat ? "filled" : "outlined"}
                  color={categoryFilter === cat ? "primary" : "default"}
                  onClick={() => setCategoryFilter(categoryFilter === cat ? "all" : cat)}
                />
              ))}
            </Box>
          </Box>
        </Box>
        
        {/* Filters */}
        <Box sx={{ p: 2, display: "flex", gap: 2, alignItems: "center", flexWrap: "wrap", borderBottom: `1px solid ${theme.palette.divider}` }}>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Risk Level</InputLabel>
            <Select
              value={riskFilter}
              label="Risk Level"
              onChange={(e) => setRiskFilter(e.target.value)}
            >
              <MenuItem value="all">All Risks</MenuItem>
              <MenuItem value="critical">🔴 Critical</MenuItem>
              <MenuItem value="high">🟠 High</MenuItem>
              <MenuItem value="medium">🟡 Medium</MenuItem>
              <MenuItem value="low">🟢 Low</MenuItem>
            </Select>
          </FormControl>
          
          <Typography variant="body2" color="text.secondary">
            Showing {sortedFindings.length} of {findings.length} findings
          </Typography>
        </Box>
        
        {/* Findings Table */}
        <TableContainer sx={{ maxHeight: 500 }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell>Category</TableCell>
                <TableCell>Value</TableCell>
                <TableCell>Location</TableCell>
                <TableCell>Risk</TableCell>
                <TableCell>AI Confidence</TableCell>
                <TableCell>Details</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {sortedFindings.map((finding: any, idx: number) => (
                <TableRow 
                  key={idx}
                  sx={{ 
                    bgcolor: finding.ai_verification?.risk_level === 'critical' 
                      ? alpha(theme.palette.error.main, 0.08) 
                      : finding.ai_verification?.risk_level === 'high'
                      ? alpha(theme.palette.warning.main, 0.05)
                      : undefined
                  }}
                >
                  <TableCell>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                      {categoryIcons[finding.category]}
                      <Typography variant="body2" fontWeight={500}>
                        {categoryLabels[finding.category] || finding.category}
                      </Typography>
                    </Box>
                    {finding.ai_verification?.specific_type && (
                      <Typography variant="caption" color="text.secondary" display="block">
                        {finding.ai_verification.specific_type}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Tooltip title={`Full value (masked): ${finding.masked_value}`}>
                      <Typography 
                        variant="body2" 
                        fontFamily="monospace"
                        sx={{ 
                          maxWidth: 200, 
                          overflow: "hidden", 
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          cursor: "pointer"
                        }}
                      >
                        {finding.masked_value}
                      </Typography>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" fontFamily="monospace" display="block">
                      {finding.file_path?.split('/').pop() || 'Unknown'}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Line {finding.line}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={finding.ai_verification?.risk_level || 'unverified'} 
                      size="small"
                      color={riskColors[finding.ai_verification?.risk_level] || "default"}
                    />
                  </TableCell>
                  <TableCell>
                    {finding.ai_verification?.confidence ? (
                      <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                        <LinearProgress 
                          variant="determinate" 
                          value={finding.ai_verification.confidence * 100}
                          sx={{ width: 60, height: 6, borderRadius: 3 }}
                          color={finding.ai_verification.confidence > 0.8 ? "success" : finding.ai_verification.confidence > 0.5 ? "warning" : "error"}
                        />
                        <Typography variant="caption">
                          {(finding.ai_verification.confidence * 100).toFixed(0)}%
                        </Typography>
                      </Box>
                    ) : (
                      <Typography variant="caption" color="text.secondary">N/A</Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Tooltip 
                      title={
                        <Box>
                          <Typography variant="caption" fontWeight={600}>AI Reasoning:</Typography>
                          <Typography variant="caption" display="block">
                            {finding.ai_verification?.reasoning || 'No AI analysis available'}
                          </Typography>
                          {finding.code_context && (
                            <>
                              <Typography variant="caption" fontWeight={600} sx={{ mt: 1 }} display="block">Code Context:</Typography>
                              <Typography variant="caption" fontFamily="monospace" display="block" sx={{ whiteSpace: "pre-wrap" }}>
                                {finding.code_context}
                              </Typography>
                            </>
                          )}
                        </Box>
                      }
                      arrow
                      placement="left"
                    >
                      <IconButton size="small">
                        <InfoIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        
        {/* Filtered Out Section */}
        {filteredOut.length > 0 && (
          <Box sx={{ p: 2, borderTop: `1px solid ${theme.palette.divider}` }}>
            <Button
              size="small"
              onClick={() => setShowFiltered(!showFiltered)}
              startIcon={showFiltered ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            >
              {showFiltered ? "Hide" : "Show"} {filteredOut.length} Filtered False Positives
            </Button>
            <Collapse in={showFiltered}>
              <Box sx={{ mt: 2, p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), borderRadius: 1 }}>
                <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                  These matches were filtered out by AI as false positives:
                </Typography>
                {filteredOut.slice(0, 20).map((item: any, idx: number) => (
                  <Box key={idx} sx={{ py: 0.5, borderBottom: `1px dashed ${theme.palette.divider}` }}>
                    <Typography variant="caption" fontFamily="monospace">
                      [{item.category}] {item.value?.substring(0, 50)}...
                    </Typography>
                    <Typography variant="caption" color="text.secondary" display="block">
                      Filtered: {item.filter_reason}
                    </Typography>
                  </Box>
                ))}
                {filteredOut.length > 20 && (
                  <Typography variant="caption" color="text.secondary">
                    ... and {filteredOut.length - 20} more
                  </Typography>
                )}
              </Box>
            </Collapse>
          </Box>
        )}
      </Collapse>
    </Paper>
  );
}

function DecompiledCodeFindingsAccordion({ findings, summary, jadxSessionId }: DecompiledCodeFindingsAccordionProps) {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<typeof findings[0] | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  
  const severityColors: Record<string, "error" | "warning" | "info" | "success" | "default" | "primary"> = {
    critical: "error",
    high: "error",
    medium: "warning",
    low: "info",
    advisory: "primary", // Blue for hardening suggestions (not vulnerabilities)
    info: "default"
  };
  
  const severityOrder = ["critical", "high", "medium", "low", "info", "advisory"];
  
  const filteredFindings = findings.filter(f => {
    if (severityFilter !== "all" && f.severity !== severityFilter) return false;
    if (categoryFilter !== "all" && f.category !== categoryFilter) return false;
    return true;
  });
  
  const sortedFindings = [...filteredFindings].sort((a, b) => {
    const aIdx = severityOrder.indexOf(a.severity);
    const bIdx = severityOrder.indexOf(b.severity);
    return aIdx - bIdx;
  });
  
  const categories = [...new Set(findings.map(f => f.category))];
  
  const criticalCount = summary?.by_severity?.critical || 0;
  const highCount = summary?.by_severity?.high || 0;
  
  return (
    <>
      <Accordion expanded={expanded} onChange={(_, exp) => setExpanded(exp)}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
            <BugReportIcon color="error" />
            <strong>Source Code Vulnerabilities ({findings.length})</strong>
            {criticalCount > 0 && (
              <Chip label={`${criticalCount} Critical`} size="small" color="error" />
            )}
            {highCount > 0 && (
              <Chip label={`${highCount} High`} size="small" color="error" variant="outlined" />
            )}
            {summary?.files_scanned && (
              <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                ({summary.files_scanned} files scanned)
              </Typography>
            )}
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          {/* Summary chips */}
          {summary && (
            <Box sx={{ mb: 2, display: "flex", gap: 1, flexWrap: "wrap" }}>
              {Object.entries(summary.by_severity || {}).map(([sev, count]) => (
                <Chip 
                  key={sev} 
                  label={`${sev}: ${count}`} 
                  size="small"
                  color={severityColors[sev] || "default"}
                  variant={severityFilter === sev ? "filled" : "outlined"}
                  onClick={() => setSeverityFilter(severityFilter === sev ? "all" : sev)}
                  sx={{ cursor: "pointer" }}
                />
              ))}
            </Box>
          )}
          
          {/* Category filter */}
          <Box sx={{ mb: 2 }}>
            <FormControl size="small" sx={{ minWidth: 200 }}>
              <InputLabel>Category</InputLabel>
              <Select
                value={categoryFilter}
                label="Category"
                onChange={(e) => setCategoryFilter(e.target.value)}
              >
                <MenuItem value="all">All Categories</MenuItem>
                {categories.map(cat => (
                  <MenuItem key={cat} value={cat}>{cat}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Box>
          
          {/* Findings table */}
          <TableContainer component={Paper} variant="outlined" sx={{ maxHeight: 400, overflow: "auto" }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell>Severity</TableCell>
                  <TableCell>Title</TableCell>
                  <TableCell>Category</TableCell>
                  <TableCell>File</TableCell>
                  <TableCell>Line</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {sortedFindings.slice(0, 100).map((finding, idx) => (
                  <TableRow 
                    key={idx}
                    hover
                    sx={{ 
                      cursor: "pointer",
                      bgcolor: finding.severity === "critical" ? alpha(theme.palette.error.main, 0.05) : undefined
                    }}
                    onClick={() => setSelectedFinding(finding)}
                  >
                    <TableCell>
                      <Chip 
                        label={finding.severity.toUpperCase()} 
                        size="small" 
                        color={severityColors[finding.severity]}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {finding.title}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={finding.category} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" fontFamily="monospace">
                        {finding.class_name}.java
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" fontFamily="monospace">
                        L{finding.line_number}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Tooltip title="View Details">
                        <IconButton size="small" onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(finding);
                        }}>
                          <CodeIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          
          {sortedFindings.length > 100 && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              Showing 100 of {sortedFindings.length} findings. Apply filters to narrow down.
            </Typography>
          )}
        </AccordionDetails>
      </Accordion>
      
      {/* Finding Detail Dialog */}
      <Dialog 
        open={!!selectedFinding} 
        onClose={() => setSelectedFinding(null)}
        maxWidth="md"
        fullWidth
      >
        {selectedFinding && (
          <>
            <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <Chip 
                label={selectedFinding.severity.toUpperCase()} 
                color={severityColors[selectedFinding.severity]}
              />
              {selectedFinding.title}
              {selectedFinding.cwe_id && (
                <Chip label={selectedFinding.cwe_id} size="small" variant="outlined" />
              )}
            </DialogTitle>
            <DialogContent dividers>
              <Typography variant="body1" paragraph>
                {selectedFinding.description}
              </Typography>
              
              <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                📍 Location
              </Typography>
              <Box sx={{ 
                bgcolor: alpha(theme.palette.background.default, 0.5), 
                p: 1, 
                borderRadius: 1,
                fontFamily: "monospace",
                fontSize: "0.85rem"
              }}>
                <strong>{selectedFinding.file_path}</strong> at line {selectedFinding.line_number}
              </Box>
              
              <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                💻 Vulnerable Code
              </Typography>
              <Box sx={{ 
                bgcolor: "#1e1e1e", 
                color: "#d4d4d4", 
                p: 2, 
                borderRadius: 1,
                fontFamily: "monospace",
                fontSize: "0.8rem",
                overflow: "auto",
                whiteSpace: "pre-wrap"
              }}>
                {selectedFinding.context_before && (
                  <Box sx={{ color: "#808080" }}>{selectedFinding.context_before}</Box>
                )}
                <Box sx={{ 
                  bgcolor: alpha(theme.palette.error.main, 0.2),
                  borderLeft: `3px solid ${theme.palette.error.main}`,
                  pl: 1,
                  my: 0.5
                }}>
                  {selectedFinding.code_snippet}
                </Box>
                {selectedFinding.context_after && (
                  <Box sx={{ color: "#808080" }}>{selectedFinding.context_after}</Box>
                )}
              </Box>
              
              <Typography variant="subtitle2" gutterBottom sx={{ mt: 3, color: "error.main" }}>
                🎯 Exploitation
              </Typography>
              <Box sx={{ 
                bgcolor: alpha(theme.palette.error.main, 0.05), 
                p: 2, 
                borderRadius: 1,
                border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`,
                whiteSpace: "pre-wrap",
                fontSize: "0.9rem"
              }}>
                {selectedFinding.exploitation}
              </Box>
              
              <Typography variant="subtitle2" gutterBottom sx={{ mt: 3, color: "success.main" }}>
                ✅ Remediation
              </Typography>
              <Box sx={{ 
                bgcolor: alpha(theme.palette.success.main, 0.05), 
                p: 2, 
                borderRadius: 1,
                border: `1px solid ${alpha(theme.palette.success.main, 0.2)}`,
                whiteSpace: "pre-wrap",
                fontSize: "0.9rem"
              }}>
                {selectedFinding.remediation}
              </Box>
              
              <Box sx={{ mt: 2, display: "flex", gap: 1 }}>
                <Chip label={`Scanner: ${selectedFinding.scanner}`} size="small" variant="outlined" />
                <Chip label={`Confidence: ${selectedFinding.confidence}`} size="small" variant="outlined" />
              </Box>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setSelectedFinding(null)}>Close</Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </>
  );
}

// ============================================================================
// Saved Source Code Viewer Component - For viewing saved decompiled source
// ============================================================================

interface SavedSourceCodeViewerProps {
  samples: Array<{
    class_name: string;
    package_name: string;
    file_path: string;
    source_code: string;
    is_activity: boolean;
    is_service: boolean;
    line_count: number;
  }>;
}

function SavedSourceCodeViewer({ samples }: SavedSourceCodeViewerProps) {
  const theme = useTheme();
  const [selectedClass, setSelectedClass] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  
  const filteredSamples = samples.filter(s => 
    s.class_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    s.package_name.toLowerCase().includes(searchQuery.toLowerCase())
  );
  
  const selectedSample = samples.find(s => s.class_name === selectedClass);
  
  return (
    <Paper sx={{ p: 2, mt: 3 }}>
      <Typography variant="subtitle1" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <CodeIcon color="primary" /> Saved Decompiled Source Code ({samples.length} classes)
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Source code for Activities, Services, and security-sensitive classes saved with this report
      </Typography>
      
      <Grid container spacing={2}>
        {/* Class List */}
        <Grid item xs={12} md={4}>
          <TextField
            size="small"
            fullWidth
            placeholder="Search classes..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            sx={{ mb: 1 }}
            InputProps={{
              startAdornment: <SearchIcon sx={{ color: "text.secondary", mr: 1, fontSize: 20 }} />
            }}
          />
          <Paper variant="outlined" sx={{ maxHeight: 400, overflow: "auto" }}>
            <List dense disablePadding>
              {filteredSamples.map((sample) => (
                <ListItem 
                  key={sample.class_name}
                  button
                  selected={selectedClass === sample.class_name}
                  onClick={() => setSelectedClass(sample.class_name)}
                  sx={{
                    borderBottom: `1px solid ${alpha(theme.palette.divider, 0.5)}`,
                    "&.Mui-selected": { bgcolor: alpha(theme.palette.primary.main, 0.1) }
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 36 }}>
                    {sample.is_activity ? (
                      <Chip label="A" size="small" color="primary" sx={{ width: 24, height: 24, fontSize: "0.7rem" }} />
                    ) : sample.is_service ? (
                      <Chip label="S" size="small" color="secondary" sx={{ width: 24, height: 24, fontSize: "0.7rem" }} />
                    ) : (
                      <CodeIcon fontSize="small" color="action" />
                    )}
                  </ListItemIcon>
                  <ListItemText 
                    primary={<Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{sample.class_name}</Typography>}
                    secondary={<Typography variant="caption" color="text.secondary">{sample.line_count} lines</Typography>}
                  />
                </ListItem>
              ))}
            </List>
          </Paper>
        </Grid>
        
        {/* Source Code Viewer */}
        <Grid item xs={12} md={8}>
          {selectedSample ? (
            <Paper 
              variant="outlined" 
              sx={{ 
                height: 500, 
                overflow: "auto", 
                bgcolor: "#1e1e1e",
                borderRadius: 1
              }}
            >
              <Box sx={{ 
                position: "sticky", 
                top: 0, 
                bgcolor: "#252526", 
                borderBottom: `1px solid ${alpha(theme.palette.divider, 0.2)}`,
                p: 1,
                display: "flex",
                alignItems: "center",
                gap: 1,
                zIndex: 1
              }}>
                <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#cccccc" }}>
                  {selectedSample.file_path}
                </Typography>
                {selectedSample.is_activity && <Chip label="Activity" size="small" color="primary" sx={{ height: 20 }} />}
                {selectedSample.is_service && <Chip label="Service" size="small" color="secondary" sx={{ height: 20 }} />}
              </Box>
              <Box sx={{ p: 1 }}>
                <pre style={{ 
                  margin: 0, 
                  fontFamily: "'Fira Code', 'Consolas', monospace",
                  fontSize: "0.8rem",
                  lineHeight: 1.5,
                  color: "#d4d4d4",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word"
                }}>
                  {selectedSample.source_code}
                </pre>
              </Box>
            </Paper>
          ) : (
            <Paper 
              variant="outlined" 
              sx={{ 
                height: 500, 
                display: "flex", 
                alignItems: "center", 
                justifyContent: "center",
                bgcolor: alpha(theme.palette.background.default, 0.5)
              }}
            >
              <Box sx={{ textAlign: "center", color: "text.secondary" }}>
                <CodeIcon sx={{ fontSize: 48, mb: 1, opacity: 0.5 }} />
                <Typography>Select a class from the list to view its source code</Typography>
              </Box>
            </Paper>
          )}
        </Grid>
      </Grid>
    </Paper>
  );
}

// ============================================================================
// Unified Frida Scripts Accordion - Standard bypass scripts (SSL, Root, Crypto, etc.)
// ============================================================================

interface UnifiedFridaScriptsAccordionProps {
  dynamicAnalysis: import("../api/client").DynamicAnalysis;
}

function UnifiedFridaScriptsAccordion({ dynamicAnalysis }: UnifiedFridaScriptsAccordionProps) {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(false);
  const [selectedScript, setSelectedScript] = useState<string>("");
  const [copied, setCopied] = useState(false);
  
  const handleCopyScript = async (scriptCode: string) => {
    try {
      await navigator.clipboard.writeText(scriptCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };
  
  const handleDownloadScript = (script: import("../api/client").FridaScript) => {
    const blob = new Blob([script.script_code], { type: "text/javascript" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${script.category}_${dynamicAnalysis.package_name.replace(/\./g, "_")}.js`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };
  
  const currentScript = selectedScript 
    ? dynamicAnalysis.frida_scripts.find(s => s.name === selectedScript)
    : null;
  
  const getCategoryIcon = (category: string) => {
    switch (category) {
      case "ssl_bypass": return "🔓";
      case "root_bypass": return "🌱";
      case "crypto_hook": return "🔐";
      case "auth_hook": return "🔑";
      case "network_hook": return "🌐";
      case "emulator_bypass": return "📱";
      case "debugger_bypass": return "🐛";
      case "tampering_bypass": return "🛡️";
      default: return "📜";
    }
  };
  
  const getCategoryColor = (category: string) => {
    switch (category) {
      case "ssl_bypass": return theme.palette.warning.main;
      case "root_bypass": return theme.palette.success.main;
      case "crypto_hook": return theme.palette.info.main;
      case "auth_hook": return theme.palette.secondary.main;
      default: return theme.palette.grey[500];
    }
  };

  const protectionsDetected = [
    dynamicAnalysis.ssl_pinning_detected && "SSL Pinning",
    dynamicAnalysis.root_detection_detected && "Root Detection",
    dynamicAnalysis.emulator_detection_detected && "Emulator Detection",
    dynamicAnalysis.debugger_detection_detected && "Debugger Detection",
    dynamicAnalysis.anti_tampering_detected && "Anti-Tampering"
  ].filter(Boolean);

  return (
    <Accordion expanded={expanded} onChange={(_, exp) => setExpanded(exp)}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
          <CodeIcon color="secondary" />
          <strong>Frida Scripts ({dynamicAnalysis.total_scripts})</strong>
          {protectionsDetected.length > 0 && (
            <Chip 
              label={`${protectionsDetected.length} protections detected`} 
              size="small" 
              color="warning" 
              variant="outlined" 
            />
          )}
          <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
            Dynamic analysis tools for runtime testing
          </Typography>
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        {/* Protection Detection Summary */}
        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
          <Typography variant="subtitle2" gutterBottom>Detection Summary</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip
              icon={<span>{dynamicAnalysis.ssl_pinning_detected ? "✅" : "❌"}</span>}
              label="SSL Pinning"
              color={dynamicAnalysis.ssl_pinning_detected ? "warning" : "default"}
              variant={dynamicAnalysis.ssl_pinning_detected ? "filled" : "outlined"}
              size="small"
            />
            <Chip
              icon={<span>{dynamicAnalysis.root_detection_detected ? "✅" : "❌"}</span>}
              label="Root Detection"
              color={dynamicAnalysis.root_detection_detected ? "warning" : "default"}
              variant={dynamicAnalysis.root_detection_detected ? "filled" : "outlined"}
              size="small"
            />
            <Chip
              icon={<span>{dynamicAnalysis.emulator_detection_detected ? "✅" : "❌"}</span>}
              label="Emulator Check"
              color={dynamicAnalysis.emulator_detection_detected ? "warning" : "default"}
              variant={dynamicAnalysis.emulator_detection_detected ? "filled" : "outlined"}
              size="small"
            />
            <Chip
              icon={<span>{dynamicAnalysis.debugger_detection_detected ? "✅" : "❌"}</span>}
              label="Debugger Check"
              color={dynamicAnalysis.debugger_detection_detected ? "warning" : "default"}
              variant={dynamicAnalysis.debugger_detection_detected ? "filled" : "outlined"}
              size="small"
            />
            <Chip
              icon={<span>{dynamicAnalysis.anti_tampering_detected ? "✅" : "❌"}</span>}
              label="Anti-Tamper"
              color={dynamicAnalysis.anti_tampering_detected ? "warning" : "default"}
              variant={dynamicAnalysis.anti_tampering_detected ? "filled" : "outlined"}
              size="small"
            />
          </Box>
          
          {/* Frida Commands */}
          <Box sx={{ mt: 2 }}>
            <Typography variant="caption" color="text.secondary">Frida Commands:</Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 0.5 }}>
              <Chip
                label={dynamicAnalysis.frida_spawn_command}
                size="small"
                sx={{ fontFamily: "monospace", fontSize: 10, cursor: "pointer" }}
                onClick={() => handleCopyScript(dynamicAnalysis.frida_spawn_command)}
              />
              <Chip
                label={dynamicAnalysis.frida_attach_command}
                size="small"
                sx={{ fontFamily: "monospace", fontSize: 10, cursor: "pointer" }}
                onClick={() => handleCopyScript(dynamicAnalysis.frida_attach_command)}
              />
            </Box>
          </Box>
        </Paper>

        {/* Getting Started Guide for Beginners */}
        <Accordion sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <span>📚</span> Getting Started with Frida (Beginner Guide)
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {/* What is Frida */}
              <Grid item xs={12}>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.info.main, 0.05), border: `1px solid ${alpha(theme.palette.info.main, 0.2)}` }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>🔧</span> What is Frida?
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Frida is a dynamic instrumentation toolkit that lets you inject JavaScript into running apps to monitor and modify their behavior.
                    These auto-generated scripts hook into specific methods detected during static analysis to help you bypass security controls and inspect runtime data.
                  </Typography>
                </Paper>
              </Grid>

              {/* Prerequisites */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, height: "100%" }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>✅</span> Prerequisites
                  </Typography>
                  <Box component="ul" sx={{ m: 0, pl: 2.5, "& li": { mb: 0.5 } }}>
                    <Typography component="li" variant="body2">Python 3.7+ installed on your computer</Typography>
                    <Typography component="li" variant="body2">Android device (rooted) or emulator with root</Typography>
                    <Typography component="li" variant="body2">USB debugging enabled on the device</Typography>
                    <Typography component="li" variant="body2">ADB (Android Debug Bridge) installed</Typography>
                  </Box>
                </Paper>
              </Grid>

              {/* Installation Steps */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, height: "100%" }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>📦</span> Installation
                  </Typography>
                  <Box sx={{ fontFamily: "monospace", fontSize: 12, bgcolor: "#1e1e1e", p: 1.5, borderRadius: 1 }}>
                    <Typography variant="body2" sx={{ color: "#6a9955", mb: 0.5 }}># Install Frida tools</Typography>
                    <Typography variant="body2" sx={{ color: "#d4d4d4", mb: 1 }}>pip install frida-tools</Typography>
                    <Typography variant="body2" sx={{ color: "#6a9955", mb: 0.5 }}># Check installation</Typography>
                    <Typography variant="body2" sx={{ color: "#d4d4d4" }}>frida --version</Typography>
                  </Box>
                </Paper>
              </Grid>

              {/* Device Setup */}
              <Grid item xs={12}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>📱</span> Device Setup (One-Time)
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="body2" fontWeight={600} gutterBottom>1. Download frida-server:</Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        Visit <code style={{ background: "#1e1e1e", padding: "2px 6px", borderRadius: 4 }}>github.com/frida/frida/releases</code> and download the frida-server matching your device architecture (arm64 for most modern phones).
                      </Typography>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="body2" fontWeight={600} gutterBottom>2. Push to device & run:</Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: 11, bgcolor: "#1e1e1e", p: 1, borderRadius: 1 }}>
                        <Typography variant="body2" sx={{ color: "#d4d4d4", fontSize: 11 }}>adb push frida-server /data/local/tmp/</Typography>
                        <Typography variant="body2" sx={{ color: "#d4d4d4", fontSize: 11 }}>adb shell "chmod 755 /data/local/tmp/frida-server"</Typography>
                        <Typography variant="body2" sx={{ color: "#d4d4d4", fontSize: 11 }}>adb shell "su -c /data/local/tmp/frida-server &"</Typography>
                      </Box>
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>

              {/* How to Run */}
              <Grid item xs={12}>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.success.main, 0.05), border: `1px solid ${alpha(theme.palette.success.main, 0.2)}` }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>▶️</span> Running the Scripts
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="body2" fontWeight={600} gutterBottom>Option A: Spawn Mode (Recommended)</Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        Starts the app fresh with hooks attached from the beginning.
                      </Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: 11, bgcolor: "#1e1e1e", p: 1, borderRadius: 1 }}>
                        <Typography variant="body2" sx={{ color: "#d4d4d4", fontSize: 11 }}>
                          frida -U -f {dynamicAnalysis.package_name} -l script.js
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="body2" fontWeight={600} gutterBottom>Option B: Attach Mode</Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        Attaches to an already running app.
                      </Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: 11, bgcolor: "#1e1e1e", p: 1, borderRadius: 1 }}>
                        <Typography variant="body2" sx={{ color: "#d4d4d4", fontSize: 11 }}>
                          frida -U {dynamicAnalysis.package_name} -l script.js
                        </Typography>
                      </Box>
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>

              {/* Troubleshooting */}
              <Grid item xs={12}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>🔍</span> Common Issues & Solutions
                  </Typography>
                  <Grid container spacing={1}>
                    <Grid item xs={12} sm={6} md={4}>
                      <Box sx={{ p: 1, bgcolor: alpha(theme.palette.error.main, 0.05), borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight={600} color="error.main">Failed to spawn</Typography>
                        <Typography variant="caption" display="block" color="text.secondary">
                          → Ensure frida-server is running on device
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6} md={4}>
                      <Box sx={{ p: 1, bgcolor: alpha(theme.palette.error.main, 0.05), borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight={600} color="error.main">Unable to find device</Typography>
                        <Typography variant="caption" display="block" color="text.secondary">
                          → Check USB debugging & run: adb devices
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6} md={4}>
                      <Box sx={{ p: 1, bgcolor: alpha(theme.palette.error.main, 0.05), borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight={600} color="error.main">Version mismatch</Typography>
                        <Typography variant="caption" display="block" color="text.secondary">
                          → Match frida-tools and frida-server versions
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6} md={4}>
                      <Box sx={{ p: 1, bgcolor: alpha(theme.palette.error.main, 0.05), borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight={600} color="error.main">App crashes immediately</Typography>
                        <Typography variant="caption" display="block" color="text.secondary">
                          → Try --no-pause flag or use attach mode
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6} md={4}>
                      <Box sx={{ p: 1, bgcolor: alpha(theme.palette.error.main, 0.05), borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight={600} color="error.main">Class not found</Typography>
                        <Typography variant="caption" display="block" color="text.secondary">
                          → Class may load later; try setTimeout wrapper
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6} md={4}>
                      <Box sx={{ p: 1, bgcolor: alpha(theme.palette.warning.main, 0.1), borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight={600} color="warning.main">Need more help?</Typography>
                        <Typography variant="caption" display="block" color="text.secondary">
                          → Visit frida.re/docs for full documentation
                        </Typography>
                      </Box>
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>

              {/* Tips */}
              <Grid item xs={12}>
                <Alert severity="info" sx={{ "& .MuiAlert-message": { width: "100%" } }}>
                  <Typography variant="body2" fontWeight={600} gutterBottom>💡 Pro Tips</Typography>
                  <Box component="ul" sx={{ m: 0, pl: 2, "& li": { mb: 0.25 } }}>
                    <Typography component="li" variant="body2">Start with SSL Bypass if you need to intercept HTTPS traffic with Burp Suite</Typography>
                    <Typography component="li" variant="body2">Use Root/Emulator Bypass if the app refuses to run on your test device</Typography>
                    <Typography component="li" variant="body2">The Combined script includes all bypasses - use it for comprehensive testing</Typography>
                    <Typography component="li" variant="body2">Watch the terminal output for hooked method calls and intercepted data</Typography>
                  </Box>
                </Alert>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>
        
        <Grid container spacing={2}>
          {/* Script List */}
          <Grid item xs={12} md={4}>
            <Paper variant="outlined" sx={{ p: 1, maxHeight: 400, overflow: "auto" }}>
              <Typography variant="subtitle2" sx={{ px: 1, py: 0.5 }}>
                Available Scripts
              </Typography>
              <List dense disablePadding>
                {dynamicAnalysis.frida_scripts.map((script) => (
                  <ListItem
                    key={script.name}
                    button
                    selected={selectedScript === script.name}
                    onClick={() => setSelectedScript(script.name)}
                    sx={{
                      borderLeft: selectedScript === script.name 
                        ? `3px solid ${getCategoryColor(script.category)}`
                        : "3px solid transparent",
                      mb: 0.5,
                    }}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <span>{getCategoryIcon(script.category)}</span>
                          <Typography variant="body2">{script.name}</Typography>
                          {script.is_dangerous && (
                            <Chip label="Modifies Behavior" size="small" color="error" sx={{ height: 16, fontSize: 9 }} />
                          )}
                        </Box>
                      }
                      secondary={
                        <Typography variant="caption" color="text.secondary" noWrap>
                          {script.description.substring(0, 50)}...
                        </Typography>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          
          {/* Script Viewer */}
          <Grid item xs={12} md={8}>
            {currentScript ? (
              <Paper variant="outlined" sx={{ height: 400, overflow: "hidden", display: "flex", flexDirection: "column" }}>
                {/* Header */}
                <Box sx={{ 
                  p: 1.5, 
                  bgcolor: alpha(getCategoryColor(currentScript.category), 0.1),
                  borderBottom: `1px solid ${theme.palette.divider}`,
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center"
                }}>
                  <Box>
                    <Typography variant="subtitle2">{currentScript.name}</Typography>
                    <Typography variant="caption" color="text.secondary">{currentScript.description}</Typography>
                  </Box>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    <Tooltip title={copied ? "Copied!" : "Copy Script"}>
                      <IconButton size="small" onClick={() => handleCopyScript(currentScript.script_code)}>
                        {copied ? <CheckIcon color="success" /> : <CopyIcon />}
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Download Script">
                      <IconButton size="small" onClick={() => handleDownloadScript(currentScript)}>
                        <DownloadIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </Box>
                {/* Code */}
                <Box sx={{ 
                  flex: 1, 
                  overflow: "auto", 
                  bgcolor: "#1e1e1e",
                  p: 2
                }}>
                  <pre style={{ 
                    margin: 0,
                    fontFamily: "'Fira Code', monospace",
                    fontSize: "0.75rem",
                    lineHeight: 1.5,
                    color: "#d4d4d4",
                    whiteSpace: "pre-wrap"
                  }}>
                    {currentScript.script_code}
                  </pre>
                </Box>
                {/* Footer with usage */}
                <Box sx={{ p: 1, bgcolor: alpha(theme.palette.background.default, 0.5), borderTop: `1px solid ${theme.palette.divider}` }}>
                  <Typography variant="caption" color="text.secondary">
                    Usage: <code style={{ fontSize: "0.75rem" }}>{currentScript.usage_instructions}</code>
                  </Typography>
                </Box>
              </Paper>
            ) : (
              <Paper 
                variant="outlined" 
                sx={{ 
                  height: 400, 
                  display: "flex", 
                  alignItems: "center", 
                  justifyContent: "center",
                  bgcolor: alpha(theme.palette.background.default, 0.3)
                }}
              >
                <Box sx={{ textAlign: "center", color: "text.secondary" }}>
                  <CodeIcon sx={{ fontSize: 48, mb: 1, opacity: 0.5 }} />
                  <Typography>Select a script from the list to view its code</Typography>
                </Box>
              </Paper>
            )}
          </Grid>
        </Grid>
      </AccordionDetails>
    </Accordion>
  );
}

// ============================================================================
// Vulnerability-Specific Frida Hooks Accordion - Auto-generated from findings
// ============================================================================

interface VulnerabilityFridaHooksAccordionProps {
  hooks: import("../api/client").VulnerabilityFridaHooks;
}

function VulnerabilityFridaHooksAccordion({ hooks }: VulnerabilityFridaHooksAccordionProps) {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(false);
  const [selectedScript, setSelectedScript] = useState<string>("");
  const [copied, setCopied] = useState(false);
  
  const handleCopyScript = async (scriptCode: string) => {
    try {
      await navigator.clipboard.writeText(scriptCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };
  
  const handleDownloadScript = (script: import("../api/client").VulnerabilityFridaScript) => {
    const blob = new Blob([script.script_code], { type: "text/javascript" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${script.category}_${hooks.package_name.replace(/\./g, "_")}.js`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };
  
  const currentScript = selectedScript 
    ? hooks.vulnerability_scripts.find(s => s.name === selectedScript)
    : null;
  
  const getCategoryIcon = (category: string) => {
    switch (category) {
      case "deep_link_exploit": return "🔗";
      case "crypto_exploit": return "🔐";
      case "provider_exploit": return "📂";
      case "webview_exploit": return "🌐";
      case "auth_bypass": return "🔑";
      case "kotlin_monitor": return "🅺";
      default: return "🎯";
    }
  };
  
  const getCategoryColor = (category: string) => {
    switch (category) {
      case "deep_link_exploit": return theme.palette.error.main;
      case "crypto_exploit": return theme.palette.warning.main;
      case "provider_exploit": return theme.palette.info.main;
      case "webview_exploit": return "#e91e63";
      case "auth_bypass": return theme.palette.secondary.main;
      case "kotlin_monitor": return "#7c4dff";
      default: return theme.palette.grey[500];
    }
  };

  return (
    <Accordion expanded={expanded} onChange={(_, exp) => setExpanded(exp)}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
          <TargetIcon sx={{ color: theme.palette.error.main }} />
          <strong>Vulnerability-Specific Frida Hooks ({hooks.vulnerability_scripts.length})</strong>
          <Chip 
            label="Auto-Generated" 
            size="small" 
            color="error" 
            variant="outlined" 
          />
          <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
            Targeted exploitation scripts based on {hooks.findings_analyzed} findings
          </Typography>
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        {/* Info Banner */}
        <Alert severity="warning" sx={{ mb: 2 }}>
          <Typography variant="body2">
            <strong>⚠️ These scripts are auto-generated based on discovered vulnerabilities.</strong> They are designed to help 
            test and exploit specific weaknesses found during static analysis. Use responsibly and only on authorized targets.
          </Typography>
        </Alert>
        
        {/* Category Summary */}
        <Box sx={{ mb: 2, display: "flex", gap: 1, flexWrap: "wrap" }}>
          {hooks.vulnerability_scripts.map((script) => (
            <Chip
              key={script.name}
              icon={<span>{getCategoryIcon(script.category)}</span>}
              label={`${script.name} (${script.findings_count})`}
              size="small"
              sx={{ 
                borderColor: getCategoryColor(script.category),
                cursor: "pointer"
              }}
              variant={selectedScript === script.name ? "filled" : "outlined"}
              onClick={() => setSelectedScript(script.name)}
            />
          ))}
        </Box>
        
        <Grid container spacing={2}>
          {/* Script List */}
          <Grid item xs={12} md={4}>
            <Paper variant="outlined" sx={{ p: 1, maxHeight: 400, overflow: "auto" }}>
              <Typography variant="subtitle2" sx={{ px: 1, py: 0.5, color: "error.main" }}>
                🎯 Targeted Scripts
              </Typography>
              <List dense disablePadding>
                {hooks.vulnerability_scripts.map((script) => (
                  <ListItem
                    key={script.name}
                    button
                    selected={selectedScript === script.name}
                    onClick={() => setSelectedScript(script.name)}
                    sx={{
                      borderLeft: selectedScript === script.name 
                        ? `3px solid ${getCategoryColor(script.category)}`
                        : "3px solid transparent",
                      mb: 0.5,
                      bgcolor: selectedScript === script.name 
                        ? alpha(getCategoryColor(script.category), 0.1)
                        : "transparent"
                    }}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <span>{getCategoryIcon(script.category)}</span>
                          <Typography variant="body2" fontWeight={selectedScript === script.name ? 600 : 400}>
                            {script.name}
                          </Typography>
                        </Box>
                      }
                      secondary={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mt: 0.5 }}>
                          <Chip 
                            label={`${script.findings_count} vulns`} 
                            size="small" 
                            color="error" 
                            sx={{ height: 16, fontSize: 9 }} 
                          />
                          <Typography variant="caption" color="text.secondary">
                            {script.target_classes.length} classes
                          </Typography>
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          
          {/* Script Viewer */}
          <Grid item xs={12} md={8}>
            {currentScript ? (
              <Paper variant="outlined" sx={{ height: 400, overflow: "hidden", display: "flex", flexDirection: "column" }}>
                {/* Header */}
                <Box sx={{ 
                  p: 1.5, 
                  bgcolor: alpha(getCategoryColor(currentScript.category), 0.15),
                  borderBottom: `1px solid ${theme.palette.divider}`,
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center"
                }}>
                  <Box>
                    <Typography variant="subtitle2" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      {getCategoryIcon(currentScript.category)} {currentScript.name}
                      <Chip label={`${currentScript.findings_count} vulnerabilities`} size="small" color="error" sx={{ height: 18 }} />
                    </Typography>
                    <Typography variant="caption" color="text.secondary">{currentScript.description}</Typography>
                  </Box>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    <Tooltip title={copied ? "Copied!" : "Copy Script"}>
                      <IconButton size="small" onClick={() => handleCopyScript(currentScript.script_code)}>
                        {copied ? <CheckIcon color="success" /> : <CopyIcon />}
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Download Script">
                      <IconButton size="small" onClick={() => handleDownloadScript(currentScript)}>
                        <DownloadIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </Box>
                
                {/* Target Classes */}
                {currentScript.target_classes.length > 0 && (
                  <Box sx={{ px: 1.5, py: 0.5, bgcolor: alpha(theme.palette.background.default, 0.5), borderBottom: `1px solid ${theme.palette.divider}` }}>
                    <Typography variant="caption" color="text.secondary">
                      Targets: {currentScript.target_classes.slice(0, 3).join(", ")}
                      {currentScript.target_classes.length > 3 && ` +${currentScript.target_classes.length - 3} more`}
                    </Typography>
                  </Box>
                )}
                
                {/* Code */}
                <Box sx={{ 
                  flex: 1, 
                  overflow: "auto", 
                  bgcolor: "#1e1e1e",
                  p: 2
                }}>
                  <pre style={{ 
                    margin: 0,
                    fontFamily: "'Fira Code', monospace",
                    fontSize: "0.75rem",
                    lineHeight: 1.5,
                    color: "#d4d4d4",
                    whiteSpace: "pre-wrap"
                  }}>
                    {currentScript.script_code}
                  </pre>
                </Box>
                
                {/* Footer with usage */}
                <Box sx={{ p: 1, bgcolor: alpha(theme.palette.error.main, 0.05), borderTop: `1px solid ${theme.palette.divider}` }}>
                  <Typography variant="caption" color="text.secondary">
                    Usage: <code style={{ fontSize: "0.75rem", color: theme.palette.error.main }}>{currentScript.usage_instructions}</code>
                  </Typography>
                </Box>
              </Paper>
            ) : (
              <Paper 
                variant="outlined" 
                sx={{ 
                  height: 400, 
                  display: "flex", 
                  alignItems: "center", 
                  justifyContent: "center",
                  bgcolor: alpha(theme.palette.error.main, 0.03)
                }}
              >
                <Box sx={{ textAlign: "center", color: "text.secondary" }}>
                  <TargetIcon sx={{ fontSize: 48, mb: 1, opacity: 0.5, color: theme.palette.error.main }} />
                  <Typography>Select a vulnerability-specific script to view</Typography>
                  <Typography variant="caption">These are auto-generated based on discovered vulnerabilities</Typography>
                </Box>
              </Paper>
            )}
          </Grid>
        </Grid>
      </AccordionDetails>
    </Accordion>
  );
}

// ============================================================================
// Unified APK Results Component - Single Source of Truth
// ============================================================================

interface UnifiedApkResultsProps {
  result: UnifiedApkScanResult;
  jadxSessionId: string | null;
  onBrowseSource: () => void;
  apkFile: File | null;
  onEnhancedSecurityComplete?: (result: EnhancedSecurityResult) => void;
}

function UnifiedApkResults({ result, jadxSessionId, onBrowseSource, apkFile, onEnhancedSecurityComplete }: UnifiedApkResultsProps) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  
  // Whether we're viewing a saved report (no live JADX session)
  const isViewingOnly = !jadxSessionId && result.scan_id.startsWith('saved-');
  
  // Enhanced Security Scan State
  const [enhancedSecurityResult, setEnhancedSecurityResult] = useState<EnhancedSecurityResult | null>(
    // Initialize from saved data if available
    result.saved_enhanced_security || null
  );
  const [enhancedSecurityLoading, setEnhancedSecurityLoading] = useState(false);
  const [enhancedSecurityOptions, setEnhancedSecurityOptions] = useState({
    includeAiScan: true,
    includeCveLookup: true,
    aiScanType: "quick" as "quick" | "deep" | "focused"
  });
  const [securityExportAnchor, setSecurityExportAnchor] = useState<HTMLElement | null>(null);
  const [securityExporting, setSecurityExporting] = useState<string | null>(null);
  
  // Progress tracker for Full Security Scan
  const [scanProgress, setScanProgress] = useState<{
    phase: number;
    phaseName: string;
    progress: number;
    startTime: number;
    estimatedTotal: number;
  } | null>(null);
  
  // Update enhanced security result when result changes (e.g., switching between saved reports)
  useEffect(() => {
    if (result.saved_enhanced_security) {
      setEnhancedSecurityResult(result.saved_enhanced_security);
    }
  }, [result.scan_id, result.saved_enhanced_security]);

  // Progress simulation for security scan phases
  useEffect(() => {
    if (!enhancedSecurityLoading || !scanProgress) return;
    
    const phases = [
      { name: "Pattern-based Security Scan", duration: 15 },
      { name: "AI False Positive Filtering", duration: 10 },
      { name: "AI Cross-Class Analysis", duration: 45 },
      { name: "CVE Lookup (Libraries)", duration: 15 },
      { name: "Combining Findings", duration: 5 },
      { name: "Generating Risk Assessment", duration: 10 },
      { name: "Creating Offensive Plan", duration: 20 },
    ];
    
    const totalDuration = phases.reduce((sum, p) => sum + p.duration, 0);
    let elapsed = 0;
    
    const interval = setInterval(() => {
      const now = Date.now();
      const elapsedSecs = (now - scanProgress.startTime) / 1000;
      
      // Find current phase
      let accumulatedTime = 0;
      let currentPhase = 0;
      for (let i = 0; i < phases.length; i++) {
        if (elapsedSecs < accumulatedTime + phases[i].duration) {
          currentPhase = i;
          break;
        }
        accumulatedTime += phases[i].duration;
        if (i === phases.length - 1) currentPhase = i;
      }
      
      // Calculate progress within phase
      const phaseElapsed = elapsedSecs - accumulatedTime;
      const phaseProgress = Math.min(95, (phaseElapsed / phases[currentPhase].duration) * 100);
      const overallProgress = Math.min(95, (elapsedSecs / totalDuration) * 100);
      
      setScanProgress(prev => prev ? {
        ...prev,
        phase: currentPhase + 1,
        phaseName: phases[currentPhase].name,
        progress: overallProgress,
      } : null);
      
    }, 500);
    
    return () => clearInterval(interval);
  }, [enhancedSecurityLoading, scanProgress?.startTime]);

  // Enhanced Security Scan Handler
  const handleEnhancedSecurityScan = async () => {
    if (!jadxSessionId) return;
    
    setEnhancedSecurityLoading(true);
    setScanProgress({
      phase: 1,
      phaseName: "Pattern-based Security Scan",
      progress: 0,
      startTime: Date.now(),
      estimatedTotal: 120, // 2 minutes estimate
    });
    try {
      const res = await reverseEngineeringClient.enhancedSecurityScan(
        jadxSessionId,
        {
          includeAiScan: enhancedSecurityOptions.includeAiScan,
          includeCveLookup: enhancedSecurityOptions.includeCveLookup,
          aiScanType: enhancedSecurityOptions.aiScanType,
        }
      );
      setEnhancedSecurityResult(res);
      setScanProgress(prev => prev ? { ...prev, progress: 100, phaseName: "Complete!" } : null);
      // Notify parent component so save report can include this data
      if (onEnhancedSecurityComplete) {
        onEnhancedSecurityComplete(res);
      }
    } catch (err) {
      console.error("Enhanced security scan failed:", err);
      setScanProgress(null);
    } finally {
      setEnhancedSecurityLoading(false);
      // Clear progress after a short delay to show completion
      setTimeout(() => setScanProgress(null), 1500);
    }
  };

  // Security Export Handler
  const handleSecurityExport = async (format: "markdown" | "pdf" | "docx") => {
    if (!enhancedSecurityResult) return;
    
    setSecurityExporting(format);
    setSecurityExportAnchor(null);
    
    try {
      const blob = await reverseEngineeringClient.exportEnhancedSecurity(
        enhancedSecurityResult,
        format
      );
      
      // Download the file
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `security-report-${result.package_name || "analysis"}.${format === "markdown" ? "md" : format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (err) {
      console.error("Export failed:", err);
    } finally {
      setSecurityExporting(null);
    }
  };
  
  // Common HTML content styles for AI reports
  const htmlContentStyles = {
    fontFamily: theme.typography.fontFamily,
    "& h3": {
      fontSize: "1.15rem",
      fontWeight: 700,
      color: theme.palette.text.primary,
      mt: 3,
      mb: 1.5,
      pt: 1,
      borderBottom: `1px solid ${alpha(theme.palette.divider, 0.5)}`,
      pb: 1,
    },
    "& h3:first-of-type": { mt: 0, pt: 0 },
    "& h4": {
      fontSize: "1rem",
      fontWeight: 600,
      mt: 2,
      mb: 1,
    },
    "& p": {
      mb: 1.5,
      lineHeight: 1.8,
      color: theme.palette.text.secondary,
    },
    "& ul, & ol": { pl: 3, mb: 2 },
    "& li": { mb: 1, lineHeight: 1.7, color: theme.palette.text.secondary },
    "& code": {
      bgcolor: alpha(theme.palette.grey[500], 0.15),
      px: 0.75,
      py: 0.25,
      borderRadius: 0.5,
      fontFamily: "monospace",
      fontSize: "0.85em",
    },
    "& pre": {
      bgcolor: alpha(theme.palette.grey[900], 0.9),
      p: 2,
      borderRadius: 1,
      overflow: "auto",
      "& code": { bgcolor: "transparent", p: 0 },
    },
  };
  
  // Recursive source tree renderer for saved reports
  const renderSourceTree = (tree: Record<string, unknown>, depth: number): React.ReactNode => {
    const entries = Object.entries(tree);
    if (entries.length === 0) return null;
    
    return entries.map(([name, value]) => {
      const isFolder = value && typeof value === 'object' && !Array.isArray(value);
      const indent = depth * 16;
      
      if (isFolder) {
        return (
          <Box key={name} sx={{ pl: `${indent}px` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, py: 0.25, color: "primary.main" }}>
              <FolderIcon sx={{ fontSize: 16 }} />
              <Typography variant="body2" sx={{ fontWeight: 500 }}>{name}/</Typography>
            </Box>
            {renderSourceTree(value as Record<string, unknown>, depth + 1)}
          </Box>
        );
      }
      
      return (
        <Box key={name} sx={{ pl: `${indent}px`, display: "flex", alignItems: "center", gap: 0.5, py: 0.25 }}>
          <InsertDriveFileIcon sx={{ fontSize: 14, color: "text.secondary" }} />
          <Typography variant="body2" color="text.secondary">{name}</Typography>
        </Box>
      );
    });
  };
  
  return (
    <Box>
      {/* Summary Header */}
      <Paper sx={{ p: 3, mb: 3, background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)} 0%, ${alpha(theme.palette.secondary.main, 0.05)} 100%)` }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={6}>
            <Typography variant="h5" fontWeight="bold" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <ApkIcon color="primary" /> {result.package_name || result.filename}
            </Typography>
            {result.version_name && (
              <Typography variant="body2" color="text.secondary">
                Version {result.version_name} (code: {result.version_code}) • SDK {result.min_sdk}-{result.target_sdk}
              </Typography>
            )}
          </Grid>
          <Grid item xs={12} md={6}>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", justifyContent: { xs: "flex-start", md: "flex-end" } }}>
              <Chip 
                icon={<LockIcon />} 
                label={`${result.dangerous_permissions_count} Dangerous Permissions`}
                color={result.dangerous_permissions_count > 5 ? "error" : result.dangerous_permissions_count > 0 ? "warning" : "success"}
                size="small"
              />
              <Chip 
                icon={<SecretIcon />} 
                label={`${result.secrets.length} Secrets`}
                color={result.secrets.length > 0 ? "warning" : "success"}
                size="small"
              />
              <Chip 
                icon={<CodeIcon />} 
                label={`${result.total_classes} Classes`}
                color="info"
                size="small"
              />
              <Chip 
                icon={<BugIcon />} 
                label={`${result.security_issues.length + result.jadx_security_issues.length} Issues`}
                color={result.security_issues.length > 0 ? "error" : "success"}
                size="small"
              />
            </Box>
          </Grid>
        </Grid>
        
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          Scan completed in {result.scan_time.toFixed(1)}s • JADX decompilation: {result.decompilation_time.toFixed(1)}s • {result.total_files} files
        </Typography>
        
        {jadxSessionId && (
          <Button 
            variant="outlined" 
            size="small" 
            onClick={onBrowseSource}
            startIcon={<CodeIcon />}
            sx={{ mt: 2 }}
          >
            Browse Decompiled Source
          </Button>
        )}
      </Paper>
      
      {/* Main Tabs */}
      <Paper sx={{ overflow: "hidden" }}>
        <Tabs
          value={activeTab}
          onChange={(_, v) => setActiveTab(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ borderBottom: 1, borderColor: "divider" }}
        >
          <Tab icon={<InfoIcon />} label="What Does This APK Do?" iconPosition="start" />
          <Tab icon={<SecurityIcon />} label="Security Findings" iconPosition="start" />
          <Tab icon={<ArchitectureIcon />} label="Architecture Diagram" iconPosition="start" />
          <Tab icon={<ShieldIcon />} label="Attack Surface Map" iconPosition="start" />
          <Tab icon={<CodeIcon />} label="Decompiled Classes" iconPosition="start" />
        </Tabs>
        
        <Box sx={{ p: 3 }}>
          {/* Tab 0: Functionality Report */}
          {activeTab === 0 && (
            result.ai_functionality_report ? (
              <Box sx={htmlContentStyles} dangerouslySetInnerHTML={{ __html: result.ai_functionality_report }} />
            ) : (
              <Alert severity="info">
                Functionality report not available. This may happen if AI analysis encountered an error.
              </Alert>
            )
          )}
          
          {/* Tab 1: Security Findings */}
          {activeTab === 1 && (
            <Box>
              {/* Full Security Scan Controls - Only show when no AI report and not viewing saved report */}
              {!isViewingOnly && !result.ai_security_report && (
                <Paper sx={{ mb: 3, p: 2, bgcolor: alpha(theme.palette.error.main, 0.05), border: `1px solid ${alpha(theme.palette.error.main, 0.2)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <RadarIcon color="error" />
                      <Typography variant="subtitle1" color="error.main" fontWeight={600}>Full Security Scan</Typography>
                      <Chip label="Pattern + AI + CVE" size="small" variant="outlined" color="error" sx={{ height: 20, fontSize: "0.6rem" }} />
                    </Box>
                    <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
                      <FormControl size="small" sx={{ minWidth: 100 }}>
                        <Select
                          value={enhancedSecurityOptions.aiScanType}
                          onChange={(e) => setEnhancedSecurityOptions(prev => ({ ...prev, aiScanType: e.target.value as "quick" | "deep" | "focused" }))}
                          sx={{ height: 32 }}
                        >
                          <MenuItem value="quick">Quick</MenuItem>
                          <MenuItem value="deep">Deep</MenuItem>
                          <MenuItem value="focused">Focused</MenuItem>
                        </Select>
                      </FormControl>
                      <Button 
                        variant="contained" 
                        color="error"
                        size="small"
                        onClick={handleEnhancedSecurityScan}
                        disabled={enhancedSecurityLoading || !jadxSessionId}
                        startIcon={enhancedSecurityLoading ? <CircularProgress size={16} /> : <RadarIcon />}
                      >
                        Run Full Scan
                      </Button>
                    </Box>
                  </Box>

                  {/* Scan Options */}
                  <Box sx={{ display: "flex", gap: 2, mb: 1 }}>
                    <FormControl size="small">
                      <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                        <input
                          type="checkbox"
                          checked={enhancedSecurityOptions.includeAiScan}
                          onChange={(e) => setEnhancedSecurityOptions(prev => ({ ...prev, includeAiScan: e.target.checked }))}
                          id="unifiedAiScanOption"
                        />
                        <label htmlFor="unifiedAiScanOption">
                          <Typography variant="caption">AI Cross-Class Analysis</Typography>
                        </label>
                      </Box>
                    </FormControl>
                    <FormControl size="small">
                      <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                        <input
                          type="checkbox"
                          checked={enhancedSecurityOptions.includeCveLookup}
                          onChange={(e) => setEnhancedSecurityOptions(prev => ({ ...prev, includeCveLookup: e.target.checked }))}
                          id="unifiedCveOption"
                        />
                        <label htmlFor="unifiedCveOption">
                          <Typography variant="caption">CVE Lookup (Libraries)</Typography>
                        </label>
                      </Box>
                    </FormControl>
                  </Box>

                  {!jadxSessionId && (
                    <Alert severity="info" sx={{ mt: 1 }}>
                      Full scan requires decompiled sources. The scan will run after JADX decompilation completes.
                    </Alert>
                  )}
                </Paper>
              )}
              
              {/* Viewing Saved Report Banner - Show when viewing */}
              {isViewingOnly && !enhancedSecurityResult && (
                <Alert severity="info" sx={{ mb: 3 }}>
                  <Typography variant="body2">
                    <strong>Viewing saved report.</strong> No full security scan data was saved with this report.
                    To run a new full security scan, analyze a new APK file.
                  </Typography>
                </Alert>
              )}
              
              {isViewingOnly && enhancedSecurityResult && (
                <Alert severity="success" sx={{ mb: 3 }}>
                  <Typography variant="body2">
                    <strong>Viewing saved security scan results.</strong> This report includes full security analysis data.
                  </Typography>
                </Alert>
              )}

              {/* Loading State with Progress Tracker */}
              {enhancedSecurityLoading && scanProgress && (
                <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.03), border: `1px solid ${alpha(theme.palette.error.main, 0.15)}` }}>
                  <Box sx={{ textAlign: "center", mb: 3 }}>
                    <Typography variant="h6" color="error.main" fontWeight={600} gutterBottom>
                      Full Security Scan in Progress
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Analyzing {result.package_name || "APK"} with 80+ classes
                    </Typography>
                  </Box>
                  
                  {/* Overall Progress Bar */}
                  <Box sx={{ mb: 3 }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
                      <Typography variant="body2" fontWeight={500}>
                        Phase {scanProgress.phase}/7: {scanProgress.phaseName}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {Math.round(scanProgress.progress)}%
                      </Typography>
                    </Box>
                    <LinearProgress 
                      variant="determinate" 
                      value={scanProgress.progress} 
                      color="error"
                      sx={{ height: 8, borderRadius: 4 }}
                    />
                  </Box>
                  
                  {/* Phase List */}
                  <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 1 }}>
                    {[
                      { num: 1, name: "Pattern Scan", icon: "🔍" },
                      { num: 2, name: "AI Filtering", icon: "🧹" },
                      { num: 3, name: "AI Analysis", icon: "🤖" },
                      { num: 4, name: "CVE Lookup", icon: "📚" },
                      { num: 5, name: "Combine Findings", icon: "📊" },
                      { num: 6, name: "Risk Assessment", icon: "⚠️" },
                      { num: 7, name: "Offensive Plan", icon: "🎯" },
                    ].map((phase) => {
                      const isActive = scanProgress.phase === phase.num;
                      const isComplete = scanProgress.phase > phase.num;
                      return (
                        <Box 
                          key={phase.num}
                          sx={{ 
                            display: "flex", 
                            alignItems: "center", 
                            gap: 1,
                            p: 1,
                            borderRadius: 1,
                            bgcolor: isActive ? alpha(theme.palette.error.main, 0.1) : isComplete ? alpha(theme.palette.success.main, 0.1) : "transparent",
                            border: isActive ? `1px solid ${theme.palette.error.main}` : "1px solid transparent",
                          }}
                        >
                          {isComplete ? (
                            <CheckIcon sx={{ fontSize: 18, color: "success.main" }} />
                          ) : isActive ? (
                            <CircularProgress size={16} color="error" />
                          ) : (
                            <Box sx={{ width: 18, height: 18, borderRadius: "50%", border: "2px solid", borderColor: "divider", display: "flex", alignItems: "center", justifyContent: "center" }}>
                              <Typography variant="caption" sx={{ fontSize: 9 }}>{phase.num}</Typography>
                            </Box>
                          )}
                          <Typography 
                            variant="caption" 
                            sx={{ 
                              fontWeight: isActive ? 600 : 400,
                              color: isComplete ? "success.main" : isActive ? "error.main" : "text.secondary"
                            }}
                          >
                            {phase.icon} {phase.name}
                          </Typography>
                        </Box>
                      );
                    })}
                  </Box>
                  
                  {/* Time Elapsed */}
                  <Box sx={{ mt: 2, textAlign: "center" }}>
                    <Typography variant="caption" color="text.secondary">
                      Elapsed: {Math.floor((Date.now() - scanProgress.startTime) / 1000)}s • Estimated: 2-4 minutes
                    </Typography>
                  </Box>
                </Paper>
              )}

              {/* Enhanced Security Results */}
              {enhancedSecurityResult && !enhancedSecurityLoading && (
                <Box>
                  {/* Executive Summary */}
                  <Box sx={{ 
                    p: 2,
                    borderRadius: 1,
                    bgcolor: alpha(getSeverityColor(enhancedSecurityResult.overall_risk === "none" ? "low" : enhancedSecurityResult.overall_risk), 0.15),
                    border: `1px solid ${getSeverityColor(enhancedSecurityResult.overall_risk === "none" ? "low" : enhancedSecurityResult.overall_risk)}`,
                    mb: 3
                  }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                      <Chip 
                        label={`${enhancedSecurityResult.overall_risk.toUpperCase()} RISK`} 
                        sx={{ 
                          bgcolor: getSeverityColor(enhancedSecurityResult.overall_risk === "none" ? "low" : enhancedSecurityResult.overall_risk),
                          color: "white",
                          fontWeight: 700
                        }} 
                      />
                      <Typography variant="body2" color="grey.300">
                        {enhancedSecurityResult.combined_findings.length} findings from {enhancedSecurityResult.analysis_metadata.classes_scanned} classes
                      </Typography>
                    </Box>
                    <Typography variant="body2" color="grey.400">
                      {enhancedSecurityResult.executive_summary}
                    </Typography>
                  </Box>

                  {/* Analysis Metadata */}
                  <Box sx={{ display: "flex", gap: 1, mb: 3, flexWrap: "wrap", alignItems: "center" }}>
                    <Chip 
                      label={`Pattern: ${enhancedSecurityResult.pattern_findings.length}`} 
                      size="small" 
                      variant="outlined"
                      color="info"
                    />
                    <Chip 
                      label={`AI: ${enhancedSecurityResult.ai_findings.length}`} 
                      size="small" 
                      variant="outlined"
                      color="warning"
                    />
                    <Chip 
                      label={`CVEs: ${enhancedSecurityResult.analysis_metadata.cves_found}`} 
                      size="small" 
                      variant="outlined"
                      color="error"
                    />
                    <Chip 
                      label={`Libraries: ${enhancedSecurityResult.analysis_metadata.libraries_detected}`} 
                      size="small" 
                      variant="outlined"
                    />
                    <Box sx={{ flexGrow: 1 }} />
                    {/* Export Dropdown */}
                    <Button
                      size="small"
                      variant="outlined"
                      startIcon={<DownloadIcon />}
                      onClick={(e) => setSecurityExportAnchor(e.currentTarget)}
                      disabled={!!securityExporting}
                    >
                      {securityExporting ? `Exporting ${securityExporting.toUpperCase()}...` : "Export Report"}
                    </Button>
                    <Menu
                      anchorEl={securityExportAnchor}
                      open={Boolean(securityExportAnchor)}
                      onClose={() => setSecurityExportAnchor(null)}
                    >
                      <MenuItem onClick={() => handleSecurityExport("markdown")}>
                        📄 Markdown (.md)
                      </MenuItem>
                      <MenuItem onClick={() => handleSecurityExport("pdf")}>
                        📑 PDF Document
                      </MenuItem>
                      <MenuItem onClick={() => handleSecurityExport("docx")}>
                        📝 Word Document (.docx)
                      </MenuItem>
                    </Menu>
                  </Box>

                  {/* Risk Summary */}
                  <Grid container spacing={1} sx={{ mb: 3 }}>
                    <Grid item xs={2.4}>
                      <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#dc2626", 0.1) }}>
                        <Typography variant="h4" color="error">{enhancedSecurityResult.risk_summary.critical}</Typography>
                        <Typography variant="caption">Critical</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={2.4}>
                      <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#ea580c", 0.1) }}>
                        <Typography variant="h4" sx={{ color: "#ea580c" }}>{enhancedSecurityResult.risk_summary.high}</Typography>
                        <Typography variant="caption">High</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={2.4}>
                      <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#ca8a04", 0.1) }}>
                        <Typography variant="h4" sx={{ color: "#ca8a04" }}>{enhancedSecurityResult.risk_summary.medium}</Typography>
                        <Typography variant="caption">Medium</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={2.4}>
                      <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#16a34a", 0.1) }}>
                        <Typography variant="h4" color="success.main">{enhancedSecurityResult.risk_summary.low}</Typography>
                        <Typography variant="caption">Low</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={2.4}>
                      <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#6b7280", 0.1) }}>
                        <Typography variant="h4" sx={{ color: "#6b7280" }}>{enhancedSecurityResult.risk_summary.info}</Typography>
                        <Typography variant="caption">Info</Typography>
                      </Paper>
                    </Grid>
                  </Grid>

                  {/* AI Offensive Security Plan Summary */}
                  {enhancedSecurityResult.offensive_plan_summary && (
                    <Paper sx={{ p: 2, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.05), border: `1px solid ${alpha(theme.palette.error.main, 0.3)}` }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                        <Typography variant="h6" color="error.main" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          🎯 Offensive Security Assessment
                        </Typography>
                        <Chip 
                          label={`${enhancedSecurityResult.offensive_plan_summary.risk_rating?.toUpperCase() || 'UNKNOWN'} RISK`}
                          size="small"
                          sx={{ 
                            bgcolor: getSeverityColor(enhancedSecurityResult.offensive_plan_summary.risk_rating || 'medium'),
                            color: 'white'
                          }}
                        />
                        <Chip 
                          label={`Confidence: ${enhancedSecurityResult.offensive_plan_summary.confidence_level || 'unknown'}`}
                          size="small"
                          variant="outlined"
                        />
                      </Box>
                      
                      {/* Threat Assessment */}
                      {enhancedSecurityResult.offensive_plan_summary.threat_assessment && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" color="error.light" gutterBottom>
                            Threat Assessment
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: "pre-wrap" }}>
                            {enhancedSecurityResult.offensive_plan_summary.threat_assessment}
                          </Typography>
                        </Box>
                      )}
                      
                      {/* Attack Surface Summary */}
                      {enhancedSecurityResult.offensive_plan_summary.attack_surface_summary && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" color="warning.main" gutterBottom>
                            Attack Surface
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: "pre-wrap" }}>
                            {enhancedSecurityResult.offensive_plan_summary.attack_surface_summary}
                          </Typography>
                        </Box>
                      )}
                      
                      {/* Primary Attack Vectors */}
                      {enhancedSecurityResult.offensive_plan_summary.primary_attack_vectors?.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" color="error.light" gutterBottom>
                            Primary Attack Vectors
                          </Typography>
                          {enhancedSecurityResult.offensive_plan_summary.primary_attack_vectors.map((vector: any, idx: number) => (
                            <Paper key={idx} sx={{ p: 1.5, mb: 1, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                                <Typography variant="body2" fontWeight={600}>{vector.vector}</Typography>
                                <Chip 
                                  label={vector.likelihood} 
                                  size="small" 
                                  sx={{ 
                                    height: 18, 
                                    fontSize: "0.6rem",
                                    bgcolor: vector.likelihood === 'high' ? '#dc2626' : vector.likelihood === 'medium' ? '#ca8a04' : '#16a34a',
                                    color: 'white'
                                  }}
                                />
                              </Box>
                              <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                                {vector.description}
                              </Typography>
                              {vector.prerequisites && (
                                <Typography variant="caption" color="info.main" sx={{ display: "block", mt: 0.5 }}>
                                  Prerequisites: {vector.prerequisites}
                                </Typography>
                              )}
                              {vector.impact && (
                                <Typography variant="caption" color="error.main" sx={{ display: "block" }}>
                                  Impact: {vector.impact}
                                </Typography>
                              )}
                            </Paper>
                          ))}
                        </Box>
                      )}
                      
                      {/* Recommended Test Scenarios */}
                      {enhancedSecurityResult.offensive_plan_summary.recommended_test_scenarios?.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" color="info.main" gutterBottom>
                            Recommended Penetration Tests
                          </Typography>
                          <List dense disablePadding>
                            {enhancedSecurityResult.offensive_plan_summary.recommended_test_scenarios.map((scenario: string, idx: number) => (
                              <ListItem key={idx} sx={{ py: 0.25, pl: 1 }}>
                                <ListItemIcon sx={{ minWidth: 24 }}>
                                  <Typography variant="caption" color="info.main">{idx + 1}.</Typography>
                                </ListItemIcon>
                                <ListItemText 
                                  primary={scenario}
                                  primaryTypographyProps={{ variant: "caption", color: "text.secondary" }}
                                />
                              </ListItem>
                            ))}
                          </List>
                        </Box>
                      )}
                      
                      {/* Priority Targets */}
                      {enhancedSecurityResult.offensive_plan_summary.priority_targets?.length > 0 && (
                        <Box>
                          <Typography variant="subtitle2" color="warning.main" gutterBottom>
                            Priority Targets
                          </Typography>
                          <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                            {enhancedSecurityResult.offensive_plan_summary.priority_targets.map((target: string, idx: number) => (
                              <Chip key={idx} label={target} size="small" variant="outlined" color="warning" sx={{ fontSize: "0.7rem" }} />
                            ))}
                          </Box>
                        </Box>
                      )}
                    </Paper>
                  )}

                  {/* Combined Vulnerabilities - Collapsed by default */}
                  {enhancedSecurityResult.combined_findings.length > 0 && (
                    <Accordion sx={{ mb: 2 }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="body2" color="error.main">
                          Individual Findings ({enhancedSecurityResult.combined_findings.length}) - Click to expand
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        {enhancedSecurityResult.combined_findings.map((finding, idx) => (
                          <Accordion 
                            key={idx} 
                            sx={{ 
                              bgcolor: alpha(getSeverityColor(finding.severity), 0.1),
                              "&:before": { display: "none" },
                              mb: 1
                            }}
                          >
                            <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                                <Chip 
                                  label={finding.severity} 
                                  size="small"
                                  sx={{ 
                                    bgcolor: getSeverityColor(finding.severity),
                                    color: "white",
                                    fontSize: "0.65rem",
                                    height: 20
                                  }} 
                                />
                                <Chip 
                                  label={finding.source.toUpperCase()} 
                                  size="small"
                                  variant="outlined"
                                  sx={{ height: 18, fontSize: "0.6rem" }}
                                />
                                <Typography variant="body2" fontWeight={600}>
                                  {finding.title}
                                </Typography>
                                {finding.cve_id && (
                                  <Chip label={finding.cve_id} size="small" color="error" sx={{ height: 18, fontSize: "0.6rem" }} />
                                )}
                                {finding.cwe_id && (
                                  <Chip label={finding.cwe_id} size="small" variant="outlined" sx={{ height: 18, fontSize: "0.6rem" }} />
                                )}
                              </Box>
                            </AccordionSummary>
                            <AccordionDetails>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                {finding.description}
                              </Typography>
                              {finding.affected_class && (
                                <Typography variant="caption" color="info.main" sx={{ display: "block", mb: 1 }}>
                                  Location: {finding.affected_class} {finding.affected_method ? `→ ${finding.affected_method}` : ""} {finding.line_number ? `(line ${finding.line_number})` : ""}
                                </Typography>
                              )}
                              {finding.affected_library && (
                                <Typography variant="caption" color="warning.main" sx={{ display: "block", mb: 1 }}>
                                  Library: {finding.affected_library}
                                  {(finding as any).version_confirmed && " (version confirmed)"}
                                </Typography>
                              )}
                              {finding.cvss_score && (
                                <Typography variant="caption" color="error.main" sx={{ display: "block", mb: 1 }}>
                                  CVSS Score: {finding.cvss_score}
                                </Typography>
                              )}
                              {(finding as any).cve_confidence && (
                                <Typography variant="caption" color={(finding as any).cve_confidence === "high" ? "success.main" : (finding as any).cve_confidence === "medium" ? "warning.main" : "text.secondary"} sx={{ display: "block", mb: 1 }}>
                                  CVE Confidence: {(finding as any).cve_confidence}
                                  {(finding as any).fixed_version && ` (fixed in ${(finding as any).fixed_version})`}
                                </Typography>
                              )}
                              {finding.code_snippet && (
                                <Box sx={{ 
                                  p: 1, 
                                  bgcolor: alpha(theme.palette.background.paper, 0.3),
                                  borderRadius: 1,
                                  fontFamily: "monospace",
                                  fontSize: "0.75rem",
                                  color: "warning.main",
                                  mb: 1,
                                  whiteSpace: "pre-wrap",
                                  overflow: "auto",
                                  maxHeight: 150
                                }}>
                                  {finding.code_snippet}
                                </Box>
                              )}
                              {finding.impact && (
                                <Typography variant="caption" color="error.main" sx={{ display: "block", mb: 0.5 }}>
                                  Impact: {finding.impact}
                                </Typography>
                              )}
                              {finding.exploitation_potential && (
                                <Typography variant="caption" color="warning.main" sx={{ display: "block", mb: 0.5 }}>
                                  Exploitation: {finding.exploitation_potential}
                                </Typography>
                              )}
                              {finding.attack_vector && (
                                <Typography variant="caption" color="info.main" sx={{ display: "block", mb: 0.5 }}>
                                  Attack Vector: {finding.attack_vector}
                                </Typography>
                              )}
                              {finding.remediation && (
                                <Typography variant="caption" color="success.main" sx={{ display: "block" }}>
                                  Fix: {finding.remediation}
                                </Typography>
                              )}
                            </AccordionDetails>
                          </Accordion>
                        ))}
                      </AccordionDetails>
                    </Accordion>
                  )}

                  {/* Attack Chains */}
                  {enhancedSecurityResult.attack_chains.length > 0 && (
                    <Accordion sx={{ mb: 2 }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="body2" color="warning.main">
                          Attack Chains ({enhancedSecurityResult.attack_chains.length})
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        {enhancedSecurityResult.attack_chains.map((chain, idx) => (
                          <Paper key={idx} sx={{ p: 2, mb: 1, bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                              <Typography variant="subtitle2" fontWeight={700}>
                                {chain.name}
                              </Typography>
                              <Chip 
                                label={chain.likelihood} 
                                size="small" 
                                color={chain.likelihood === "high" ? "error" : chain.likelihood === "medium" ? "warning" : "info"}
                              />
                            </Box>
                            <Box sx={{ pl: 2, borderLeft: `2px solid ${theme.palette.warning.main}` }}>
                              {chain.steps.map((step, sidx) => (
                                <Typography key={sidx} variant="body2" sx={{ mb: 0.5 }}>
                                  {sidx + 1}. {step}
                                </Typography>
                              ))}
                            </Box>
                            {chain.classes_involved && chain.classes_involved.length > 0 && (
                              <Box sx={{ mt: 1, display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                                {chain.classes_involved.map((cls, cidx) => (
                                  <Chip key={cidx} label={cls} size="small" variant="outlined" sx={{ fontSize: "0.6rem" }} />
                                ))}
                              </Box>
                            )}
                            <Typography variant="caption" color="error.main" sx={{ mt: 1, display: "block" }}>
                              Impact: {chain.impact}
                            </Typography>
                          </Paper>
                        ))}
                      </AccordionDetails>
                    </Accordion>
                  )}

                  {/* Recommendations */}
                  {enhancedSecurityResult.recommendations.length > 0 && (
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="body2" color="success.main">
                          Recommendations ({enhancedSecurityResult.recommendations.length})
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <List dense>
                          {enhancedSecurityResult.recommendations.map((rec, idx) => (
                            <ListItem key={idx}>
                              <ListItemIcon sx={{ minWidth: 32 }}>
                                <CheckIcon fontSize="small" color="success" />
                              </ListItemIcon>
                              <ListItemText 
                                primary={rec}
                                primaryTypographyProps={{ variant: "body2", color: "text.secondary" }}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </AccordionDetails>
                    </Accordion>
                  )}
                </Box>
              )}

              {/* AI Security Report (if available and no full scan yet) */}
              {!enhancedSecurityResult && !enhancedSecurityLoading && result.ai_security_report && (
                <Box sx={{ mt: 2 }}>
                  <Box sx={htmlContentStyles} dangerouslySetInnerHTML={{ __html: result.ai_security_report }} />
                </Box>
              )}

              {/* Fallback: Show raw security issues if no AI report and no full scan */}
              {!enhancedSecurityResult && !enhancedSecurityLoading && !result.ai_security_report && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="h6" gutterBottom>Security Issues Found</Typography>
                  {result.security_issues.length === 0 && result.jadx_security_issues.length === 0 ? (
                    <Alert severity="success">No security issues detected! Run a full security scan for comprehensive analysis.</Alert>
                  ) : (
                    <List>
                      {[
                        ...result.security_issues,
                        ...result.jadx_security_issues.map(i => ({
                          category: String(i.category || "Security Issue"),
                          severity: String(i.severity || "medium"),
                          description: String(i.description || ""),
                        }))
                      ].map((issue, idx) => (
                        <ListItem key={idx}>
                          <ListItemIcon>
                            <WarningIcon color={issue.severity === "high" || issue.severity === "critical" ? "error" : "warning"} />
                          </ListItemIcon>
                          <ListItemText 
                            primary={issue.category || issue.description}
                            secondary={issue.description}
                          />
                          <Chip label={issue.severity} size="small" color={issue.severity === "high" ? "error" : "warning"} />
                        </ListItem>
                      ))}
                    </List>
                  )}
                </Box>
              )}
            </Box>
          )}
          
          {/* Tab 2: Architecture Diagram */}
          {activeTab === 2 && (
            result.ai_architecture_diagram ? (
              <MermaidDiagram 
                code={result.ai_architecture_diagram}
                title="APK Architecture"
                maxHeight={600}
                showControls={true}
                showCodeToggle={true}
              />
            ) : (
              <Alert severity="info">
                Architecture diagram not available. This may happen if AI analysis encountered an error.
              </Alert>
            )
          )}
          
          {/* Tab 3: Attack Surface Map */}
          {activeTab === 3 && (
            result.ai_attack_surface_map ? (
              <MermaidDiagram 
                code={result.ai_attack_surface_map}
                title="Attack Surface Map"
                maxHeight={600}
                showControls={true}
                showCodeToggle={true}
              />
            ) : (
              <Alert severity="info">
                Attack surface map not available. Run a Full Security Scan to generate an attack surface visualization.
              </Alert>
            )
          )}
          
          {/* Tab 4: Decompiled Classes */}
          {activeTab === 4 && (
            <Box>
              {/* Stats Header */}
              <Box sx={{ mb: 3, display: "flex", gap: 2, flexWrap: "wrap" }}>
                <Chip 
                  icon={<CodeIcon />} 
                  label={`${result.total_classes.toLocaleString()} Classes`} 
                  color="primary" 
                />
                <Chip 
                  icon={<FolderIcon />} 
                  label={`${result.total_files.toLocaleString()} Files`} 
                  variant="outlined" 
                />
                {result.jadx_security_issues.length > 0 && (
                  <Chip 
                    icon={<SecurityIcon />} 
                    label={`${result.jadx_security_issues.length} Security Issues`} 
                    color="error" 
                  />
                )}
              </Box>
              
              {/* Source Tree Viewer (if available) */}
              {result.source_tree && Object.keys(result.source_tree).length > 0 ? (
                <Paper sx={{ p: 2, mb: 3, maxHeight: 400, overflow: "auto" }}>
                  <Typography variant="subtitle1" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <FolderIcon color="primary" /> Source Tree Structure
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {isViewingOnly ? "Read-only view from saved report. Upload APK to browse live source code." : "Decompiled source structure"}
                  </Typography>
                  <Box sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
                    {renderSourceTree(result.source_tree, 0)}
                  </Box>
                </Paper>
              ) : (
                <Alert severity="info" sx={{ mb: 3 }}>
                  Source tree structure not available. Run a new APK scan to see the decompiled file structure.
                </Alert>
              )}
              
              {/* Classes Summary Table */}
              {result.classes_summary && result.classes_summary.length > 0 ? (
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle1" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <LayersIcon color="secondary" /> Decompiled Classes ({result.classes_summary.length} of {result.total_classes})
                  </Typography>
                  <TableContainer sx={{ maxHeight: 400 }}>
                    <Table size="small" stickyHeader>
                      <TableHead>
                        <TableRow>
                          <TableCell>Class Name</TableCell>
                          <TableCell>Package</TableCell>
                          <TableCell>Type</TableCell>
                          <TableCell align="right">Security Issues</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {result.classes_summary.map((cls, idx) => (
                          <TableRow key={idx} hover>
                            <TableCell>
                              <code style={{ fontSize: "0.8em" }}>{cls.class_name}</code>
                            </TableCell>
                            <TableCell>
                              <Typography variant="caption" color="text.secondary">
                                {cls.package_name}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              {cls.is_activity && <Chip label="Activity" size="small" color="primary" sx={{ mr: 0.5 }} />}
                              {cls.is_service && <Chip label="Service" size="small" color="secondary" sx={{ mr: 0.5 }} />}
                              {!cls.is_activity && !cls.is_service && <Chip label="Class" size="small" variant="outlined" />}
                            </TableCell>
                            <TableCell align="right">
                              {cls.security_issues_count > 0 ? (
                                <Chip label={cls.security_issues_count} size="small" color="error" />
                              ) : (
                                <Typography variant="caption" color="text.secondary">—</Typography>
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  {result.classes_summary.length < result.total_classes && (
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1, textAlign: "center" }}>
                      Showing {result.classes_summary.length} of {result.total_classes.toLocaleString()} classes
                    </Typography>
                  )}
                </Paper>
              ) : (
                <Alert severity="info">
                  Class details not available. Run a new APK scan to see decompiled class information.
                </Alert>
              )}
              
              {/* JADX Security Issues */}
              {result.jadx_security_issues.length > 0 && (
                <Paper sx={{ p: 2, mt: 3 }}>
                  <Typography variant="subtitle1" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, color: "error.main" }}>
                    <SecurityIcon /> Security Issues Found in Decompiled Code
                  </Typography>
                  <TableContainer sx={{ maxHeight: 300 }}>
                    <Table size="small" stickyHeader>
                      <TableHead>
                        <TableRow>
                          <TableCell>Severity</TableCell>
                          <TableCell>Issue Type</TableCell>
                          <TableCell>Class</TableCell>
                          <TableCell>Description</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {result.jadx_security_issues.slice(0, 50).map((issue, idx) => {
                          const severity = (issue as any).severity as string || "medium";
                          const issueType = (issue as any).type as string || (issue as any).issue_type as string || "Unknown";
                          const className = (issue as any).class_name as string || "N/A";
                          const description = (issue as any).description as string || (issue as any).message as string || "No description";
                          return (
                          <TableRow key={idx} hover>
                            <TableCell>
                              <Chip 
                                label={severity} 
                                size="small" 
                                color={
                                  severity === "critical" ? "error" :
                                  severity === "high" ? "error" :
                                  severity === "medium" ? "warning" : "default"
                                }
                              />
                            </TableCell>
                            <TableCell>{issueType}</TableCell>
                            <TableCell>
                              <code style={{ fontSize: "0.75em" }}>{className}</code>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" sx={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis" }}>
                                {description}
                              </Typography>
                            </TableCell>
                          </TableRow>
                        )})}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  {result.jadx_security_issues.length > 50 && (
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1, textAlign: "center" }}>
                      Showing 50 of {result.jadx_security_issues.length} security issues
                    </Typography>
                  )}
                </Paper>
              )}
              
              {/* Saved Source Code Viewer */}
              {result.saved_source_code_samples && result.saved_source_code_samples.length > 0 && (
                <SavedSourceCodeViewer samples={result.saved_source_code_samples} />
              )}
            </Box>
          )}
        </Box>
      </Paper>
      
      {/* Additional Details Accordions */}
      <Box sx={{ mt: 3 }}>
        {/* Permissions */}
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <LockIcon color="primary" />
              Permissions ({result.permissions.length})
              {result.dangerous_permissions_count > 0 && (
                <Chip label={`${result.dangerous_permissions_count} dangerous`} size="small" color="error" sx={{ ml: 1 }} />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={1}>
              {result.permissions.map((perm, idx) => (
                <Grid item xs={12} sm={6} key={idx}>
                  <Chip
                    label={perm.name.replace("android.permission.", "")}
                    color={perm.is_dangerous ? "error" : "default"}
                    variant={perm.is_dangerous ? "filled" : "outlined"}
                    size="small"
                    sx={{ m: 0.25 }}
                  />
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>
        
        {/* Secrets */}
        {result.secrets.length > 0 && (
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <SecretIcon color="warning" />
                Hardcoded Secrets ({result.secrets.length})
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Type</TableCell>
                      <TableCell>Value (Masked)</TableCell>
                      <TableCell>Severity</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {result.secrets.map((secret, idx) => (
                      <TableRow key={idx}>
                        <TableCell><Chip label={secret.type} size="small" /></TableCell>
                        <TableCell><code>{secret.masked_value}</code></TableCell>
                        <TableCell>
                          <Chip 
                            label={secret.severity} 
                            size="small" 
                            color={secret.severity === "high" ? "error" : secret.severity === "medium" ? "warning" : "info"} 
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>
        )}
        
        {/* URLs */}
        {result.urls.length > 0 && (
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <LinkIcon color="info" />
                URLs Found ({result.urls.length})
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                {result.urls.slice(0, 50).map((url, idx) => (
                  <ListItem key={idx}>
                    <ListItemText 
                      primary={<code style={{ fontSize: "0.85em", wordBreak: "break-all" }}>{url}</code>}
                    />
                  </ListItem>
                ))}
                {result.urls.length > 50 && (
                  <ListItem>
                    <Typography variant="body2" color="text.secondary">
                      ... and {result.urls.length - 50} more URLs
                    </Typography>
                  </ListItem>
                )}
              </List>
            </AccordionDetails>
          </Accordion>
        )}
        
        {/* Components */}
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <LayersIcon color="secondary" />
              Components ({result.components.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Exported</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {result.components.slice(0, 30).map((comp, idx) => (
                    <TableRow key={idx}>
                      <TableCell><code style={{ fontSize: "0.8em" }}>{comp.name.split(".").pop()}</code></TableCell>
                      <TableCell><Chip label={comp.component_type} size="small" /></TableCell>
                      <TableCell>
                        {comp.is_exported ? (
                          <Chip label="Exported" size="small" color="warning" />
                        ) : (
                          <Chip label="Internal" size="small" variant="outlined" />
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            {result.components.length > 30 && (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                ... and {result.components.length - 30} more components
              </Typography>
            )}
          </AccordionDetails>
        </Accordion>

        {/* Decompiled Code Security Findings */}
        {result.decompiled_code_findings && result.decompiled_code_findings.length > 0 && (
          <DecompiledCodeFindingsAccordion 
            findings={result.decompiled_code_findings} 
            summary={result.decompiled_code_summary}
            jadxSessionId={result.jadx_session_id}
          />
        )}

        {/* Standard Frida Scripts (SSL Bypass, Root Detection, etc.) */}
        {result.dynamic_analysis && (
          <UnifiedFridaScriptsAccordion dynamicAnalysis={result.dynamic_analysis} />
        )}

        {/* Vulnerability-Specific Frida Hooks (Auto-generated from findings) */}
        {result.vulnerability_frida_hooks && result.vulnerability_frida_hooks.vulnerability_scripts && result.vulnerability_frida_hooks.vulnerability_scripts.length > 0 && (
          <VulnerabilityFridaHooksAccordion hooks={result.vulnerability_frida_hooks} />
        )}
      </Box>
      
      {/* Advanced Analysis Tools - Manifest Visualization, Obfuscation */}
      {apkFile && (
        <AdvancedAnalysisToolsTabs 
          apkFile={apkFile} 
          autoStart={false}
          precomputedManifestViz={result.manifest_visualization}
          precomputedObfuscation={result.obfuscation_analysis}
        />
      )}
    </Box>
  );
}

// Binary Analysis Results Component
function BinaryResults({ result }: { result: BinaryAnalysisResult }) {
  const theme = useTheme();
  const [stringsExpanded, setStringsExpanded] = useState(false);
  const [ghidraExpanded, setGhidraExpanded] = useState(false);
  const [ghidraFilter, setGhidraFilter] = useState("");
  const ghidra = result.ghidra_analysis;
  const ghidraFunctions = ghidra?.functions || [];
  const ghidraTotal = ghidra?.functions_total || ghidraFunctions.length;
  const filteredGhidraFunctions = ghidraFilter
    ? ghidraFunctions.filter((fn) => {
        const needle = ghidraFilter.toLowerCase();
        return (
          fn.name.toLowerCase().includes(needle) ||
          fn.entry.toLowerCase().includes(needle)
        );
      })
    : ghidraFunctions;
  const visibleGhidraFunctions = filteredGhidraFunctions.slice(0, 50);
  const ghidraSummaryMap = new Map(
    (result.ghidra_ai_summaries || []).map((s) => [`${s.name}:${s.entry}`, s])
  );
  const isPeBinary = result.metadata.file_type?.includes("PE");
  const fuzzyHashes = result.fuzzy_hashes || {};
  const yaraMatches = result.yara_matches || [];
  const capaSummary = result.capa_summary || null;
  const deobfuscatedStrings = result.deobfuscated_strings || [];
  const peDelayImports = result.metadata.pe_delay_imports || [];
  const peRelocations = result.metadata.pe_relocations || {};
  const peDebug = result.metadata.pe_debug || {};
  const peDataDirectories = result.metadata.pe_data_directories || [];
  const peManifest = result.metadata.pe_manifest || "";
  const peMitigations = result.metadata.mitigations || {};
  const tlsCallbacks = result.metadata.tls_callbacks || [];
  const resourceSummary = result.metadata.resource_summary || {};
  const versionInfo = result.metadata.version_info || {};
  const authenticode = result.metadata.authenticode || null;
  const overlay = result.metadata.overlay || null;
  const elfDynamic = result.metadata.elf_dynamic || {};
  const elfRelocations = result.metadata.elf_relocations || {};
  const elfVersionInfo = result.metadata.elf_version_info || {};
  const elfBuildId = result.metadata.elf_build_id;
  const elfProgramHeaders = result.metadata.elf_program_headers || [];
  const preferredVersionKeys = [
    "CompanyName",
    "FileDescription",
    "ProductName",
    "ProductVersion",
    "FileVersion",
    "OriginalFilename",
    "InternalName",
  ];
  const versionInfoEntries = preferredVersionKeys
    .filter((key) => versionInfo[key])
    .map((key) => [key, String(versionInfo[key])]);
  const extraVersionEntries = Object.entries(versionInfo)
    .filter(([key, value]) => !preferredVersionKeys.includes(key) && value)
    .slice(0, 6)
    .map(([key, value]) => [key, String(value)]);
  const allVersionEntries = [...versionInfoEntries, ...extraVersionEntries];
  const mitigationFlags = [
    { key: "aslr", label: "ASLR" },
    { key: "dep", label: "DEP" },
    { key: "cfg", label: "CFG" },
    { key: "gs_cookie", label: "GS Cookie" },
    { key: "safe_seh", label: "SafeSEH" },
    { key: "high_entropy_va", label: "High Entropy VA" },
    { key: "force_integrity", label: "Force Integrity" },
    { key: "no_seh", label: "No SEH" },
    { key: "app_container", label: "AppContainer" },
    { key: "terminal_server_aware", label: "Terminal Server Aware" },
  ];
  const mitigationChips = mitigationFlags
    .map((flag) => ({
      label: flag.label,
      value: peMitigations[flag.key],
    }))
    .filter((entry): entry is { label: string; value: boolean } => typeof entry.value === "boolean");
  const hasPeDeepDetails =
    isPeBinary &&
    (peDelayImports.length > 0 ||
      (peRelocations.total_entries || 0) > 0 ||
      (peDebug.count || 0) > 0 ||
      peDataDirectories.length > 0 ||
      Boolean(peManifest));
  const hasElfDynamicValues =
    Boolean(elfDynamic.soname || elfDynamic.rpath || elfDynamic.runpath) ||
    (elfDynamic.flags?.length || 0) > 0 ||
    (elfDynamic.flags_1?.length || 0) > 0 ||
    (elfDynamic.needed?.length || 0) > 0;
  const hasElfDeepDetails =
    result.metadata.file_type?.includes("ELF") &&
    (Boolean(elfBuildId) ||
      hasElfDynamicValues ||
      (elfRelocations.total || 0) > 0 ||
      (elfVersionInfo.definitions?.length || 0) > 0 ||
      (elfVersionInfo.requirements?.length || 0) > 0 ||
      elfProgramHeaders.length > 0);
  const hasIntel =
    Object.keys(fuzzyHashes).length > 0 ||
    yaraMatches.length > 0 ||
    Boolean(capaSummary) ||
    deobfuscatedStrings.length > 0;

  return (
    <Box>
      {/* Metadata Section */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.background.paper, 0.7) }}>
        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <BinaryIcon color="primary" /> Binary Metadata
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">File Type</Typography>
            <Typography variant="body1">{result.metadata.file_type}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Architecture</Typography>
            <Typography variant="body1">{result.metadata.architecture}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">File Size</Typography>
            <Typography variant="body1">{(result.metadata.file_size / 1024).toFixed(1)} KB</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Entry Point</Typography>
            <Typography variant="body1" fontFamily="monospace">
              {result.metadata.entry_point ? `0x${result.metadata.entry_point.toString(16)}` : "N/A"}
            </Typography>
          </Grid>
          {result.metadata.is_packed && (
            <Grid item xs={12}>
              <Chip
                icon={<WarningIcon />}
                label={`Packed binary detected: ${result.metadata.packer_name || "Unknown packer"}`}
                color="warning"
                variant="outlined"
              />
            </Grid>
          )}
          {result.metadata.compile_time && (
            <Grid item xs={12} sm={6}>
              <Typography variant="caption" color="text.secondary">Compile Time</Typography>
              <Typography variant="body1">{result.metadata.compile_time}</Typography>
            </Grid>
          )}
        </Grid>
      </Paper>

      {/* Suspicious Indicators */}
      {result.suspicious_indicators.length > 0 && (
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon color="error" /> Suspicious Indicators ({result.suspicious_indicators.length})
          </Typography>
          <List dense>
            {result.suspicious_indicators.map((indicator, idx) => (
              <ListItem key={idx}>
                <ListItemIcon>
                  <Chip
                    label={indicator.severity}
                    size="small"
                    sx={{
                      bgcolor: alpha(getSeverityColor(indicator.severity), 0.2),
                      color: getSeverityColor(indicator.severity),
                      fontWeight: 600,
                    }}
                  />
                </ListItemIcon>
                <ListItemText
                  primary={indicator.description}
                  secondary={indicator.category}
                />
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* Secrets Found */}
      {result.secrets.length > 0 && (
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SecretIcon color="error" /> Secrets Found ({result.secrets.length})
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>Value</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Offset</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {result.secrets.map((secret, idx) => (
                  <TableRow key={idx}>
                    <TableCell>{secret.type}</TableCell>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                        {secret.masked_value}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={secret.severity}
                        size="small"
                        sx={{
                          bgcolor: alpha(getSeverityColor(secret.severity), 0.2),
                          color: getSeverityColor(secret.severity),
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        {secret.offset ? `0x${secret.offset.toString(16)}` : "-"}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* Imports */}
      {result.imports.length > 0 && (
        <Accordion defaultExpanded={result.imports.some(i => i.is_suspicious)}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <FunctionIcon color="primary" /> Imported Functions ({result.imports.length})
              {result.imports.filter(i => i.is_suspicious).length > 0 && (
                <Chip
                  label={`${result.imports.filter(i => i.is_suspicious).length} suspicious`}
                  size="small"
                  color="warning"
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer sx={{ maxHeight: 400 }}>
              <Table size="small" stickyHeader>
                <TableHead>
                  <TableRow>
                    <TableCell>Function</TableCell>
                    <TableCell>Library</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {result.imports
                    .sort((a, b) => (b.is_suspicious ? 1 : 0) - (a.is_suspicious ? 1 : 0))
                    .map((imp, idx) => (
                      <TableRow
                        key={idx}
                        sx={{
                          bgcolor: imp.is_suspicious
                            ? alpha(theme.palette.warning.main, 0.1)
                            : "transparent",
                        }}
                      >
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {imp.name}
                          </Typography>
                        </TableCell>
                        <TableCell>{imp.library}</TableCell>
                        <TableCell>
                          {imp.is_suspicious ? (
                            <Tooltip title={imp.reason || "Suspicious API"}>
                              <Chip label="⚠️ Suspicious" size="small" color="warning" />
                            </Tooltip>
                          ) : (
                            <Chip label="Normal" size="small" variant="outlined" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Strings */}
      <Accordion expanded={stringsExpanded} onChange={() => setStringsExpanded(!stringsExpanded)}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon color="primary" /> Extracted Strings ({result.strings_count} total, showing {result.strings_sample.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Box sx={{ maxHeight: 400, overflow: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell width={100}>Offset</TableCell>
                  <TableCell width={100}>Category</TableCell>
                  <TableCell>Value</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {result.strings_sample.map((str, idx) => (
                  <TableRow key={idx}>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        0x{str.offset.toString(16)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={str.category || "general"}
                        size="small"
                        variant="outlined"
                        color={
                          str.category === "url"
                            ? "info"
                            : str.category === "path"
                            ? "secondary"
                            : str.category === "email"
                            ? "warning"
                            : "default"
                        }
                      />
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        fontFamily="monospace"
                        sx={{ wordBreak: "break-all" }}
                      >
                        {str.value}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Box>
        </AccordionDetails>
      </Accordion>

      {/* ELF Security Features */}
      {result.metadata.file_type?.includes("ELF") && (
        <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon color="info" /> ELF Security Features
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: "center", p: 1 }}>
                <Chip
                  label={result.metadata.nx_enabled ? "NX Enabled" : "NX Disabled"}
                  color={result.metadata.nx_enabled ? "success" : "error"}
                  variant="outlined"
                />
                <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
                  No-Execute Stack
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: "center", p: 1 }}>
                <Chip
                  label={result.metadata.pie_enabled ? "PIE Enabled" : "No PIE"}
                  color={result.metadata.pie_enabled ? "success" : "warning"}
                  variant="outlined"
                />
                <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
                  Position Independent
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: "center", p: 1 }}>
                <Chip
                  label={result.metadata.stack_canary ? "Canary Enabled" : "No Canary"}
                  color={result.metadata.stack_canary ? "success" : "error"}
                  variant="outlined"
                />
                <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
                  Stack Protection
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: "center", p: 1 }}>
                <Chip
                  label={result.metadata.relro || "No RELRO"}
                  color={result.metadata.relro === "Full" ? "success" : result.metadata.relro === "Partial" ? "warning" : "error"}
                  variant="outlined"
                />
                <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
                  RELRO Protection
                </Typography>
              </Box>
            </Grid>
            {result.metadata.interpreter && (
              <Grid item xs={12}>
                <Typography variant="caption" color="text.secondary">Interpreter</Typography>
                <Typography variant="body2" fontFamily="monospace">{result.metadata.interpreter}</Typography>
              </Grid>
            )}
            {result.metadata.linked_libraries && result.metadata.linked_libraries.length > 0 && (
              <Grid item xs={12}>
                <Typography variant="caption" color="text.secondary">Linked Libraries</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                  {result.metadata.linked_libraries.map((lib, idx) => (
                    <Chip key={idx} label={lib} size="small" variant="outlined" />
                  ))}
                </Box>
              </Grid>
            )}
          </Grid>
        </Paper>
      )}

      {/* PE Rich Header & Imphash - Compiler/Linker Info */}
      {isPeBinary && (result.metadata.rich_header || result.metadata.imphash) && (
        <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon color="info" /> PE Rich Header & Build Info
          </Typography>
          
          {/* Imphash and Rich Hash */}
          <Grid container spacing={2} sx={{ mb: 2 }}>
            {result.metadata.imphash && (
              <Grid item xs={12} sm={6}>
                <Typography variant="caption" color="text.secondary">Import Hash (imphash)</Typography>
                <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                  {result.metadata.imphash}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Use for malware family identification
                </Typography>
              </Grid>
            )}
            {result.metadata.rich_header && (
              <Grid item xs={12} sm={6}>
                <Typography variant="caption" color="text.secondary">Rich Header Hash</Typography>
                <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                  {result.metadata.rich_header.rich_hash}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Checksum: 0x{result.metadata.rich_header.checksum.toString(16).toUpperCase()}
                </Typography>
              </Grid>
            )}
          </Grid>

          {/* Rich Header Entries - Compiler/Linker Table */}
          {result.metadata.rich_header && result.metadata.rich_header.entries.length > 0 && (
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Build Tools ({result.metadata.rich_header.entries.length} components)
              </Typography>
              <TableContainer sx={{ maxHeight: 300 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell>Product</TableCell>
                      <TableCell>Product ID</TableCell>
                      <TableCell>Build ID</TableCell>
                      <TableCell>Count</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {result.metadata.rich_header.entries.map((entry, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Typography variant="body2">
                            {entry.product_name || `Unknown (${entry.product_id})`}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {entry.product_id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {entry.build_id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {entry.count}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </Paper>
      )}

      {/* PE Deep Details */}
      {hasPeDeepDetails && (
        <Accordion sx={{ mt: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <SecurityIcon color="info" /> PE Deep Details
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {peDelayImports.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Delay Imports</Typography>
                  <TableContainer sx={{ maxHeight: 220 }}>
                    <Table size="small" stickyHeader>
                      <TableHead>
                        <TableRow>
                          <TableCell>DLL</TableCell>
                          <TableCell>Count</TableCell>
                          <TableCell>Sample Imports</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {peDelayImports.slice(0, 6).map((entry, idx) => (
                          <TableRow key={`${entry.dll}-${idx}`}>
                            <TableCell>{entry.dll}</TableCell>
                            <TableCell>{entry.count}</TableCell>
                            <TableCell>
                              <Typography variant="body2" color="text.secondary">
                                {entry.imports.slice(0, 4).map((imp) => imp.name).join(", ") || "-"}
                              </Typography>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Grid>
              )}
              {(peRelocations.total_entries || 0) > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Relocations</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Blocks: {peRelocations.total_blocks || 0} | Entries: {peRelocations.total_entries || 0}
                  </Typography>
                  {Array.isArray(peRelocations.blocks) && peRelocations.blocks.length > 0 && (
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                      {peRelocations.blocks.slice(0, 6).map((block, idx) => (
                        <Chip
                          key={`${block.base_rva}-${idx}`}
                          label={`0x${block.base_rva.toString(16)} (${block.entries_count})`}
                          size="small"
                          variant="outlined"
                        />
                      ))}
                    </Box>
                  )}
                </Grid>
              )}
              {(peDebug.count || 0) > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Debug Info</Typography>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                    {peDebug.entries?.slice(0, 3).map((entry, idx) => (
                      <Typography key={`${entry.type}-${idx}`} variant="caption" color="text.secondary">
                        {entry.type} {entry.pdb_path ? `- ${entry.pdb_path}` : ""}
                      </Typography>
                    ))}
                  </Box>
                </Grid>
              )}
              {peDataDirectories.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Data Directories</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {peDataDirectories.slice(0, 8).map((entry) => (
                      <Chip
                        key={entry.name}
                        label={`${entry.name} (${entry.size})`}
                        size="small"
                        variant="outlined"
                      />
                    ))}
                  </Box>
                </Grid>
              )}
              {peManifest && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>Manifest</Typography>
                  <Typography variant="body2" fontFamily="monospace" sx={{ whiteSpace: "pre-wrap" }}>
                    {peManifest}
                  </Typography>
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>
      )}

      {/* ELF Deep Details */}
      {hasElfDeepDetails && (
        <Accordion sx={{ mt: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <SecurityIcon color="info" /> ELF Deep Details
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {elfBuildId && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Build ID</Typography>
                  <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                    {elfBuildId}
                  </Typography>
                </Grid>
              )}
              {(elfDynamic.soname || elfDynamic.rpath || elfDynamic.runpath) && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Dynamic Info</Typography>
                  {elfDynamic.soname && (
                    <Typography variant="caption" color="text.secondary" display="block">
                      SONAME: {elfDynamic.soname}
                    </Typography>
                  )}
                  {elfDynamic.rpath && (
                    <Typography variant="caption" color="text.secondary" display="block">
                      RPATH: {elfDynamic.rpath}
                    </Typography>
                  )}
                  {elfDynamic.runpath && (
                    <Typography variant="caption" color="text.secondary" display="block">
                      RUNPATH: {elfDynamic.runpath}
                    </Typography>
                  )}
                </Grid>
              )}
              {(elfDynamic.flags?.length || 0) > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>DT_FLAGS</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {elfDynamic.flags?.map((flag) => (
                      <Chip key={flag} label={flag} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
              {(elfDynamic.flags_1?.length || 0) > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>DT_FLAGS_1</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {elfDynamic.flags_1?.map((flag) => (
                      <Chip key={flag} label={flag} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
              {(elfRelocations.total || 0) > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Relocations</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total relocations: {elfRelocations.total}
                  </Typography>
                  {Array.isArray(elfRelocations.sections) && elfRelocations.sections.length > 0 && (
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                      {elfRelocations.sections.slice(0, 6).map((section) => (
                        <Chip
                          key={section.name}
                          label={`${section.name} (${section.relocations})`}
                          size="small"
                          variant="outlined"
                        />
                      ))}
                    </Box>
                  )}
                </Grid>
              )}
              {(elfVersionInfo.definitions?.length || 0) > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Version Definitions</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {elfVersionInfo.definitions?.slice(0, 6).map((entry, idx) => (
                      <Chip
                        key={`${entry.name || "def"}-${idx}`}
                        label={entry.name || `Index ${entry.index ?? "-"}`}
                        size="small"
                        variant="outlined"
                      />
                    ))}
                  </Box>
                </Grid>
              )}
              {(elfVersionInfo.requirements?.length || 0) > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Version Requirements</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {elfVersionInfo.requirements?.slice(0, 6).map((entry, idx) => (
                      <Chip
                        key={`${entry.file || "req"}-${idx}`}
                        label={entry.file || "unknown"}
                        size="small"
                        variant="outlined"
                      />
                    ))}
                  </Box>
                </Grid>
              )}
              {elfProgramHeaders.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>Program Headers</Typography>
                  <TableContainer sx={{ maxHeight: 220 }}>
                    <Table size="small" stickyHeader>
                      <TableHead>
                        <TableRow>
                          <TableCell>Type</TableCell>
                          <TableCell>Offset</TableCell>
                          <TableCell>Vaddr</TableCell>
                          <TableCell>Filesz</TableCell>
                          <TableCell>Memsz</TableCell>
                          <TableCell>Flags</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {elfProgramHeaders.slice(0, 8).map((seg, idx) => (
                          <TableRow key={`${seg.type}-${idx}`}>
                            <TableCell>{seg.type}</TableCell>
                            <TableCell>
                              <Typography variant="body2" fontFamily="monospace">
                                0x{seg.offset.toString(16)}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" fontFamily="monospace">
                                0x{seg.vaddr.toString(16)}
                              </Typography>
                            </TableCell>
                            <TableCell>{seg.filesz}</TableCell>
                            <TableCell>{seg.memsz}</TableCell>
                            <TableCell>{seg.flags}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>
      )}

      {/* PE Security & Metadata */}
      {isPeBinary && (
        <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.info.main, 0.04) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon color="info" /> PE Security & Metadata
          </Typography>

          {mitigationChips.length > 0 && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" gutterBottom>Mitigations</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.75 }}>
                {mitigationChips.map((chip) => (
                  <Chip
                    key={chip.label}
                    label={`${chip.label}: ${chip.value ? "On" : "Off"}`}
                    size="small"
                    color={chip.value ? "success" : "error"}
                    variant="outlined"
                  />
                ))}
              </Box>
              {peMitigations.dll_characteristics && (
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
                  DLL Characteristics: {peMitigations.dll_characteristics}
                </Typography>
              )}
              {peMitigations.guard_flags && (
                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                  Guard Flags: {peMitigations.guard_flags}
                </Typography>
              )}
            </Box>
          )}

          {(tlsCallbacks.length > 0 || overlay || authenticode || Object.keys(resourceSummary).length > 0 || allVersionEntries.length > 0) ? (
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>TLS Callbacks</Typography>
                {tlsCallbacks.length > 0 ? (
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {tlsCallbacks.slice(0, 10).map((cb) => (
                      <Chip key={cb} label={`0x${cb.toString(16)}`} size="small" variant="outlined" />
                    ))}
                    {tlsCallbacks.length > 10 && (
                      <Chip label={`+${tlsCallbacks.length - 10} more`} size="small" variant="outlined" />
                    )}
                  </Box>
                ) : (
                  <Typography variant="body2" color="text.secondary">None detected</Typography>
                )}
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>Authenticode</Typography>
                {authenticode ? (
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                    <Chip
                      label={authenticode.signed ? "Signed" : "Unsigned"}
                      size="small"
                      color={authenticode.signed ? "success" : "warning"}
                      variant="outlined"
                    />
                    {authenticode.certificate_type && (
                      <Typography variant="caption" color="text.secondary">
                        Type: {authenticode.certificate_type}
                      </Typography>
                    )}
                    {authenticode.certificate_size && (
                      <Typography variant="caption" color="text.secondary">
                        Certificate Size: {(authenticode.certificate_size / 1024).toFixed(1)} KB
                      </Typography>
                    )}
                    {authenticode.status && (
                      <Typography variant="caption" color="text.secondary">
                        Status: {authenticode.status}
                      </Typography>
                    )}
                  </Box>
                ) : (
                  <Typography variant="body2" color="text.secondary">Not available</Typography>
                )}
              </Grid>

              {Object.keys(resourceSummary).length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Resources</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total: {resourceSummary.total_count || 0} items, {(resourceSummary.total_size || 0) / 1024 >= 0.1
                      ? `${((resourceSummary.total_size || 0) / 1024).toFixed(1)} KB`
                      : `${resourceSummary.total_size || 0} B`}
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                    <Chip
                      label={resourceSummary.has_manifest ? "Manifest Present" : "No Manifest"}
                      size="small"
                      color={resourceSummary.has_manifest ? "success" : "default"}
                      variant="outlined"
                    />
                    <Chip
                      label={resourceSummary.has_version_info ? "Version Info Present" : "No Version Info"}
                      size="small"
                      color={resourceSummary.has_version_info ? "success" : "default"}
                      variant="outlined"
                    />
                  </Box>
                  {Array.isArray(resourceSummary.types) && resourceSummary.types.length > 0 && (
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                      {resourceSummary.types.slice(0, 8).map((type) => (
                        <Chip
                          key={type.type}
                          label={`${type.type} (${type.count})`}
                          size="small"
                          variant="outlined"
                        />
                      ))}
                    </Box>
                  )}
                </Grid>
              )}

              {allVersionEntries.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Version Info</Typography>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                    {allVersionEntries.map(([key, value]) => (
                      <Typography key={key} variant="caption" color="text.secondary">
                        {key}: {value}
                      </Typography>
                    ))}
                  </Box>
                </Grid>
              )}

              {overlay && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>Overlay</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Offset: 0x{overlay.offset.toString(16)} | Size: {(overlay.size / 1024).toFixed(1)} KB
                  </Typography>
                </Grid>
              )}
            </Grid>
          ) : (
            <Typography variant="body2" color="text.secondary">
              Additional PE metadata not available.
            </Typography>
          )}
        </Paper>
      )}

      {/* Binary Intelligence */}
      {hasIntel && (
        <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.warning.main, 0.04) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon color="warning" /> Binary Intelligence
          </Typography>
          <Grid container spacing={2}>
            {Object.keys(fuzzyHashes).length > 0 && (
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>Fuzzy Hashes</Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                  {Object.entries(fuzzyHashes).map(([name, value]) => (
                    <Typography key={name} variant="caption" color="text.secondary" fontFamily="monospace">
                      {name}: {value || "N/A"}
                    </Typography>
                  ))}
                </Box>
              </Grid>
            )}

            {yaraMatches.length > 0 && (
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>YARA Matches</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {yaraMatches.slice(0, 10).map((match, idx) => (
                    <Chip
                      key={`${match.rule}-${idx}`}
                      label={match.rule}
                      size="small"
                      color="warning"
                      variant="outlined"
                    />
                  ))}
                  {yaraMatches.length > 10 && (
                    <Chip label={`+${yaraMatches.length - 10} more`} size="small" variant="outlined" />
                  )}
                </Box>
              </Grid>
            )}

            {capaSummary && (
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>capa Capabilities</Typography>
                {capaSummary.error ? (
                  <Typography variant="body2" color="text.secondary">
                    {capaSummary.error}
                  </Typography>
                ) : (
                  <>
                    <Typography variant="body2" color="text.secondary">
                      {capaSummary.rule_count || 0} capabilities detected
                    </Typography>
                    {Array.isArray(capaSummary.capabilities) && capaSummary.capabilities.length > 0 && (
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                        {capaSummary.capabilities.slice(0, 12).map((capability, idx) => (
                          <Chip key={`${capability}-${idx}`} label={capability} size="small" variant="outlined" />
                        ))}
                      </Box>
                    )}
                  </>
                )}
              </Grid>
            )}

            {deobfuscatedStrings.length > 0 && (
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>Deobfuscated Strings</Typography>
                <TableContainer sx={{ maxHeight: 220 }}>
                  <Table size="small" stickyHeader>
                    <TableHead>
                      <TableRow>
                        <TableCell>Method</TableCell>
                        <TableCell>Decoded</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {deobfuscatedStrings.slice(0, 6).map((entry, idx) => (
                        <TableRow key={`${entry.method}-${idx}`}>
                          <TableCell>
                            <Chip label={entry.method} size="small" variant="outlined" />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                              {entry.decoded}
                            </Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
                {deobfuscatedStrings.length > 6 && (
                  <Typography variant="caption" color="text.secondary">
                    ...and {deobfuscatedStrings.length - 6} more
                  </Typography>
                )}
              </Grid>
            )}
          </Grid>
        </Paper>
      )}

      {/* ELF Symbols */}
      {result.symbols && result.symbols.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <FunctionIcon color="secondary" /> ELF Symbols ({result.symbols.length})
              {result.symbols.filter(s => s.is_suspicious).length > 0 && (
                <Chip
                  label={`${result.symbols.filter(s => s.is_suspicious).length} suspicious`}
                  size="small"
                  color="warning"
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer sx={{ maxHeight: 400 }}>
              <Table size="small" stickyHeader>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Address</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Binding</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {result.symbols
                    .sort((a, b) => (b.is_suspicious ? 1 : 0) - (a.is_suspicious ? 1 : 0))
                    .slice(0, 100)
                    .map((sym, idx) => (
                      <TableRow
                        key={idx}
                        sx={{
                          bgcolor: sym.is_suspicious
                            ? alpha(theme.palette.warning.main, 0.1)
                            : sym.is_imported
                            ? alpha(theme.palette.info.main, 0.05)
                            : "transparent",
                        }}
                      >
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {sym.name}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            0x{sym.address.toString(16)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip label={sym.symbol_type} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell>{sym.binding}</TableCell>
                        <TableCell>
                          {sym.is_suspicious ? (
                            <Tooltip title={sym.reason || "Suspicious function"}>
                              <Chip label="⚠️ Suspicious" size="small" color="warning" />
                            </Tooltip>
                          ) : sym.is_imported ? (
                            <Chip label="Imported" size="small" color="info" variant="outlined" />
                          ) : sym.is_exported ? (
                            <Chip label="Exported" size="small" color="success" variant="outlined" />
                          ) : (
                            <Chip label="Local" size="small" variant="outlined" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Disassembly */}
      {result.disassembly && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <CodeIcon color="error" /> Disassembly ({result.disassembly.architecture} {result.disassembly.mode})
              {result.disassembly.suspicious_instructions.length > 0 && (
                <Chip
                  label={`${result.disassembly.suspicious_instructions.length} suspicious patterns`}
                  size="small"
                  color="error"
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            {/* Entry Point Disassembly */}
            {result.disassembly.entry_point_disasm.length > 0 && (
              <Box sx={{ mb: 3 }}>
                <Typography variant="subtitle2" gutterBottom>Entry Point</Typography>
                <Box
                  sx={{
                    bgcolor: "grey.900",
                    color: "grey.100",
                    p: 2,
                    borderRadius: 1,
                    fontFamily: "monospace",
                    fontSize: "0.8rem",
                    maxHeight: 300,
                    overflow: "auto",
                  }}
                >
                  {result.disassembly.entry_point_disasm.map((insn, idx) => (
                    <Box
                      key={idx}
                      sx={{
                        display: "flex",
                        gap: 2,
                        py: 0.25,
                        bgcolor: insn.is_suspicious ? alpha("#ff5722", 0.3) : "transparent",
                        "&:hover": { bgcolor: alpha("#fff", 0.05) },
                      }}
                    >
                      <Typography component="span" sx={{ color: "info.main", minWidth: 100 }}>
                        0x{insn.address.toString(16).padStart(8, "0")}
                      </Typography>
                      <Typography component="span" sx={{ color: "grey.500", minWidth: 80 }}>
                        {insn.bytes_hex}
                      </Typography>
                      <Typography
                        component="span"
                        sx={{
                          color: insn.is_call ? "success.main" : insn.is_jump ? "warning.main" : "grey.100",
                          minWidth: 60,
                        }}
                      >
                        {insn.mnemonic}
                      </Typography>
                      <Typography component="span" sx={{ color: "grey.300" }}>
                        {insn.op_str}
                      </Typography>
                      {insn.comment && (
                        <Typography component="span" sx={{ color: "error.main", ml: "auto" }}>
                          ; {insn.comment}
                        </Typography>
                      )}
                    </Box>
                  ))}
                </Box>
              </Box>
            )}

            {/* Function Disassembly */}
            {result.disassembly.functions.length > 0 && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Analyzed Functions ({result.disassembly.functions.length})
                </Typography>
                {result.disassembly.functions.map((func, fIdx) => (
                  <Accordion key={fIdx} sx={{ mb: 1 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography sx={{ fontFamily: "monospace", display: "flex", alignItems: "center", gap: 1 }}>
                        {func.name}
                        <Typography component="span" variant="caption" color="text.secondary">
                          @ 0x{func.address.toString(16)} ({func.size} bytes)
                        </Typography>
                        {func.suspicious_patterns.length > 0 && (
                          <Chip label="⚠️" size="small" color="warning" />
                        )}
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      {func.calls.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="caption" color="text.secondary">Calls:</Typography>
                          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                            {func.calls.map((call, cIdx) => (
                              <Chip key={cIdx} label={call} size="small" variant="outlined" />
                            ))}
                          </Box>
                        </Box>
                      )}
                      <Box
                        sx={{
                          bgcolor: "grey.900",
                          color: "grey.100",
                          p: 1,
                          borderRadius: 1,
                          fontFamily: "monospace",
                          fontSize: "0.75rem",
                          maxHeight: 200,
                          overflow: "auto",
                        }}
                      >
                        {func.instructions.slice(0, 50).map((insn, iIdx) => (
                          <Box key={iIdx} sx={{ display: "flex", gap: 1, py: 0.125 }}>
                            <Typography component="span" sx={{ color: "info.main", minWidth: 80, fontSize: "inherit" }}>
                              0x{insn.address.toString(16).padStart(8, "0")}
                            </Typography>
                            <Typography component="span" sx={{ color: insn.is_call ? "success.main" : "grey.100", minWidth: 50, fontSize: "inherit" }}>
                              {insn.mnemonic}
                            </Typography>
                            <Typography component="span" sx={{ color: "grey.400", fontSize: "inherit" }}>
                              {insn.op_str}
                            </Typography>
                          </Box>
                        ))}
                      </Box>
                    </AccordionDetails>
                  </Accordion>
                ))}
              </Box>
          )}
        </AccordionDetails>
      </Accordion>
      )}

      {/* Ghidra Decompilation */}
      {ghidra && (
        <Accordion expanded={ghidraExpanded} onChange={() => setGhidraExpanded(!ghidraExpanded)}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <CodeIcon color="primary" /> Ghidra Decompilation
              {ghidra.error ? (
                <Chip label="Error" size="small" color="error" />
              ) : (
                <Chip label={`${ghidraTotal} functions`} size="small" variant="outlined" />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            {ghidra.error ? (
              <Alert severity="warning">{ghidra.error}</Alert>
            ) : (
              <Box>
                {ghidra.program && (
                  <Grid container spacing={2} sx={{ mb: 2 }}>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="caption" color="text.secondary">Program</Typography>
                      <Typography variant="body2" fontFamily="monospace">{ghidra.program.name}</Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="caption" color="text.secondary">Processor</Typography>
                      <Typography variant="body2" fontFamily="monospace">{ghidra.program.processor}</Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="caption" color="text.secondary">Language</Typography>
                      <Typography variant="body2" fontFamily="monospace">{ghidra.program.language_id}</Typography>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Typography variant="caption" color="text.secondary">Compiler Spec</Typography>
                      <Typography variant="body2" fontFamily="monospace">{ghidra.program.compiler_spec}</Typography>
                    </Grid>
                  </Grid>
                )}

                <TextField
                  label="Filter functions"
                  placeholder="Search by name or entry"
                  value={ghidraFilter}
                  onChange={(e) => setGhidraFilter(e.target.value)}
                  fullWidth
                  size="small"
                  sx={{ mb: 2 }}
                />

                <Typography variant="caption" color="text.secondary">
                  Showing {visibleGhidraFunctions.length} of {filteredGhidraFunctions.length} filtered functions
                  {filteredGhidraFunctions.length !== ghidraTotal && ` (total ${ghidraTotal})`}
                </Typography>

                <Divider sx={{ my: 2 }} />

                {visibleGhidraFunctions.map((func, idx) => {
                  const summaryKey = `${func.name}:${func.entry}`;
                  const summary = ghidraSummaryMap.get(summaryKey);
                  return (
                    <Accordion key={`${func.entry}-${idx}`} sx={{ mb: 1 }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography sx={{ fontFamily: "monospace", display: "flex", alignItems: "center", gap: 1 }}>
                          {func.name}
                          <Typography component="span" variant="caption" color="text.secondary">
                            @ {func.entry} ({func.size} bytes)
                          </Typography>
                          {func.is_thunk && <Chip label="Thunk" size="small" variant="outlined" />}
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        {summary?.summary && (
                          <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
                            <Typography variant="subtitle2" gutterBottom>
                              Gemini Summary
                            </Typography>
                            <Typography
                              variant="body2"
                              component="pre"
                              sx={{ whiteSpace: "pre-wrap", fontFamily: "inherit", m: 0 }}
                            >
                              {summary.summary}
                            </Typography>
                          </Paper>
                        )}

                        {func.called_functions && func.called_functions.length > 0 && (
                          <Box sx={{ mb: 2 }}>
                            <Typography variant="caption" color="text.secondary">Calls</Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                              {func.called_functions.slice(0, 12).map((call, cIdx) => (
                                <Chip key={cIdx} label={call} size="small" variant="outlined" />
                              ))}
                              {func.called_functions.length > 12 && (
                                <Chip label={`+${func.called_functions.length - 12} more`} size="small" variant="outlined" />
                              )}
                            </Box>
                          </Box>
                        )}

                        {func.decompiled && (
                          <Box
                            sx={{
                              bgcolor: "grey.900",
                              color: "grey.100",
                              p: 2,
                              borderRadius: 1,
                              fontFamily: "monospace",
                              fontSize: "0.75rem",
                              maxHeight: 300,
                              overflow: "auto",
                            }}
                          >
                            <Typography component="pre" sx={{ m: 0, whiteSpace: "pre-wrap" }}>
                              {func.decompiled}
                            </Typography>
                          </Box>
                        )}
                      </AccordionDetails>
                    </Accordion>
                  );
                })}
              </Box>
            )}
          </AccordionDetails>
        </Accordion>
      )}

      {/* DWARF Debug Info */}
      {result.dwarf_info?.has_debug_info && (
        <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.success.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon color="success" /> Debug Information (DWARF)
          </Typography>
          {result.dwarf_info.compilation_units && result.dwarf_info.compilation_units.length > 0 && (
            <Box>
              <Typography variant="subtitle2" gutterBottom>Compilation Units</Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Source File</TableCell>
                      <TableCell>Compiler</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {result.dwarf_info.compilation_units.map((cu, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">{cu.name}</Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontSize: "0.75rem" }}>{cu.producer || "Unknown"}</Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </Paper>
      )}

      {/* AI Analysis */}
      {result.ai_analysis && (
        <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <AiIcon color="info" /> AI Analysis
          </Typography>
          <Typography
            variant="body2"
            component="pre"
            sx={{
              whiteSpace: "pre-wrap",
              fontFamily: "inherit",
              m: 0,
            }}
          >
            {result.ai_analysis}
          </Typography>
        </Paper>
      )}
    </Box>
  );
}

// APK Analysis Results Component
function ApkResults({ 
  result, 
  jadxResult,
  apkFile 
}: { 
  result: ApkAnalysisResult; 
  jadxResult?: JadxDecompilationResult | null;
  apkFile: File | null;
}) {
  const theme = useTheme();

  return (
    <Box>
      {/* App Info */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.background.paper, 0.7) }}>
        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <ApkIcon color="success" /> APK Information
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <Typography variant="caption" color="text.secondary">Package Name</Typography>
            <Typography variant="body1" fontFamily="monospace">{result.package_name}</Typography>
          </Grid>
          {result.app_name && (
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">App Name</Typography>
              <Typography variant="body1">{result.app_name}</Typography>
            </Grid>
          )}
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Version</Typography>
            <Typography variant="body1">{result.version_name} ({result.version_code})</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Target SDK</Typography>
            <Typography variant="body1">API {result.target_sdk}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Min SDK</Typography>
            <Typography variant="body1">API {result.min_sdk}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Strings Found</Typography>
            <Typography variant="body1">{result.strings_count.toLocaleString()}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Debuggable</Typography>
            <Chip 
              label={result.debuggable ? "Yes" : "No"} 
              size="small" 
              color={result.debuggable ? "error" : "success"}
            />
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Allow Backup</Typography>
            <Chip 
              label={result.allow_backup ? "Yes" : "No"} 
              size="small" 
              color={result.allow_backup ? "warning" : "success"}
            />
          </Grid>
        </Grid>
      </Paper>

      {/* AI Quick Summary - Two tabs */}
      <ApkQuickAISummary result={result} />

      {/* Certificate Info */}
      {result.certificate && (
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(
          result.certificate.is_debug_cert || result.certificate.is_expired 
            ? theme.palette.error.main 
            : theme.palette.success.main, 0.05
        )}}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <LockIcon color={result.certificate.is_debug_cert ? "error" : "success"} /> 
            Signing Certificate
            {result.certificate.is_debug_cert && (
              <Chip label="DEBUG" size="small" color="error" />
            )}
            {result.certificate.is_expired && (
              <Chip label="EXPIRED" size="small" color="error" />
            )}
            <Chip 
              label={`${result.certificate.signature_version} signature`} 
              size="small" 
              color={result.certificate.signature_version === "v1" ? "warning" : "success"}
              variant="outlined"
            />
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <Typography variant="caption" color="text.secondary">Subject</Typography>
              <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                {result.certificate.subject}
              </Typography>
            </Grid>
            <Grid item xs={12} sm={6}>
              <Typography variant="caption" color="text.secondary">Issuer</Typography>
              <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                {result.certificate.issuer}
              </Typography>
            </Grid>
            <Grid item xs={12}>
              <Typography variant="caption" color="text.secondary">SHA-256 Fingerprint</Typography>
              <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all", fontSize: "0.75rem" }}>
                {result.certificate.fingerprint_sha256}
              </Typography>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">Valid From</Typography>
              <Typography variant="body2">{result.certificate.valid_from}</Typography>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">Valid Until</Typography>
              <Typography variant="body2" color={result.certificate.is_expired ? "error" : "inherit"}>
                {result.certificate.valid_until}
              </Typography>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">Public Key</Typography>
              <Typography variant="body2">
                {result.certificate.public_key_algorithm} {result.certificate.public_key_bits && `(${result.certificate.public_key_bits} bits)`}
              </Typography>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">Self-Signed</Typography>
              <Typography variant="body2">{result.certificate.is_self_signed ? "Yes" : "No"}</Typography>
            </Grid>
          </Grid>
        </Paper>
      )}

      {/* Security Issues */}
      {result.security_issues.length > 0 && (
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <BugIcon color="error" /> Security Issues ({result.security_issues.length})
          </Typography>
          <List dense>
            {result.security_issues.map((issue, idx) => (
              <ListItem key={idx} sx={{ flexDirection: "column", alignItems: "flex-start" }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%", mb: 0.5 }}>
                  <Chip
                    label={issue.severity}
                    size="small"
                    sx={{
                      bgcolor: alpha(getSeverityColor(issue.severity), 0.2),
                      color: getSeverityColor(issue.severity),
                      fontWeight: 600,
                      minWidth: 70,
                    }}
                  />
                  <Chip
                    label={issue.category}
                    size="small"
                    variant="outlined"
                    sx={{ fontSize: "0.7rem" }}
                  />
                </Box>
                <Typography variant="body2" sx={{ ml: 0 }}>
                  {issue.description}
                </Typography>
                {issue.recommendation && (
                  <Typography variant="caption" color="text.secondary" sx={{ ml: 0, mt: 0.5 }}>
                    💡 {issue.recommendation}
                  </Typography>
                )}
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* Permissions */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <LockIcon color="warning" /> Permissions ({result.permissions.length})
          {result.dangerous_permissions_count > 0 && (
            <Chip
              label={`${result.dangerous_permissions_count} dangerous`}
              size="small"
              color="error"
            />
          )}
        </Typography>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
          {result.permissions
            .sort((a, b) => (b.is_dangerous ? 1 : 0) - (a.is_dangerous ? 1 : 0))
            .map((perm, idx) => (
              <Tooltip key={idx} title={perm.description || perm.name}>
                <Chip
                  label={perm.name.replace("android.permission.", "")}
                  size="small"
                  color={perm.is_dangerous ? "error" : "default"}
                  variant={perm.is_dangerous ? "filled" : "outlined"}
                />
              </Tooltip>
            ))}
        </Box>
      </Paper>

      {/* Secrets */}
      {result.secrets.length > 0 && (
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SecretIcon color="error" /> Hardcoded Secrets ({result.secrets.length})
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>Value</TableCell>
                  <TableCell>Severity</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {result.secrets.map((secret, idx) => (
                  <TableRow key={idx}>
                    <TableCell>{secret.type}</TableCell>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                        {secret.masked_value}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={secret.severity}
                        size="small"
                        sx={{
                          bgcolor: alpha(getSeverityColor(secret.severity), 0.2),
                          color: getSeverityColor(secret.severity),
                        }}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* AI-Verified Sensitive Data Discovery Section */}
      <SensitiveDataFindingsSection result={result} />

      {/* URLs */}
      {result.urls.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <SearchIcon color="primary" /> URLs Found ({result.urls.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Box sx={{ maxHeight: 300, overflow: "auto" }}>
              {result.urls.map((url, idx) => (
                <Typography
                  key={idx}
                  variant="body2"
                  fontFamily="monospace"
                  sx={{ mb: 0.5, wordBreak: "break-all" }}
                >
                  {url}
                </Typography>
              ))}
            </Box>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Components */}
      {result.components.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <LayersIcon color="primary" /> App Components ({result.components.length})
              {result.components.filter(c => c.is_exported).length > 0 && (
                <Chip
                  label={`${result.components.filter(c => c.is_exported).length} exported`}
                  size="small"
                  color="warning"
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer sx={{ maxHeight: 400 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Exported</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {result.components.map((comp, idx) => (
                    <TableRow key={idx}>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                          {comp.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={comp.component_type} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        {comp.is_exported ? (
                          <Chip label="Exported" size="small" color="warning" />
                        ) : (
                          <Chip label="Internal" size="small" variant="outlined" />
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Native Libraries */}
      {result.native_libraries.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <BinaryIcon color="primary" /> Native Libraries ({result.native_libraries.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {result.native_libraries.map((lib, idx) => (
                <Chip key={idx} label={lib} size="small" variant="outlined" />
              ))}
            </Box>
          </AccordionDetails>
        </Accordion>
      )}

      {/* DEX Analysis */}
      {result.dex_analysis && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <CodeIcon color="primary" /> DEX Analysis
              <Chip label={`${result.dex_analysis.total_classes} classes`} size="small" variant="outlined" />
              <Chip label={`${result.dex_analysis.total_methods} methods`} size="small" variant="outlined" />
              {result.dex_analysis.detected_trackers?.length > 0 && (
                <Chip 
                  label={`${result.dex_analysis.detected_trackers.length} trackers`} 
                  size="small" 
                  color="warning" 
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {/* Detected Trackers */}
              {result.dex_analysis.detected_trackers?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="warning.main">
                    🔍 Detected Trackers/SDKs
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2 }}>
                    {result.dex_analysis.detected_trackers.map((tracker, idx) => (
                      <Tooltip key={idx} title={tracker.package}>
                        <Chip label={tracker.name} size="small" color="warning" />
                      </Tooltip>
                    ))}
                  </Box>
                </Grid>
              )}
              
              {/* Suspicious Patterns */}
              {result.dex_analysis.reflection_usage?.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    🔄 Reflection Usage ({result.dex_analysis.reflection_usage.length})
                  </Typography>
                  <Box sx={{ maxHeight: 150, overflow: "auto" }}>
                    {result.dex_analysis.reflection_usage.slice(0, 10).map((item, idx) => (
                      <Typography key={idx} variant="caption" display="block" fontFamily="monospace">
                        {item.class.split('.').pop()}.{item.method}
                      </Typography>
                    ))}
                  </Box>
                </Grid>
              )}
              
              {result.dex_analysis.crypto_usage?.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    🔐 Crypto Usage ({result.dex_analysis.crypto_usage.length})
                  </Typography>
                  <Box sx={{ maxHeight: 150, overflow: "auto" }}>
                    {result.dex_analysis.crypto_usage.slice(0, 10).map((item, idx) => (
                      <Typography key={idx} variant="caption" display="block" fontFamily="monospace">
                        {item.pattern}
                      </Typography>
                    ))}
                  </Box>
                </Grid>
              )}
              
              {result.dex_analysis.native_calls?.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    ⚙️ Native Calls ({result.dex_analysis.native_calls.length})
                  </Typography>
                  <Box sx={{ maxHeight: 150, overflow: "auto" }}>
                    {result.dex_analysis.native_calls.slice(0, 10).map((item, idx) => (
                      <Typography key={idx} variant="caption" display="block" fontFamily="monospace">
                        {item.class.split('.').pop()}.{item.method}
                      </Typography>
                    ))}
                  </Box>
                </Grid>
              )}
              
              {result.dex_analysis.dynamic_loading?.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom color="error.main">
                    ⚠️ Dynamic Loading ({result.dex_analysis.dynamic_loading.length})
                  </Typography>
                  <Box sx={{ maxHeight: 150, overflow: "auto" }}>
                    {result.dex_analysis.dynamic_loading.slice(0, 10).map((item, idx) => (
                      <Typography key={idx} variant="caption" display="block" fontFamily="monospace">
                        {item.pattern}
                      </Typography>
                    ))}
                  </Box>
                </Grid>
              )}
              
              {result.dex_analysis.anti_analysis_detected?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="warning.main">
                    🛡️ Anti-Analysis Techniques ({result.dex_analysis.anti_analysis_detected.length})
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {result.dex_analysis.anti_analysis_detected.map((item, idx) => (
                      <Chip key={idx} label={item.pattern} size="small" color="warning" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Resource Analysis */}
      {result.resource_analysis && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <StorageIcon color="primary" /> Resources
              <Chip label={`${result.resource_analysis.string_count || 0} strings`} size="small" variant="outlined" />
              <Chip label={`${result.resource_analysis.asset_files?.length || 0} assets`} size="small" variant="outlined" />
              {result.resource_analysis.potential_secrets?.length > 0 && (
                <Chip 
                  label={`${result.resource_analysis.potential_secrets.length} secrets`} 
                  size="small" 
                  color="error" 
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {/* Resource Stats */}
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Drawables</Typography>
                <Typography variant="body1">{result.resource_analysis.drawable_count || 0}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Layouts</Typography>
                <Typography variant="body1">{result.resource_analysis.layout_count || 0}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Raw Resources</Typography>
                <Typography variant="body1">{result.resource_analysis.raw_resources?.length || 0}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Config Files</Typography>
                <Typography variant="body1">{result.resource_analysis.config_files?.length || 0}</Typography>
              </Grid>
              
              {/* Secrets in Resources */}
              {result.resource_analysis.potential_secrets?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="error.main">
                    ⚠️ Potential Secrets in Resources
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Type</TableCell>
                          <TableCell>Source</TableCell>
                          <TableCell>Preview</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {result.resource_analysis.potential_secrets.slice(0, 10).map((secret, idx) => (
                          <TableRow key={idx}>
                            <TableCell>
                              <Chip label={secret.type} size="small" color="error" variant="outlined" />
                            </TableCell>
                            <TableCell>
                              <Typography variant="caption" fontFamily="monospace">
                                {secret.source}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="caption" fontFamily="monospace">
                                {secret.value_preview}
                              </Typography>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Grid>
              )}
              
              {/* Database Files */}
              {result.resource_analysis.database_files?.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    🗄️ Database Files
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {result.resource_analysis.database_files.map((file, idx) => (
                      <Chip key={idx} label={file} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
              
              {/* Config Files */}
              {result.resource_analysis.config_files?.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    ⚙️ Config Files
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {result.resource_analysis.config_files.map((file, idx) => (
                      <Chip key={idx} label={file} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Intent Filter / Deep Link Analysis */}
      {result.intent_filter_analysis && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <LinkIcon color="primary" /> Deep Links & Intent Filters
              {result.intent_filter_analysis.deep_links?.length > 0 && (
                <Chip 
                  label={`${result.intent_filter_analysis.deep_links.length} deep links`} 
                  size="small" 
                  color="info" 
                />
              )}
              {result.intent_filter_analysis.attack_surface_summary?.custom_uri_schemes?.length > 0 && (
                <Chip 
                  label={`${result.intent_filter_analysis.attack_surface_summary.custom_uri_schemes.length} custom schemes`} 
                  size="small" 
                  color="warning" 
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {/* Attack Surface Summary */}
              {result.intent_filter_analysis.attack_surface_summary && (
                <Grid item xs={12}>
                  <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.warning.main, 0.05) }}>
                    <Typography variant="subtitle2" gutterBottom>Attack Surface Summary</Typography>
                    <Grid container spacing={1}>
                      <Grid item xs={6} sm={2}>
                        <Typography variant="caption" color="text.secondary">Deep Links</Typography>
                        <Typography variant="body2">{result.intent_filter_analysis.attack_surface_summary.total_deep_links}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={2}>
                        <Typography variant="caption" color="text.secondary">Browsable</Typography>
                        <Typography variant="body2">{result.intent_filter_analysis.attack_surface_summary.browsable_activities_count}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={2}>
                        <Typography variant="caption" color="text.secondary">Exp. Activities</Typography>
                        <Typography variant="body2">{result.intent_filter_analysis.attack_surface_summary.exported_activities}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={2}>
                        <Typography variant="caption" color="text.secondary">Exp. Services</Typography>
                        <Typography variant="body2">{result.intent_filter_analysis.attack_surface_summary.exported_services}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={2}>
                        <Typography variant="caption" color="text.secondary">Exp. Receivers</Typography>
                        <Typography variant="body2">{result.intent_filter_analysis.attack_surface_summary.exported_receivers}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={2}>
                        <Typography variant="caption" color="text.secondary">Exp. Providers</Typography>
                        <Typography variant="body2">{result.intent_filter_analysis.attack_surface_summary.exported_providers}</Typography>
                      </Grid>
                    </Grid>
                  </Paper>
                </Grid>
              )}
              
              {/* Custom URI Schemes */}
              {result.intent_filter_analysis.attack_surface_summary?.custom_uri_schemes?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="warning.main">
                    🔗 Custom URI Schemes
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {result.intent_filter_analysis.attack_surface_summary.custom_uri_schemes.map((scheme, idx) => (
                      <Chip key={idx} label={`${scheme}://`} size="small" color="warning" />
                    ))}
                  </Box>
                </Grid>
              )}
              
              {/* Deep Links */}
              {result.intent_filter_analysis.deep_links?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>
                    🌐 Deep Links
                  </Typography>
                  <TableContainer sx={{ maxHeight: 200 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>URL</TableCell>
                          <TableCell>Component</TableCell>
                          <TableCell>Type</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {result.intent_filter_analysis.deep_links.slice(0, 20).map((link, idx) => (
                          <TableRow key={idx}>
                            <TableCell>
                              <Typography variant="caption" fontFamily="monospace">
                                {link.url}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="caption" fontFamily="monospace">
                                {link.component.split('.').pop()}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Chip label={link.type} size="small" variant="outlined" />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Network Security Config */}
      {result.network_config_analysis && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <SecurityIcon color="primary" /> Network Security Config
              {result.network_config_analysis.has_config ? (
                <Chip label="Configured" size="small" color="success" />
              ) : (
                <Chip label="Not Found" size="small" color="warning" />
              )}
              {result.network_config_analysis.cleartext_permitted && (
                <Chip label="Cleartext Allowed" size="small" color="error" />
              )}
              {result.network_config_analysis.certificate_pins?.length > 0 && (
                <Chip label="Pinning Enabled" size="small" color="success" />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {/* Config Status */}
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Has Config</Typography>
                <Typography variant="body2">{result.network_config_analysis.has_config ? "Yes" : "No"}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Cleartext Default</Typography>
                <Typography variant="body2" color={result.network_config_analysis.cleartext_permitted ? "error.main" : "success.main"}>
                  {result.network_config_analysis.cleartext_permitted ? "Allowed" : "Blocked"}
                </Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Trust Anchors</Typography>
                <Typography variant="body2">{result.network_config_analysis.trust_anchors?.length || 0}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Pin Sets</Typography>
                <Typography variant="body2">{result.network_config_analysis.certificate_pins?.length || 0}</Typography>
              </Grid>
              
              {/* Security Issues */}
              {result.network_config_analysis.security_issues?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="error.main">
                    ⚠️ Network Security Issues
                  </Typography>
                  <List dense>
                    {result.network_config_analysis.security_issues.map((issue, idx) => (
                      <ListItem key={idx}>
                        <ListItemIcon sx={{ minWidth: 30 }}>
                          <WarningIcon color="error" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={issue} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              )}
              
              {/* Cleartext Domains */}
              {result.network_config_analysis.cleartext_domains?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="warning.main">
                    🌐 Cleartext (HTTP) Allowed Domains
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {result.network_config_analysis.cleartext_domains.map((domain, idx) => (
                      <Chip key={idx} label={domain} size="small" color="warning" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
              
              {/* Certificate Pins */}
              {result.network_config_analysis.certificate_pins?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="success.main">
                    📌 Certificate Pinning
                  </Typography>
                  {result.network_config_analysis.certificate_pins.map((pinSet, idx) => (
                    <Paper key={idx} sx={{ p: 1.5, mb: 1, bgcolor: alpha(theme.palette.success.main, 0.05) }}>
                      <Typography variant="caption" color="text.secondary">
                        Domains: {pinSet.domains?.join(", ")}
                      </Typography>
                      {pinSet.expiration && (
                        <Typography variant="caption" display="block" color="text.secondary">
                          Expires: {pinSet.expiration}
                        </Typography>
                      )}
                      <Typography variant="caption" display="block">
                        {pinSet.pins?.length || 0} pin(s) configured
                      </Typography>
                    </Paper>
                  ))}
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Smali/Bytecode Decompilation */}
      {result.smali_analysis && (
        <SmaliViewer smali={result.smali_analysis} />
      )}

      {/* Dynamic Analysis / Frida Scripts */}
      {result.dynamic_analysis && (
        <FridaScriptsViewer dynamicAnalysis={result.dynamic_analysis} />
      )}

      {/* Native Library Analysis */}
      {result.native_analysis && result.native_analysis.total_libraries > 0 && (
        <NativeLibraryViewer nativeAnalysis={result.native_analysis} />
      )}

      {/* Data Flow / Taint Analysis */}
      {result.data_flow_analysis && (
        <DataFlowAnalysisViewer dataFlowAnalysis={result.data_flow_analysis} />
      )}

      {/* Hardening Score */}
      {result.hardening_score && (
        <HardeningScoreCard hardeningScore={result.hardening_score} />
      )}

      {/* Advanced Analysis Tools - Tabbed interface for better viewing */}
      {apkFile && (
        <AdvancedAnalysisToolsTabs apkFile={apkFile} autoStart={!!result} />
      )}

      {/* AI Analysis Reports - Hidden when JADX decompiler has run (single source of truth) */}
      {!jadxResult && <ApkAIReports result={result} />}

      {/* AI-Powered Analysis Tools */}
      <ApkAITools analysisResult={result} jadxResult={jadxResult} />

      {/* Deep Code Analysis CTA - Small inline hint when JADX hasn't been run */}
      {!jadxResult && (
        <Alert 
          id="jadx-decompiler-cta"
          severity="info"
          icon={<CodeIcon />}
          sx={{ mt: 2 }}
          action={
            <Button
              color="inherit"
              size="small"
              startIcon={<CodeIcon />}
              onClick={() => {
                document.getElementById('advanced-apk-analysis')?.scrollIntoView({ behavior: 'smooth' });
              }}
            >
              Decompile with JADX
            </Button>
          }
        >
          <Typography variant="body2">
            <strong>Want deeper analysis?</strong> Use JADX Decompiler below for full source code context.
          </Typography>
        </Alert>
      )}
    </Box>
  );
}

// ============================================================================
// Advanced Analysis Tools Tabs - Full-width tabbed interface
// ============================================================================
interface AdvancedAnalysisToolsTabsProps {
  apkFile: File;
  autoStart: boolean;
  onAttackSurfaceResult?: (result: AttackSurfaceMapResult) => void;
  // Pre-computed results from unified scan (no need to re-run if available)
  precomputedManifestViz?: UnifiedApkScanResult['manifest_visualization'];
  precomputedObfuscation?: UnifiedApkScanResult['obfuscation_analysis'];
}

function AdvancedAnalysisToolsTabs({ apkFile, autoStart, onAttackSurfaceResult, precomputedManifestViz, precomputedObfuscation }: AdvancedAnalysisToolsTabsProps) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);

  return (
    <Paper sx={{ mt: 3, overflow: 'hidden' }}>
      {/* Header */}
      <Box 
        sx={{ 
          p: 2, 
          background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.1)} 100%)`,
          borderBottom: `1px solid ${theme.palette.divider}`
        }}
      >
        <Typography variant="h6" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          🔬 Advanced Analysis Tools
          {autoStart && (
            <Chip 
              label="Auto-Running" 
              size="small" 
              color="success" 
              variant="outlined" 
              sx={{ ml: 1 }} 
            />
          )}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          Deep analysis tools that complement the Quick Scan results
        </Typography>
      </Box>

      {/* Tabs */}
      <Tabs 
        value={activeTab} 
        onChange={(_, newValue) => setActiveTab(newValue)}
        variant="fullWidth"
        sx={{
          borderBottom: `1px solid ${theme.palette.divider}`,
          '& .MuiTab-root': {
            py: 2,
            fontWeight: 500,
          }
        }}
      >
        <Tab 
          label={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <span>📋</span>
              <span>Manifest Visualization</span>
            </Box>
          }
        />
        <Tab 
          label={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <span>🔐</span>
              <span>Obfuscation Analysis</span>
            </Box>
          }
        />
      </Tabs>

      {/* Tab Panels - Use precomputed data if available, otherwise fallback to on-demand components */}
      <Box sx={{ p: 0 }}>
        <Box sx={{ p: 2, display: activeTab === 0 ? 'block' : 'none' }}>
          {precomputedManifestViz ? (
            <PrecomputedManifestVisualization data={precomputedManifestViz} />
          ) : (
            <ManifestVisualizer apkFile={apkFile} autoStart={autoStart} />
          )}
        </Box>
        <Box sx={{ p: 2, display: activeTab === 1 ? 'block' : 'none' }}>
          {precomputedObfuscation ? (
            <PrecomputedObfuscationAnalysis data={precomputedObfuscation} />
          ) : (
            <ObfuscationAnalyzer apkFile={apkFile} autoStart={autoStart} />
          )}
        </Box>
      </Box>
    </Paper>
  );
}

// ============================================================================
// Precomputed Manifest Visualization Display (from unified scan)
// ============================================================================
function PrecomputedManifestVisualization({ data }: { data: NonNullable<UnifiedApkScanResult['manifest_visualization']> }) {
  const theme = useTheme();
  const [showMermaid, setShowMermaid] = useState(true);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        📋 Manifest Visualization
        <Chip label="Pre-computed" size="small" color="success" />
      </Typography>

      {/* Summary Stats */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={6} sm={3}>
          <Paper sx={{ p: 2, textAlign: 'center', bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
            <Typography variant="h4">{data.component_counts?.activities || 0}</Typography>
            <Typography variant="caption">Activities</Typography>
          </Paper>
        </Grid>
        <Grid item xs={6} sm={3}>
          <Paper sx={{ p: 2, textAlign: 'center', bgcolor: alpha(theme.palette.secondary.main, 0.1) }}>
            <Typography variant="h4">{data.component_counts?.services || 0}</Typography>
            <Typography variant="caption">Services</Typography>
          </Paper>
        </Grid>
        <Grid item xs={6} sm={3}>
          <Paper sx={{ p: 2, textAlign: 'center', bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
            <Typography variant="h4">{data.exported_count || 0}</Typography>
            <Typography variant="caption">Exported</Typography>
          </Paper>
        </Grid>
        <Grid item xs={6} sm={3}>
          <Paper sx={{ p: 2, textAlign: 'center', bgcolor: alpha(theme.palette.error.main, 0.1) }}>
            <Typography variant="h4">{data.permission_summary?.dangerous || 0}</Typography>
            <Typography variant="caption">Dangerous Perms</Typography>
          </Paper>
        </Grid>
      </Grid>

      {/* Deep Link Schemes */}
      {data.deep_link_schemes && data.deep_link_schemes.length > 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          <Typography variant="subtitle2">Deep Link Schemes</Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1 }}>
            {data.deep_link_schemes.map((scheme, idx) => (
              <Chip key={idx} label={scheme} size="small" variant="outlined" />
            ))}
          </Box>
        </Alert>
      )}

      {/* AI Analysis */}
      {data.ai_analysis && (
        <Accordion defaultExpanded sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              🤖 AI Analysis
              <Chip label="AI" size="small" color="secondary" />
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
              {data.ai_analysis}
            </Typography>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Security Assessment */}
      {data.security_assessment && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          <Typography variant="subtitle2">Security Assessment</Typography>
          <Typography variant="body2" sx={{ mt: 1, whiteSpace: 'pre-wrap' }}>
            {data.security_assessment}
          </Typography>
        </Alert>
      )}

      {/* Mermaid Diagram */}
      {data.mermaid_diagram && (
        <Box>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
            <Typography variant="subtitle2">Component Graph</Typography>
            <Box>
              <Button size="small" onClick={() => setShowMermaid(!showMermaid)}>
                {showMermaid ? 'Hide' : 'Show'} Diagram
              </Button>
              <Button size="small" onClick={() => copyToClipboard(data.mermaid_diagram)}>
                Copy Mermaid
              </Button>
            </Box>
          </Box>
          {showMermaid && (
            <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), overflowX: 'auto' }}>
              <pre style={{ margin: 0, fontSize: '0.75rem', whiteSpace: 'pre-wrap' }}>
                {data.mermaid_diagram}
              </pre>
            </Paper>
          )}
        </Box>
      )}
    </Box>
  );
}

// ============================================================================
// Precomputed Obfuscation Analysis Display (from unified scan)
// ============================================================================
function PrecomputedObfuscationAnalysis({ data }: { data: NonNullable<UnifiedApkScanResult['obfuscation_analysis']> }) {
  const theme = useTheme();

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'none': return theme.palette.success.main;
      case 'light': return theme.palette.info.main;
      case 'moderate': return theme.palette.warning.main;
      case 'heavy': return theme.palette.error.main;
      case 'extreme': return theme.palette.error.dark;
      default: return theme.palette.grey[500];
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        🔐 Obfuscation Analysis
        <Chip label="Pre-computed" size="small" color="success" />
      </Typography>

      {/* Overall Score */}
      <Paper sx={{ p: 3, mb: 3, textAlign: 'center', bgcolor: alpha(getLevelColor(data.overall_obfuscation_level), 0.1) }}>
        <Typography variant="h2" sx={{ color: getLevelColor(data.overall_obfuscation_level), fontWeight: 700 }}>
          {data.obfuscation_score}/100
        </Typography>
        <Typography variant="h5" sx={{ textTransform: 'capitalize', color: getLevelColor(data.overall_obfuscation_level) }}>
          {data.overall_obfuscation_level} Obfuscation
        </Typography>
        {data.reverse_engineering_difficulty && (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            RE Difficulty: {data.reverse_engineering_difficulty}
          </Typography>
        )}
      </Paper>

      {/* Class Naming Analysis */}
      {data.class_naming && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: 'center' }}>
              <Typography variant="h5">{data.class_naming.total_classes}</Typography>
              <Typography variant="caption">Total Classes</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: 'center', bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
              <Typography variant="h5">{data.class_naming.obfuscated_count}</Typography>
              <Typography variant="caption">Obfuscated</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: 'center', bgcolor: alpha(theme.palette.success.main, 0.1) }}>
              <Typography variant="h5">{data.class_naming.readable_count}</Typography>
              <Typography variant="caption">Readable</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Paper sx={{ p: 2, textAlign: 'center' }}>
              <Typography variant="h5">{(data.class_naming.obfuscation_ratio * 100).toFixed(0)}%</Typography>
              <Typography variant="caption">Obfuscation Ratio</Typography>
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* Detected Tools */}
      {data.detected_tools && data.detected_tools.length > 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          <Typography variant="subtitle2">Detected Obfuscation Tools</Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1 }}>
            {data.detected_tools.map((tool, idx) => (
              <Chip key={idx} label={tool} size="small" color="secondary" />
            ))}
          </Box>
        </Alert>
      )}

      {/* AI Summary */}
      {data.ai_analysis_summary && (
        <Accordion defaultExpanded sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              🤖 AI Analysis Summary
              <Chip label="AI" size="small" color="secondary" />
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
              {data.ai_analysis_summary}
            </Typography>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Deobfuscation Strategies */}
      {data.deobfuscation_strategies && data.deobfuscation_strategies.length > 0 && (
        <Accordion sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography>🛠️ Deobfuscation Strategies ({data.deobfuscation_strategies.length})</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <List dense>
              {data.deobfuscation_strategies.map((strategy, idx) => (
                <ListItem key={idx}>
                  <ListItemText primary={strategy} />
                </ListItem>
              ))}
            </List>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Recommended Tools */}
      {data.recommended_tools && data.recommended_tools.length > 0 && (
        <Box sx={{ mb: 2 }}>
          <Typography variant="subtitle2" gutterBottom>Recommended Tools</Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
            {data.recommended_tools.map((tool, idx) => (
              <Chip key={idx} label={tool} size="small" variant="outlined" />
            ))}
          </Box>
        </Box>
      )}

      {/* Frida Hooks */}
      {data.frida_hooks && data.frida_hooks.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography>🔧 Frida Hooks ({data.frida_hooks.length})</Typography>
          </AccordionSummary>
          <AccordionDetails>
            {data.frida_hooks.map((hook, idx) => (
              <Paper key={idx} sx={{ p: 2, mb: 1, bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 1 }}>
                  <Button size="small" onClick={() => copyToClipboard(hook)}>Copy</Button>
                </Box>
                <pre style={{ margin: 0, fontSize: '0.75rem', overflowX: 'auto' }}>{hook}</pre>
              </Paper>
            ))}
          </AccordionDetails>
        </Accordion>
      )}

      {/* Warnings */}
      {data.warnings && data.warnings.length > 0 && (
        <Alert severity="warning" sx={{ mt: 2 }}>
          <Typography variant="subtitle2">Warnings</Typography>
          <ul style={{ margin: '8px 0', paddingLeft: '20px' }}>
            {data.warnings.map((warning, idx) => (
              <li key={idx}><Typography variant="body2">{warning}</Typography></li>
            ))}
          </ul>
        </Alert>
      )}
    </Box>
  );
}

// ============================================================================
// APK Quick AI Summary Component - "What Does This APK Do?" and "Quick Security Findings"
// ============================================================================
function ApkQuickAISummary({ result }: { result: ApkAnalysisResult }) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  const [functionalitySummary, setFunctionalitySummary] = useState<string | null>(null);
  const [securitySummary, setSecuritySummary] = useState<string | null>(null);
  const [isLoadingFunc, setIsLoadingFunc] = useState(false);
  const [isLoadingSec, setIsLoadingSec] = useState(false);
  const [errorFunc, setErrorFunc] = useState<string | null>(null);
  const [errorSec, setErrorSec] = useState<string | null>(null);

  // Format markdown to HTML with proper styling
  const formatMarkdownToHtml = (markdown: string): string => {
    if (!markdown) return "";
    
    let html = markdown;
    
    // Headers
    html = html.replace(/^#### (.*$)/gim, '<h4 style="font-size: 1rem; font-weight: 600; margin: 1rem 0 0.5rem 0; color: inherit;">$1</h4>');
    html = html.replace(/^### (.*$)/gim, '<h3 style="font-size: 1.1rem; font-weight: 700; margin: 1.25rem 0 0.5rem 0; color: #60a5fa;">$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2 style="font-size: 1.2rem; font-weight: 700; margin: 1.5rem 0 0.75rem 0; color: inherit;">$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1 style="font-size: 1.3rem; font-weight: 700; margin: 1.5rem 0 0.75rem 0;">$1</h1>');
    
    // Bold and italic
    html = html.replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>');
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong style="font-weight: 600; color: inherit;">$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    
    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code style="background: rgba(0,0,0,0.3); padding: 0.1rem 0.3rem; border-radius: 0.25rem; font-size: 0.85em; font-family: monospace;">$1</code>');
    
    // Process lines for lists and paragraphs
    const lines = html.split('\n');
    const processedLines: string[] = [];
    let inList = false;
    let listType: 'ul' | 'ol' = 'ul';
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const bulletMatch = line.match(/^[\s]*[-*•]\s+(.*)$/);
      const numberedMatch = line.match(/^[\s]*(\d+)\.\s+(.*)$/);
      
      if (bulletMatch) {
        if (!inList || listType !== 'ul') {
          if (inList) processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
          processedLines.push('<ul style="margin: 0.5rem 0; padding-left: 1.25rem; list-style-type: disc;">');
          inList = true;
          listType = 'ul';
        }
        processedLines.push(`<li style="margin: 0.35rem 0; line-height: 1.5;">${bulletMatch[1]}</li>`);
      } else if (numberedMatch) {
        if (!inList || listType !== 'ol') {
          if (inList) processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
          processedLines.push('<ol style="margin: 0.5rem 0; padding-left: 1.25rem;">');
          inList = true;
          listType = 'ol';
        }
        processedLines.push(`<li style="margin: 0.35rem 0; line-height: 1.5;">${numberedMatch[2]}</li>`);
      } else {
        if (inList) {
          processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
          inList = false;
        }
        // Handle paragraphs - skip empty lines, wrap non-empty text
        const trimmedLine = line.trim();
        if (trimmedLine && !trimmedLine.startsWith('<h') && !trimmedLine.startsWith('<pre') && !trimmedLine.startsWith('<ul') && !trimmedLine.startsWith('<ol')) {
          processedLines.push(`<p style="margin: 0.5rem 0; line-height: 1.6;">${line}</p>`);
        } else if (trimmedLine) {
          processedLines.push(line);
        }
      }
    }
    
    if (inList) {
      processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
    }
    
    return processedLines.join('\n');
  };

  // Generate functionality summary
  const generateFunctionalitySummary = async () => {
    if (functionalitySummary) return; // Already generated
    setIsLoadingFunc(true);
    setErrorFunc(null);
    try {
      const request = {
        message: `Based on the APK analysis results, provide a clear summary explaining what this app does.

Use proper markdown formatting with:
- **Bold text** for important terms
- ### Headers for sections
- Bullet points for lists

Structure your response as:

### App Overview
Brief 1-2 sentence description of the app's main purpose.

### Key Features
- Feature 1 based on permissions/components
- Feature 2
- Feature 3

### Target Audience
Who this app is designed for and typical use cases.

Be concise and user-friendly. Focus on what matters most.`,
        conversation_history: [],
        analysis_context: result as unknown as Record<string, unknown>,
        beginner_mode: true,
      };
      const response = await reverseEngineeringClient.chatAboutApk(request);
      setFunctionalitySummary(response.response);
    } catch (err) {
      setErrorFunc(err instanceof Error ? err.message : "Failed to generate summary");
    } finally {
      setIsLoadingFunc(false);
    }
  };

  // Generate security summary
  const generateSecuritySummary = async () => {
    if (securitySummary) return; // Already generated
    setIsLoadingSec(true);
    setErrorSec(null);
    try {
      const request = {
        message: `Based on the APK analysis results, provide a security assessment.

Use proper markdown formatting with:
- **Bold text** for important terms and severity levels
- ### Headers for sections  
- Bullet points for findings

Structure your response as:

### Security Rating
**[Good/Moderate/Concerning]** - Brief 1 sentence explanation.

### Key Security Concerns
- **Issue 1**: Brief description
- **Issue 2**: Brief description
- **Issue 3**: Brief description

### Recommendations
- Recommendation 1
- Recommendation 2

Be direct and actionable. Prioritize the most important issues.`,
        conversation_history: [],
        analysis_context: result as unknown as Record<string, unknown>,
        beginner_mode: true,
      };
      const response = await reverseEngineeringClient.chatAboutApk(request);
      setSecuritySummary(response.response);
    } catch (err) {
      setErrorSec(err instanceof Error ? err.message : "Failed to generate summary");
    } finally {
      setIsLoadingSec(false);
    }
  };

  // Auto-generate on tab switch
  useEffect(() => {
    if (activeTab === 0 && !functionalitySummary && !isLoadingFunc) {
      generateFunctionalitySummary();
    } else if (activeTab === 1 && !securitySummary && !isLoadingSec) {
      generateSecuritySummary();
    }
  }, [activeTab]);

  return (
    <Paper sx={{ p: 0, mb: 3, overflow: "hidden" }}>
      {/* Tabs Header */}
      <Box sx={{ 
        borderBottom: 1, 
        borderColor: "divider",
        bgcolor: alpha(theme.palette.primary.main, 0.03),
      }}>
        <Tabs
          value={activeTab}
          onChange={(_, newValue) => setActiveTab(newValue)}
          centered
          sx={{
            "& .MuiTab-root": {
              fontWeight: 600,
              py: 2,
              px: 4,
              textTransform: "none",
              fontSize: "1rem",
              minHeight: 56,
            },
          }}
        >
          <Tab
            icon={<AiIcon sx={{ fontSize: 22 }} />}
            iconPosition="start"
            label="🤔 What Does This APK Do?"
            sx={{ gap: 1 }}
          />
          <Tab
            icon={<ShieldIcon sx={{ fontSize: 22 }} />}
            iconPosition="start"
            label="🔒 Quick Security Findings"
            sx={{ gap: 1 }}
          />
        </Tabs>
      </Box>

      {/* Tab Content */}
      <Box sx={{ p: 2.5, minHeight: 150 }}>
        {/* Functionality Tab */}
        {activeTab === 0 && (
          <Box>
            {isLoadingFunc ? (
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, py: 3, justifyContent: "center" }}>
                <CircularProgress size={24} />
                <Typography variant="body2" color="text.secondary">
                  Analyzing app functionality...
                </Typography>
              </Box>
            ) : errorFunc ? (
              <Alert 
                severity="error" 
                action={
                  <Button color="inherit" size="small" onClick={generateFunctionalitySummary}>
                    Retry
                  </Button>
                }
              >
                {errorFunc}
              </Alert>
            ) : functionalitySummary ? (
              <Box 
                sx={{ 
                  lineHeight: 1.6,
                  color: theme.palette.text.secondary,
                  '& h1, & h2, & h3, & h4': { color: theme.palette.text.primary },
                  '& strong': { color: theme.palette.text.primary },
                  '& ul, & ol': { marginLeft: 0 },
                  '& p:first-of-type': { marginTop: 0 },
                }}
                dangerouslySetInnerHTML={{ __html: formatMarkdownToHtml(functionalitySummary) }}
              />
            ) : (
              <Box sx={{ textAlign: "center", py: 2 }}>
                <Button
                  variant="outlined"
                  startIcon={<AiIcon />}
                  onClick={generateFunctionalitySummary}
                >
                  Generate Summary
                </Button>
              </Box>
            )}
          </Box>
        )}

        {/* Security Tab */}
        {activeTab === 1 && (
          <Box>
            {isLoadingSec ? (
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, py: 3, justifyContent: "center" }}>
                <CircularProgress size={24} />
                <Typography variant="body2" color="text.secondary">
                  Analyzing security posture...
                </Typography>
              </Box>
            ) : errorSec ? (
              <Alert 
                severity="error" 
                action={
                  <Button color="inherit" size="small" onClick={generateSecuritySummary}>
                    Retry
                  </Button>
                }
              >
                {errorSec}
              </Alert>
            ) : securitySummary ? (
              <Box 
                sx={{ 
                  lineHeight: 1.6,
                  color: theme.palette.text.secondary,
                  '& h1, & h2, & h3, & h4': { color: theme.palette.text.primary },
                  '& strong': { color: theme.palette.text.primary },
                  '& ul, & ol': { marginLeft: 0 },
                  '& p:first-of-type': { marginTop: 0 },
                }}
                dangerouslySetInnerHTML={{ __html: formatMarkdownToHtml(securitySummary) }}
              />
            ) : (
              <Box sx={{ textAlign: "center", py: 2 }}>
                <Button
                  variant="outlined"
                  startIcon={<ShieldIcon />}
                  onClick={generateSecuritySummary}
                >
                  Generate Summary
                </Button>
              </Box>
            )}
          </Box>
        )}
      </Box>
    </Paper>
  );
}

// ============================================================================
// Deep Analysis Reports Component - Full reports after JADX decompilation
// ============================================================================
interface DeepAnalysisReportsProps {
  jadxResult: JadxDecompilationResult;
  quickScanResult: ApkAnalysisResult;
  // Callbacks to share report data with parent for saving
  onFunctionalityReportGenerated?: (report: string) => void;
  onSecurityReportGenerated?: (report: string) => void;
}

function DeepAnalysisReports({ 
  jadxResult, 
  quickScanResult, 
  onFunctionalityReportGenerated,
  onSecurityReportGenerated
}: DeepAnalysisReportsProps) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  const [functionalityReport, setFunctionalityReport] = useState<string | null>(null);
  const [securityReport, setSecurityReport] = useState<string | null>(null);
  const [architectureDiagram, setArchitectureDiagram] = useState<string | null>(null);
  const [isLoadingFunc, setIsLoadingFunc] = useState(false);
  const [isLoadingSec, setIsLoadingSec] = useState(false);
  const [isLoadingDiagram, setIsLoadingDiagram] = useState(false);
  const [errorFunc, setErrorFunc] = useState<string | null>(null);
  const [errorSec, setErrorSec] = useState<string | null>(null);
  const [errorDiagram, setErrorDiagram] = useState<string | null>(null);
  const [autoGenerated, setAutoGenerated] = useState(false);

  // Format markdown to HTML with proper styling
  const formatMarkdownToHtml = (markdown: string): string => {
    if (!markdown) return "";
    
    let html = markdown;
    
    // Headers
    html = html.replace(/^#### (.*$)/gim, '<h4 style="font-size: 1rem; font-weight: 600; margin: 1.5rem 0 0.75rem 0; color: inherit;">$1</h4>');
    html = html.replace(/^### (.*$)/gim, '<h3 style="font-size: 1.1rem; font-weight: 700; margin: 1.75rem 0 0.75rem 0; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.5rem;">$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2 style="font-size: 1.25rem; font-weight: 700; margin: 2rem 0 1rem 0; color: inherit;">$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1 style="font-size: 1.5rem; font-weight: 700; margin: 2rem 0 1rem 0;">$1</h1>');
    
    // Bold and italic
    html = html.replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>');
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong style="font-weight: 600;">$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    
    // Code blocks
    html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, (_, lang, code) => {
      return `<pre style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 0.5rem; overflow-x: auto; margin: 1rem 0; font-size: 0.85rem;"><code>${code.trim()}</code></pre>`;
    });
    
    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code style="background: rgba(0,0,0,0.2); padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.9em;">$1</code>');
    
    // Process lines for lists and paragraphs
    const lines = html.split('\n');
    const processedLines: string[] = [];
    let inList = false;
    let listType: 'ul' | 'ol' = 'ul';
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const bulletMatch = line.match(/^[\s]*[-*•]\s+(.*)$/);
      const numberedMatch = line.match(/^[\s]*(\d+)\.\s+(.*)$/);
      
      if (bulletMatch) {
        if (!inList || listType !== 'ul') {
          if (inList) processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
          processedLines.push('<ul style="margin: 0.75rem 0; padding-left: 1.5rem;">');
          inList = true;
          listType = 'ul';
        }
        processedLines.push(`<li style="margin: 0.5rem 0; line-height: 1.6;">${bulletMatch[1]}</li>`);
      } else if (numberedMatch) {
        if (!inList || listType !== 'ol') {
          if (inList) processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
          processedLines.push('<ol style="margin: 0.75rem 0; padding-left: 1.5rem;">');
          inList = true;
          listType = 'ol';
        }
        processedLines.push(`<li style="margin: 0.5rem 0; line-height: 1.6;">${numberedMatch[2]}</li>`);
      } else {
        if (inList) {
          processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
          inList = false;
        }
        // Wrap non-empty lines that aren't already tags in <p>
        const trimmedLine = line.trim();
        if (trimmedLine && !trimmedLine.startsWith('<')) {
          processedLines.push(`<p style="margin: 0.75rem 0; line-height: 1.7;">${trimmedLine}</p>`);
        } else if (trimmedLine) {
          processedLines.push(line);
        }
      }
    }
    if (inList) {
      processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
    }
    
    return processedLines.join('\n');
  };

  // Generate comprehensive functionality report
  const generateFunctionalityReport = async () => {
    if (functionalityReport) return;
    setIsLoadingFunc(true);
    setErrorFunc(null);
    
    try {
      // Build context from both JADX and quick scan
      const context = {
        ...quickScanResult,
        jadx_info: {
          total_classes: jadxResult.total_classes,
          total_files: jadxResult.total_files,
          output_directory: jadxResult.output_directory,
          class_list_sample: jadxResult.classes?.slice(0, 50).map(c => c.class_name) || [],
          security_issues_count: jadxResult.security_issues?.length || 0,
        }
      };
      
      const request = {
        message: `You are analyzing a decompiled Android APK. Generate a comprehensive, well-formatted report explaining what this app does.

Use proper markdown formatting with:
- **Bold headers** using ## and ###
- Bullet point lists for features
- Code formatting for technical terms

Structure the report as follows:

## 📱 Application Overview
Brief description of the app's main purpose and target users.

## 🎯 Core Functionality
List the main features and what the app does:
- Feature 1: Description
- Feature 2: Description
- etc.

## 🔧 Technical Architecture
- SDK targets and compatibility
- Key libraries and frameworks used
- Native code components (if any)

## 📡 Network & Communication
- API endpoints and services
- Data synchronization patterns
- Third-party integrations

## 💾 Data Handling
- What data the app collects
- Storage mechanisms used
- Data sharing capabilities

## 🎨 User Experience
- Main UI components and activities
- User workflows and navigation
- Content providers and services

## 📊 Summary
Brief conclusion about the app's purpose and sophistication level.

Be specific and technical but accessible. Reference actual class names, permissions, and components found in the analysis.`,
        conversation_history: [],
        analysis_context: context as unknown as Record<string, unknown>,
        beginner_mode: false,
      };
      
      const response = await reverseEngineeringClient.chatAboutApk(request);
      setFunctionalityReport(response.response);
      // Notify parent component for saving
      onFunctionalityReportGenerated?.(response.response);
    } catch (err) {
      setErrorFunc(err instanceof Error ? err.message : "Failed to generate report");
    } finally {
      setIsLoadingFunc(false);
    }
  };

  // Generate comprehensive security report with exploit scenarios
  const generateSecurityReport = async () => {
    if (securityReport) return;
    setIsLoadingSec(true);
    setErrorSec(null);
    
    try {
      const context = {
        ...quickScanResult,
        jadx_info: {
          total_classes: jadxResult.total_classes,
          total_files: jadxResult.total_files,
          output_directory: jadxResult.output_directory,
          class_list_sample: jadxResult.classes?.slice(0, 50).map(c => c.class_name) || [],
          security_issues_count: jadxResult.security_issues?.length || 0,
        }
      };
      
      const request = {
        message: `You are a security researcher analyzing a decompiled Android APK. Generate a comprehensive security assessment report with exploit scenarios.

Use proper markdown formatting with:
- **Bold headers** using ## and ###  
- Bullet points and numbered lists
- Code blocks for technical details
- Severity indicators (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)

Structure the report as follows:

## 🛡️ Executive Summary
Overall security posture rating and key findings summary.

## 🔴 Critical & High Severity Issues
For each critical/high issue found:
### Issue Name
- **Severity:** 🔴 Critical / 🟠 High
- **Location:** Specific class/method
- **Description:** What the vulnerability is
- **Impact:** What could happen if exploited
- **Exploit Scenario:** Step-by-step attack path

## 🟡 Medium Severity Issues
Similar structure for medium issues.

## 🟢 Low Severity & Informational
Brief list of minor issues and hardening recommendations.

## 🎯 Attack Surface Analysis
- Exported components and their risks
- Deep link attack vectors
- Intent handling weaknesses
- Content provider exposure

## 🔐 Cryptographic Assessment
- Encryption methods used
- Key management practices
- Certificate validation
- Weaknesses found

## 📡 Network Security
- SSL/TLS implementation
- Certificate pinning status
- Cleartext traffic risks
- API security concerns

## 💾 Data Storage Security
- Sensitive data storage methods
- SharedPreferences security
- Database encryption
- File permissions

## 🛠️ Exploit Scenarios
Provide 2-3 detailed attack scenarios:

### Scenario 1: [Attack Name]
1. **Preconditions:** What attacker needs
2. **Attack Steps:** Numbered exploitation steps
3. **Tools Required:** Frida, adb, etc.
4. **Expected Outcome:** What attacker gains
5. **Mitigation:** How to fix

## 📋 Prioritized Recommendations
Numbered list of fixes in order of priority.

## 📊 Risk Matrix
Summary table of all findings by severity.

Be specific with class names, methods, and technical details from the decompiled code.`,
        conversation_history: [],
        analysis_context: context as unknown as Record<string, unknown>,
        beginner_mode: false,
      };
      
      const response = await reverseEngineeringClient.chatAboutApk(request);
      setSecurityReport(response.response);
      // Notify parent component for saving
      onSecurityReportGenerated?.(response.response);
    } catch (err) {
      setErrorSec(err instanceof Error ? err.message : "Failed to generate report");
    } finally {
      setIsLoadingSec(false);
    }
  };

  // Generate architecture diagram
  const generateArchitectureDiagram = async () => {
    if (architectureDiagram) return;
    setIsLoadingDiagram(true);
    setErrorDiagram(null);
    try {
      // output_directory is actually the session_id
      const result = await reverseEngineeringClient.generateArchitectureDiagram(jadxResult.output_directory);
      if (result.error) {
        setErrorDiagram(result.error);
      } else if (result.architecture_diagram) {
        setArchitectureDiagram(result.architecture_diagram);
      } else {
        setErrorDiagram("No diagram was generated. Please ensure Gemini API is configured.");
      }
    } catch (err) {
      setErrorDiagram(err instanceof Error ? err.message : "Failed to generate diagram");
    } finally {
      setIsLoadingDiagram(false);
    }
  };

  // Auto-generate reports when component mounts
  useEffect(() => {
    if (!autoGenerated) {
      setAutoGenerated(true);
      // Start generating both reports and diagram
      generateFunctionalityReport();
      generateSecurityReport();
      generateArchitectureDiagram();
    }
  }, []);

  // Generate report when tab changes if not already generated
  useEffect(() => {
    if (activeTab === 0 && !functionalityReport && !isLoadingFunc) {
      generateFunctionalityReport();
    } else if (activeTab === 1 && !securityReport && !isLoadingSec) {
      generateSecurityReport();
    } else if (activeTab === 2 && !architectureDiagram && !isLoadingDiagram) {
      generateArchitectureDiagram();
    }
  }, [activeTab]);

  return (
    <Paper sx={{ mt: 4, overflow: "hidden" }}>
      {/* Header */}
      <Box sx={{ 
        p: 2, 
        background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.15)} 0%, ${alpha(theme.palette.secondary.main, 0.15)} 100%)`,
        borderBottom: `1px solid ${alpha(theme.palette.divider, 0.3)}`,
      }}>
        <Typography variant="h6" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <AiIcon color="primary" />
          📊 Deep Analysis Reports
          <Chip 
            label="Source Code Context" 
            size="small" 
            color="success" 
            icon={<CodeIcon />}
            sx={{ ml: 1 }}
          />
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          Comprehensive AI-generated reports based on {jadxResult.total_classes.toLocaleString()} decompiled classes
        </Typography>
      </Box>

      {/* Tabs */}
      <Box sx={{ 
        borderBottom: 1, 
        borderColor: "divider",
        bgcolor: alpha(theme.palette.background.paper, 0.5),
      }}>
        <Tabs
          value={activeTab}
          onChange={(_, newValue) => setActiveTab(newValue)}
          sx={{
            "& .MuiTab-root": {
              fontWeight: 600,
              py: 2,
              textTransform: "none",
              fontSize: "0.95rem",
            },
          }}
        >
          <Tab
            icon={<ApkIcon sx={{ fontSize: 20 }} />}
            iconPosition="start"
            label="📱 What Does This APK Do (Full Report)"
            sx={{ gap: 0.5 }}
          />
          <Tab
            icon={<ShieldIcon sx={{ fontSize: 20 }} />}
            iconPosition="start"
            label="🔒 Advanced Security & Exploits"
            sx={{ gap: 0.5 }}
          />
          <Tab
            icon={<LayersIcon sx={{ fontSize: 20 }} />}
            iconPosition="start"
            label="🕸️ Architecture Diagram"
            sx={{ gap: 0.5 }}
          />
        </Tabs>
      </Box>

      {/* Tab Content */}
      <Box sx={{ p: 3, minHeight: 400 }}>
        {/* Functionality Report Tab */}
        {activeTab === 0 && (
          <Box>
            {isLoadingFunc ? (
              <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2, py: 6 }}>
                <CircularProgress size={40} />
                <Typography variant="body1" color="text.secondary">
                  Generating comprehensive functionality report...
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Analyzing {jadxResult.total_classes.toLocaleString()} classes and {jadxResult.total_files.toLocaleString()} files
                </Typography>
              </Box>
            ) : errorFunc ? (
              <Alert 
                severity="error" 
                action={
                  <Button color="inherit" size="small" onClick={() => { setFunctionalityReport(null); generateFunctionalityReport(); }}>
                    Retry
                  </Button>
                }
              >
                {errorFunc}
              </Alert>
            ) : functionalityReport ? (
              <Box
                sx={{
                  "& h1, & h2, & h3, & h4": { color: theme.palette.text.primary },
                  "& p": { color: theme.palette.text.secondary },
                  "& li": { color: theme.palette.text.secondary },
                  "& code": { color: theme.palette.primary.main, bgcolor: alpha(theme.palette.primary.main, 0.1) },
                  "& pre": { bgcolor: alpha(theme.palette.common.black, 0.2) },
                }}
                dangerouslySetInnerHTML={{ __html: formatMarkdownToHtml(functionalityReport) }}
              />
            ) : (
              <Box sx={{ textAlign: "center", py: 4 }}>
                <Button
                  variant="contained"
                  startIcon={<AiIcon />}
                  onClick={generateFunctionalityReport}
                  size="large"
                >
                  Generate Full Functionality Report
                </Button>
              </Box>
            )}
          </Box>
        )}

        {/* Security Report Tab */}
        {activeTab === 1 && (
          <Box>
            {isLoadingSec ? (
              <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2, py: 6 }}>
                <CircularProgress size={40} color="error" />
                <Typography variant="body1" color="text.secondary">
                  Generating advanced security report with exploit scenarios...
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Analyzing attack surface, vulnerabilities, and exploitation paths
                </Typography>
              </Box>
            ) : errorSec ? (
              <Alert 
                severity="error" 
                action={
                  <Button color="inherit" size="small" onClick={() => { setSecurityReport(null); generateSecurityReport(); }}>
                    Retry
                  </Button>
                }
              >
                {errorSec}
              </Alert>
            ) : securityReport ? (
              <Box
                sx={{
                  "& h1, & h2, & h3, & h4": { color: theme.palette.text.primary },
                  "& p": { color: theme.palette.text.secondary },
                  "& li": { color: theme.palette.text.secondary },
                  "& code": { color: theme.palette.error.main, bgcolor: alpha(theme.palette.error.main, 0.1) },
                  "& pre": { bgcolor: alpha(theme.palette.common.black, 0.2) },
                }}
                dangerouslySetInnerHTML={{ __html: formatMarkdownToHtml(securityReport) }}
              />
            ) : (
              <Box sx={{ textAlign: "center", py: 4 }}>
                <Button
                  variant="contained"
                  color="error"
                  startIcon={<ShieldIcon />}
                  onClick={generateSecurityReport}
                  size="large"
                >
                  Generate Security & Exploit Report
                </Button>
              </Box>
            )}
          </Box>
        )}

        {/* Architecture Diagram Tab */}
        {activeTab === 2 && (
          <Box>
            {isLoadingDiagram ? (
              <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2, py: 6 }}>
                <CircularProgress size={40} color="info" />
                <Typography variant="body1" color="text.secondary">
                  Generating architecture diagram from decompiled source...
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Analyzing component relationships and data flows
                </Typography>
              </Box>
            ) : errorDiagram ? (
              <Alert 
                severity="error" 
                action={
                  <Button color="inherit" size="small" onClick={() => { setArchitectureDiagram(null); generateArchitectureDiagram(); }}>
                    Retry
                  </Button>
                }
              >
                {errorDiagram}
              </Alert>
            ) : architectureDiagram ? (
              <Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  AI-generated architecture visualization based on {jadxResult.total_classes.toLocaleString()} decompiled classes.
                </Typography>
                <MermaidDiagram 
                  code={architectureDiagram}
                  title="APK Architecture"
                  maxHeight={600}
                  showControls={true}
                  showCodeToggle={true}
                />
              </Box>
            ) : (
              <Box sx={{ textAlign: "center", py: 4 }}>
                <Button
                  variant="contained"
                  color="info"
                  startIcon={<LayersIcon />}
                  onClick={generateArchitectureDiagram}
                  size="large"
                >
                  Generate Architecture Diagram
                </Button>
              </Box>
            )}
          </Box>
        )}
      </Box>
    </Paper>
  );
}

// ============================================================================
// APK AI Reports Component - Two Formatted Reports with Export
// ============================================================================

// Helper function to convert markdown-like content to HTML
function formatReportContent(content: string): string {
  if (!content) return "";
  
  let html = content;
  
  // If it's already HTML (has HTML tags), just clean it up
  if (html.includes("<h3>") || html.includes("<ul>") || html.includes("<p>")) {
    // Already HTML, just ensure proper formatting
    return html;
  }
  
  // Convert markdown to HTML
  // Headers
  html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^## (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^# (.*$)/gim, '<h3>$1</h3>');
  
  // Bold text
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/__(.*?)__/g, '<strong>$1</strong>');
  
  // Italic text
  html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
  html = html.replace(/_(.*?)_/g, '<em>$1</em>');
  
  // Code blocks
  html = html.replace(/```[\s\S]*?```/g, (match) => {
    const code = match.replace(/```\w*\n?/g, '').replace(/```/g, '');
    return `<pre><code>${code}</code></pre>`;
  });
  
  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  
  // Convert bullet lists
  const lines = html.split('\n');
  let inList = false;
  const processedLines: string[] = [];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isBullet = /^[\s]*[-*•]\s+(.*)/.test(line);
    const isNumbered = /^[\s]*\d+\.\s+(.*)/.test(line);
    
    if (isBullet || isNumbered) {
      if (!inList) {
        processedLines.push(isBullet ? '<ul>' : '<ol>');
        inList = true;
      }
      const content = line.replace(/^[\s]*[-*•]\s+/, '').replace(/^[\s]*\d+\.\s+/, '');
      processedLines.push(`<li>${content}</li>`);
    } else {
      if (inList) {
        processedLines.push('</ul>');
        inList = false;
      }
      // Wrap non-empty lines that aren't already tags in <p>
      if (line.trim() && !line.trim().startsWith('<')) {
        processedLines.push(`<p>${line}</p>`);
      } else {
        processedLines.push(line);
      }
    }
  }
  if (inList) {
    processedLines.push('</ul>');
  }
  
  return processedLines.join('\n');
}

function ApkAIReports({ result }: { result: ApkAnalysisResult }) {
  const theme = useTheme();
  const [activeReport, setActiveReport] = useState(0);
  const [exportMenuAnchor, setExportMenuAnchor] = useState<null | HTMLElement>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportSuccess, setExportSuccess] = useState<string | null>(null);

  // Check if we have the new structured reports (diagrams now only shown in DeepAnalysisReports)
  const hasStructuredReports = result.ai_report_functionality || result.ai_report_security;
  const hasLegacyReport = result.ai_analysis && !hasStructuredReports;

  if (!hasStructuredReports && !hasLegacyReport) {
    return null;
  }

  // Common styles for HTML content - improved for better rendering
  const htmlContentStyles = {
    fontFamily: theme.typography.fontFamily,
    "& h3": {
      fontSize: "1.15rem",
      fontWeight: 700,
      color: theme.palette.text.primary,
      mt: 3,
      mb: 1.5,
      pt: 1,
      borderBottom: `1px solid ${alpha(theme.palette.divider, 0.5)}`,
      pb: 1,
      display: "flex",
      alignItems: "center",
      gap: 1,
    },
    "& h3:first-of-type": {
      mt: 0,
      pt: 0,
    },
    "& h4": {
      fontSize: "1rem",
      fontWeight: 600,
      color: theme.palette.text.primary,
      mt: 2,
      mb: 1,
    },
    "& p": {
      mb: 1.5,
      lineHeight: 1.8,
      color: theme.palette.text.secondary,
      fontSize: "0.95rem",
    },
    "& ul, & ol": {
      pl: 3,
      mb: 2,
      mt: 1,
    },
    "& li": {
      mb: 1,
      lineHeight: 1.7,
      color: theme.palette.text.secondary,
      fontSize: "0.95rem",
      "& strong": {
        color: theme.palette.text.primary,
        fontWeight: 600,
      },
    },
    "& strong": {
      fontWeight: 600,
      color: theme.palette.text.primary,
    },
    "& em": {
      fontStyle: "italic",
    },
    "& code": {
      bgcolor: alpha(theme.palette.primary.main, 0.08),
      color: theme.palette.primary.main,
      px: 0.75,
      py: 0.25,
      borderRadius: 0.5,
      fontFamily: "monospace",
      fontSize: "0.85em",
    },
    "& pre": {
      bgcolor: alpha(theme.palette.grey[900], 0.05),
      p: 2,
      borderRadius: 1,
      overflow: "auto",
      "& code": {
        bgcolor: "transparent",
        p: 0,
      },
    },
    "& span[style*='color: #dc2626']": {
      bgcolor: alpha("#dc2626", 0.1),
      px: 1,
      py: 0.25,
      borderRadius: 0.5,
    },
    "& span[style*='color: #ea580c']": {
      bgcolor: alpha("#ea580c", 0.1),
      px: 1,
      py: 0.25,
      borderRadius: 0.5,
    },
    "& span[style*='color: #ca8a04']": {
      bgcolor: alpha("#ca8a04", 0.1),
      px: 1,
      py: 0.25,
      borderRadius: 0.5,
    },
    "& span[style*='color: #16a34a']": {
      bgcolor: alpha("#16a34a", 0.1),
      px: 1,
      py: 0.25,
      borderRadius: 0.5,
    },
  };

  // Export handler for current report
  const handleExport = async (format: "markdown" | "pdf" | "docx") => {
    setExportMenuAnchor(null);
    setExporting(true);
    setExportError(null);
    setExportSuccess(null);
    
    try {
      // Determine which report type to export based on active tab
      const reportType = activeReport === 0 ? "functionality" : activeReport === 1 ? "security" : "both";
      
      const blob = await reverseEngineeringClient.exportApkReportFromResult(result, format, reportType);
      
      // Create download link
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const packageName = result.package_name?.split(".").pop() || "apk";
      const reportSuffix = reportType === "both" ? "" : `_${reportType}`;
      a.download = `${packageName}${reportSuffix}_report.${format === "docx" ? "docx" : format === "pdf" ? "pdf" : "md"}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      setExportSuccess(`Report exported as ${format.toUpperCase()}`);
      setTimeout(() => setExportSuccess(null), 3000);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  // Export handler for both reports combined
  const handleExportBoth = async (format: "markdown" | "pdf" | "docx") => {
    setExportMenuAnchor(null);
    setExporting(true);
    setExportError(null);
    setExportSuccess(null);
    
    try {
      const blob = await reverseEngineeringClient.exportApkReportFromResult(result, format, "both");
      
      // Create download link
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const packageName = result.package_name?.split(".").pop() || "apk";
      a.download = `${packageName}_full_report.${format === "docx" ? "docx" : format === "pdf" ? "pdf" : "md"}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      setExportSuccess(`Full report exported as ${format.toUpperCase()}`);
      setTimeout(() => setExportSuccess(null), 3000);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(false);
      // Reset to first tab
      setActiveReport(0);
    }
  };

  // Legacy report display (plain text)
  if (hasLegacyReport) {
    return (
      <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <AiIcon color="info" /> AI Analysis
        </Typography>
        <Typography
          variant="body2"
          component="pre"
          sx={{
            whiteSpace: "pre-wrap",
            fontFamily: "inherit",
            m: 0,
          }}
        >
          {result.ai_analysis}
        </Typography>
      </Paper>
    );
  }

  // New structured reports with tabs
  return (
    <>
    <Paper sx={{ mt: 3, overflow: "hidden" }}>
      {/* Tabs Header with Export Button */}
      <Box sx={{ 
        borderBottom: 1, 
        borderColor: "divider",
        bgcolor: alpha(theme.palette.primary.main, 0.03),
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        pr: 2,
      }}>
        <Tabs
          value={activeReport}
          onChange={(_, newValue) => setActiveReport(newValue)}
          sx={{
            "& .MuiTab-root": {
              fontWeight: 600,
              py: 2,
              textTransform: "none",
              fontSize: "0.95rem",
            },
          }}
        >
          <Tab
            icon={<ApkIcon />}
            iconPosition="start"
            label="📱 What Does This APK Do"
            sx={{ gap: 1 }}
          />
          <Tab
            icon={<ShieldIcon />}
            iconPosition="start"
            label="🔒 Security Findings"
            sx={{ gap: 1 }}
          />
        </Tabs>
        
        {/* Export Button */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          {exporting && <CircularProgress size={20} />}
          <Button
            variant="outlined"
            size="small"
            startIcon={<DownloadIcon />}
            onClick={(e) => setExportMenuAnchor(e.currentTarget)}
            disabled={exporting}
            sx={{ textTransform: "none" }}
          >
            Export Report
          </Button>
          <Menu
            anchorEl={exportMenuAnchor}
            open={Boolean(exportMenuAnchor)}
            onClose={() => setExportMenuAnchor(null)}
          >
            <Typography variant="caption" sx={{ px: 2, py: 0.5, color: "text.secondary", display: "block" }}>
              Export Current Report
            </Typography>
            <MenuItem onClick={() => handleExport("markdown")}>
              <ListItemIcon>
                <CodeIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Markdown (.md)</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleExport("pdf")}>
              <ListItemIcon>
                <PdfIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>PDF (.pdf)</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleExport("docx")}>
              <ListItemIcon>
                <DocIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Word (.docx)</ListItemText>
            </MenuItem>
            <Divider sx={{ my: 1 }} />
            <Typography variant="caption" sx={{ px: 2, py: 0.5, color: "text.secondary", display: "block" }}>
              Export Both Reports
            </Typography>
            <MenuItem onClick={() => handleExportBoth("markdown")}>
              <ListItemIcon>
                <CodeIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Both as Markdown (.md)</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleExportBoth("pdf")}>
              <ListItemIcon>
                <PdfIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Both as PDF (.pdf)</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleExportBoth("docx")}>
              <ListItemIcon>
                <DocIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Both as Word (.docx)</ListItemText>
            </MenuItem>
          </Menu>
        </Box>
      </Box>

      {/* Success/Error Messages */}
      {exportSuccess && (
        <Alert severity="success" sx={{ m: 2 }} onClose={() => setExportSuccess(null)}>
          {exportSuccess}
        </Alert>
      )}
      {exportError && (
        <Alert severity="error" sx={{ m: 2 }} onClose={() => setExportError(null)}>
          {exportError}
        </Alert>
      )}

      {/* Report Content */}
      <Box sx={{ p: 3 }}>
        {/* Functionality Report */}
        {activeReport === 0 && result.ai_report_functionality && (
          <Box
            sx={htmlContentStyles}
            dangerouslySetInnerHTML={{ __html: formatReportContent(result.ai_report_functionality) }}
          />
        )}
        {activeReport === 0 && !result.ai_report_functionality && (
          <Alert severity="info">
            Functionality analysis not available. Run analysis with AI enabled.
          </Alert>
        )}

        {/* Security Report */}
        {activeReport === 1 && result.ai_report_security && (
          <Box
            sx={htmlContentStyles}
            dangerouslySetInnerHTML={{ __html: formatReportContent(result.ai_report_security) }}
          />
        )}
        {activeReport === 1 && !result.ai_report_security && (
          <Alert severity="info">
            Security analysis not available. Run analysis with AI enabled.
          </Alert>
        )}
      </Box>
    </Paper>

    </>
  );
}

// ============================================================================
// AI-Powered APK Analysis Components
// ============================================================================

import type {
  ApkChatMessage,
  ApkChatRequest,
  ApkChatResponse,
  ThreatModelRequest,
  ThreatModelResponse,
  ExploitSuggestionRequest,
  ExploitSuggestionResponse,
  AnalysisWalkthroughResponse,
  WalkthroughStep,
  ChatExportRequest,
  CodeExplanationRequest,
  CodeExplanationResponse,
  CodeSearchAIRequest,
  CodeSearchAIResponse,
} from "../api/client";

// Chat Icon import
import ChatIcon from "@mui/icons-material/Chat";
import SchoolIcon from "@mui/icons-material/School";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import SendIcon from "@mui/icons-material/Send";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import SkipNextIcon from "@mui/icons-material/SkipNext";
import SkipPreviousIcon from "@mui/icons-material/SkipPrevious";
import HelpOutlineIcon from "@mui/icons-material/HelpOutline";
import AssessmentIcon from "@mui/icons-material/Assessment";
// TargetIcon is imported at the top of the file as TrackChanges
import MenuBookIcon from "@mui/icons-material/MenuBook";
import SaveAltIcon from "@mui/icons-material/SaveAlt";
import RadarIcon from "@mui/icons-material/Radar";

// APK AI Tools Container Component
function ApkAITools({ 
  analysisResult, 
  jadxResult 
}: { 
  analysisResult: ApkAnalysisResult;
  jadxResult?: JadxDecompilationResult | null;
}) {
  const theme = useTheme();
  const [activeAiTab, setActiveAiTab] = useState(0);
  const [beginnerMode, setBeginnerMode] = useState(false);
  
  // Cross-Class Vulnerability Scan State
  const [aiVulnScanResult, setAiVulnScanResult] = useState<AIVulnScanResult | null>(null);
  const [aiVulnScanLoading, setAiVulnScanLoading] = useState(false);
  const [aiVulnScanType, setAiVulnScanType] = useState<"quick" | "deep" | "focused">("quick");

  // AI Full Vulnerability Scan Handler
  const handleAiVulnScan = async () => {
    if (!jadxResult) return;
    
    setAiVulnScanLoading(true);
    setAiVulnScanResult(null);
    
    try {
      const res = await reverseEngineeringClient.aiVulnScan(
        jadxResult.output_directory,
        aiVulnScanType,
        ["authentication", "data_storage", "network", "crypto"]
      );
      setAiVulnScanResult(res);
    } catch (err) {
      console.error("AI vulnerability scan failed:", err);
    } finally {
      setAiVulnScanLoading(false);
    }
  };

  // Check if we have deep code context
  const hasDeepContext = !!jadxResult;

  return (
    <Paper sx={{ p: 3, mt: 3 }}>
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
          <Typography variant="h6" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <AiIcon color="primary" /> AI-Powered Analysis Tools
          </Typography>
          {hasDeepContext ? (
            <Chip 
              icon={<CodeIcon />} 
              label="Deep Context (JADX)" 
              color="success" 
              size="small"
              variant="outlined"
            />
          ) : (
            <Chip 
              label="Basic Context (Quick Scan)" 
              color="warning" 
              size="small"
              variant="outlined"
            />
          )}
        </Box>
        <FormControlLabel
          control={
            <Switch 
              checked={beginnerMode} 
              onChange={(e) => setBeginnerMode(e.target.checked)}
              color="info"
            />
          }
          label={<Typography variant="body2">🎓 Beginner Mode</Typography>}
        />
      </Box>
      
      <Tabs 
        value={activeAiTab} 
        onChange={(_, v) => setActiveAiTab(v)}
        sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}
        variant="scrollable"
        scrollButtons="auto"
      >
        <Tab icon={<ChatIcon />} label="AI Chat" iconPosition="start" />
        <Tab icon={<TargetIcon />} label="Threat Model" iconPosition="start" />
        <Tab icon={<BugIcon />} label="Exploit Suggestions" iconPosition="start" />
        <Tab icon={<SchoolIcon />} label="Walkthrough" iconPosition="start" />
        <Tab 
          icon={<RadarIcon />} 
          label="Cross-Class Vuln Scan" 
          iconPosition="start"
          disabled={!hasDeepContext}
        />
      </Tabs>

      {activeAiTab === 0 && (
        <ApkAIChatPanel analysisResult={analysisResult} jadxResult={jadxResult} beginnerMode={beginnerMode} />
      )}
      {activeAiTab === 1 && (
        <ThreatModelViewer analysisResult={analysisResult} jadxResult={jadxResult} />
      )}
      {activeAiTab === 2 && (
        <ExploitSuggestionsPanel analysisResult={analysisResult} jadxResult={jadxResult} beginnerMode={beginnerMode} />
      )}
      {activeAiTab === 3 && (
        <WalkthroughPanel analysisResult={analysisResult} jadxResult={jadxResult} />
      )}
      {activeAiTab === 4 && (
        <CrossClassVulnScanPanel 
          jadxResult={jadxResult}
          aiVulnScanResult={aiVulnScanResult}
          aiVulnScanLoading={aiVulnScanLoading}
          aiVulnScanType={aiVulnScanType}
          setAiVulnScanType={setAiVulnScanType}
          onScan={handleAiVulnScan}
        />
      )}
    </Paper>
  );
}

// AI Chat Panel Component
function ApkAIChatPanel({ 
  analysisResult, 
  jadxResult,
  beginnerMode 
}: { 
  analysisResult: ApkAnalysisResult;
  jadxResult?: JadxDecompilationResult | null;
  beginnerMode: boolean;
}) {
  const theme = useTheme();
  const [messages, setMessages] = useState<ApkChatMessage[]>([]);
  const [inputMessage, setInputMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [suggestedQuestions, setSuggestedQuestions] = useState<string[]>([
    "What are the most critical security issues in this APK?",
    "Explain the dangerous permissions and their risks",
    "Are there any signs of malware or suspicious behavior?",
    "What data could this app leak?",
    "How secure is the app's cryptographic implementation?",
  ]);
  const [learningTip, setLearningTip] = useState<string | null>(null);
  const [exportMenuAnchor, setExportMenuAnchor] = useState<null | HTMLElement>(null);
  const [exporting, setExporting] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSendMessage = async (message?: string) => {
    const msgToSend = message || inputMessage.trim();
    if (!msgToSend) return;

    const userMessage: ApkChatMessage = {
      role: "user",
      content: msgToSend,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInputMessage("");
    setIsLoading(true);

    try {
      const request: ApkChatRequest = {
        message: msgToSend,
        conversation_history: messages,
        analysis_context: analysisResult as unknown as Record<string, unknown>,
        beginner_mode: beginnerMode,
      };

      const response = await reverseEngineeringClient.chatAboutApk(request);

      const assistantMessage: ApkChatMessage = {
        role: "assistant",
        content: response.response,
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, assistantMessage]);
      if (response.suggested_questions?.length > 0) {
        setSuggestedQuestions(response.suggested_questions);
      }
      if (response.learning_tip) {
        setLearningTip(response.learning_tip);
      }
    } catch (error) {
      console.error("Chat error:", error);
      const errorMessage: ApkChatMessage = {
        role: "assistant",
        content: "Sorry, I encountered an error processing your question. Please try again.",
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleExportChat = async (format: "markdown" | "json" | "pdf") => {
    setExportMenuAnchor(null);
    if (messages.length === 0) return;
    
    setExporting(true);
    try {
      const request: ChatExportRequest = {
        messages: messages,
        analysis_context: analysisResult as unknown as Record<string, unknown>,
        format: format,
      };
      
      const blob = await reverseEngineeringClient.exportApkChat(request);
      
      // Create download link
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const ext = format === "markdown" ? "md" : format;
      a.download = `${analysisResult.package_name?.split(".").pop() || "apk"}_chat.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Export failed:", error);
    } finally {
      setExporting(false);
    }
  };

  const clearChat = () => {
    setMessages([]);
    setLearningTip(null);
  };

  return (
    <Box>
      {/* Header with actions */}
      <Box sx={{ display: "flex", justifyContent: "flex-end", gap: 1, mb: 1 }}>
        {messages.length > 0 && (
          <>
            <Button
              size="small"
              startIcon={exporting ? <CircularProgress size={16} /> : <SaveAltIcon />}
              onClick={(e) => setExportMenuAnchor(e.currentTarget)}
              disabled={exporting}
            >
              Save Chat
            </Button>
            <Menu
              anchorEl={exportMenuAnchor}
              open={Boolean(exportMenuAnchor)}
              onClose={() => setExportMenuAnchor(null)}
            >
              <MenuItem onClick={() => handleExportChat("markdown")}>
                <DocIcon sx={{ mr: 1 }} /> Markdown (.md)
              </MenuItem>
              <MenuItem onClick={() => handleExportChat("json")}>
                <CodeIcon sx={{ mr: 1 }} /> JSON (.json)
              </MenuItem>
              <MenuItem onClick={() => handleExportChat("pdf")}>
                <PdfIcon sx={{ mr: 1 }} /> PDF (.pdf)
              </MenuItem>
            </Menu>
            <Button
              size="small"
              color="error"
              startIcon={<DeleteIcon />}
              onClick={clearChat}
            >
              Clear
            </Button>
          </>
        )}
      </Box>

      {/* Chat Messages */}
      <Paper 
        sx={{ 
          height: 400, 
          overflow: "auto", 
          p: 2, 
          mb: 2, 
          bgcolor: alpha(theme.palette.background.default, 0.5) 
        }}
      >
        {messages.length === 0 && (
          <Box sx={{ textAlign: "center", py: 4 }}>
            <AiIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              Ask me anything about this APK
            </Typography>
            <Typography variant="body2" color="text.secondary">
              I can help explain security findings, suggest remediation steps, 
              and answer questions about the analysis results.
            </Typography>
          </Box>
        )}
        
        {messages.map((msg, idx) => (
          <Box
            key={idx}
            sx={{
              display: "flex",
              justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
              mb: 2,
            }}
          >
            <Paper
              sx={{
                p: 2,
                maxWidth: "80%",
                bgcolor: msg.role === "user" 
                  ? alpha(theme.palette.primary.main, 0.1)
                  : alpha(theme.palette.grey[500], 0.1),
                borderRadius: 2,
              }}
            >
              <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                {msg.content}
              </Typography>
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                {msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : ""}
              </Typography>
            </Paper>
          </Box>
        ))}
        
        {isLoading && (
          <Box sx={{ display: "flex", gap: 1, alignItems: "center", ml: 2 }}>
            <CircularProgress size={20} />
            <Typography variant="body2" color="text.secondary">
              Analyzing...
            </Typography>
          </Box>
        )}
        <div ref={messagesEndRef} />
      </Paper>

      {/* Learning Tip */}
      {learningTip && beginnerMode && (
        <Alert 
          severity="info" 
          icon={<LightbulbIcon />}
          sx={{ mb: 2 }}
          onClose={() => setLearningTip(null)}
        >
          <Typography variant="subtitle2" gutterBottom>💡 Learning Tip</Typography>
          <Typography variant="body2">{learningTip}</Typography>
        </Alert>
      )}

      {/* Suggested Questions */}
      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="text.secondary" gutterBottom>
          Suggested questions:
        </Typography>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mt: 0.5 }}>
          {suggestedQuestions.slice(0, 4).map((q, idx) => (
            <Chip
              key={idx}
              label={q}
              size="small"
              variant="outlined"
              onClick={() => handleSendMessage(q)}
              disabled={isLoading}
              sx={{ 
                cursor: "pointer",
                "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) }
              }}
            />
          ))}
        </Box>
      </Box>

      {/* Input */}
      <Box sx={{ display: "flex", gap: 1 }}>
        <TextField
          fullWidth
          placeholder="Ask about the APK analysis..."
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          onKeyPress={(e) => e.key === "Enter" && !e.shiftKey && handleSendMessage()}
          disabled={isLoading}
          multiline
          maxRows={3}
        />
        <Button
          variant="contained"
          onClick={() => handleSendMessage()}
          disabled={isLoading || !inputMessage.trim()}
          sx={{ minWidth: 100 }}
        >
          <SendIcon />
        </Button>
      </Box>
    </Box>
  );
}

// Threat Model Viewer Component
function ThreatModelViewer({ 
  analysisResult,
  jadxResult 
}: { 
  analysisResult: ApkAnalysisResult;
  jadxResult?: JadxDecompilationResult | null;
}) {
  const theme = useTheme();
  const [threatModel, setThreatModel] = useState<ThreatModelResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attackerProfile, setAttackerProfile] = useState<"script_kiddie" | "skilled" | "nation_state">("skilled");

  const generateThreatModel = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const request: ThreatModelRequest = {
        analysis_context: analysisResult as unknown as Record<string, unknown>,
        attacker_profile: attackerProfile,
      };
      const response = await reverseEngineeringClient.generateThreatModel(request);
      setThreatModel(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate threat model");
    } finally {
      setIsLoading(false);
    }
  };

  if (!threatModel) {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <TargetIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
        <Typography variant="h6" gutterBottom>Generate AI Threat Model</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Create a comprehensive threat model based on the APK analysis findings.
        </Typography>
        
        <Box sx={{ mb: 3, display: "flex", justifyContent: "center", gap: 1 }}>
          <Typography variant="body2" sx={{ alignSelf: "center" }}>Attacker Profile:</Typography>
          {(["script_kiddie", "skilled", "nation_state"] as const).map((profile) => (
            <Chip
              key={profile}
              label={profile.replace("_", " ").toUpperCase()}
              variant={attackerProfile === profile ? "filled" : "outlined"}
              color={attackerProfile === profile ? "primary" : "default"}
              onClick={() => setAttackerProfile(profile)}
            />
          ))}
        </Box>

        <Button
          variant="contained"
          onClick={generateThreatModel}
          disabled={isLoading}
          startIcon={isLoading ? <CircularProgress size={20} /> : <PlayArrowIcon />}
        >
          {isLoading ? "Generating..." : "Generate Threat Model"}
        </Button>
        
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Box>
    );
  }

  return (
    <Box>
      {/* Executive Summary */}
      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>Executive Summary</Typography>
        <Typography variant="body2">{threatModel.executive_summary}</Typography>
      </Alert>

      {/* Threat Actors */}
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon color="error" /> Threat Actors ({threatModel.threat_actors.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            {threatModel.threat_actors.map((actor, idx) => (
              <Grid item xs={12} md={6} key={idx}>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
                  <Typography variant="subtitle1" fontWeight="bold">{actor.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    {actor.description}
                  </Typography>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    <Chip label={`Capability: ${actor.capability}`} size="small" />
                    <Chip label={`Likelihood: ${actor.likelihood}`} size="small" />
                  </Box>
                  <Typography variant="caption" sx={{ mt: 1, display: "block" }}>
                    <strong>Motivation:</strong> {actor.motivation}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Attack Scenarios */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <BugIcon color="warning" /> Attack Scenarios ({threatModel.attack_scenarios.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          {threatModel.attack_scenarios.map((scenario, idx) => (
            <Paper key={idx} sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.warning.main, 0.05) }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                <Typography variant="subtitle1" fontWeight="bold">{scenario.name}</Typography>
                <Chip 
                  label={scenario.severity} 
                  size="small" 
                  sx={{
                    bgcolor: alpha(getSeverityColor(scenario.severity), 0.2),
                    color: getSeverityColor(scenario.severity),
                  }}
                />
              </Box>
              <Typography variant="body2" sx={{ mb: 2 }}>{scenario.description}</Typography>
              
              <Typography variant="caption" fontWeight="bold">Attack Steps:</Typography>
              <List dense>
                {scenario.attack_steps.map((step, stepIdx) => (
                  <ListItem key={stepIdx} sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 30 }}>
                      <Typography variant="caption">{stepIdx + 1}.</Typography>
                    </ListItemIcon>
                    <ListItemText primary={<Typography variant="body2">{step}</Typography>} />
                  </ListItem>
                ))}
              </List>
              
              <Typography variant="caption" color="error.main">
                <strong>Impact:</strong> {scenario.impact}
              </Typography>
              
              {scenario.mitre_techniques.length > 0 && (
                <Box sx={{ mt: 1 }}>
                  <Typography variant="caption">MITRE ATT&CK: </Typography>
                  {scenario.mitre_techniques.map((tech, techIdx) => (
                    <Chip key={techIdx} label={tech} size="small" variant="outlined" sx={{ mr: 0.5 }} />
                  ))}
                </Box>
              )}
            </Paper>
          ))}
        </AccordionDetails>
      </Accordion>

      {/* Attack Tree */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <AssessmentIcon color="primary" /> Attack Tree
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
            <Typography variant="h6" gutterBottom>🎯 {threatModel.attack_tree.goal}</Typography>
            {threatModel.attack_tree.branches.map((branch, idx) => (
              <Box key={idx} sx={{ ml: 2, mb: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Typography variant="subtitle2">📍 {branch.method}</Typography>
                  <Chip 
                    label={branch.difficulty} 
                    size="small" 
                    color={branch.difficulty === "Easy" ? "success" : branch.difficulty === "Medium" ? "warning" : "error"}
                  />
                </Box>
                {branch.sub_branches.length > 0 && (
                  <List dense sx={{ ml: 2 }}>
                    {branch.sub_branches.map((sub, subIdx) => (
                      <ListItem key={subIdx} sx={{ py: 0 }}>
                        <ListItemText primary={<Typography variant="body2">↳ {sub}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                )}
              </Box>
            ))}
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* MITRE ATT&CK Mappings */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <ShieldIcon color="secondary" /> MITRE ATT&CK Mappings ({threatModel.mitre_attack_mappings.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Technique</TableCell>
                  <TableCell>Tactic</TableCell>
                  <TableCell>Relevance</TableCell>
                  <TableCell>Finding</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {threatModel.mitre_attack_mappings.map((mapping, idx) => (
                  <TableRow key={idx}>
                    <TableCell>
                      <Chip label={mapping.technique_id} size="small" color="secondary" />
                      <Typography variant="body2">{mapping.technique_name}</Typography>
                    </TableCell>
                    <TableCell>{mapping.tactic}</TableCell>
                    <TableCell>{mapping.relevance}</TableCell>
                    <TableCell>
                      <Typography variant="caption">{mapping.finding_reference}</Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* Risk Matrix */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon color="error" /> Risk Matrix
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            {threatModel.risk_matrix.critical_risks.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.1), border: `1px solid ${alpha("#dc2626", 0.3)}` }}>
                  <Typography variant="subtitle2" color="#dc2626" gutterBottom>🔴 Critical Risks</Typography>
                  <List dense>
                    {threatModel.risk_matrix.critical_risks.map((risk, idx) => (
                      <ListItem key={idx} sx={{ py: 0 }}>
                        <ListItemText primary={<Typography variant="body2">{risk}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            )}
            {threatModel.risk_matrix.high_risks.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ea580c", 0.1), border: `1px solid ${alpha("#ea580c", 0.3)}` }}>
                  <Typography variant="subtitle2" color="#ea580c" gutterBottom>🟠 High Risks</Typography>
                  <List dense>
                    {threatModel.risk_matrix.high_risks.map((risk, idx) => (
                      <ListItem key={idx} sx={{ py: 0 }}>
                        <ListItemText primary={<Typography variant="body2">{risk}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            )}
            {threatModel.risk_matrix.medium_risks.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ca8a04", 0.1), border: `1px solid ${alpha("#ca8a04", 0.3)}` }}>
                  <Typography variant="subtitle2" color="#ca8a04" gutterBottom>🟡 Medium Risks</Typography>
                  <List dense>
                    {threatModel.risk_matrix.medium_risks.map((risk, idx) => (
                      <ListItem key={idx} sx={{ py: 0 }}>
                        <ListItemText primary={<Typography variant="body2">{risk}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            )}
            {threatModel.risk_matrix.low_risks.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#16a34a", 0.1), border: `1px solid ${alpha("#16a34a", 0.3)}` }}>
                  <Typography variant="subtitle2" color="#16a34a" gutterBottom>🟢 Low Risks</Typography>
                  <List dense>
                    {threatModel.risk_matrix.low_risks.map((risk, idx) => (
                      <ListItem key={idx} sx={{ py: 0 }}>
                        <ListItemText primary={<Typography variant="body2">{risk}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            )}
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Prioritized Threats */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <GpsFixedIcon color="primary" /> Prioritized Threats ({threatModel.prioritized_threats.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          {threatModel.prioritized_threats.map((threat, idx) => (
            <Paper key={idx} sx={{ p: 2, mb: 2, display: "flex", gap: 2 }}>
              <Box sx={{ 
                width: 50, 
                height: 50, 
                borderRadius: "50%", 
                display: "flex", 
                alignItems: "center", 
                justifyContent: "center",
                bgcolor: alpha(theme.palette.primary.main, 0.1),
                color: theme.palette.primary.main,
                fontWeight: "bold",
                fontSize: "1.2rem"
              }}>
                #{threat.rank}
              </Box>
              <Box sx={{ flex: 1 }}>
                <Typography variant="subtitle1" fontWeight="bold">{threat.threat}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {threat.rationale}
                </Typography>
                <Chip label={`Risk Score: ${threat.risk_score}/100`} size="small" color="warning" sx={{ mr: 1 }} />
                <Typography variant="caption" color="success.main">
                  <strong>Recommendation:</strong> {threat.recommendation}
                </Typography>
              </Box>
            </Paper>
          ))}
        </AccordionDetails>
      </Accordion>

      <Button
        variant="outlined"
        onClick={() => setThreatModel(null)}
        sx={{ mt: 2 }}
      >
        Regenerate Threat Model
      </Button>
    </Box>
  );
}

// Exploit Suggestions Panel Component
function ExploitSuggestionsPanel({ 
  analysisResult,
  jadxResult,
  beginnerMode 
}: { 
  analysisResult: ApkAnalysisResult;
  jadxResult?: JadxDecompilationResult | null;
  beginnerMode: boolean;
}) {
  const theme = useTheme();
  const [exploitSuggestions, setExploitSuggestions] = useState<ExploitSuggestionResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [skillLevel, setSkillLevel] = useState<"beginner" | "intermediate" | "advanced">("intermediate");
  const [includePoc, setIncludePoc] = useState(true);

  const generateExploitSuggestions = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const request: ExploitSuggestionRequest = {
        analysis_context: analysisResult as unknown as Record<string, unknown>,
        include_poc: includePoc,
        skill_level: skillLevel,
      };
      const response = await reverseEngineeringClient.getExploitSuggestions(request);
      setExploitSuggestions(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate exploit suggestions");
    } finally {
      setIsLoading(false);
    }
  };

  if (!exploitSuggestions) {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <BugIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
        <Typography variant="h6" gutterBottom>AI Exploit Suggestions</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Generate exploitation paths and proof-of-concept scripts for educational and defensive purposes.
        </Typography>
        
        <Alert severity="warning" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
          <Typography variant="body2">
            ⚠️ This feature is for <strong>educational and defensive security research only</strong>. 
            Use responsibly and only on applications you own or have permission to test.
          </Typography>
        </Alert>

        <Box sx={{ mb: 3, display: "flex", justifyContent: "center", gap: 2, flexWrap: "wrap" }}>
          <Box>
            <Typography variant="caption" color="text.secondary">Skill Level:</Typography>
            <Box sx={{ display: "flex", gap: 1, mt: 0.5 }}>
              {(["beginner", "intermediate", "advanced"] as const).map((level) => (
                <Chip
                  key={level}
                  label={level.toUpperCase()}
                  variant={skillLevel === level ? "filled" : "outlined"}
                  color={skillLevel === level ? "primary" : "default"}
                  onClick={() => setSkillLevel(level)}
                />
              ))}
            </Box>
          </Box>
          <FormControlLabel
            control={<Switch checked={includePoc} onChange={(e) => setIncludePoc(e.target.checked)} />}
            label="Include PoC Scripts"
          />
        </Box>

        <Button
          variant="contained"
          color="warning"
          onClick={generateExploitSuggestions}
          disabled={isLoading}
          startIcon={isLoading ? <CircularProgress size={20} /> : <PlayArrowIcon />}
        >
          {isLoading ? "Generating..." : "Generate Exploit Suggestions"}
        </Button>
        
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Box>
    );
  }

  return (
    <Box>
      {/* Difficulty Assessment */}
      <Alert 
        severity={
          exploitSuggestions.difficulty_assessment.overall_difficulty === "Easy" ? "error" :
          exploitSuggestions.difficulty_assessment.overall_difficulty === "Medium" ? "warning" : "info"
        }
        sx={{ mb: 3 }}
      >
        <Typography variant="subtitle2" gutterBottom>Difficulty Assessment</Typography>
        <Grid container spacing={2}>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Overall</Typography>
            <Typography variant="body2" fontWeight="bold">
              {exploitSuggestions.difficulty_assessment.overall_difficulty}
            </Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Time Estimate</Typography>
            <Typography variant="body2">{exploitSuggestions.difficulty_assessment.time_estimate}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Success Probability</Typography>
            <Typography variant="body2">{exploitSuggestions.difficulty_assessment.success_probability}</Typography>
          </Grid>
          <Grid item xs={12}>
            <Typography variant="caption" color="text.secondary">Skills Required:</Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
              {exploitSuggestions.difficulty_assessment.skill_requirements.map((skill, idx) => (
                <Chip key={idx} label={skill} size="small" variant="outlined" />
              ))}
            </Box>
          </Grid>
        </Grid>
      </Alert>

      {/* Vulnerabilities */}
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <BugIcon color="error" /> Exploitable Vulnerabilities ({exploitSuggestions.vulnerabilities.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          {exploitSuggestions.vulnerabilities.map((vuln, idx) => (
            <Paper key={idx} sx={{ p: 2, mb: 2, bgcolor: alpha(getSeverityColor(vuln.severity), 0.05) }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                <Chip 
                  label={vuln.severity} 
                  size="small"
                  sx={{
                    bgcolor: alpha(getSeverityColor(vuln.severity), 0.2),
                    color: getSeverityColor(vuln.severity),
                  }}
                />
                <Typography variant="subtitle1" fontWeight="bold">{vuln.name}</Typography>
                <Chip label={vuln.category} size="small" variant="outlined" />
              </Box>
              <Typography variant="body2" sx={{ mb: 1 }}>{vuln.description}</Typography>
              <Typography variant="caption">
                <strong>Root Cause:</strong> {vuln.root_cause}
              </Typography>
              <br />
              <Typography variant="caption" color="text.secondary">
                <strong>Affected:</strong> {vuln.affected_component}
              </Typography>
            </Paper>
          ))}
        </AccordionDetails>
      </Accordion>

      {/* Exploitation Paths */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <GpsFixedIcon color="warning" /> Exploitation Paths ({exploitSuggestions.exploitation_paths.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          {exploitSuggestions.exploitation_paths.map((path, idx) => (
            <Paper key={idx} sx={{ p: 2, mb: 2 }}>
              <Typography variant="subtitle1" fontWeight="bold" gutterBottom>{path.name}</Typography>
              
              <Typography variant="caption" fontWeight="bold">Prerequisites:</Typography>
              <List dense sx={{ mb: 1 }}>
                {path.prerequisites.map((prereq, pIdx) => (
                  <ListItem key={pIdx} sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>✓</ListItemIcon>
                    <ListItemText primary={<Typography variant="body2">{prereq}</Typography>} />
                  </ListItem>
                ))}
              </List>

              <Typography variant="caption" fontWeight="bold">Exploitation Steps:</Typography>
              <List dense sx={{ mb: 1 }}>
                {path.steps.map((step, sIdx) => (
                  <ListItem key={sIdx} sx={{ py: 0.5, flexDirection: "column", alignItems: "flex-start" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Chip label={step.step} size="small" color="primary" />
                      <Typography variant="body2">{step.action}</Typography>
                    </Box>
                    {step.command && (
                      <Paper sx={{ p: 1, mt: 0.5, bgcolor: alpha(theme.palette.grey[900], 0.9), width: "100%" }}>
                        <Typography variant="caption" fontFamily="monospace" color="success.light">
                          $ {step.command}
                        </Typography>
                      </Paper>
                    )}
                    <Typography variant="caption" color="text.secondary">
                      Expected: {step.expected_result}
                    </Typography>
                  </ListItem>
                ))}
              </List>

              <Typography variant="caption" color="error.main">
                <strong>Impact:</strong> {path.impact}
              </Typography>
            </Paper>
          ))}
        </AccordionDetails>
      </Accordion>

      {/* Required Tools */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon color="primary" /> Required Tools ({exploitSuggestions.tools_required.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            {exploitSuggestions.tools_required.map((tool, idx) => (
              <Grid item xs={12} md={6} key={idx}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" fontWeight="bold">{tool.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    {tool.purpose}
                  </Typography>
                  <Typography variant="caption" display="block">
                    <strong>Install:</strong> <code>{tool.installation}</code>
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    <strong>Example:</strong> {tool.usage_example}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* PoC Scripts */}
      {exploitSuggestions.poc_scripts.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <CodeIcon color="secondary" /> Proof-of-Concept Scripts ({exploitSuggestions.poc_scripts.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            {exploitSuggestions.poc_scripts.map((poc, idx) => (
              <Paper key={idx} sx={{ p: 2, mb: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <Typography variant="subtitle2" fontWeight="bold">{poc.name}</Typography>
                  <Chip label={poc.language} size="small" color="secondary" />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {poc.description}
                </Typography>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.grey[900], 0.95), overflow: "auto", maxHeight: 300 }}>
                  <pre style={{ margin: 0, color: "#e0e0e0", fontSize: "0.8rem" }}>
                    {poc.code}
                  </pre>
                </Paper>
                <Typography variant="caption" sx={{ mt: 1, display: "block" }}>
                  <strong>Usage:</strong> {poc.usage}
                </Typography>
              </Paper>
            ))}
          </AccordionDetails>
        </Accordion>
      )}

      {/* Mitigation Bypasses */}
      {exploitSuggestions.mitigation_bypasses.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <ShieldIcon color="warning" /> Mitigation Bypasses ({exploitSuggestions.mitigation_bypasses.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            {exploitSuggestions.mitigation_bypasses.map((bypass, idx) => (
              <Paper key={idx} sx={{ p: 2, mb: 2 }}>
                <Typography variant="subtitle2" fontWeight="bold">{bypass.protection}</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>{bypass.bypass_method}</Typography>
                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                  <Chip 
                    label={`Difficulty: ${bypass.difficulty}`} 
                    size="small"
                    color={bypass.difficulty === "Easy" ? "success" : bypass.difficulty === "Medium" ? "warning" : "error"}
                  />
                  <Chip label={`Detection Risk: ${bypass.detection_risk}`} size="small" variant="outlined" />
                </Box>
                {bypass.tools.length > 0 && (
                  <Typography variant="caption" sx={{ mt: 1, display: "block" }}>
                    <strong>Tools:</strong> {bypass.tools.join(", ")}
                  </Typography>
                )}
              </Paper>
            ))}
          </AccordionDetails>
        </Accordion>
      )}

      <Button
        variant="outlined"
        onClick={() => setExploitSuggestions(null)}
        sx={{ mt: 2 }}
      >
        Regenerate Suggestions
      </Button>
    </Box>
  );
}

// Walkthrough Panel Component
function WalkthroughPanel({ 
  analysisResult,
  jadxResult 
}: { 
  analysisResult: ApkAnalysisResult;
  jadxResult?: JadxDecompilationResult | null;
}) {
  const theme = useTheme();
  const [walkthrough, setWalkthrough] = useState<AnalysisWalkthroughResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentStep, setCurrentStep] = useState(0);
  const [showGlossary, setShowGlossary] = useState(false);

  const generateWalkthrough = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await reverseEngineeringClient.getAnalysisWalkthrough(
        analysisResult as unknown as Record<string, unknown>
      );
      setWalkthrough(response);
      setCurrentStep(0);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate walkthrough");
    } finally {
      setIsLoading(false);
    }
  };

  if (!walkthrough) {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <SchoolIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
        <Typography variant="h6" gutterBottom>🎓 Educational Walkthrough</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Get a step-by-step guided tour of the APK analysis with beginner-friendly explanations.
        </Typography>
        
        <Button
          variant="contained"
          color="info"
          onClick={generateWalkthrough}
          disabled={isLoading}
          startIcon={isLoading ? <CircularProgress size={20} /> : <PlayArrowIcon />}
        >
          {isLoading ? "Generating..." : "Start Walkthrough"}
        </Button>
        
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Box>
    );
  }

  const step = walkthrough.steps[currentStep];

  return (
    <Box>
      {/* Progress Bar */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
          <Typography variant="body2">
            Step {currentStep + 1} of {walkthrough.total_steps}
          </Typography>
          <Typography variant="body2">
            {step.progress_percent}% Complete
          </Typography>
        </Box>
        <LinearProgress 
          variant="determinate" 
          value={step.progress_percent} 
          sx={{ height: 8, borderRadius: 4 }}
        />
      </Box>

      {/* Step Content */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
          <Chip 
            label={step.phase} 
            color="primary" 
            size="small"
          />
          {step.severity && (
            <Chip 
              label={step.severity} 
              size="small"
              sx={{
                bgcolor: alpha(getSeverityColor(step.severity), 0.2),
                color: getSeverityColor(step.severity),
              }}
            />
          )}
          {step.findings_count > 0 && (
            <Chip 
              label={`${step.findings_count} findings`} 
              size="small" 
              variant="outlined"
            />
          )}
        </Box>

        <Typography variant="h5" gutterBottom>{step.title}</Typography>
        <Typography variant="body1" sx={{ mb: 3 }}>{step.description}</Typography>

        <Divider sx={{ my: 2 }} />

        {/* Technical Detail */}
        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.grey[500], 0.1) }}>
          <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon fontSize="small" /> Technical Detail
          </Typography>
          <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
            {step.technical_detail}
          </Typography>
        </Paper>

        {/* Beginner Explanation */}
        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.info.main, 0.1) }}>
          <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SchoolIcon fontSize="small" color="info" /> Beginner Explanation
          </Typography>
          <Typography variant="body2">{step.beginner_explanation}</Typography>
        </Paper>

        {/* Why It Matters */}
        <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
          <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <LightbulbIcon fontSize="small" color="warning" /> Why This Matters
          </Typography>
          <Typography variant="body2">{step.why_it_matters}</Typography>
        </Paper>
      </Paper>

      {/* Navigation */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Button
          variant="outlined"
          onClick={() => setCurrentStep(0)}
          disabled={currentStep === 0}
          startIcon={<FirstPageIcon />}
        >
          First
        </Button>
        <Button
          variant="outlined"
          onClick={() => setCurrentStep(currentStep - 1)}
          disabled={currentStep === 0}
          startIcon={<SkipPreviousIcon />}
        >
          Previous
        </Button>
        <Typography variant="body2">
          {walkthrough.steps.map((_, idx) => (
            <IconButton
              key={idx}
              size="small"
              onClick={() => setCurrentStep(idx)}
              sx={{
                mx: 0.25,
                width: 24,
                height: 24,
                bgcolor: idx === currentStep ? "primary.main" : alpha(theme.palette.grey[500], 0.2),
                color: idx === currentStep ? "white" : "text.secondary",
                fontSize: "0.7rem",
                "&:hover": { bgcolor: idx === currentStep ? "primary.dark" : alpha(theme.palette.grey[500], 0.4) },
              }}
            >
              {idx + 1}
            </IconButton>
          ))}
        </Typography>
        <Button
          variant="outlined"
          onClick={() => setCurrentStep(currentStep + 1)}
          disabled={currentStep === walkthrough.total_steps - 1}
          endIcon={<SkipNextIcon />}
        >
          Next
        </Button>
        <Button
          variant="outlined"
          onClick={() => setCurrentStep(walkthrough.total_steps - 1)}
          disabled={currentStep === walkthrough.total_steps - 1}
          endIcon={<LastPageIcon />}
        >
          Last
        </Button>
      </Box>

      {/* Glossary Toggle */}
      <Accordion expanded={showGlossary} onChange={() => setShowGlossary(!showGlossary)}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <MenuBookIcon color="primary" /> Glossary ({Object.keys(walkthrough.glossary).length} terms)
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            {Object.entries(walkthrough.glossary).map(([term, definition], idx) => (
              <Grid item xs={12} md={6} key={idx}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" fontWeight="bold">{term}</Typography>
                  <Typography variant="body2" color="text.secondary">{definition}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Learning Resources */}
      {walkthrough.learning_resources.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <LinkIcon color="primary" /> Learning Resources ({walkthrough.learning_resources.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <List dense>
              {walkthrough.learning_resources.map((resource, idx) => (
                <ListItem key={idx} component="a" href={resource.url} target="_blank" sx={{ 
                  cursor: "pointer",
                  "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) }
                }}>
                  <ListItemIcon><LinkIcon color="primary" /></ListItemIcon>
                  <ListItemText 
                    primary={resource.title}
                    secondary={resource.description}
                  />
                </ListItem>
              ))}
            </List>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Next Steps */}
      {walkthrough.next_steps.length > 0 && (
        <Alert severity="success" sx={{ mt: 2 }}>
          <Typography variant="subtitle2" gutterBottom>🎯 Recommended Next Steps</Typography>
          <List dense>
            {walkthrough.next_steps.map((nextStep, idx) => (
              <ListItem key={idx} sx={{ py: 0 }}>
                <ListItemIcon sx={{ minWidth: 24 }}>{idx + 1}.</ListItemIcon>
                <ListItemText primary={<Typography variant="body2">{nextStep}</Typography>} />
              </ListItem>
            ))}
          </List>
        </Alert>
      )}

      <Button
        variant="outlined"
        onClick={() => setWalkthrough(null)}
        sx={{ mt: 2 }}
      >
        Restart Walkthrough
      </Button>
    </Box>
  );
}

// Cross-Class Vulnerability Scan Panel Component
function CrossClassVulnScanPanel({
  jadxResult,
  aiVulnScanResult,
  aiVulnScanLoading,
  aiVulnScanType,
  setAiVulnScanType,
  onScan,
}: {
  jadxResult?: JadxDecompilationResult | null;
  aiVulnScanResult: AIVulnScanResult | null;
  aiVulnScanLoading: boolean;
  aiVulnScanType: "quick" | "deep" | "focused";
  setAiVulnScanType: (type: "quick" | "deep" | "focused") => void;
  onScan: () => void;
}) {
  const theme = useTheme();

  const getSeverityColor = (severity: string): string => {
    switch (severity.toLowerCase()) {
      case "critical": return "#dc2626";
      case "high": return "#ea580c";
      case "medium": return "#ca8a04";
      case "low": return "#16a34a";
      default: return "#6b7280";
    }
  };

  if (!jadxResult) {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <RadarIcon sx={{ fontSize: 64, color: theme.palette.grey[400], mb: 2 }} />
        <Typography variant="h6" color="text.secondary" gutterBottom>
          Decompilation Required
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2, maxWidth: 400, mx: "auto" }}>
          The Cross-Class Vulnerability Scanner analyzes decompiled Java source code to find security issues across the entire codebase.
        </Typography>
        <Button
          variant="outlined"
          onClick={() => {
            document.getElementById('advanced-apk-analysis')?.scrollIntoView({ behavior: 'smooth' });
          }}
        >
          Go to JADX Decompiler
        </Button>
      </Box>
    );
  }

  return (
    <Box>
      {/* Scan Controls */}
      <Box sx={{ 
        display: "flex", 
        alignItems: "center", 
        justifyContent: "space-between", 
        mb: 3,
        p: 2,
        borderRadius: 1,
        bgcolor: alpha(theme.palette.error.main, 0.05),
        border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`
      }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <RadarIcon color="error" />
          <Box>
            <Typography variant="subtitle1" fontWeight="bold">
              AI Cross-Class Vulnerability Scan
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Scans {jadxResult.total_classes} classes for security vulnerabilities
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <Select
              value={aiVulnScanType}
              onChange={(e) => setAiVulnScanType(e.target.value as "quick" | "deep" | "focused")}
            >
              <MenuItem value="quick">⚡ Quick Scan</MenuItem>
              <MenuItem value="deep">🔍 Deep Scan</MenuItem>
              <MenuItem value="focused">🎯 Focused Scan</MenuItem>
            </Select>
          </FormControl>
          <Button 
            variant="contained" 
            color="error"
            onClick={onScan}
            disabled={aiVulnScanLoading}
            startIcon={aiVulnScanLoading ? <CircularProgress size={16} /> : <RadarIcon />}
          >
            {aiVulnScanLoading ? "Scanning..." : "Run Scan"}
          </Button>
        </Box>
      </Box>

      {/* Scan Type Description */}
      <Alert severity="info" sx={{ mb: 2 }}>
        <Typography variant="body2">
          {aiVulnScanType === "quick" && "⚡ Quick Scan: Fast analysis of critical security patterns (< 1 minute)"}
          {aiVulnScanType === "deep" && "🔍 Deep Scan: Comprehensive analysis including data flow tracking (2-5 minutes)"}
          {aiVulnScanType === "focused" && "🎯 Focused Scan: Targeted analysis of auth, storage, network & crypto (1-2 minutes)"}
        </Typography>
      </Alert>

      {/* Loading State */}
      {aiVulnScanLoading && (
        <Box sx={{ textAlign: "center", py: 4 }}>
          <CircularProgress color="error" />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            AI is scanning entire codebase for vulnerabilities...
          </Typography>
          <Typography variant="caption" color="text.secondary">
            This may take a minute for large apps
          </Typography>
        </Box>
      )}

      {/* Results */}
      {aiVulnScanResult && !aiVulnScanLoading && (
        <Box>
          {/* Overall Risk */}
          <Paper sx={{ 
            p: 2, 
            mb: 2,
            bgcolor: alpha(getSeverityColor(aiVulnScanResult.overall_risk), 0.1),
            border: `2px solid ${getSeverityColor(aiVulnScanResult.overall_risk)}`
          }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Chip 
                label={`${aiVulnScanResult.overall_risk.toUpperCase()} RISK`} 
                sx={{ 
                  bgcolor: getSeverityColor(aiVulnScanResult.overall_risk),
                  color: "white",
                  fontWeight: 700
                }} 
              />
              <Typography variant="body1">{aiVulnScanResult.summary}</Typography>
            </Box>
          </Paper>

          {/* Risk Summary */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#dc2626", 0.1) }}>
                <Typography variant="h4" color="error">{aiVulnScanResult.risk_summary.critical}</Typography>
                <Typography variant="body2">Critical</Typography>
              </Paper>
            </Grid>
            <Grid item xs={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#ea580c", 0.1) }}>
                <Typography variant="h4" sx={{ color: "#ea580c" }}>{aiVulnScanResult.risk_summary.high}</Typography>
                <Typography variant="body2">High</Typography>
              </Paper>
            </Grid>
            <Grid item xs={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#ca8a04", 0.1) }}>
                <Typography variant="h4" sx={{ color: "#ca8a04" }}>{aiVulnScanResult.risk_summary.medium}</Typography>
                <Typography variant="body2">Medium</Typography>
              </Paper>
            </Grid>
            <Grid item xs={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#16a34a", 0.1) }}>
                <Typography variant="h4" color="success.main">{aiVulnScanResult.risk_summary.low}</Typography>
                <Typography variant="body2">Low</Typography>
              </Paper>
            </Grid>
          </Grid>

          {/* Vulnerability Details */}
          <Typography variant="h6" gutterBottom>
            Discovered Vulnerabilities ({aiVulnScanResult.vulnerabilities.length})
          </Typography>
          
          {aiVulnScanResult.vulnerabilities.length === 0 ? (
            <Alert severity="success" sx={{ mb: 2 }}>
              No vulnerabilities found in the scanned code!
            </Alert>
          ) : (
            <List>
              {aiVulnScanResult.vulnerabilities.map((vuln, idx) => (
                <Paper key={idx} sx={{ mb: 1, overflow: "hidden" }}>
                  <ListItem sx={{ 
                    borderLeft: `4px solid ${getSeverityColor(vuln.severity)}`,
                    bgcolor: alpha(getSeverityColor(vuln.severity), 0.05)
                  }}>
                    <ListItemText
                      primary={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                          <Chip 
                            label={vuln.severity} 
                            size="small" 
                            sx={{ 
                              bgcolor: getSeverityColor(vuln.severity),
                              color: "white",
                              fontWeight: 600,
                              textTransform: "uppercase"
                            }}
                          />
                          <Typography variant="subtitle1" fontWeight="bold">
                            {vuln.title}
                          </Typography>
                          {vuln.cwe_id && (
                            <Chip label={vuln.cwe_id} size="small" variant="outlined" />
                          )}
                        </Box>
                      }
                      secondary={
                        <Box sx={{ mt: 1 }}>
                          <Typography variant="body2" color="text.secondary" paragraph>
                            {vuln.description}
                          </Typography>
                          <Typography variant="caption" sx={{ 
                            fontFamily: "monospace",
                            bgcolor: alpha(theme.palette.common.black, 0.05),
                            p: 0.5,
                            borderRadius: 0.5,
                            display: "block",
                            mb: 1
                          }}>
                            📍 {vuln.affected_class}.{vuln.affected_method}
                          </Typography>
                          {vuln.code_snippet && (
                            <Box sx={{
                              bgcolor: alpha(theme.palette.common.black, 0.05),
                              p: 1,
                              borderRadius: 1,
                              mb: 1,
                              fontFamily: "monospace",
                              fontSize: "0.75rem",
                              overflow: "auto",
                              maxHeight: 100
                            }}>
                              <pre style={{ margin: 0 }}>{vuln.code_snippet}</pre>
                            </Box>
                          )}
                          {vuln.remediation && (
                            <Alert severity="info" sx={{ mt: 1 }}>
                              <Typography variant="body2">
                                <strong>Remediation:</strong> {vuln.remediation}
                              </Typography>
                            </Alert>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                </Paper>
              ))}
            </List>
          )}

          {/* Attack Chains */}
          {aiVulnScanResult.attack_chains && aiVulnScanResult.attack_chains.length > 0 && (
            <Box sx={{ mt: 3 }}>
              <Typography variant="h6" gutterBottom>
                🔗 Attack Chains
              </Typography>
              {aiVulnScanResult.attack_chains.map((chain, idx) => (
                <Paper key={idx} sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Typography variant="subtitle1" fontWeight="bold">{chain.name}</Typography>
                    <Chip label={chain.likelihood} size="small" color={
                      chain.likelihood === "high" ? "error" : 
                      chain.likelihood === "medium" ? "warning" : "info"
                    } />
                  </Box>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    <strong>Impact:</strong> {chain.impact}
                  </Typography>
                  <List dense>
                    {chain.steps.map((step, stepIdx) => (
                      <ListItem key={stepIdx} sx={{ py: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <Chip label={stepIdx + 1} size="small" sx={{ width: 20, height: 20, fontSize: "0.7rem" }} />
                        </ListItemIcon>
                        <ListItemText primary={step} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              ))}
            </Box>
          )}

          {/* Recommendations */}
          {aiVulnScanResult.recommendations && aiVulnScanResult.recommendations.length > 0 && (
            <Box sx={{ mt: 3 }}>
              <Typography variant="h6" gutterBottom>
                📋 Recommendations
              </Typography>
              <List>
                {aiVulnScanResult.recommendations.map((item, idx) => (
                  <ListItem key={idx} sx={{ alignItems: "flex-start" }}>
                    <ListItemIcon>
                      <Chip label={idx + 1} size="small" color="primary" />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}
        </Box>
      )}
    </Box>
  );
}

// Smali/Bytecode Viewer Component
function SmaliViewer({ smali }: { smali: import("../api/client").SmaliAnalysis }) {
  const theme = useTheme();
  const [selectedClass, setSelectedClass] = useState<string>("");
  const [selectedMethod, setSelectedMethod] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState("");
  const [viewMode, setViewMode] = useState<"methods" | "classes">("methods");
  
  // Get class names from decompiled methods
  const classNames = [...new Set(smali.decompiled_methods.map(m => m.class_name))].sort();
  
  // Filter methods based on search and selected class
  const filteredMethods = smali.decompiled_methods.filter(method => {
    const matchesSearch = !searchQuery || 
      method.method_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      method.class_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      method.instructions.some(i => i.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesClass = !selectedClass || method.class_name === selectedClass;
    return matchesSearch && matchesClass;
  });
  
  // Get selected method's full code
  const currentMethod = selectedMethod 
    ? smali.decompiled_methods.find(m => `${m.class_name}.${m.method_name}${m.method_signature}` === selectedMethod)
    : null;
  
  return (
    <Accordion defaultExpanded={false}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <CodeIcon color="secondary" /> Smali Bytecode Decompilation
          <Chip 
            label={`${smali.statistics.total_methods_analyzed} methods`} 
            size="small" 
            color="secondary" 
          />
          <Chip 
            label={`${smali.statistics.classes_analyzed} classes`} 
            size="small" 
            variant="outlined"
          />
          {smali.interesting_methods.length > 0 && (
            <Chip 
              label={`${smali.interesting_methods.length} interesting`} 
              size="small" 
              color="warning"
            />
          )}
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        <Grid container spacing={2}>
          {/* Stats Overview */}
          <Grid item xs={6} sm={2}>
            <Typography variant="caption" color="text.secondary">Methods</Typography>
            <Typography variant="h6">{smali.statistics.total_methods_analyzed}</Typography>
          </Grid>
          <Grid item xs={6} sm={2}>
            <Typography variant="caption" color="text.secondary">Instructions</Typography>
            <Typography variant="h6">{smali.statistics.total_instructions.toLocaleString()}</Typography>
          </Grid>
          <Grid item xs={6} sm={2}>
            <Typography variant="caption" color="text.secondary">Classes</Typography>
            <Typography variant="h6">{smali.statistics.classes_analyzed}</Typography>
          </Grid>
          <Grid item xs={6} sm={2}>
            <Typography variant="caption" color="text.secondary">Native Methods</Typography>
            <Typography variant="h6">{smali.statistics.native_methods}</Typography>
          </Grid>
          <Grid item xs={6} sm={2}>
            <Typography variant="caption" color="text.secondary">Abstract</Typography>
            <Typography variant="h6">{smali.statistics.abstract_methods}</Typography>
          </Grid>
          
          {/* Search & Filter */}
          <Grid item xs={12}>
            <Divider sx={{ my: 2 }} />
            <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", alignItems: "center" }}>
              <TextField
                size="small"
                label="Search methods/classes"
                placeholder="e.g., onCreate, crypto, http"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                sx={{ minWidth: 250 }}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: "text.secondary" }} />,
                }}
              />
              <Autocomplete
                size="small"
                options={classNames}
                value={selectedClass}
                onChange={(_, value) => setSelectedClass(value || "")}
                renderInput={(params) => (
                  <TextField {...params} label="Filter by class" placeholder="All classes" />
                )}
                sx={{ minWidth: 300 }}
              />
              <Chip 
                label={`${filteredMethods.length} methods shown`}
                size="small"
                variant="outlined"
              />
            </Box>
          </Grid>
          
          {/* Interesting Methods Highlight */}
          {smali.interesting_methods.length > 0 && (
            <Grid item xs={12}>
              <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.warning.main, 0.08) }}>
                <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <WarningIcon color="warning" fontSize="small" />
                  Interesting Methods ({smali.interesting_methods.length})
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                  {smali.interesting_methods.slice(0, 15).map((method, idx) => (
                    <Tooltip 
                      key={idx} 
                      title={`${method.class}.${method.method} - ${method.pattern}`}
                    >
                      <Chip
                        label={`${method.method} (${method.pattern})`}
                        size="small"
                        color="warning"
                        variant="outlined"
                        onClick={() => {
                          setSelectedClass(method.class);
                          setSearchQuery(method.method);
                        }}
                        sx={{ cursor: "pointer" }}
                      />
                    </Tooltip>
                  ))}
                </Box>
              </Paper>
            </Grid>
          )}
          
          {/* Method List */}
          <Grid item xs={12} md={4}>
            <Paper sx={{ maxHeight: 500, overflow: "auto", bgcolor: alpha(theme.palette.background.default, 0.5) }}>
              <List dense>
                {filteredMethods.slice(0, 100).map((method, idx) => {
                  const methodKey = `${method.class_name}.${method.method_name}${method.method_signature}`;
                  const isSelected = selectedMethod === methodKey;
                  return (
                    <ListItem
                      key={idx}
                      button
                      selected={isSelected}
                      onClick={() => setSelectedMethod(isSelected ? "" : methodKey)}
                      sx={{
                        borderLeft: isSelected ? `3px solid ${theme.palette.primary.main}` : "none",
                        "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.08) },
                      }}
                    >
                      <ListItemIcon sx={{ minWidth: 30 }}>
                        {method.is_native ? (
                          <Tooltip title="Native method"><CodeIcon fontSize="small" color="warning" /></Tooltip>
                        ) : method.is_abstract ? (
                          <Tooltip title="Abstract method"><CodeIcon fontSize="small" color="disabled" /></Tooltip>
                        ) : (
                          <FunctionIcon fontSize="small" color="primary" />
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={method.method_name}
                        secondary={
                          <Typography variant="caption" color="text.secondary" noWrap>
                            {method.class_name.split('.').pop()} • {method.instruction_count} inst
                          </Typography>
                        }
                        primaryTypographyProps={{ noWrap: true, variant: "body2" }}
                      />
                      {method.has_try_catch && (
                        <Chip label="try" size="small" sx={{ height: 18, fontSize: 10 }} />
                      )}
                    </ListItem>
                  );
                })}
                {filteredMethods.length > 100 && (
                  <ListItem>
                    <ListItemText 
                      primary={`... and ${filteredMethods.length - 100} more methods`}
                      primaryTypographyProps={{ color: "text.secondary", variant: "caption" }}
                    />
                  </ListItem>
                )}
              </List>
            </Paper>
          </Grid>
          
          {/* Code Viewer */}
          <Grid item xs={12} md={8}>
            <Paper 
              sx={{ 
                p: 2, 
                bgcolor: "#1e1e1e", 
                minHeight: 400,
                maxHeight: 500,
                overflow: "auto",
              }}
            >
              {currentMethod ? (
                <>
                  <Box sx={{ mb: 2, display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <Box>
                      <Typography variant="subtitle2" color="primary.light">
                        {currentMethod.class_name}
                      </Typography>
                      <Typography variant="body2" color="grey.300" fontFamily="monospace">
                        {currentMethod.access_flags} {currentMethod.method_name}({currentMethod.parameters.join(", ")}) → {currentMethod.return_type}
                      </Typography>
                      <Typography variant="caption" color="grey.500">
                        {currentMethod.registers_count} registers • {currentMethod.instruction_count} instructions
                        {currentMethod.has_try_catch && " • has try-catch"}
                      </Typography>
                    </Box>
                    <Chip 
                      label={currentMethod.is_native ? "native" : currentMethod.is_abstract ? "abstract" : "bytecode"}
                      size="small"
                      color={currentMethod.is_native ? "warning" : currentMethod.is_abstract ? "default" : "success"}
                      variant="outlined"
                    />
                  </Box>
                  <Divider sx={{ borderColor: "grey.800", mb: 2 }} />
                  <Box 
                    component="pre" 
                    sx={{ 
                      m: 0, 
                      fontFamily: "'Fira Code', 'Consolas', monospace",
                      fontSize: 12,
                      lineHeight: 1.6,
                      color: "#d4d4d4",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                    }}
                  >
                    {currentMethod.instructions.length > 0 ? (
                      currentMethod.instructions.map((inst, idx) => {
                        // Syntax highlighting
                        let color = "#d4d4d4";
                        if (inst.includes("invoke-")) color = "#dcdcaa"; // Yellow for invokes
                        else if (inst.includes("const")) color = "#b5cea8"; // Green for constants
                        else if (inst.includes("return")) color = "#c586c0"; // Purple for returns
                        else if (inst.includes("if-") || inst.includes("goto")) color = "#569cd6"; // Blue for branches
                        else if (inst.includes("move")) color = "#9cdcfe"; // Light blue for moves
                        else if (inst.trim().startsWith("#")) color = "#6a9955"; // Green for comments
                        
                        return (
                          <div key={idx} style={{ color }}>
                            <span style={{ color: "#858585", marginRight: 8, userSelect: "none" }}>
                              {String(idx).padStart(4, " ")}
                            </span>
                            {inst}
                          </div>
                        );
                      })
                    ) : (
                      <Typography variant="body2" color="grey.500" fontStyle="italic">
                        {currentMethod.is_native 
                          ? "Native method - no bytecode available" 
                          : currentMethod.is_abstract
                          ? "Abstract method - no implementation"
                          : "No instructions"}
                      </Typography>
                    )}
                  </Box>
                </>
              ) : (
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: 400, color: "grey.500" }}>
                  <Typography variant="body2">
                    Select a method from the list to view its Smali bytecode
                  </Typography>
                </Box>
              )}
            </Paper>
          </Grid>
          
          {/* Full Class View */}
          {selectedClass && smali.class_smali[selectedClass] && (
            <Grid item xs={12}>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="body2">
                    View Full Class: {selectedClass.split('.').pop()}
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Paper 
                    sx={{ 
                      p: 2, 
                      bgcolor: "#1e1e1e", 
                      maxHeight: 500,
                      overflow: "auto",
                    }}
                  >
                    <Box 
                      component="pre" 
                      sx={{ 
                        m: 0, 
                        fontFamily: "'Fira Code', 'Consolas', monospace",
                        fontSize: 11,
                        lineHeight: 1.5,
                        color: "#d4d4d4",
                        whiteSpace: "pre",
                      }}
                    >
                      {smali.class_smali[selectedClass]}
                    </Box>
                  </Paper>
                </AccordionDetails>
              </Accordion>
            </Grid>
          )}
        </Grid>
      </AccordionDetails>
    </Accordion>
  );
}

// AI-Assisted Code Explainer Component
function AICodeExplainer({ 
  sourceCode, 
  className,
  language = "java"
}: { 
  sourceCode: string; 
  className: string;
  language?: "java" | "smali" | "kotlin";
}) {
  const theme = useTheme();
  const [explanation, setExplanation] = useState<CodeExplanationResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [focusArea, setFocusArea] = useState<"security" | "functionality" | "data_flow" | null>(null);
  const [beginnerMode, setBeginnerMode] = useState(false);

  const analyzeCode = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const request: CodeExplanationRequest = {
        source_code: sourceCode,
        class_name: className,
        language: language,
        focus_area: focusArea,
        beginner_mode: beginnerMode,
      };
      const response = await reverseEngineeringClient.explainCode(request);
      setExplanation(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to analyze code");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Box sx={{ mt: 2 }}>
      <Box sx={{ display: "flex", gap: 2, alignItems: "center", mb: 2, flexWrap: "wrap" }}>
        <Typography variant="subtitle2" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <AiIcon color="primary" fontSize="small" /> AI Code Analysis
        </Typography>
        
        <Box sx={{ display: "flex", gap: 1 }}>
          {(["security", "functionality", "data_flow", null] as const).map((area) => (
            <Chip
              key={area || "general"}
              label={area ? area.replace("_", " ").toUpperCase() : "GENERAL"}
              size="small"
              variant={focusArea === area ? "filled" : "outlined"}
              color={focusArea === area ? "primary" : "default"}
              onClick={() => setFocusArea(area)}
            />
          ))}
        </Box>
        
        <FormControlLabel
          control={
            <Switch
              size="small"
              checked={beginnerMode}
              onChange={(e) => setBeginnerMode(e.target.checked)}
            />
          }
          label="Beginner Mode"
          sx={{ ml: "auto" }}
        />
        
        <Button
          variant="contained"
          size="small"
          onClick={analyzeCode}
          disabled={isLoading || !sourceCode}
          startIcon={isLoading ? <CircularProgress size={16} /> : <AiIcon />}
        >
          {isLoading ? "Analyzing..." : "Explain Code"}
        </Button>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {explanation && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {/* Summary */}
          <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
            <Typography variant="subtitle2" gutterBottom>
              <AiIcon fontSize="small" sx={{ mr: 1, verticalAlign: "middle" }} />
              Summary
            </Typography>
            <Typography variant="body2">{explanation.summary}</Typography>
          </Paper>

          {/* Detailed Explanation */}
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="subtitle2">Detailed Explanation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                {explanation.detailed_explanation}
              </Typography>
            </AccordionDetails>
          </Accordion>

          {/* Security Concerns */}
          {explanation.security_concerns.length > 0 && (
            <Accordion defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle2" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <SecurityIcon color="error" fontSize="small" />
                  Security Concerns ({explanation.security_concerns.length})
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                {explanation.security_concerns.map((concern, idx) => (
                  <Paper 
                    key={idx} 
                    sx={{ 
                      p: 2, 
                      mb: 1, 
                      borderLeft: `4px solid ${
                        concern.severity === "critical" ? "#dc2626" :
                        concern.severity === "high" ? "#ea580c" :
                        concern.severity === "medium" ? "#ca8a04" : "#22c55e"
                      }` 
                    }}
                  >
                    <Box sx={{ display: "flex", gap: 1, mb: 1 }}>
                      <Chip 
                        label={concern.severity.toUpperCase()} 
                        size="small"
                        sx={{
                          bgcolor: alpha(
                            concern.severity === "critical" ? "#dc2626" :
                            concern.severity === "high" ? "#ea580c" :
                            concern.severity === "medium" ? "#ca8a04" : "#22c55e",
                            0.2
                          ),
                        }}
                      />
                      {concern.location && (
                        <Chip label={concern.location} size="small" variant="outlined" />
                      )}
                    </Box>
                    <Typography variant="body2" fontWeight="medium" gutterBottom>
                      {concern.issue}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {concern.recommendation}
                    </Typography>
                  </Paper>
                ))}
              </AccordionDetails>
            </Accordion>
          )}

          {/* Data Flow Analysis */}
          {explanation.data_flow_analysis && (
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle2">Data Flow Analysis</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                  {explanation.data_flow_analysis}
                </Typography>
              </AccordionDetails>
            </Accordion>
          )}

          {/* Interesting Findings */}
          {explanation.interesting_findings.length > 0 && (
            <Paper sx={{ p: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                <LightbulbIcon fontSize="small" sx={{ mr: 1, verticalAlign: "middle", color: "warning.main" }} />
                Interesting Findings
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                {explanation.interesting_findings.map((finding, idx) => (
                  <Chip key={idx} label={finding} size="small" variant="outlined" />
                ))}
              </Box>
            </Paper>
          )}

          {/* Suggested Focus Points */}
          {explanation.suggested_focus_points.length > 0 && (
            <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
              <Typography variant="subtitle2" gutterBottom>
                <SearchIcon fontSize="small" sx={{ mr: 1, verticalAlign: "middle" }} />
                Suggested Focus Points
              </Typography>
              <List dense>
                {explanation.suggested_focus_points.map((point, idx) => (
                  <ListItem key={idx}>
                    <ListItemText primary={point} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          )}

          {/* Code Quality Notes */}
          {explanation.code_quality_notes.length > 0 && (
            <Paper sx={{ p: 2 }}>
              <Typography variant="subtitle2" gutterBottom>Code Quality Notes</Typography>
              <List dense>
                {explanation.code_quality_notes.map((note, idx) => (
                  <ListItem key={idx}>
                    <ListItemIcon sx={{ minWidth: 30 }}>
                      <InfoIcon fontSize="small" color="info" />
                    </ListItemIcon>
                    <ListItemText primary={note} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          )}
        </Box>
      )}
    </Box>
  );
}

// Dynamic Analysis / Frida Scripts Viewer Component
function FridaScriptsViewer({ dynamicAnalysis }: { dynamicAnalysis: import("../api/client").DynamicAnalysis }) {
  const theme = useTheme();
  const [selectedScript, setSelectedScript] = useState<string>("");
  const [copied, setCopied] = useState(false);
  const [downloadedScript, setDownloadedScript] = useState<string | null>(null);
  
  const handleCopyScript = async (scriptCode: string) => {
    try {
      await navigator.clipboard.writeText(scriptCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };
  
  const handleDownloadScript = (script: import("../api/client").FridaScript) => {
    const blob = new Blob([script.script_code], { type: "text/javascript" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${script.category}_${dynamicAnalysis.package_name.replace(/\./g, "_")}.js`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setDownloadedScript(script.name);
    setTimeout(() => setDownloadedScript(null), 2000);
  };

  const currentScript = selectedScript 
    ? dynamicAnalysis.frida_scripts.find(s => s.name === selectedScript)
    : null;

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case "ssl_bypass": return "🔓";
      case "root_bypass": return "🌱";
      case "crypto_hook": return "🔐";
      case "auth_hook": return "🔑";
      case "method_trace": return "📍";
      case "network_hook": return "🌐";
      case "combined": return "⚡";
      case "emulator_bypass": return "📱";
      case "debugger_bypass": return "🐛";
      case "tampering_bypass": return "🛡️";
      case "screenshot_bypass": return "📸";
      default: return "📜";
    }
  };
  
  const getCategoryColor = (category: string) => {
    switch (category) {
      case "ssl_bypass": return theme.palette.warning.main;
      case "root_bypass": return theme.palette.success.main;
      case "crypto_hook": return theme.palette.info.main;
      case "auth_hook": return theme.palette.secondary.main;
      case "method_trace": return theme.palette.primary.main;
      case "network_hook": return "#00bcd4";
      case "combined": return theme.palette.error.main;
      case "emulator_bypass": return "#9c27b0";
      case "debugger_bypass": return "#ff5722";
      case "tampering_bypass": return "#607d8b";
      case "screenshot_bypass": return "#795548";
      default: return theme.palette.grey[500];
    }
  };

  return (
    <Accordion defaultExpanded={false}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <CodeIcon color="secondary" />
          Dynamic Analysis - Frida Scripts ({dynamicAnalysis.total_scripts} scripts generated)
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        {/* Detection Summary */}
        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
          <Typography variant="subtitle2" gutterBottom>Detection Summary</Typography>
          <Grid container spacing={1}>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                icon={<span>{dynamicAnalysis.ssl_pinning_detected ? "✅" : "❌"}</span>}
                label="SSL Pinning"
                color={dynamicAnalysis.ssl_pinning_detected ? "warning" : "default"}
                variant={dynamicAnalysis.ssl_pinning_detected ? "filled" : "outlined"}
                size="small"
                sx={{ width: "100%" }}
              />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                icon={<span>{dynamicAnalysis.root_detection_detected ? "✅" : "❌"}</span>}
                label="Root Detection"
                color={dynamicAnalysis.root_detection_detected ? "warning" : "default"}
                variant={dynamicAnalysis.root_detection_detected ? "filled" : "outlined"}
                size="small"
                sx={{ width: "100%" }}
              />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                icon={<span>{dynamicAnalysis.emulator_detection_detected ? "✅" : "❌"}</span>}
                label="Emulator Check"
                color={dynamicAnalysis.emulator_detection_detected ? "warning" : "default"}
                variant={dynamicAnalysis.emulator_detection_detected ? "filled" : "outlined"}
                size="small"
                sx={{ width: "100%" }}
              />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                icon={<span>{dynamicAnalysis.debugger_detection_detected ? "✅" : "❌"}</span>}
                label="Debugger Check"
                color={dynamicAnalysis.debugger_detection_detected ? "warning" : "default"}
                variant={dynamicAnalysis.debugger_detection_detected ? "filled" : "outlined"}
                size="small"
                sx={{ width: "100%" }}
              />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                icon={<span>{dynamicAnalysis.anti_tampering_detected ? "✅" : "❌"}</span>}
                label="Anti-Tamper"
                color={dynamicAnalysis.anti_tampering_detected ? "warning" : "default"}
                variant={dynamicAnalysis.anti_tampering_detected ? "filled" : "outlined"}
                size="small"
                sx={{ width: "100%" }}
              />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                icon={<span>🔐</span>}
                label={`${dynamicAnalysis.crypto_methods.length} Crypto`}
                color={dynamicAnalysis.crypto_methods.length > 0 ? "info" : "default"}
                variant="outlined"
                size="small"
                sx={{ width: "100%" }}
              />
            </Grid>
          </Grid>
          
          {/* Commands */}
          <Box sx={{ mt: 2 }}>
            <Typography variant="caption" color="text.secondary">Frida Commands:</Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 0.5 }}>
              <Chip
                label={dynamicAnalysis.frida_spawn_command}
                size="small"
                sx={{ fontFamily: "monospace", fontSize: 10 }}
                onClick={() => handleCopyScript(dynamicAnalysis.frida_spawn_command)}
              />
              <Chip
                label={dynamicAnalysis.frida_attach_command}
                size="small"
                sx={{ fontFamily: "monospace", fontSize: 10 }}
                onClick={() => handleCopyScript(dynamicAnalysis.frida_attach_command)}
              />
            </Box>
          </Box>
        </Paper>

        {/* Getting Started Guide for Beginners */}
        <Accordion sx={{ mb: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <span>📚</span> Getting Started with Frida (Beginner Guide)
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {/* What is Frida */}
              <Grid item xs={12}>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.info.main, 0.05), border: `1px solid ${alpha(theme.palette.info.main, 0.2)}` }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>🔧</span> What is Frida?
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Frida is a dynamic instrumentation toolkit that lets you inject JavaScript into running apps to monitor and modify their behavior. 
                    These auto-generated scripts hook into specific methods detected during static analysis to help you bypass security controls and inspect runtime data.
                  </Typography>
                </Paper>
              </Grid>

              {/* Prerequisites */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, height: "100%" }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>✅</span> Prerequisites
                  </Typography>
                  <Box component="ul" sx={{ m: 0, pl: 2.5, "& li": { mb: 0.5 } }}>
                    <Typography component="li" variant="body2">Python 3.7+ installed on your computer</Typography>
                    <Typography component="li" variant="body2">Android device (rooted) or emulator with root</Typography>
                    <Typography component="li" variant="body2">USB debugging enabled on the device</Typography>
                    <Typography component="li" variant="body2">ADB (Android Debug Bridge) installed</Typography>
                  </Box>
                </Paper>
              </Grid>

              {/* Installation Steps */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, height: "100%" }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>📦</span> Installation
                  </Typography>
                  <Box sx={{ fontFamily: "monospace", fontSize: 12, bgcolor: "#1e1e1e", p: 1.5, borderRadius: 1 }}>
                    <Typography variant="body2" sx={{ color: "#6a9955", mb: 0.5 }}># Install Frida tools</Typography>
                    <Typography variant="body2" sx={{ color: "#d4d4d4", mb: 1 }}>pip install frida-tools</Typography>
                    <Typography variant="body2" sx={{ color: "#6a9955", mb: 0.5 }}># Check installation</Typography>
                    <Typography variant="body2" sx={{ color: "#d4d4d4" }}>frida --version</Typography>
                  </Box>
                </Paper>
              </Grid>

              {/* Device Setup */}
              <Grid item xs={12}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>📱</span> Device Setup (One-Time)
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="body2" fontWeight={600} gutterBottom>1. Download frida-server:</Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        Visit <code style={{ background: "#1e1e1e", padding: "2px 6px", borderRadius: 4 }}>github.com/frida/frida/releases</code> and download the frida-server matching your device architecture (arm64 for most modern phones).
                      </Typography>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="body2" fontWeight={600} gutterBottom>2. Push to device & run:</Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: 11, bgcolor: "#1e1e1e", p: 1, borderRadius: 1 }}>
                        <Typography variant="body2" sx={{ color: "#d4d4d4", fontSize: 11 }}>adb push frida-server /data/local/tmp/</Typography>
                        <Typography variant="body2" sx={{ color: "#d4d4d4", fontSize: 11 }}>adb shell "chmod 755 /data/local/tmp/frida-server"</Typography>
                        <Typography variant="body2" sx={{ color: "#d4d4d4", fontSize: 11 }}>adb shell "su -c /data/local/tmp/frida-server &"</Typography>
                      </Box>
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>

              {/* How to Run */}
              <Grid item xs={12}>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.success.main, 0.05), border: `1px solid ${alpha(theme.palette.success.main, 0.2)}` }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>▶️</span> Running the Scripts
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="body2" fontWeight={600} gutterBottom>Option A: Spawn Mode (Recommended)</Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        Starts the app fresh with hooks attached from the beginning.
                      </Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: 11, bgcolor: "#1e1e1e", p: 1, borderRadius: 1 }}>
                        <Typography variant="body2" sx={{ color: "#d4d4d4", fontSize: 11 }}>
                          frida -U -f {dynamicAnalysis.package_name} -l script.js
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="body2" fontWeight={600} gutterBottom>Option B: Attach Mode</Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        Attaches to an already running app.
                      </Typography>
                      <Box sx={{ fontFamily: "monospace", fontSize: 11, bgcolor: "#1e1e1e", p: 1, borderRadius: 1 }}>
                        <Typography variant="body2" sx={{ color: "#d4d4d4", fontSize: 11 }}>
                          frida -U {dynamicAnalysis.package_name} -l script.js
                        </Typography>
                      </Box>
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>

              {/* Troubleshooting */}
              <Grid item xs={12}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>🔍</span> Common Issues & Solutions
                  </Typography>
                  <Grid container spacing={1}>
                    <Grid item xs={12} sm={6} md={4}>
                      <Box sx={{ p: 1, bgcolor: alpha(theme.palette.error.main, 0.05), borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight={600} color="error.main">Failed to spawn</Typography>
                        <Typography variant="caption" display="block" color="text.secondary">
                          → Ensure frida-server is running on device
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6} md={4}>
                      <Box sx={{ p: 1, bgcolor: alpha(theme.palette.error.main, 0.05), borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight={600} color="error.main">Unable to find device</Typography>
                        <Typography variant="caption" display="block" color="text.secondary">
                          → Check USB debugging & run: adb devices
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6} md={4}>
                      <Box sx={{ p: 1, bgcolor: alpha(theme.palette.error.main, 0.05), borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight={600} color="error.main">Version mismatch</Typography>
                        <Typography variant="caption" display="block" color="text.secondary">
                          → Match frida-tools and frida-server versions
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6} md={4}>
                      <Box sx={{ p: 1, bgcolor: alpha(theme.palette.error.main, 0.05), borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight={600} color="error.main">App crashes immediately</Typography>
                        <Typography variant="caption" display="block" color="text.secondary">
                          → Try --no-pause flag or use attach mode
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6} md={4}>
                      <Box sx={{ p: 1, bgcolor: alpha(theme.palette.error.main, 0.05), borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight={600} color="error.main">Class not found</Typography>
                        <Typography variant="caption" display="block" color="text.secondary">
                          → Class may load later; try setTimeout wrapper
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6} md={4}>
                      <Box sx={{ p: 1, bgcolor: alpha(theme.palette.warning.main, 0.1), borderRadius: 1 }}>
                        <Typography variant="caption" fontWeight={600} color="warning.main">Need more help?</Typography>
                        <Typography variant="caption" display="block" color="text.secondary">
                          → Visit frida.re/docs for full documentation
                        </Typography>
                      </Box>
                    </Grid>
                  </Grid>
                </Paper>
              </Grid>

              {/* Tips */}
              <Grid item xs={12}>
                <Alert severity="info" sx={{ "& .MuiAlert-message": { width: "100%" } }}>
                  <Typography variant="body2" fontWeight={600} gutterBottom>💡 Pro Tips</Typography>
                  <Box component="ul" sx={{ m: 0, pl: 2, "& li": { mb: 0.25 } }}>
                    <Typography component="li" variant="body2">Start with SSL Bypass if you need to intercept HTTPS traffic with Burp Suite</Typography>
                    <Typography component="li" variant="body2">Use Root/Emulator Bypass if the app refuses to run on your test device</Typography>
                    <Typography component="li" variant="body2">The Combined script includes all bypasses - use it for comprehensive testing</Typography>
                    <Typography component="li" variant="body2">Watch the terminal output for hooked method calls and intercepted data</Typography>
                  </Box>
                </Alert>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>
        
        <Grid container spacing={2}>
          {/* Script List */}
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 1, maxHeight: 500, overflow: "auto" }}>
              <Typography variant="subtitle2" sx={{ px: 1, py: 0.5 }}>
                Available Scripts
              </Typography>
              <List dense>
                {dynamicAnalysis.frida_scripts.map((script) => (
                  <ListItem
                    key={script.name}
                    sx={{
                      cursor: "pointer",
                      bgcolor: selectedScript === script.name 
                        ? alpha(getCategoryColor(script.category), 0.15)
                        : "transparent",
                      borderLeft: selectedScript === script.name 
                        ? `3px solid ${getCategoryColor(script.category)}`
                        : "3px solid transparent",
                      "&:hover": {
                        bgcolor: alpha(getCategoryColor(script.category), 0.08),
                      },
                      borderRadius: 1,
                      mb: 0.5,
                    }}
                    onClick={() => setSelectedScript(script.name)}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <span>{getCategoryIcon(script.category)}</span>
                          <Typography variant="body2" sx={{ fontWeight: selectedScript === script.name ? 600 : 400 }}>
                            {script.name}
                          </Typography>
                          {script.is_dangerous && (
                            <Chip label="Modifies Behavior" size="small" color="error" sx={{ height: 18, fontSize: 9 }} />
                          )}
                        </Box>
                      }
                      secondary={
                        <Typography variant="caption" color="text.secondary" sx={{ fontSize: 10 }}>
                          {script.description.substring(0, 60)}...
                        </Typography>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          
          {/* Script Viewer */}
          <Grid item xs={12} md={8}>
            <Paper sx={{ bgcolor: "#1e1e1e", height: 500, display: "flex", flexDirection: "column" }}>
              {currentScript ? (
                <>
                  {/* Script Header */}
                  <Box sx={{ 
                    p: 1.5, 
                    borderBottom: "1px solid #333",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center"
                  }}>
                    <Box>
                      <Typography variant="subtitle2" sx={{ color: "#fff", display: "flex", alignItems: "center", gap: 1 }}>
                        {getCategoryIcon(currentScript.category)} {currentScript.name}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "#888" }}>
                        {currentScript.description}
                      </Typography>
                    </Box>
                    <Box sx={{ display: "flex", gap: 1 }}>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={copied ? <CheckIcon /> : <CopyIcon />}
                        onClick={() => handleCopyScript(currentScript.script_code)}
                        sx={{ 
                          color: copied ? "#4caf50" : "#fff", 
                          borderColor: copied ? "#4caf50" : "#555",
                          fontSize: 11,
                        }}
                      >
                        {copied ? "Copied!" : "Copy"}
                      </Button>
                      <Button
                        size="small"
                        variant="contained"
                        startIcon={downloadedScript === currentScript.name ? <CheckIcon /> : <DownloadIcon />}
                        onClick={() => handleDownloadScript(currentScript)}
                        sx={{ fontSize: 11 }}
                        color={downloadedScript === currentScript.name ? "success" : "primary"}
                      >
                        {downloadedScript === currentScript.name ? "Downloaded!" : "Download .js"}
                      </Button>
                    </Box>
                  </Box>
                  
                  {/* Usage Instructions */}
                  <Box sx={{ px: 2, py: 1, bgcolor: "#252526", borderBottom: "1px solid #333" }}>
                    <Typography variant="caption" sx={{ color: "#569cd6" }}>
                      Usage: <code style={{ color: "#ce9178" }}>{currentScript.usage_instructions}</code>
                    </Typography>
                  </Box>
                  
                  {/* Script Code */}
                  <Box sx={{ flex: 1, overflow: "auto", p: 2 }}>
                    <Box
                      component="pre"
                      sx={{
                        m: 0,
                        fontFamily: "'Fira Code', 'Consolas', monospace",
                        fontSize: 11,
                        lineHeight: 1.5,
                        color: "#d4d4d4",
                        whiteSpace: "pre",
                      }}
                    >
                      {currentScript.script_code.split('\n').map((line, idx) => {
                        // Basic JavaScript syntax highlighting
                        let highlighted = line;
                        
                        // Comments
                        if (line.trim().startsWith('//')) {
                          highlighted = `<span style="color: #6a9955">${line}</span>`;
                        }
                        // Strings
                        else {
                          highlighted = line
                            .replace(/(["'])((?:(?!\1)[^\\]|\\.)*)(\1)/g, '<span style="color: #ce9178">$1$2$3</span>')
                            .replace(/\b(function|var|let|const|return|if|else|try|catch|for|while|true|false|null|undefined|this|new)\b/g, '<span style="color: #569cd6">$1</span>')
                            .replace(/\b(console)\.(log|warn|error)/g, '<span style="color: #dcdcaa">$1</span>.<span style="color: #dcdcaa">$2</span>')
                            .replace(/\b(Java)\.(use|perform|registerClass|cast|enumerateLoadedClasses)/g, '<span style="color: #4ec9b0">$1</span>.<span style="color: #dcdcaa">$2</span>')
                            .replace(/\.implementation/g, '.<span style="color: #9cdcfe">implementation</span>');
                        }
                        
                        return (
                          <Box 
                            key={idx} 
                            component="span" 
                            sx={{ display: "block" }}
                            dangerouslySetInnerHTML={{ __html: highlighted }}
                          />
                        );
                      })}
                    </Box>
                  </Box>
                  
                  {/* Target Info */}
                  <Box sx={{ 
                    px: 2, 
                    py: 1, 
                    bgcolor: "#252526",
                    borderTop: "1px solid #333",
                    display: "flex",
                    gap: 2,
                    flexWrap: "wrap"
                  }}>
                    <Typography variant="caption" sx={{ color: "#888" }}>
                      <strong style={{ color: "#569cd6" }}>Target Classes:</strong>{" "}
                      {currentScript.target_classes.slice(0, 3).join(", ")}
                      {currentScript.target_classes.length > 3 && ` +${currentScript.target_classes.length - 3} more`}
                    </Typography>
                  </Box>
                </>
              ) : (
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "#888" }}>
                  <Typography variant="body2">
                    Select a script from the list to view and download
                  </Typography>
                </Box>
              )}
            </Paper>
          </Grid>
        </Grid>
        
        {/* Suggested Test Cases */}
        {dynamicAnalysis.suggested_test_cases.length > 0 && (
          <Paper sx={{ p: 2, mt: 2, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
            <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <span>📋</span> Suggested Test Cases
            </Typography>
            <List dense>
              {dynamicAnalysis.suggested_test_cases.map((testCase, idx) => (
                <ListItem key={idx} sx={{ py: 0.25 }}>
                  <ListItemText
                    primary={
                      <Typography variant="body2" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <span style={{ color: theme.palette.primary.main }}>•</span>
                        {testCase}
                      </Typography>
                    }
                  />
                </ListItem>
              ))}
            </List>
          </Paper>
        )}
        
        {/* Crypto Methods Found */}
        {dynamicAnalysis.crypto_methods.length > 0 && (
          <Accordion sx={{ mt: 2 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="body2">
                🔐 Cryptographic Operations Detected ({dynamicAnalysis.crypto_methods.length})
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={1}>
                {dynamicAnalysis.crypto_methods.map((method, idx) => (
                  <Grid item xs={12} sm={6} key={idx}>
                    <Paper sx={{ p: 1.5, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
                      <Typography variant="subtitle2">{method.pattern}</Typography>
                      <Typography variant="caption" color="text.secondary">{method.description}</Typography>
                      <Typography 
                        variant="caption" 
                        component="div" 
                        sx={{ 
                          fontFamily: "monospace", 
                          mt: 0.5, 
                          p: 0.5, 
                          bgcolor: "rgba(0,0,0,0.2)", 
                          borderRadius: 0.5,
                          fontSize: 10,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap"
                        }}
                      >
                        {method.context}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>
        )}
      </AccordionDetails>
    </Accordion>
  );
}

// Native Library Analysis Viewer Component
function NativeLibraryViewer({ nativeAnalysis }: { nativeAnalysis: import("../api/client").NativeAnalysisResult }) {
  const theme = useTheme();
  const [selectedLib, setSelectedLib] = useState<string>("");
  
  const getRiskColor = (risk: string) => {
    switch (risk) {
      case "critical": return theme.palette.error.main;
      case "high": return theme.palette.warning.main;
      case "medium": return theme.palette.info.main;
      default: return theme.palette.success.main;
    }
  };

  const currentLib = selectedLib 
    ? nativeAnalysis.libraries.find(l => l.name === selectedLib)
    : null;

  return (
    <Accordion defaultExpanded={false}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <span>⚙️</span> Native Library Analysis
          <Chip label={`${nativeAnalysis.total_libraries} libraries`} size="small" />
          <Chip 
            label={nativeAnalysis.risk_level.toUpperCase()} 
            size="small" 
            sx={{ 
              bgcolor: alpha(getRiskColor(nativeAnalysis.risk_level), 0.2),
              color: getRiskColor(nativeAnalysis.risk_level),
              fontWeight: 600,
            }}
          />
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        {/* Summary Stats */}
        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
          <Grid container spacing={2}>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Libraries</Typography>
              <Typography variant="h6">{nativeAnalysis.total_libraries}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Architectures</Typography>
              <Typography variant="body2">{nativeAnalysis.architectures.join(", ") || "N/A"}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">JNI Functions</Typography>
              <Typography variant="h6">{nativeAnalysis.total_jni_functions}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Suspicious</Typography>
              <Typography variant="h6" color="warning.main">{nativeAnalysis.total_suspicious_functions}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Chip
                icon={<span>{nativeAnalysis.has_native_anti_debug ? "🛡️" : "✓"}</span>}
                label="Anti-Debug"
                color={nativeAnalysis.has_native_anti_debug ? "warning" : "default"}
                size="small"
              />
            </Grid>
            <Grid item xs={6} sm={2}>
              <Chip
                icon={<span>{nativeAnalysis.has_native_crypto ? "🔐" : "✓"}</span>}
                label="Native Crypto"
                color={nativeAnalysis.has_native_crypto ? "info" : "default"}
                size="small"
              />
            </Grid>
          </Grid>
          {nativeAnalysis.summary && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {nativeAnalysis.summary}
            </Typography>
          )}
        </Paper>

        {/* Native Secrets Found */}
        {nativeAnalysis.native_secrets && nativeAnalysis.native_secrets.length > 0 && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            <Typography variant="subtitle2" gutterBottom>
              ⚠️ {nativeAnalysis.native_secrets.length} Potential Secrets Found in Native Code
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 1 }}>
              {nativeAnalysis.native_secrets.slice(0, 10).map((secret, idx) => (
                <Chip 
                  key={idx} 
                  label={secret.length > 30 ? secret.substring(0, 30) + "..." : secret} 
                  size="small" 
                  sx={{ fontFamily: "monospace", fontSize: 10 }}
                />
              ))}
              {nativeAnalysis.native_secrets.length > 10 && (
                <Chip label={`+${nativeAnalysis.native_secrets.length - 10} more`} size="small" variant="outlined" />
              )}
            </Box>
          </Alert>
        )}

        <Grid container spacing={2}>
          {/* Library List */}
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 1, maxHeight: 400, overflow: "auto" }}>
              <Typography variant="subtitle2" sx={{ px: 1, py: 0.5 }}>
                Native Libraries ({nativeAnalysis.libraries.length})
              </Typography>
              <List dense>
                {nativeAnalysis.libraries.map((lib) => (
                  <ListItem
                    key={lib.name}
                    sx={{
                      cursor: "pointer",
                      bgcolor: selectedLib === lib.name 
                        ? alpha(theme.palette.primary.main, 0.1)
                        : "transparent",
                      borderLeft: selectedLib === lib.name 
                        ? `3px solid ${theme.palette.primary.main}`
                        : "3px solid transparent",
                      "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) },
                      borderRadius: 1,
                      mb: 0.5,
                    }}
                    onClick={() => setSelectedLib(lib.name)}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                          <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: 11 }}>
                            {lib.name}
                          </Typography>
                          {lib.has_anti_debug && <span title="Anti-Debug">🛡️</span>}
                          {lib.has_crypto && <span title="Crypto">🔐</span>}
                          {lib.has_jni && <span title="JNI">☕</span>}
                        </Box>
                      }
                      secondary={
                        <Typography variant="caption" color="text.secondary">
                          {lib.architecture} • {(lib.size / 1024).toFixed(1)} KB
                          {lib.is_stripped && " • stripped"}
                        </Typography>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          {/* Library Details */}
          <Grid item xs={12} md={8}>
            <Paper sx={{ p: 2, minHeight: 400, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
              {currentLib ? (
                <>
                  <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>📚</span> {currentLib.name}
                  </Typography>
                  
                  <Grid container spacing={1} sx={{ mb: 2 }}>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Architecture</Typography>
                      <Typography variant="body2">{currentLib.architecture}</Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Size</Typography>
                      <Typography variant="body2">{(currentLib.size / 1024).toFixed(2)} KB</Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Stripped</Typography>
                      <Typography variant="body2">{currentLib.is_stripped ? "Yes" : "No"}</Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Functions</Typography>
                      <Typography variant="body2">{currentLib.functions?.length || 0}</Typography>
                    </Grid>
                  </Grid>

                  {/* JNI Functions */}
                  {currentLib.jni_functions && currentLib.jni_functions.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        ☕ JNI Functions ({currentLib.jni_functions.length})
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {currentLib.jni_functions.slice(0, 15).map((fn, idx) => (
                          <Chip 
                            key={idx}
                            label={fn.name}
                            size="small"
                            color="primary"
                            variant="outlined"
                            sx={{ fontFamily: "monospace", fontSize: 10 }}
                          />
                        ))}
                        {currentLib.jni_functions.length > 15 && (
                          <Chip label={`+${currentLib.jni_functions.length - 15} more`} size="small" />
                        )}
                      </Box>
                    </Box>
                  )}

                  {/* Anti-Debug Indicators */}
                  {currentLib.anti_debug_indicators && currentLib.anti_debug_indicators.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" gutterBottom color="warning.main">
                        🛡️ Anti-Debug Indicators ({currentLib.anti_debug_indicators.length})
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {currentLib.anti_debug_indicators.map((indicator, idx) => (
                          <Chip 
                            key={idx}
                            label={indicator}
                            size="small"
                            color="warning"
                            sx={{ fontFamily: "monospace", fontSize: 10 }}
                          />
                        ))}
                      </Box>
                    </Box>
                  )}

                  {/* Crypto Indicators */}
                  {currentLib.crypto_indicators && currentLib.crypto_indicators.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" gutterBottom color="info.main">
                        🔐 Crypto Functions ({currentLib.crypto_indicators.length})
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {currentLib.crypto_indicators.slice(0, 10).map((indicator, idx) => (
                          <Chip 
                            key={idx}
                            label={indicator}
                            size="small"
                            color="info"
                            variant="outlined"
                            sx={{ fontFamily: "monospace", fontSize: 10 }}
                          />
                        ))}
                      </Box>
                    </Box>
                  )}

                  {/* URLs Found */}
                  {currentLib.urls_found && currentLib.urls_found.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        🌐 URLs Found ({currentLib.urls_found.length})
                      </Typography>
                      <List dense sx={{ maxHeight: 100, overflow: "auto" }}>
                        {currentLib.urls_found.slice(0, 10).map((url, idx) => (
                          <ListItem key={idx} sx={{ py: 0 }}>
                            <ListItemText 
                              primary={<Typography variant="caption" fontFamily="monospace">{url}</Typography>}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}

                  {/* Secrets Found */}
                  {currentLib.secrets_found && currentLib.secrets_found.length > 0 && (
                    <Alert severity="error" sx={{ mt: 1 }}>
                      <Typography variant="subtitle2">
                        ⚠️ Potential Secrets Found ({currentLib.secrets_found.length})
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                        {currentLib.secrets_found.slice(0, 5).map((secret, idx) => (
                          <Chip 
                            key={idx}
                            label={secret.length > 40 ? secret.substring(0, 40) + "..." : secret}
                            size="small"
                            color="error"
                            sx={{ fontFamily: "monospace", fontSize: 9 }}
                          />
                        ))}
                      </Box>
                    </Alert>
                  )}
                </>
              ) : (
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", minHeight: 200 }}>
                  <Typography variant="body2" color="text.secondary">
                    Select a library to view details
                  </Typography>
                </Box>
              )}
            </Paper>
          </Grid>
        </Grid>
      </AccordionDetails>
    </Accordion>
  );
}

// ============================================================================
// Data Flow / Taint Analysis Viewer
// ============================================================================

function DataFlowAnalysisViewer({ dataFlowAnalysis }: { dataFlowAnalysis: DataFlowAnalysisResult }) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  const [selectedFlow, setSelectedFlow] = useState<number | null>(null);

  const getSeverityColor = (severity: string): string => {
    switch (severity.toLowerCase()) {
      case "critical": return theme.palette.error.main;
      case "high": return "#ea580c";
      case "medium": return theme.palette.warning.main;
      case "low": return theme.palette.success.main;
      default: return theme.palette.grey[500];
    }
  };

  const getSourceIcon = (sourceType: string): string => {
    switch (sourceType) {
      case "location": return "📍";
      case "device_info": return "📱";
      case "contacts": return "👥";
      case "sms": return "💬";
      case "accounts": return "🔑";
      case "clipboard": return "📋";
      case "media": return "🖼️";
      case "file_system": return "📁";
      case "network_response": return "🌐";
      case "crypto": return "🔐";
      default: return "📥";
    }
  };

  const getSinkIcon = (sinkType: string): string => {
    switch (sinkType) {
      case "network": return "🌍";
      case "storage": return "💾";
      case "logging": return "📝";
      case "ipc": return "🔗";
      case "sms_send": return "📤";
      case "external_storage": return "📂";
      case "process_execution": return "⚙️";
      case "reflection": return "🔄";
      case "native": return "🔧";
      default: return "📤";
    }
  };

  return (
    <Accordion defaultExpanded={dataFlowAnalysis.critical_flows > 0 || dataFlowAnalysis.high_risk_flows > 0}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <span>🔀</span> Data Flow Analysis
          <Chip label={`${dataFlowAnalysis.total_flows} flows`} size="small" />
          {dataFlowAnalysis.critical_flows > 0 && (
            <Chip 
              label={`${dataFlowAnalysis.critical_flows} critical`} 
              size="small" 
              sx={{ 
                bgcolor: alpha(theme.palette.error.main, 0.2),
                color: theme.palette.error.main,
                fontWeight: 600,
              }}
            />
          )}
          {dataFlowAnalysis.high_risk_flows > 0 && (
            <Chip 
              label={`${dataFlowAnalysis.high_risk_flows} high`} 
              size="small" 
              sx={{ 
                bgcolor: alpha("#ea580c", 0.2),
                color: "#ea580c",
                fontWeight: 600,
              }}
            />
          )}
          {dataFlowAnalysis.privacy_violations.length > 0 && (
            <Chip 
              label={`${dataFlowAnalysis.privacy_violations.length} privacy issues`} 
              size="small" 
              color="warning"
            />
          )}
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        {/* Summary Stats */}
        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
          <Grid container spacing={2}>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Sources Found</Typography>
              <Typography variant="h6">{dataFlowAnalysis.total_sources}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Sinks Found</Typography>
              <Typography variant="h6">{dataFlowAnalysis.total_sinks}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Data Flows</Typography>
              <Typography variant="h6">{dataFlowAnalysis.total_flows}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Critical</Typography>
              <Typography variant="h6" color="error.main">{dataFlowAnalysis.critical_flows}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">High Risk</Typography>
              <Typography variant="h6" sx={{ color: "#ea580c" }}>{dataFlowAnalysis.high_risk_flows}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Privacy Violations</Typography>
              <Typography variant="h6" color="warning.main">{dataFlowAnalysis.privacy_violations.length}</Typography>
            </Grid>
          </Grid>
          {dataFlowAnalysis.summary && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {dataFlowAnalysis.summary}
            </Typography>
          )}
        </Paper>

        {/* Tabs for different views */}
        <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} sx={{ mb: 2 }}>
          <Tab label="Data Flow Paths" />
          <Tab label={`Sources (${dataFlowAnalysis.sources_found.length})`} />
          <Tab label={`Sinks (${dataFlowAnalysis.sinks_found.length})`} />
          <Tab label="Privacy & Recommendations" />
        </Tabs>

        {/* Tab 0: Data Flow Paths */}
        {activeTab === 0 && (
          <Grid container spacing={2}>
            {/* Flow List */}
            <Grid item xs={12} md={5}>
              <Paper sx={{ p: 1, maxHeight: 400, overflow: "auto" }}>
                <Typography variant="subtitle2" sx={{ px: 1, py: 0.5, display: "flex", alignItems: "center", gap: 1 }}>
                  🔀 Data Flow Paths ({dataFlowAnalysis.data_flow_paths.length})
                </Typography>
                {dataFlowAnalysis.data_flow_paths.length === 0 ? (
                  <Box sx={{ p: 2, textAlign: "center" }}>
                    <Typography variant="body2" color="text.secondary">
                      ✅ No problematic data flows detected
                    </Typography>
                  </Box>
                ) : (
                  <List dense>
                    {dataFlowAnalysis.data_flow_paths.map((flow, idx) => (
                      <ListItem
                        key={idx}
                        sx={{
                          cursor: "pointer",
                          bgcolor: selectedFlow === idx 
                            ? alpha(theme.palette.primary.main, 0.1)
                            : "transparent",
                          borderLeft: `3px solid ${getSeverityColor(flow.severity)}`,
                          "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) },
                          borderRadius: 1,
                          mb: 0.5,
                          flexDirection: "column",
                          alignItems: "flex-start",
                        }}
                        onClick={() => setSelectedFlow(idx)}
                      >
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                          <span>{getSourceIcon(flow.source.source_type)}</span>
                          <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: 11 }}>
                            {flow.source.source_type}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">→</Typography>
                          <span>{getSinkIcon(flow.sink.sink_type)}</span>
                          <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: 11 }}>
                            {flow.sink.sink_type}
                          </Typography>
                          <Box sx={{ flexGrow: 1 }} />
                          <Chip 
                            label={flow.severity} 
                            size="small" 
                            sx={{ 
                              bgcolor: alpha(getSeverityColor(flow.severity), 0.2),
                              color: getSeverityColor(flow.severity),
                              fontWeight: 600,
                              fontSize: 9,
                              height: 18,
                            }}
                          />
                        </Box>
                        <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
                          {flow.affected_class.split("/").pop()}.{flow.affected_method.split("(")[0]}
                        </Typography>
                      </ListItem>
                    ))}
                  </List>
                )}
              </Paper>
            </Grid>

            {/* Flow Details */}
            <Grid item xs={12} md={7}>
              <Paper sx={{ p: 2, minHeight: 400, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
                {selectedFlow !== null && dataFlowAnalysis.data_flow_paths[selectedFlow] ? (
                  (() => {
                    const flow = dataFlowAnalysis.data_flow_paths[selectedFlow];
                    return (
                      <>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                          <Chip 
                            label={flow.severity.toUpperCase()} 
                            size="small" 
                            sx={{ 
                              bgcolor: alpha(getSeverityColor(flow.severity), 0.2),
                              color: getSeverityColor(flow.severity),
                              fontWeight: 600,
                            }}
                          />
                          {flow.is_privacy_violation && (
                            <Chip label="Privacy Issue" size="small" color="warning" />
                          )}
                          {flow.gdpr_relevant && (
                            <Chip label="GDPR Relevant" size="small" color="error" variant="outlined" />
                          )}
                          <Chip label={flow.owasp_category} size="small" variant="outlined" />
                        </Box>

                        <Typography variant="subtitle2" gutterBottom>📍 Source (Data Origin)</Typography>
                        <Paper sx={{ p: 1.5, mb: 2, bgcolor: alpha(theme.palette.info.main, 0.05), border: `1px solid ${alpha(theme.palette.info.main, 0.3)}` }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                            <span style={{ fontSize: 20 }}>{getSourceIcon(flow.source.source_type)}</span>
                            <Typography variant="subtitle2">{flow.source.source_type}</Typography>
                            <Chip 
                              label={flow.source.sensitivity} 
                              size="small" 
                              sx={{ 
                                bgcolor: alpha(getSeverityColor(flow.source.sensitivity), 0.2),
                                color: getSeverityColor(flow.source.sensitivity),
                                fontSize: 10,
                              }}
                            />
                          </Box>
                          <Typography variant="caption" display="block" fontFamily="monospace">
                            {flow.source.class_name.split("/").pop()}.{flow.source.method_name}()
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                            {flow.source.description}
                          </Typography>
                        </Paper>

                        <Typography variant="subtitle2" gutterBottom>📤 Sink (Data Destination)</Typography>
                        <Paper sx={{ p: 1.5, mb: 2, bgcolor: alpha(theme.palette.error.main, 0.05), border: `1px solid ${alpha(theme.palette.error.main, 0.3)}` }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                            <span style={{ fontSize: 20 }}>{getSinkIcon(flow.sink.sink_type)}</span>
                            <Typography variant="subtitle2">{flow.sink.sink_type}</Typography>
                            <Chip 
                              label={flow.sink.risk_level} 
                              size="small" 
                              sx={{ 
                                bgcolor: alpha(getSeverityColor(flow.sink.risk_level), 0.2),
                                color: getSeverityColor(flow.sink.risk_level),
                                fontSize: 10,
                              }}
                            />
                          </Box>
                          <Typography variant="caption" display="block" fontFamily="monospace">
                            {flow.sink.class_name.split("/").pop()}.{flow.sink.method_name}()
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                            {flow.sink.description}
                          </Typography>
                        </Paper>

                        <Typography variant="subtitle2" gutterBottom>📍 Location</Typography>
                        <Typography variant="caption" fontFamily="monospace" display="block" sx={{ mb: 2 }}>
                          {flow.affected_class}
                          <br />
                          Method: {flow.affected_method}
                        </Typography>

                        <Typography variant="subtitle2" gutterBottom>📝 Description</Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          {flow.description}
                        </Typography>

                        <Alert severity="info" sx={{ mt: 1 }}>
                          <Typography variant="subtitle2" gutterBottom>💡 Recommendation</Typography>
                          <Typography variant="body2">
                            {flow.recommendation}
                          </Typography>
                        </Alert>
                      </>
                    );
                  })()
                ) : (
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", minHeight: 200 }}>
                    <Typography variant="body2" color="text.secondary">
                      Select a data flow to view details
                    </Typography>
                  </Box>
                )}
              </Paper>
            </Grid>
          </Grid>
        )}

        {/* Tab 1: Sources */}
        {activeTab === 1 && (
          <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>API Call</TableCell>
                  <TableCell>Sensitivity</TableCell>
                  <TableCell>Location</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {dataFlowAnalysis.sources_found.map((source, idx) => (
                  <TableRow key={idx}>
                    <TableCell>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <span>{getSourceIcon(source.source_type)}</span>
                        <Typography variant="body2">{source.source_type}</Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" fontFamily="monospace">
                        {source.class_name.split("/").pop()}.{source.method_name}()
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={source.sensitivity} 
                        size="small" 
                        sx={{ 
                          bgcolor: alpha(getSeverityColor(source.sensitivity), 0.2),
                          color: getSeverityColor(source.sensitivity),
                          fontWeight: 600,
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" fontFamily="monospace">
                        {source.affected_method}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
                {dataFlowAnalysis.sources_found.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} align="center">
                      <Typography variant="body2" color="text.secondary">
                        No sensitive data sources detected
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {/* Tab 2: Sinks */}
        {activeTab === 2 && (
          <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>API Call</TableCell>
                  <TableCell>Risk Level</TableCell>
                  <TableCell>Location</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {dataFlowAnalysis.sinks_found.map((sink, idx) => (
                  <TableRow key={idx}>
                    <TableCell>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <span>{getSinkIcon(sink.sink_type)}</span>
                        <Typography variant="body2">{sink.sink_type}</Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" fontFamily="monospace">
                        {sink.class_name.split("/").pop()}.{sink.method_name}()
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={sink.risk_level} 
                        size="small" 
                        sx={{ 
                          bgcolor: alpha(getSeverityColor(sink.risk_level), 0.2),
                          color: getSeverityColor(sink.risk_level),
                          fontWeight: 600,
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" fontFamily="monospace">
                        {sink.affected_method}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
                {dataFlowAnalysis.sinks_found.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} align="center">
                      <Typography variant="body2" color="text.secondary">
                        No data sinks detected
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {/* Tab 3: Privacy & Recommendations */}
        {activeTab === 3 && (
          <Grid container spacing={2}>
            {/* Privacy Violations */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, height: "100%" }}>
                <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <span>🔒</span> Privacy Violations ({dataFlowAnalysis.privacy_violations.length})
                </Typography>
                {dataFlowAnalysis.privacy_violations.length === 0 ? (
                  <Box sx={{ p: 2, textAlign: "center" }}>
                    <Typography variant="body2" color="success.main">
                      ✅ No privacy violations detected
                    </Typography>
                  </Box>
                ) : (
                  <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                    {dataFlowAnalysis.privacy_violations.map((violation, idx) => (
                      <ListItem key={idx} sx={{ 
                        flexDirection: "column", 
                        alignItems: "flex-start",
                        bgcolor: alpha(theme.palette.warning.main, 0.05),
                        borderRadius: 1,
                        mb: 1,
                        border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
                      }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                          <Chip label={violation.data_type} size="small" color="warning" />
                          <Typography variant="caption" fontFamily="monospace">
                            {violation.source} → {violation.sink}
                          </Typography>
                        </Box>
                        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                          {violation.description}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {violation.affected_class.split("/").pop()}.{violation.affected_method}
                        </Typography>
                      </ListItem>
                    ))}
                  </List>
                )}
              </Paper>
            </Grid>

            {/* Recommendations */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, height: "100%" }}>
                <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <span>💡</span> Recommendations
                </Typography>
                {dataFlowAnalysis.recommendations.length === 0 ? (
                  <Box sx={{ p: 2, textAlign: "center" }}>
                    <Typography variant="body2" color="success.main">
                      ✅ No recommendations at this time
                    </Typography>
                  </Box>
                ) : (
                  <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                    {dataFlowAnalysis.recommendations.map((rec, idx) => (
                      <ListItem key={idx}>
                        <ListItemIcon sx={{ minWidth: 30 }}>
                          <InfoIcon color="info" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText 
                          primary={rec}
                          primaryTypographyProps={{ variant: "body2" }}
                        />
                      </ListItem>
                    ))}
                  </List>
                )}
              </Paper>
            </Grid>

            {/* Data Leak Risks */}
            {dataFlowAnalysis.data_leak_risks.length > 0 && (
              <Grid item xs={12}>
                <Alert severity="error">
                  <Typography variant="subtitle2" gutterBottom>
                    ⚠️ Data Leak Risks ({dataFlowAnalysis.data_leak_risks.length})
                  </Typography>
                  <List dense>
                    {dataFlowAnalysis.data_leak_risks.slice(0, 5).map((risk, idx) => (
                      <ListItem key={idx} sx={{ py: 0 }}>
                        <ListItemText
                          primary={
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              <Chip 
                                label={risk.severity} 
                                size="small" 
                                sx={{ 
                                  bgcolor: alpha(getSeverityColor(risk.severity), 0.2),
                                  color: getSeverityColor(risk.severity),
                                  fontSize: 10,
                                }}
                              />
                              <Typography variant="body2">{risk.description}</Typography>
                            </Box>
                          }
                          secondary={`${risk.source} → ${risk.sink}`}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Alert>
              </Grid>
            )}
          </Grid>
        )}
      </AccordionDetails>
    </Accordion>
  );
}

// Hardening Score Card Component
function HardeningScoreCard({ hardeningScore }: { hardeningScore: import("../api/client").HardeningScore }) {
  const theme = useTheme();
  
  const getGradeColor = (grade: string) => {
    switch (grade) {
      case "A": return theme.palette.success.main;
      case "B": return theme.palette.success.light;
      case "C": return theme.palette.warning.main;
      case "D": return theme.palette.warning.dark;
      case "F": return theme.palette.error.main;
      default: return theme.palette.grey[500];
    }
  };
  
  const getRiskColor = (risk: string) => {
    switch (risk) {
      case "low": return theme.palette.success.main;
      case "medium": return theme.palette.warning.main;
      case "high": return theme.palette.error.light;
      case "critical": return theme.palette.error.main;
      default: return theme.palette.grey[500];
    }
  };

  const categories = hardeningScore.categories;
  const categoryOrder = [
    { key: 'code_protection', name: 'Code Protection', icon: '🛡️' },
    { key: 'network_security', name: 'Network Security', icon: '🌐' },
    { key: 'data_storage', name: 'Data Storage', icon: '💾' },
    { key: 'authentication_crypto', name: 'Auth & Crypto', icon: '🔐' },
    { key: 'platform_security', name: 'Platform Security', icon: '📱' },
  ];

  return (
    <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.background.paper, 0.7) }}>
      <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <SecurityIcon color="primary" /> Security Hardening Score
      </Typography>

      <Grid container spacing={3}>
        {/* Main Score Display */}
        <Grid item xs={12} md={4}>
          <Box sx={{ 
            textAlign: "center", 
            p: 3, 
            borderRadius: 2, 
            bgcolor: alpha(getGradeColor(hardeningScore.grade), 0.1),
            border: `2px solid ${alpha(getGradeColor(hardeningScore.grade), 0.3)}`
          }}>
            <Typography 
              variant="h1" 
              sx={{ 
                fontWeight: 700, 
                color: getGradeColor(hardeningScore.grade),
                textShadow: `0 0 20px ${alpha(getGradeColor(hardeningScore.grade), 0.5)}`
              }}
            >
              {hardeningScore.grade}
            </Typography>
            <Typography variant="h4" sx={{ fontWeight: 600, mb: 1 }}>
              {hardeningScore.overall_score}/100
            </Typography>
            <Chip 
              label={hardeningScore.risk_level.toUpperCase()} 
              sx={{ 
                bgcolor: alpha(getRiskColor(hardeningScore.risk_level), 0.2),
                color: getRiskColor(hardeningScore.risk_level),
                fontWeight: 600,
              }}
            />
            
            {/* Comparison */}
            {hardeningScore.comparison && (
              <Box sx={{ mt: 2, pt: 2, borderTop: `1px solid ${alpha(theme.palette.divider, 0.3)}` }}>
                <Typography variant="caption" color="text.secondary">
                  Industry Avg: {hardeningScore.comparison.industry_average}
                </Typography>
                <Typography variant="body2">
                  Better than {hardeningScore.comparison.percentile}% of apps
                </Typography>
              </Box>
            )}
          </Box>
        </Grid>

        {/* Category Scores */}
        <Grid item xs={12} md={8}>
          <Typography variant="subtitle2" gutterBottom>Category Breakdown</Typography>
          {categoryOrder.map(({ key, name, icon }) => {
            const category = categories[key as keyof typeof categories];
            if (!category) return null;
            
            return (
              <Box key={key} sx={{ mb: 2 }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 0.5 }}>
                  <Typography variant="body2" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                    <span>{icon}</span> {name}
                    <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                      ({category.weight * 100}% weight)
                    </Typography>
                  </Typography>
                  <Typography variant="body2" fontWeight={600}>
                    {category.score}/{category.max_score} ({category.percentage}%)
                  </Typography>
                </Box>
                <LinearProgress 
                  variant="determinate" 
                  value={category.percentage} 
                  sx={{ 
                    height: 8, 
                    borderRadius: 4,
                    bgcolor: alpha(theme.palette.grey[500], 0.2),
                    "& .MuiLinearProgress-bar": {
                      bgcolor: category.percentage >= 70 
                        ? theme.palette.success.main 
                        : category.percentage >= 40 
                          ? theme.palette.warning.main 
                          : theme.palette.error.main,
                    }
                  }}
                />
                {/* Findings preview */}
                {category.findings && category.findings.length > 0 && (
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                    {category.findings.slice(0, 2).map((finding, idx) => (
                      <Chip 
                        key={idx}
                        label={finding.issue}
                        size="small"
                        sx={{ 
                          fontSize: 10, 
                          height: 20,
                          bgcolor: alpha(getRiskColor(finding.severity), 0.1),
                          color: getRiskColor(finding.severity),
                        }}
                      />
                    ))}
                    {category.findings.length > 2 && (
                      <Chip label={`+${category.findings.length - 2}`} size="small" sx={{ fontSize: 10, height: 20 }} />
                    )}
                  </Box>
                )}
              </Box>
            );
          })}
        </Grid>
      </Grid>

      {/* Attack Surface Summary */}
      <Divider sx={{ my: 2 }} />
      <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <span>🎯</span> Attack Surface Summary
      </Typography>
      <Grid container spacing={1}>
        {hardeningScore.attack_surface_summary && (
          <>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                <Typography variant="h6">{hardeningScore.attack_surface_summary.exported_components}</Typography>
                <Typography variant="caption" color="text.secondary">Exported</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                <Typography variant="h6">{hardeningScore.attack_surface_summary.deep_links}</Typography>
                <Typography variant="caption" color="text.secondary">Deep Links</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                <Typography variant="h6">{hardeningScore.attack_surface_summary.dangerous_permissions}</Typography>
                <Typography variant="caption" color="text.secondary">Dangerous Perms</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                <Typography variant="h6">{hardeningScore.attack_surface_summary.native_libraries}</Typography>
                <Typography variant="caption" color="text.secondary">Native Libs</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                label={hardeningScore.attack_surface_summary.debug_enabled ? "Debug ON" : "Debug OFF"}
                size="small"
                color={hardeningScore.attack_surface_summary.debug_enabled ? "error" : "success"}
                sx={{ width: "100%" }}
              />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                label={hardeningScore.attack_surface_summary.cleartext_traffic ? "Cleartext" : "Encrypted"}
                size="small"
                color={hardeningScore.attack_surface_summary.cleartext_traffic ? "warning" : "success"}
                sx={{ width: "100%" }}
              />
            </Grid>
          </>
        )}
      </Grid>

      {/* Top Risks & Quick Wins */}
      <Grid container spacing={2} sx={{ mt: 1 }}>
        {hardeningScore.top_risks && hardeningScore.top_risks.length > 0 && (
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.error.main, 0.05), height: "100%" }}>
              <Typography variant="subtitle2" color="error.main" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <span>⚠️</span> Top Security Risks
              </Typography>
              <List dense>
                {hardeningScore.top_risks.slice(0, 5).map((risk, idx) => (
                  <ListItem key={idx} sx={{ py: 0.25 }}>
                    <ListItemText
                      primary={<Typography variant="body2">{risk}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        )}
        {hardeningScore.quick_wins && hardeningScore.quick_wins.length > 0 && (
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.success.main, 0.05), height: "100%" }}>
              <Typography variant="subtitle2" color="success.main" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <span>✨</span> Quick Security Wins
              </Typography>
              <List dense>
                {hardeningScore.quick_wins.slice(0, 5).map((win, idx) => (
                  <ListItem key={idx} sx={{ py: 0.25 }}>
                    <ListItemText
                      primary={<Typography variant="body2">{win}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        )}
      </Grid>
    </Paper>
  );
}

// Docker Inspector Results Component
function DockerResults({ result }: { result: DockerAnalysisResult }) {
  const theme = useTheme();

  // Categorize security issues by attack type for offensive security view
  const categorizeIssues = () => {
    const categories = {
      container_escape: [] as typeof result.security_issues,
      privilege_escalation: [] as typeof result.security_issues,
      secrets: [] as typeof result.security_issues,
      lateral_movement: [] as typeof result.security_issues,
      network_exposure: [] as typeof result.security_issues,
      supply_chain: [] as typeof result.security_issues,
      other: [] as typeof result.security_issues,
    };

    result.security_issues.forEach((issue) => {
      const cat = issue.category?.toLowerCase() || "";
      if (cat.includes("escape") || cat.includes("privileged")) {
        categories.container_escape.push(issue);
      } else if (cat.includes("privilege") || cat.includes("root") || cat.includes("suid")) {
        categories.privilege_escalation.push(issue);
      } else if (cat.includes("secret") || cat.includes("credential") || cat.includes("key")) {
        categories.secrets.push(issue);
      } else if (cat.includes("lateral") || cat.includes("ssh") || cat.includes("kube") || cat.includes("aws")) {
        categories.lateral_movement.push(issue);
      } else if (cat.includes("network") || cat.includes("port") || cat.includes("expose")) {
        categories.network_exposure.push(issue);
      } else if (cat.includes("supply") || cat.includes("registry") || cat.includes("base")) {
        categories.supply_chain.push(issue);
      } else {
        categories.other.push(issue);
      }
    });
    return categories;
  };

  const categories = categorizeIssues();

  // Calculate risk score
  const calculateRiskScore = () => {
    let score = 0;
    result.security_issues.forEach((issue) => {
      switch (issue.severity?.toLowerCase()) {
        case "critical": score += 40; break;
        case "high": score += 25; break;
        case "medium": score += 10; break;
        case "low": score += 3; break;
      }
    });
    result.secrets.forEach((s) => {
      switch (s.severity?.toLowerCase()) {
        case "critical": score += 35; break;
        case "high": score += 20; break;
        default: score += 10;
      }
    });
    return Math.min(100, score);
  };

  const riskScore = calculateRiskScore();
  const getRiskLevel = (score: number) => {
    if (score >= 70) return { level: "CRITICAL", color: "#dc2626", icon: "🔴" };
    if (score >= 40) return { level: "HIGH", color: "#f97316", icon: "🟠" };
    if (score >= 20) return { level: "MEDIUM", color: "#eab308", icon: "🟡" };
    return { level: "LOW", color: "#22c55e", icon: "🟢" };
  };
  const risk = getRiskLevel(riskScore);

  const criticalCount = result.security_issues.filter(i => i.severity?.toLowerCase() === "critical").length;
  const highCount = result.security_issues.filter(i => i.severity?.toLowerCase() === "high").length;

  return (
    <Box>
      {/* Risk Assessment Banner */}
      <Paper
        sx={{
          p: 3,
          mb: 3,
          background: `linear-gradient(135deg, ${alpha(risk.color, 0.15)} 0%, ${alpha(risk.color, 0.05)} 100%)`,
          border: `2px solid ${alpha(risk.color, 0.3)}`,
        }}
      >
        <Grid container spacing={3} alignItems="center">
          <Grid item xs={12} md={4}>
            <Box sx={{ textAlign: "center" }}>
              <Typography variant="h2" sx={{ color: risk.color, fontWeight: 700 }}>
                {risk.icon} {riskScore}
              </Typography>
              <Typography variant="h6" sx={{ color: risk.color }}>
                {risk.level} RISK
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} md={8}>
            <Typography variant="h6" gutterBottom>
              Offensive Security Assessment
            </Typography>
            <Grid container spacing={1}>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center", p: 1, bgcolor: alpha("#dc2626", 0.1), borderRadius: 1 }}>
                  <Typography variant="h5" color="error">{criticalCount}</Typography>
                  <Typography variant="caption">Critical</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center", p: 1, bgcolor: alpha("#f97316", 0.1), borderRadius: 1 }}>
                  <Typography variant="h5" sx={{ color: "#f97316" }}>{highCount}</Typography>
                  <Typography variant="caption">High</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center", p: 1, bgcolor: alpha("#dc2626", 0.1), borderRadius: 1 }}>
                  <Typography variant="h5" color="error">{result.secrets.length}</Typography>
                  <Typography variant="caption">Secrets</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center", p: 1, bgcolor: alpha(theme.palette.info.main, 0.1), borderRadius: 1 }}>
                  <Typography variant="h5" color="info">{result.total_layers}</Typography>
                  <Typography variant="caption">Layers</Typography>
                </Box>
              </Grid>
            </Grid>
          </Grid>
        </Grid>
      </Paper>

      {/* Attack Vector Categories */}
      {result.security_issues.length > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <TargetIcon color="error" /> Attack Vectors by Category
          </Typography>
          <Grid container spacing={2}>
            {categories.container_escape.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper variant="outlined" sx={{ p: 2, bgcolor: alpha("#dc2626", 0.05), borderColor: alpha("#dc2626", 0.3) }}>
                  <Typography variant="subtitle2" sx={{ color: "#dc2626", display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    🚨 Container Escape ({categories.container_escape.length})
                  </Typography>
                  {categories.container_escape.slice(0, 3).map((issue, idx) => (
                    <Box key={idx} sx={{ mb: 1 }}>
                      <Typography variant="body2">{issue.description}</Typography>
                      {issue.attack_vector && (
                        <Typography variant="caption" color="text.secondary" sx={{ fontStyle: "italic" }}>
                          → {issue.attack_vector}
                        </Typography>
                      )}
                    </Box>
                  ))}
                </Paper>
              </Grid>
            )}
            {categories.lateral_movement.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper variant="outlined" sx={{ p: 2, bgcolor: alpha("#f97316", 0.05), borderColor: alpha("#f97316", 0.3) }}>
                  <Typography variant="subtitle2" sx={{ color: "#f97316", display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    ⚠️ Lateral Movement ({categories.lateral_movement.length})
                  </Typography>
                  {categories.lateral_movement.slice(0, 3).map((issue, idx) => (
                    <Box key={idx} sx={{ mb: 1 }}>
                      <Typography variant="body2">{issue.description}</Typography>
                      {issue.attack_vector && (
                        <Typography variant="caption" color="text.secondary" sx={{ fontStyle: "italic" }}>
                          → {issue.attack_vector}
                        </Typography>
                      )}
                    </Box>
                  ))}
                </Paper>
              </Grid>
            )}
            {categories.privilege_escalation.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper variant="outlined" sx={{ p: 2, bgcolor: alpha("#eab308", 0.05), borderColor: alpha("#eab308", 0.3) }}>
                  <Typography variant="subtitle2" sx={{ color: "#eab308", display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    ⬆️ Privilege Escalation ({categories.privilege_escalation.length})
                  </Typography>
                  {categories.privilege_escalation.slice(0, 3).map((issue, idx) => (
                    <Box key={idx} sx={{ mb: 1 }}>
                      <Typography variant="body2">{issue.description}</Typography>
                      {issue.attack_vector && (
                        <Typography variant="caption" color="text.secondary" sx={{ fontStyle: "italic" }}>
                          → {issue.attack_vector}
                        </Typography>
                      )}
                    </Box>
                  ))}
                </Paper>
              </Grid>
            )}
            {categories.secrets.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper variant="outlined" sx={{ p: 2, bgcolor: alpha("#dc2626", 0.05), borderColor: alpha("#dc2626", 0.3) }}>
                  <Typography variant="subtitle2" sx={{ color: "#dc2626", display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    🔑 Secrets Exposure ({categories.secrets.length})
                  </Typography>
                  {categories.secrets.slice(0, 3).map((issue, idx) => (
                    <Box key={idx} sx={{ mb: 1 }}>
                      <Typography variant="body2">{issue.description}</Typography>
                      {issue.attack_vector && (
                        <Typography variant="caption" color="text.secondary" sx={{ fontStyle: "italic" }}>
                          → {issue.attack_vector}
                        </Typography>
                      )}
                    </Box>
                  ))}
                </Paper>
              </Grid>
            )}
            {categories.network_exposure.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper variant="outlined" sx={{ p: 2, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
                  <Typography variant="subtitle2" sx={{ color: theme.palette.info.main, display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    🌐 Network Exposure ({categories.network_exposure.length})
                  </Typography>
                  {categories.network_exposure.slice(0, 3).map((issue, idx) => (
                    <Box key={idx} sx={{ mb: 1 }}>
                      <Typography variant="body2">{issue.description}</Typography>
                    </Box>
                  ))}
                </Paper>
              </Grid>
            )}
            {categories.supply_chain.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper variant="outlined" sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderColor: alpha("#8b5cf6", 0.3) }}>
                  <Typography variant="subtitle2" sx={{ color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    📦 Supply Chain ({categories.supply_chain.length})
                  </Typography>
                  {categories.supply_chain.slice(0, 3).map((issue, idx) => (
                    <Box key={idx} sx={{ mb: 1 }}>
                      <Typography variant="body2">{issue.description}</Typography>
                    </Box>
                  ))}
                </Paper>
              </Grid>
            )}
          </Grid>
        </Paper>
      )}

      {/* Image Info */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.background.paper, 0.7) }}>
        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <DockerIcon color="info" /> Image Information
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <Typography variant="caption" color="text.secondary">Image Name</Typography>
            <Typography variant="body1" fontFamily="monospace">{result.image_name}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Image ID</Typography>
            <Typography variant="body1" fontFamily="monospace">{result.image_id.slice(0, 12)}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Total Size</Typography>
            <Typography variant="body1">{result.total_size_human}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Total Layers</Typography>
            <Typography variant="body1">{result.total_layers}</Typography>
          </Grid>
          {result.base_image && (
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">Base Image</Typography>
              <Typography variant="body1">{result.base_image}</Typography>
            </Grid>
          )}
        </Grid>
      </Paper>

      {/* All Security Issues (Detailed) */}
      {result.security_issues.length > 0 && (
        <Accordion defaultExpanded>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <BugIcon color="error" /> All Security Issues ({result.security_issues.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer sx={{ maxHeight: 400 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell width={100}>Severity</TableCell>
                    <TableCell width={150}>Category</TableCell>
                    <TableCell>Issue</TableCell>
                    <TableCell>Attack Vector</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {result.security_issues.map((issue, idx) => (
                    <TableRow key={idx} sx={{ bgcolor: issue.severity?.toLowerCase() === "critical" ? alpha("#dc2626", 0.05) : "inherit" }}>
                      <TableCell>
                        <Chip
                          label={issue.severity}
                          size="small"
                          sx={{
                            bgcolor: alpha(getSeverityColor(issue.severity), 0.2),
                            color: getSeverityColor(issue.severity),
                            fontWeight: 600,
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">{issue.category}</Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">{issue.description}</Typography>
                        {issue.command && (
                          <Typography variant="caption" fontFamily="monospace" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
                            {issue.command.length > 100 ? issue.command.slice(0, 100) + "..." : issue.command}
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" color="error" sx={{ fontStyle: "italic" }}>
                          {issue.attack_vector || "-"}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Secrets in Layers */}
      {result.secrets.length > 0 && (
        <Accordion sx={{ mt: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1, color: "#dc2626" }}>
              <SecretIcon /> Secrets Found in Image ({result.secrets.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Alert severity="error" sx={{ mb: 2 }}>
              <Typography variant="body2">
                <strong>Attack Vector:</strong> Secrets in image layers can be extracted using <code>docker save</code> + <code>tar</code> even if "deleted" in later layers.
              </Typography>
            </Alert>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Layer</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Value (Masked)</TableCell>
                    <TableCell>Severity</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {result.secrets.map((secret, idx) => (
                    <TableRow key={idx}>
                      <TableCell>
                        <Tooltip title={secret.layer_command}>
                          <Typography variant="body2" fontFamily="monospace">
                            {secret.layer_id.slice(0, 8)}
                          </Typography>
                        </Tooltip>
                      </TableCell>
                      <TableCell>{secret.secret_type}</TableCell>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                          {secret.masked_value}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={secret.severity}
                          size="small"
                          sx={{
                            bgcolor: alpha(getSeverityColor(secret.severity), 0.2),
                            color: getSeverityColor(secret.severity),
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Image Layers */}
      <Accordion sx={{ mt: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <LayersIcon color="primary" /> Image Layers ({result.layers.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer sx={{ maxHeight: 400 }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell width={100}>Layer</TableCell>
                  <TableCell width={100}>Size</TableCell>
                  <TableCell>Command</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {result.layers.map((layer, idx) => (
                  <TableRow key={idx}>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        {layer.id.slice(0, 8)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {layer.size > 0 ? `${(layer.size / (1024 * 1024)).toFixed(1)} MB` : "0 B"}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        fontFamily="monospace"
                        sx={{
                          wordBreak: "break-all",
                          maxWidth: 600,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                        }}
                      >
                        {layer.command.length > 200 ? layer.command.slice(0, 200) + "..." : layer.command}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* AI Analysis */}
      {result.ai_analysis && (
        <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <AiIcon color="info" /> AI Security Analysis
          </Typography>
          <Typography
            variant="body2"
            component="pre"
            sx={{
              whiteSpace: "pre-wrap",
              fontFamily: "inherit",
              m: 0,
            }}
          >
            {result.ai_analysis}
          </Typography>
        </Paper>
      )}
    </Box>
  );
}

// Main Component
export default function ReverseEngineeringHub() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const projectId = searchParams.get('projectId') ? parseInt(searchParams.get('projectId')!) : undefined;
  const projectName = searchParams.get('projectName') ? decodeURIComponent(searchParams.get('projectName')!) : undefined;
  const initialTab = searchParams.get('tab') ? parseInt(searchParams.get('tab')!) : 0;

  const [activeTab, setActiveTab] = useState(initialTab);
  const [status, setStatus] = useState<ReverseEngineeringStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [binaryIncludeAi, setBinaryIncludeAi] = useState(true);
  const [includeGhidra, setIncludeGhidra] = useState(true);
  const [includeGhidraAi, setIncludeGhidraAi] = useState(true);
  const [extendedGhidra, setExtendedGhidra] = useState(false);
  const [ghidraMaxFunctions, setGhidraMaxFunctions] = useState(500);
  const [ghidraDecompLimit, setGhidraDecompLimit] = useState(10000);
  const [ghidraAiMaxFunctions, setGhidraAiMaxFunctions] = useState(20);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [binaryAutoSaved, setBinaryAutoSaved] = useState(false);

  // Binary state
  const [binaryFile, setBinaryFile] = useState<File | null>(null);
  const [binaryResult, setBinaryResult] = useState<BinaryAnalysisResult | null>(null);
  const [binaryLoading, setBinaryLoading] = useState(false);
  const [binaryScanProgress, setBinaryScanProgress] = useState<UnifiedBinaryScanProgress | null>(null);
  const binaryAbortRef = useRef<{ abort: () => void } | null>(null);
  const [binaryExportAnchor, setBinaryExportAnchor] = useState<null | HTMLElement>(null);
  const [exportingBinary, setExportingBinary] = useState(false);

  // Deep Vulnerability Hunt state (integrated into main scan)
  const [includeVulnHunt, setIncludeVulnHunt] = useState(true);
  const [vulnHuntResult, setVulnHuntResult] = useState<VulnerabilityHuntResult | null>(null);
  const [vulnHuntMaxPasses, setVulnHuntMaxPasses] = useState(4);
  const [vulnHuntMaxTargets, setVulnHuntMaxTargets] = useState(50);
  const [vulnHuntExpanded, setVulnHuntExpanded] = useState(false);

  // APK state
  const [apkFile, setApkFile] = useState<File | null>(null);
  const [apkResult, setApkResult] = useState<ApkAnalysisResult | null>(null);
  const [apkLoading, setApkLoading] = useState(false);
  
  // Unified APK scan state
  const [unifiedApkResult, setUnifiedApkResult] = useState<UnifiedApkScanResult | null>(null);
  const [unifiedJadxSessionId, setUnifiedJadxSessionId] = useState<string | null>(null);
  const [unifiedExportAnchor, setUnifiedExportAnchor] = useState<null | HTMLElement>(null);
  const [exportingUnified, setExportingUnified] = useState(false);
  const [autoSavedReport, setAutoSavedReport] = useState(false);
  
  // Attack Surface Map state (for saving to reports)
  const [attackSurfaceMap, setAttackSurfaceMap] = useState<string | null>(null);

  // JADX Decompilation state (lifted for sharing with AI tools)
  const [jadxResult, setJadxResult] = useState<JadxDecompilationResult | null>(null);

  // AI Reports state (lifted for saving)
  const [aiFunctionalityReport, setAiFunctionalityReport] = useState<string | null>(null);
  const [aiSecurityReport, setAiSecurityReport] = useState<string | null>(null);
  const [aiPrivacyReport, setAiPrivacyReport] = useState<string | null>(null);
  const [aiThreatModel, setAiThreatModel] = useState<Record<string, unknown> | null>(null);
  const [aiVulnScanResult, setAiVulnScanResult] = useState<Record<string, unknown> | null>(null);
  const [aiChatHistory, setAiChatHistory] = useState<Array<Record<string, unknown>> | null>(null);
  
  // Enhanced Security Analysis state (combined Pattern + AI + CVE)
  const [enhancedSecurityResult, setEnhancedSecurityResult] = useState<EnhancedSecurityResult | null>(null);

  // Docker state
  const [dockerImages, setDockerImages] = useState<DockerImageInfo[]>([]);
  const [selectedImage, setSelectedImage] = useState<string>("");
  const [dockerResult, setDockerResult] = useState<DockerAnalysisResult | null>(null);
  const [dockerLoading, setDockerLoading] = useState(false);
  const [dockerImageFilter, setDockerImageFilter] = useState("");
  const [dockerImagesLoading, setDockerImagesLoading] = useState(false);

  // Saved reports state
  const [savedReports, setSavedReports] = useState<REReportSummary[]>([]);
  const [reportsLoading, setReportsLoading] = useState(false);
  const [savingReport, setSavingReport] = useState(false);
  const [viewingReportId, setViewingReportId] = useState<number | null>(null);
  const [loadingReportView, setLoadingReportView] = useState(false);
  
  // Share dialog state
  const [shareDialogOpen, setShareDialogOpen] = useState(false);
  const [reportToShare, setReportToShare] = useState<REReportSummary | null>(null);

  // Load status on mount
  useEffect(() => {
    loadStatus();
    loadSavedReports();
  }, []);

  useEffect(() => {
    if (status && !status.ghidra_available) {
      setIncludeGhidra(false);
      setIncludeGhidraAi(false);
    }
  }, [status?.ghidra_available]);

  const loadStatus = async () => {
    try {
      setLoading(true);
      const s = await reverseEngineeringClient.getStatus();
      setStatus(s);

      // If Docker is available, load images
      if (s.docker_available) {
        const imgs = await reverseEngineeringClient.listDockerImages();
        setDockerImages(imgs.images);
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  // Refresh Docker images list
  const refreshDockerImages = async () => {
    if (!status?.docker_available) return;
    try {
      setDockerImagesLoading(true);
      const imgs = await reverseEngineeringClient.listDockerImages();
      setDockerImages(imgs.images);
    } catch (e: any) {
      console.error("Failed to refresh Docker images:", e);
    } finally {
      setDockerImagesLoading(false);
    }
  };

  // Filter docker images based on search
  const filteredDockerImages = dockerImages.filter((img) =>
    img.name.toLowerCase().includes(dockerImageFilter.toLowerCase()) ||
    img.id.toLowerCase().includes(dockerImageFilter.toLowerCase())
  );

  const loadSavedReports = async () => {
    try {
      setReportsLoading(true);
      const reports = await reverseEngineeringClient.listReports({ limit: 50 });
      setSavedReports(reports);
    } catch (e: any) {
      console.error("Failed to load reports:", e);
    } finally {
      setReportsLoading(false);
    }
  };

  const saveBinaryReport = async () => {
    if (!binaryResult || !binaryFile) return;
    try {
      setSavingReport(true);
      const report: SaveREReportRequest = {
        analysis_type: 'binary',
        title: `Binary Analysis: ${binaryResult.filename}`,
        filename: binaryResult.filename,
        project_id: projectId,
        file_type: binaryResult.metadata.file_type,
        architecture: binaryResult.metadata.architecture,
        file_size: binaryResult.metadata.file_size,
        is_packed: binaryResult.metadata.is_packed,
        packer_name: binaryResult.metadata.packer_name || undefined,
        strings_count: binaryResult.strings_count,
        imports_count: binaryResult.imports.length,
        exports_count: binaryResult.exports.length,
        secrets_count: binaryResult.secrets.length,
        suspicious_indicators: binaryResult.suspicious_indicators as any,
        ai_analysis_raw: binaryResult.ai_analysis || undefined,
        full_analysis_data: {
          metadata: binaryResult.metadata,
          strings_sample: binaryResult.strings_sample,
          imports: binaryResult.imports,
          exports: binaryResult.exports,
          secrets: binaryResult.secrets,
          ghidra_analysis: binaryResult.ghidra_analysis,
          ghidra_ai_summaries: binaryResult.ghidra_ai_summaries,
        },
      };
      await reverseEngineeringClient.saveReport(report);
      setSuccessMessage("Binary analysis report saved successfully!");
      loadSavedReports();
    } catch (e: any) {
      setError(`Failed to save report: ${e.message}`);
    } finally {
      setSavingReport(false);
    }
  };

  // Auto-save binary scan when complete
  const autoSaveBinaryResult = async (result: BinaryAnalysisResult, filename: string) => {
    try {
      const report: SaveREReportRequest = {
        analysis_type: 'binary',
        title: `Binary Analysis: ${result.filename}`,
        filename: result.filename,
        project_id: projectId,
        file_type: result.metadata.file_type,
        architecture: result.metadata.architecture,
        file_size: result.metadata.file_size,
        is_packed: result.metadata.is_packed,
        packer_name: result.metadata.packer_name || undefined,
        strings_count: result.strings_count,
        imports_count: (result.imports || []).length,
        exports_count: (result.exports || []).length,
        secrets_count: (result.secrets || []).length,
        suspicious_indicators: result.suspicious_indicators as any,
        ai_analysis_raw: result.ai_analysis || undefined,
        // AI-Generated Reports
        ai_functionality_report: result.ai_functionality_report || undefined,
        ai_security_report: result.ai_security_report || undefined,
        ai_architecture_diagram: result.ai_architecture_diagram || undefined,
        ai_attack_surface_map: result.ai_attack_surface_map || undefined,
        full_analysis_data: {
          metadata: result.metadata,
          strings_sample: result.strings_sample,
          imports: result.imports,
          exports: result.exports,
          secrets: result.secrets,
          ghidra_analysis: result.ghidra_analysis,
          ghidra_ai_summaries: result.ghidra_ai_summaries,
          vuln_hunt_result: result.vuln_hunt_result,
          obfuscation_analysis: result.obfuscation_analysis,
          attack_surface: result.attack_surface,
          pattern_scan_result: result.pattern_scan_result,
          cve_lookup_result: result.cve_lookup_result,
          verification_result: result.verification_result,
          is_legitimate_software: result.is_legitimate_software,
          legitimacy_indicators: result.legitimacy_indicators,
        },
      };
      await reverseEngineeringClient.saveReport(report);
      setBinaryAutoSaved(true);
      loadSavedReports();
    } catch (e: any) {
      console.error("Auto-save failed:", e);
      // Don't show error to user for auto-save, just log it
    }
  };

  const exportBinaryResult = async (format: "markdown" | "pdf" | "docx") => {
    if (!binaryResult) return;
    try {
      setExportingBinary(true);
      setBinaryExportAnchor(null);
      const blob = await reverseEngineeringClient.exportBinaryResult(binaryResult, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const ext = format === "markdown" ? "md" : format;
      const base = binaryResult.filename || "binary_report";
      const safeBase = base.replace(/[^a-zA-Z0-9-_]/g, "_").substring(0, 50);
      a.download = `binary_analysis_${safeBase}_${new Date().toISOString().split("T")[0]}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setSuccessMessage(`Report exported as ${format.toUpperCase()} successfully!`);
    } catch (e: any) {
      setError(`Failed to export report: ${e.message}`);
    } finally {
      setExportingBinary(false);
    }
  };

  const saveApkReport = async () => {
    if (!apkResult || !apkFile) return;
    try {
      setSavingReport(true);
      
      // Fetch source code for key classes if we have a JADX session
      let sourceCodeSamples: Array<{
        class_name: string;
        package_name: string;
        file_path: string;
        source_code: string;
        is_activity: boolean;
        is_service: boolean;
        line_count: number;
      }> = [];
      
      const sessionId = unifiedJadxSessionId || jadxResult?.output_directory;
      if (sessionId && jadxResult?.classes) {
        // Get source code for activities, services, and classes with security issues (up to 50 classes)
        const priorityClasses = jadxResult.classes
          .filter(c => c.is_activity || c.is_service || c.is_receiver || c.is_provider || c.security_issues_count > 0)
          .slice(0, 50);
        
        // Fetch source code in parallel (batches of 10)
        for (let i = 0; i < priorityClasses.length; i += 10) {
          const batch = priorityClasses.slice(i, i + 10);
          const results = await Promise.allSettled(
            batch.map(cls => 
              reverseEngineeringClient.getDecompiledSource(sessionId, cls.file_path)
            )
          );
          
          results.forEach((result, idx) => {
            if (result.status === 'fulfilled' && result.value.source_code) {
              const cls = batch[idx];
              sourceCodeSamples.push({
                class_name: cls.class_name,
                package_name: cls.package_name,
                file_path: cls.file_path,
                source_code: result.value.source_code,
                is_activity: cls.is_activity,
                is_service: cls.is_service,
                line_count: result.value.line_count || result.value.source_code.split('\n').length,
              });
            }
          });
        }
      }
      
      // Merge security issues from APK result with enhanced security findings
      let mergedSecurityIssues = [...(apkResult.security_issues || [])];
      if (enhancedSecurityResult?.combined_findings) {
        // Add enhanced security findings that aren't duplicates
        const existingTitles = new Set(mergedSecurityIssues.map((i: any) => i.title?.toLowerCase() || ''));
        for (const finding of enhancedSecurityResult.combined_findings) {
          if (!existingTitles.has(finding.title?.toLowerCase() || '')) {
            mergedSecurityIssues.push({
              type: finding.title,
              severity: finding.severity,
              description: finding.description,
              class: finding.affected_class || '',
              line: finding.line_number || 0,
              code_snippet: finding.code_snippet || '',
            } as any);
          }
        }
      }
      
      const report: SaveREReportRequest = {
        analysis_type: 'apk',
        title: `APK Analysis: ${apkResult.package_name || apkFile.name}`,
        filename: apkFile.name,
        project_id: projectId,
        package_name: apkResult.package_name,
        version_name: apkResult.version_name,
        min_sdk: apkResult.min_sdk,
        target_sdk: apkResult.target_sdk,
        secrets_count: apkResult.secrets.length,
        permissions: apkResult.permissions as any,
        security_issues: mergedSecurityIssues as any,
        ai_analysis_raw: apkResult.ai_analysis || undefined,
        full_analysis_data: {
          package_name: apkResult.package_name,
          version_name: apkResult.version_name,
          version_code: apkResult.version_code,
          permissions: apkResult.permissions,
          components: apkResult.components,
          urls: apkResult.urls,
          secrets: apkResult.secrets,
          native_libraries: apkResult.native_libraries,
          security_issues: mergedSecurityIssues,
          // Include enhanced security metadata
          enhanced_security_summary: enhancedSecurityResult ? {
            overall_risk: enhancedSecurityResult.overall_risk,
            executive_summary: enhancedSecurityResult.executive_summary,
            risk_summary: enhancedSecurityResult.risk_summary,
            pattern_findings_count: enhancedSecurityResult.pattern_findings.length,
            ai_findings_count: enhancedSecurityResult.ai_findings.length,
            cve_findings_count: enhancedSecurityResult.cve_findings.length,
            attack_chains: enhancedSecurityResult.attack_chains,
            recommendations: enhancedSecurityResult.recommendations,
            offensive_plan_summary: enhancedSecurityResult.offensive_plan_summary,
          } : undefined,
        } as any,
        // JADX Full Scan Data (Deep Analysis)
        jadx_total_classes: jadxResult?.total_classes,
        jadx_total_files: jadxResult?.total_files,
        jadx_output_directory: jadxResult?.output_directory,
        jadx_classes_sample: jadxResult?.classes?.slice(0, 100).map(c => ({
          class_name: c.class_name,
          package_name: c.package_name,
          is_activity: c.is_activity,
          is_service: c.is_service,
          security_issues_count: c.security_issues_count,
        })) as any,
        jadx_security_issues: jadxResult?.security_issues?.slice(0, 200) as any,
        jadx_source_tree: jadxResult?.source_tree as Record<string, unknown> || unifiedApkResult?.source_tree,
        jadx_source_code_samples: sourceCodeSamples.length > 0 ? sourceCodeSamples : undefined,
        // AI-Generated Reports (Deep Analysis)
        ai_functionality_report: aiFunctionalityReport || unifiedApkResult?.ai_functionality_report || undefined,
        ai_security_report: aiSecurityReport || unifiedApkResult?.ai_security_report || undefined,
        ai_privacy_report: aiPrivacyReport || undefined,
        ai_architecture_diagram: unifiedApkResult?.ai_architecture_diagram || undefined,
        ai_attack_surface_map: unifiedApkResult?.ai_attack_surface_map || undefined,
        ai_threat_model: aiThreatModel as any,
        ai_vuln_scan_result: enhancedSecurityResult ? {
          ...aiVulnScanResult,
          // Merge enhanced security into AI vuln scan result for export
          enhanced_security: {
            overall_risk: enhancedSecurityResult.overall_risk,
            executive_summary: enhancedSecurityResult.executive_summary,
            risk_summary: enhancedSecurityResult.risk_summary,
            combined_findings: enhancedSecurityResult.combined_findings,
            attack_chains: enhancedSecurityResult.attack_chains,
            recommendations: enhancedSecurityResult.recommendations,
            analysis_metadata: enhancedSecurityResult.analysis_metadata,
            offensive_plan_summary: enhancedSecurityResult.offensive_plan_summary,
          }
        } : aiVulnScanResult as any,
        ai_chat_history: aiChatHistory as any,
        // Dynamic Analysis / Frida Scripts
        dynamic_analysis: unifiedApkResult?.dynamic_analysis as any,
        // Decompiled Code Analysis Results
        decompiled_code_findings: unifiedApkResult?.decompiled_code_findings as any,
        decompiled_code_summary: unifiedApkResult?.decompiled_code_summary as any,
        // CVE Scan Results
        cve_scan_results: unifiedApkResult?.cve_scan_results as any,
        // Vulnerability-specific Frida Hooks
        vulnerability_frida_hooks: unifiedApkResult?.vulnerability_frida_hooks as any,
        // Sensitive Data Discovery
        sensitive_data_findings: unifiedApkResult?.sensitive_data_findings as any,
      } as any;
      await reverseEngineeringClient.saveReport(report);
      setSuccessMessage("APK analysis report saved successfully (including Full Scan data)!");
      loadSavedReports();
    } catch (e: any) {
      setError(`Failed to save report: ${e.message}`);
    } finally {
      setSavingReport(false);
    }
  };

  // Export unified APK scan result
  const exportUnifiedApkResult = async (format: "markdown" | "pdf" | "docx") => {
    if (!unifiedApkResult) return;
    try {
      setExportingUnified(true);
      setUnifiedExportAnchor(null);
      const blob = await reverseEngineeringClient.exportUnifiedApkScan(unifiedApkResult, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const ext = format === "markdown" ? "md" : format;
      a.download = `apk_analysis_${unifiedApkResult.package_name || "report"}_${new Date().toISOString().split("T")[0]}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setSuccessMessage(`Report exported as ${format.toUpperCase()} successfully!`);
    } catch (e: any) {
      setError(`Failed to export report: ${e.message}`);
    } finally {
      setExportingUnified(false);
    }
  };

  // Auto-save unified APK scan when complete
  const autoSaveUnifiedResult = async (result: UnifiedApkScanResult, filename: string) => {
    try {
      const report: SaveREReportRequest = {
        analysis_type: 'apk',
        title: `APK Analysis: ${result.package_name || filename}`,
        filename: filename,
        project_id: projectId,
        package_name: result.package_name,
        version_name: result.version_name,
        min_sdk: result.min_sdk,
        target_sdk: result.target_sdk,
        secrets_count: result.secrets.length,
        permissions: result.permissions as any,
        security_issues: result.security_issues as any,
        full_analysis_data: {
          package_name: result.package_name,
          version_name: result.version_name,
          version_code: result.version_code,
          permissions: result.permissions,
          components: result.components,
          urls: result.urls,
          secrets: result.secrets,
          native_libraries: result.native_libraries,
          security_issues: result.security_issues,
        },
        // JADX Full Scan Data
        jadx_total_classes: result.total_classes,
        jadx_total_files: result.total_files,
        jadx_classes_sample: result.classes_summary?.slice(0, 100).map(c => ({
          class_name: c.class_name,
          package_name: c.package_name,
          is_activity: c.is_activity,
          is_service: c.is_service,
          security_issues_count: c.security_issues_count,
        })) as any,
        jadx_security_issues: result.jadx_security_issues?.slice(0, 200) as any,
        // AI-Generated Reports
        ai_functionality_report: result.ai_functionality_report || undefined,
        ai_security_report: result.ai_security_report || undefined,
        ai_architecture_diagram: result.ai_architecture_diagram || undefined,
        ai_attack_surface_map: result.ai_attack_surface_map || undefined,
        // Dynamic Analysis / Frida Scripts
        dynamic_analysis: result.dynamic_analysis as any,
        // Decompiled Code Analysis Results
        decompiled_code_findings: result.decompiled_code_findings as any,
        decompiled_code_summary: result.decompiled_code_summary as any,
        // CVE Scan Results
        cve_scan_results: result.cve_scan_results as any,
        // Vulnerability-specific Frida Hooks
        vulnerability_frida_hooks: result.vulnerability_frida_hooks as any,
      };
      await reverseEngineeringClient.saveReport(report);
      setAutoSavedReport(true);
      loadSavedReports();
    } catch (e: any) {
      console.error("Auto-save failed:", e);
      // Don't show error to user for auto-save, just log it
    }
  };

  const saveDockerReport = async () => {
    if (!dockerResult) return;
    try {
      setSavingReport(true);

      // Calculate risk score for the report
      let riskScore = 0;
      dockerResult.security_issues.forEach((issue) => {
        switch (issue.severity?.toLowerCase()) {
          case "critical": riskScore += 40; break;
          case "high": riskScore += 25; break;
          case "medium": riskScore += 10; break;
          case "low": riskScore += 3; break;
        }
      });
      dockerResult.secrets.forEach((s) => {
        switch (s.severity?.toLowerCase()) {
          case "critical": riskScore += 35; break;
          case "high": riskScore += 20; break;
          default: riskScore += 10;
        }
      });
      riskScore = Math.min(100, riskScore);

      const getRiskLevel = (score: number) => {
        if (score >= 70) return "critical";
        if (score >= 40) return "high";
        if (score >= 20) return "medium";
        return "low";
      };

      const report: SaveREReportRequest = {
        analysis_type: 'docker',
        title: `Docker Inspector: ${dockerResult.image_name}`,
        filename: dockerResult.image_name,
        project_id: projectId,
        risk_level: getRiskLevel(riskScore),
        risk_score: riskScore,
        image_name: dockerResult.image_name,
        image_id: dockerResult.image_id,
        total_layers: dockerResult.total_layers,
        base_image: dockerResult.base_image || undefined,
        secrets_count: dockerResult.secrets.length,
        security_issues: dockerResult.security_issues as any,
        ai_analysis_raw: dockerResult.ai_analysis || undefined,
        full_analysis_data: {
          image_name: dockerResult.image_name,
          image_id: dockerResult.image_id,
          total_layers: dockerResult.total_layers,
          total_size: dockerResult.total_size,
          total_size_human: dockerResult.total_size_human,
          base_image: dockerResult.base_image,
          layers: dockerResult.layers,
          secrets: dockerResult.secrets,
          security_issues: dockerResult.security_issues,
          risk_score: riskScore,
          risk_level: getRiskLevel(riskScore),
        },
      };
      await reverseEngineeringClient.saveReport(report);
      setSuccessMessage("Docker analysis report saved successfully!");
      loadSavedReports();
    } catch (e: any) {
      setError(`Failed to save report: ${e.message}`);
    } finally {
      setSavingReport(false);
    }
  };

  const deleteReport = async (reportId: number) => {
    if (!confirm("Are you sure you want to delete this report?")) return;
    try {
      await reverseEngineeringClient.deleteReport(reportId);
      setSuccessMessage("Report deleted successfully!");
      loadSavedReports();
    } catch (e: any) {
      setError(`Failed to delete report: ${e.message}`);
    }
  };

  // Export a saved report to various formats
  const exportSavedReport = async (reportId: number, format: "markdown" | "pdf" | "docx") => {
    try {
      setSuccessMessage(`Exporting report to ${format.toUpperCase()}...`);
      const blob = await reverseEngineeringClient.exportSavedReport(reportId, format);
      
      // Find the report to get its title for the filename
      const report = savedReports.find(r => r.id === reportId);
      const baseName = report?.title || `report_${reportId}`;
      const safeBaseName = baseName.replace(/[^a-zA-Z0-9-_]/g, '_').substring(0, 50);
      
      // Determine file extension
      const ext = format === "markdown" ? "md" : format;
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${safeBaseName}_full_report.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      
      setSuccessMessage(`Report exported to ${format.toUpperCase()} successfully!`);
    } catch (e: any) {
      setError(`Failed to export report: ${e.message}`);
    }
  };

  // View a saved report - loads full data and switches to appropriate tab
  const viewSavedReport = async (reportId: number) => {
    try {
      setLoadingReportView(true);
      setError(null);
      setViewingReportId(reportId);
      
      const detail = await reverseEngineeringClient.getReport(reportId);
      
      // Populate the appropriate result state based on analysis type
      if (detail.analysis_type === 'binary') {
        // Reconstruct binary result from saved data
        const fullData = detail.full_analysis_data || {};
        setBinaryResult({
          filename: detail.filename || 'Unknown',
          metadata: fullData.metadata || {
            file_type: detail.file_type || 'Unknown',
            architecture: detail.architecture || 'Unknown',
            file_size: detail.file_size || 0,
            is_packed: detail.is_packed || 'unknown',
            packer_name: detail.packer_name,
          },
          strings_count: detail.strings_count || 0,
          strings_sample: fullData.strings_sample || [],
          imports: fullData.imports || [],
          exports: fullData.exports || [],
          secrets: fullData.secrets || [],
          suspicious_indicators: detail.suspicious_indicators || [],
          ai_analysis: detail.ai_analysis_raw,
          ghidra_analysis: fullData.ghidra_analysis || undefined,
          ghidra_ai_summaries: fullData.ghidra_ai_summaries || undefined,
        } as BinaryAnalysisResult);
        setBinaryFile(null); // No file, just viewing
        setActiveTab(0); // Binary tab
        
      } else if (detail.analysis_type === 'apk') {
        // Reconstruct unified APK result from saved data
        const fullData = detail.full_analysis_data || {};
        const jadxData = (detail.jadx_data || {}) as Record<string, unknown>;
        
        // Reconstruct enhanced security result if it was saved
        let savedEnhancedSecurity: EnhancedSecurityResult | undefined;
        const aiVulnData = (detail as any).ai_vuln_scan_result;
        const enhancedSecurityData = aiVulnData?.enhanced_security || fullData.enhanced_security_summary;
        
        if (enhancedSecurityData) {
          savedEnhancedSecurity = {
            overall_risk: enhancedSecurityData.overall_risk || 'none',
            executive_summary: enhancedSecurityData.executive_summary || '',
            risk_summary: enhancedSecurityData.risk_summary || { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            pattern_findings: aiVulnData?.pattern_findings || [],
            ai_findings: aiVulnData?.ai_findings || [],
            cve_findings: aiVulnData?.cve_findings || [],
            combined_findings: enhancedSecurityData.combined_findings || [],
            attack_chains: enhancedSecurityData.attack_chains || [],
            recommendations: enhancedSecurityData.recommendations || [],
            analysis_metadata: enhancedSecurityData.analysis_metadata || { scan_duration: 0, patterns_scanned: 0, ai_enabled: false, cve_enabled: false },
            offensive_plan_summary: enhancedSecurityData.offensive_plan_summary || null,
          } as EnhancedSecurityResult;
        }
        
        // Build the unified result structure matching UnifiedApkScanResult interface
        const unifiedResult: UnifiedApkScanResult = {
          scan_id: `saved-${detail.id}`,
          filename: detail.filename || 'Unknown',
          package_name: detail.package_name || 'Unknown',
          version_name: detail.version_name || '',
          version_code: (fullData.version_code as number) || 0,
          min_sdk: detail.min_sdk || 0,
          target_sdk: detail.target_sdk || 0,
          permissions: (detail.permissions || []) as any[],
          dangerous_permissions_count: (detail.permissions || []).filter((p: any) => p.is_dangerous).length,
          components: (fullData.components || []) as any[],
          secrets: (fullData.secrets || []) as any[],
          urls: (fullData.urls || []) as string[],
          native_libraries: (fullData.native_libraries || []) as string[],
          security_issues: (detail.security_issues || []) as any[],
          // JADX decompilation results
          jadx_session_id: (fullData.jadx_session_id as string) || undefined,
          total_classes: detail.jadx_total_classes || 0,
          total_files: detail.jadx_total_files || 0,
          classes_summary: (jadxData.classes_sample || []) as any[],
          source_tree: (jadxData.source_tree as Record<string, unknown>) || (fullData.source_tree as Record<string, unknown>) || undefined,
          jadx_security_issues: (jadxData.security_issues || []) as any[],
          decompilation_time: (fullData.decompilation_time as number) || 0,
          // AI Analysis Results
          ai_functionality_report: detail.ai_functionality_report,
          ai_security_report: detail.ai_security_report,
          ai_architecture_diagram: detail.ai_architecture_diagram,
          ai_attack_surface_map: detail.ai_attack_surface_map,
          // Pre-loaded enhanced security data from saved report
          saved_enhanced_security: savedEnhancedSecurity,
          // Saved source code samples for browsing
          saved_source_code_samples: jadxData.source_code_samples as any[] || undefined,
          // Dynamic Analysis / Frida Scripts
          dynamic_analysis: (detail as any).dynamic_analysis || undefined,
          // Decompiled Code Analysis Results
          decompiled_code_findings: (detail as any).decompiled_code_findings || undefined,
          decompiled_code_summary: (detail as any).decompiled_code_summary || undefined,
          // CVE Scan Results
          cve_scan_results: (detail as any).cve_scan_results || undefined,
          // Vulnerability-specific Frida Hooks
          vulnerability_frida_hooks: (detail as any).vulnerability_frida_hooks || undefined,
          // Sensitive Data Discovery
          sensitive_data_findings: (detail as any).sensitive_data_findings || undefined,
          // Metadata
          scan_time: (fullData.scan_time as number) || 0,
          file_size: (fullData.file_size as number) || 0,
        };
        
        setUnifiedApkResult(unifiedResult);
        setApkFile(null); // No file, just viewing
        setActiveTab(2); // APK tab
        
      } else if (detail.analysis_type === 'docker') {
        // Reconstruct Docker result
        const fullData = detail.full_analysis_data || {};
        setDockerResult({
          image_name: detail.image_name || 'Unknown',
          image_id: detail.image_id || '',
          created: (fullData.created as string) || '',
          size: (fullData.size as number) || 0,
          total_size: (fullData.total_size as number) || (fullData.size as number) || 0,
          total_size_human: (fullData.total_size_human as string) || '',
          total_layers: detail.total_layers || 0,
          layers: (fullData.layers || []) as any[],
          base_image: detail.base_image,
          packages: (fullData.packages || []) as any[],
          total_packages: (fullData.total_packages as number) || 0,
          env_vars: (fullData.env_vars || []) as any[],
          exposed_ports: (fullData.exposed_ports || []) as any[],
          entrypoint: fullData.entrypoint as any,
          cmd: fullData.cmd as any,
          security_issues: (fullData.security_issues || []) as any[],
          secrets_found: (fullData.secrets_found || []) as any[],
          secrets: (fullData.secrets || fullData.secrets_found || []) as any[],
          deleted_files: (fullData.deleted_files || []) as any[],
          ai_analysis: detail.ai_analysis_raw,
        } as DockerAnalysisResult);
        setActiveTab(3); // Docker tab
      }
      
      setSuccessMessage(`Loaded report: ${detail.title}`);
      
    } catch (e: any) {
      setError(`Failed to load report: ${e.message}`);
      setViewingReportId(null);
    } finally {
      setLoadingReportView(false);
    }
  };

  // Clear viewing state and go back to fresh analysis
  const clearViewingReport = () => {
    setViewingReportId(null);
    setBinaryResult(null);
    setBinaryFile(null);
    setUnifiedApkResult(null);
    setApkFile(null);
    setDockerResult(null);
    setSelectedImage("");
  };

  const startBinaryScan = useCallback(() => {
    if (!binaryFile) return;
    setBinaryLoading(true);
    setBinaryResult(null);
    setBinaryScanProgress(null);
    setVulnHuntResult(null); // Clear any standalone vuln hunt results
    setBinaryAutoSaved(false); // Reset auto-save flag for new scan
    setError(null);

    const controller = reverseEngineeringClient.runUnifiedBinaryScan(
      binaryFile,
      {
        includeAi: binaryIncludeAi,
        includeGhidra,
        includeGhidraAi,
        ghidraMaxFunctions,
        ghidraDecompLimit,
        ghidraAiMaxFunctions,
        extendedGhidra,
        includeVulnHunt: includeVulnHunt && includeGhidra, // Requires Ghidra
        vulnHuntMaxPasses,
        vulnHuntMaxTargets,
      },
      (progress) => {
        setBinaryScanProgress(progress);
      },
      (result) => {
        setBinaryResult(result);
        // Extract vuln hunt result from the main result
        if (result.vuln_hunt_result) {
          setVulnHuntResult(result.vuln_hunt_result);
        }
        setBinaryLoading(false);
        // Auto-save the result
        autoSaveBinaryResult(result, binaryFile.name);
      },
      (err) => {
        setError(err);
        setBinaryLoading(false);
      },
      () => {
        setBinaryLoading(false);
      }
    );

    binaryAbortRef.current = controller;
  }, [
    binaryFile,
    binaryIncludeAi,
    includeGhidra,
    includeGhidraAi,
    ghidraMaxFunctions,
    ghidraDecompLimit,
    ghidraAiMaxFunctions,
    extendedGhidra,
    includeVulnHunt,
    vulnHuntMaxPasses,
    vulnHuntMaxTargets,
  ]);

  const cancelBinaryScan = useCallback(() => {
    binaryAbortRef.current?.abort();
    setBinaryLoading(false);
    setBinaryScanProgress(null);
  }, []);

  const analyzeApk = async () => {
    if (!apkFile) return;
    try {
      setApkLoading(true);
      setError(null);
      const result = await reverseEngineeringClient.analyzeApk(apkFile, true);
      setApkResult(result);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setApkLoading(false);
    }
  };

  const analyzeDocker = async () => {
    if (!selectedImage) return;
    try {
      setDockerLoading(true);
      setError(null);
      const result = await reverseEngineeringClient.analyzeDockerImage(selectedImage, true);
      setDockerResult(result);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setDockerLoading(false);
    }
  };

  return (
    <LearnPageLayout pageTitle="Reverse Engineering Hub" pageContext={pageContext}>
    <>
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {/* Back to Projects Button */}
      <Button
        component={Link}
        to="/"
        startIcon={<HubIcon />}
        sx={{ mb: 2 }}
      >
        Back to Projects
      </Button>

      {/* Breadcrumbs */}
      <Breadcrumbs sx={{ mb: 3 }}>
        <MuiLink
          component={Link}
          to="/"
          underline="hover"
          sx={{ display: "flex", alignItems: "center", gap: 0.5 }}
        >
          <HomeIcon fontSize="small" />
          Home
        </MuiLink>
        <MuiLink
          component={Link}
          to="/learn"
          underline="hover"
          sx={{ display: "flex", alignItems: "center", gap: 0.5 }}
        >
          Learning Hub
        </MuiLink>
        <Typography color="text.primary" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
          <BinaryIcon fontSize="small" />
          Reverse Engineering Hub
        </Typography>
      </Breadcrumbs>

      {/* Header */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.1)} 100%)`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <ShieldIcon sx={{ fontSize: 48, color: theme.palette.primary.main }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              Reverse Engineering Hub
              {projectName && (
                <Chip
                  label={`Project: ${projectName}`}
                  color="primary"
                  size="small"
                  sx={{ ml: 2, verticalAlign: "middle" }}
                />
              )}
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Analyze binaries, APKs, and Docker images for secrets and security issues
              {projectId && " • Reports will be saved to this project"}
            </Typography>
          </Box>
        </Box>

        {/* Status */}
        {loading && <LinearProgress sx={{ mt: 2 }} />}
        {status && (
          <Box sx={{ mt: 2, display: "flex", gap: 2, flexWrap: "wrap" }}>
            <Chip
              icon={<BinaryIcon />}
              label="Binary Analysis"
              color={status.binary_analysis ? "success" : "default"}
              variant={status.binary_analysis ? "filled" : "outlined"}
            />
            <Chip
              icon={<ApkIcon />}
              label="APK Analysis"
              color={status.apk_analysis ? "success" : "default"}
              variant={status.apk_analysis ? "filled" : "outlined"}
            />
            <Chip
              icon={<CodeIcon />}
              label="Ghidra Decompilation"
              color={status.ghidra_available ? "success" : "default"}
              variant={status.ghidra_available ? "filled" : "outlined"}
            />
            <Chip
              icon={<DockerIcon />}
              label="Docker Inspector"
              color={status.docker_analysis ? "success" : "default"}
              variant={status.docker_analysis ? "filled" : "outlined"}
            />
            {/* AI Analysis is always enabled for best results */}
            <Chip
              icon={<AiIcon />}
              label="AI Analysis Enabled"
              color="success"
              variant="filled"
              size="small"
            />
          </Box>
        )}
      </Paper>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Success Alert */}
      {successMessage && (
        <Alert severity="success" onClose={() => setSuccessMessage(null)} sx={{ mb: 3 }}>
          {successMessage}
        </Alert>
      )}

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={activeTab}
          onChange={(_, v) => setActiveTab(v)}
          variant="fullWidth"
          sx={{
            borderBottom: 1,
            borderColor: "divider",
            "& .MuiTab-root": { py: 2 },
          }}
        >
          <Tab
            icon={<BinaryIcon />}
            label="Binary Analyzer"
            iconPosition="start"
          />
          <Tab
            icon={<ApkIcon />}
            label="APK Analyzer"
            iconPosition="start"
          />
          <Tab
            icon={<DockerIcon />}
            label="Docker Inspector"
            iconPosition="start"
            disabled={!status?.docker_available}
          />
          <Tab
            icon={<HistoryIcon />}
            label={`Saved Reports (${savedReports.length})`}
            iconPosition="start"
          />
        </Tabs>
      </Paper>

        {/* Viewing Saved Report Banner */}
        {viewingReportId && (
          <Alert 
            severity="info" 
            sx={{ mb: 2 }}
            action={
              <Button 
                color="inherit" 
                size="small" 
                onClick={clearViewingReport}
                startIcon={<RefreshIcon />}
              >
                New Analysis
              </Button>
            }
          >
            <Typography variant="body2">
              <strong>Viewing saved report:</strong> {savedReports.find(r => r.id === viewingReportId)?.title || 'Unknown'}
            </Typography>
          </Alert>
        )}

        {/* Binary Tab */}
        <TabPanel value={activeTab} index={0}>
          <Alert 
            severity="info" 
            sx={{ mb: 3, bgcolor: alpha("#f97316", 0.1) }}
            action={
              <Button 
                component={Link} 
                to="/learn/binary-analysis" 
                size="small" 
                startIcon={<SchoolIcon />}
                sx={{ color: "#f97316" }}
              >
                Learning Guide
              </Button>
            }
          >
            <Typography variant="body2">
              <strong>New to binary analysis?</strong> Check out our comprehensive guide covering PE/ELF formats, vulnerability types, and VRAgent's AI-powered tools.
            </Typography>
          </Alert>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <FileDropZone
                accept=".exe,.dll,.so,.elf,.bin,.o,.dylib"
                onFileSelect={(f) => {
                  setBinaryFile(f);
                  setBinaryResult(null);
                  setBinaryScanProgress(null);
                }}
                label="Upload Binary"
                description="EXE, DLL, ELF, SO files up to 500MB"
                icon={<BinaryIcon sx={{ fontSize: 48 }} />}
                disabled={binaryLoading}
              />
              {binaryFile && (
                <Box sx={{ mt: 2 }}>
                  <Alert severity="info">
                    Selected: <strong>{binaryFile.name}</strong> ({(binaryFile.size / 1024).toFixed(1)} KB)
                  </Alert>
                  <Button
                    variant="contained"
                    fullWidth
                    sx={{ mt: 2 }}
                    onClick={startBinaryScan}
                    disabled={binaryLoading}
                    startIcon={binaryLoading ? <CircularProgress size={20} /> : <SecurityIcon />}
                  >
                    {binaryLoading ? "Analyzing..." : "Analyze Binary"}
                  </Button>
                </Box>
              )}

              <Paper sx={{ p: 2, mt: 3 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Analysis Options
                </Typography>
                {!status?.ghidra_available && (
                  <Alert severity="warning" sx={{ mb: 2 }}>
                    Ghidra not detected. Configure `GHIDRA_HOME` to enable decompilation.
                  </Alert>
                )}
                <FormGroup>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={binaryIncludeAi}
                        onChange={(e) => setBinaryIncludeAi(e.target.checked)}
                        disabled={binaryLoading}
                      />
                    }
                    label="Gemini security summary"
                  />
                  <FormControlLabel
                    control={
                      <Switch
                        checked={includeGhidra}
                        onChange={(e) => {
                          const enabled = e.target.checked;
                          setIncludeGhidra(enabled);
                          if (!enabled) {
                            setIncludeGhidraAi(false);
                          }
                        }}
                        disabled={binaryLoading || !status?.ghidra_available}
                      />
                    }
                    label="Ghidra decompilation"
                  />
                  <FormControlLabel
                    control={
                      <Switch
                        checked={includeGhidraAi}
                        onChange={(e) => setIncludeGhidraAi(e.target.checked)}
                        disabled={binaryLoading || !includeGhidra}
                      />
                    }
                    label="Gemini function summaries"
                  />
                  <FormControlLabel
                    control={
                      <Switch
                        checked={includeVulnHunt}
                        onChange={(e) => {
                          setIncludeVulnHunt(e.target.checked);
                          if (e.target.checked) {
                            setVulnHuntExpanded(true);
                          }
                        }}
                        disabled={binaryLoading || !includeGhidra || !status?.ghidra_available}
                      />
                    }
                    label={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                        AI Vulnerability Hunt
                        <Chip label="Multi-Pass" size="small" color="error" variant="outlined" sx={{ fontSize: '0.6rem', height: 18 }} />
                      </Box>
                    }
                  />
                </FormGroup>

                <Divider sx={{ my: 2 }} />

                <Typography variant="caption" color="text.secondary">
                  Ghidra export limits
                </Typography>
                <FormControlLabel
                  sx={{ mt: 1 }}
                  control={
                    <Switch
                      checked={extendedGhidra}
                      onChange={(e) => setExtendedGhidra(e.target.checked)}
                      disabled={binaryLoading || !includeGhidra}
                      color="secondary"
                    />
                  }
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <Typography variant="body2">Extended scan (2x coverage)</Typography>
                      <Chip label="Deep" size="small" color="secondary" variant="outlined" sx={{ fontSize: '0.6rem', height: 18 }} />
                    </Box>
                  }
                />
                <Box sx={{ mt: 1 }}>
                  <Typography variant="body2">
                    Max functions: {extendedGhidra ? ghidraMaxFunctions * 2 : ghidraMaxFunctions}
                    {extendedGhidra && <Chip label="2x" size="small" color="secondary" sx={{ ml: 1, height: 16, fontSize: '0.6rem' }} />}
                  </Typography>
                  <Slider
                    value={ghidraMaxFunctions}
                    onChange={(_, value) => setGhidraMaxFunctions(value as number)}
                    min={100}
                    max={1000}
                    step={50}
                    disabled={binaryLoading || !includeGhidra}
                  />
                </Box>
                <Box sx={{ mt: 1 }}>
                  <Typography variant="body2">
                    Decompile limit: {extendedGhidra ? ghidraDecompLimit * 2 : ghidraDecompLimit} chars
                    {extendedGhidra && <Chip label="2x" size="small" color="secondary" sx={{ ml: 1, height: 16, fontSize: '0.6rem' }} />}
                  </Typography>
                  <Slider
                    value={ghidraDecompLimit}
                    onChange={(_, value) => setGhidraDecompLimit(value as number)}
                    min={2000}
                    max={20000}
                    step={1000}
                    disabled={binaryLoading || !includeGhidra}
                  />
                </Box>
                <Box sx={{ mt: 1 }}>
                  <Typography variant="body2">AI function summaries: {ghidraAiMaxFunctions}</Typography>
                  <Slider
                    value={ghidraAiMaxFunctions}
                    onChange={(_, value) => setGhidraAiMaxFunctions(value as number)}
                    min={5}
                    max={50}
                    step={5}
                    disabled={binaryLoading || !includeGhidraAi}
                  />
                </Box>
              </Paper>

              {/* Deep Vulnerability Hunt Settings - Integrated into main scan */}
              {includeVulnHunt && (
                <Accordion 
                  expanded={vulnHuntExpanded} 
                  onChange={(_, expanded) => setVulnHuntExpanded(expanded)}
                  sx={{ mt: 2, border: '1px solid', borderColor: 'error.main' }}
                >
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <BugReportIcon color="error" />
                      <Typography variant="subtitle2">Vulnerability Hunt Settings</Typography>
                      <Chip 
                        label="Enabled" 
                        size="small" 
                        color="error"
                        sx={{ fontSize: '0.65rem' }} 
                      />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Alert severity="info" sx={{ mb: 2 }}>
                      Multi-pass AI vulnerability hunting will run automatically as part of the scan after Ghidra decompilation.
                    </Alert>
                    
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="caption" color="text.secondary">
                        Hunting Passes: {vulnHuntMaxPasses}
                      </Typography>
                      <Slider
                        value={vulnHuntMaxPasses}
                        onChange={(_, value) => setVulnHuntMaxPasses(value as number)}
                        min={1}
                        max={5}
                        step={1}
                        disabled={binaryLoading}
                        marks
                      />
                      <Typography variant="caption" color="text.secondary">
                        More passes = deeper analysis but longer scan time
                      </Typography>
                    </Box>
                    
                    <Box>
                      <Typography variant="caption" color="text.secondary">
                        Targets per Pass: {vulnHuntMaxTargets}
                      </Typography>
                      <Slider
                        value={vulnHuntMaxTargets}
                        onChange={(_, value) => setVulnHuntMaxTargets(value as number)}
                        min={5}
                        max={30}
                        step={5}
                        disabled={binaryLoading}
                      />
                      <Typography variant="caption" color="text.secondary">
                        More targets = broader coverage but longer scan time
                      </Typography>
                    </Box>
                  </AccordionDetails>
                </Accordion>
              )}
            </Grid>
            <Grid item xs={12} md={8}>
              {binaryLoading && binaryScanProgress && (
                <Paper sx={{ p: 3 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
                    <Box>
                      <Typography variant="h6">
                        Analyzing: {binaryFile?.name}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {binaryScanProgress.message}
                      </Typography>
                    </Box>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Typography variant="h4" color="primary">
                        {binaryScanProgress.overall_progress}%
                      </Typography>
                      <Button
                        variant="outlined"
                        color="error"
                        size="small"
                        onClick={cancelBinaryScan}
                        startIcon={<StopIcon />}
                      >
                        Cancel
                      </Button>
                    </Box>
                  </Box>

                  <LinearProgress
                    variant="determinate"
                    value={binaryScanProgress.overall_progress}
                    sx={{ height: 8, borderRadius: 4, mb: 3 }}
                  />

                  <Stepper
                    activeStep={binaryScanProgress.phases.findIndex((p) => p.status === "in_progress")}
                    orientation="vertical"
                  >
                    {binaryScanProgress.phases.map((phase) => (
                      <Step key={phase.id} completed={phase.status === "completed"}>
                        <StepLabel
                          error={phase.status === "error"}
                          StepIconComponent={() => (
                            <Box
                              sx={{
                                width: 36,
                                height: 36,
                                borderRadius: "50%",
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                bgcolor: phase.status === "completed"
                                  ? theme.palette.success.main
                                  : phase.status === "in_progress"
                                  ? theme.palette.primary.main
                                  : phase.status === "error"
                                  ? theme.palette.error.main
                                  : alpha(theme.palette.action.disabled, 0.3),
                                color: phase.status === "pending" ? "text.disabled" : "white",
                              }}
                            >
                              {phase.status === "completed" ? (
                                <CheckIcon sx={{ fontSize: 20 }} />
                              ) : phase.status === "in_progress" ? (
                                <CircularProgress size={20} color="inherit" />
                              ) : phase.status === "error" ? (
                                <ErrorIcon sx={{ fontSize: 20 }} />
                              ) : BINARY_SCAN_PHASE_ICONS[phase.id] ? (
                                React.cloneElement(BINARY_SCAN_PHASE_ICONS[phase.id] as React.ReactElement, { sx: { fontSize: 18 } })
                              ) : (
                                <SecurityIcon sx={{ fontSize: 18 }} />
                              )}
                            </Box>
                          )}
                        >
                          <Typography fontWeight={phase.status === "in_progress" ? 700 : 500}>
                            {BINARY_SCAN_PHASE_LABELS[phase.id] || phase.label}
                          </Typography>
                        </StepLabel>
                        <StepContent>
                          <Typography variant="body2" color="text.secondary">
                            {phase.description}
                          </Typography>
                          {phase.status === "in_progress" && (
                            <>
                              <LinearProgress 
                                variant={phase.progress > 0 ? "determinate" : "indeterminate"}
                                value={phase.progress || 0}
                                sx={{ mt: 1.5, borderRadius: 1, height: 6 }} 
                              />
                              {phase.details && (
                                <Typography 
                                  variant="caption" 
                                  color="info.main" 
                                  sx={{ 
                                    mt: 0.5, 
                                    display: "block",
                                    fontStyle: "italic",
                                    animation: "pulse 2s infinite",
                                    "@keyframes pulse": {
                                      "0%, 100%": { opacity: 1 },
                                      "50%": { opacity: 0.6 },
                                    }
                                  }}
                                >
                                  ⏳ {phase.details}
                                </Typography>
                              )}
                            </>
                          )}
                          {phase.status === "completed" && phase.details && (
                            <Typography variant="caption" color="success.main" sx={{ mt: 0.5, display: "block" }}>
                              ✓ {phase.details}
                            </Typography>
                          )}
                          {phase.status === "error" && phase.details && (
                            <Typography variant="caption" color="error" sx={{ mt: 0.5, display: "block" }}>
                              ✗ {phase.details}
                            </Typography>
                          )}
                        </StepContent>
                      </Step>
                    ))}
                  </Stepper>
                  
                  {/* Time Estimates */}
                  <Box sx={{ mt: 3, p: 2, bgcolor: alpha(theme.palette.primary.main, 0.1), borderRadius: 1 }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 1 }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <AccessTimeIcon sx={{ fontSize: 18, color: "text.secondary" }} />
                        <Typography variant="body2" color="text.secondary">
                          {binaryScanProgress.elapsed_seconds !== undefined ? (
                            <>Elapsed: <strong>{formatTimeSeconds(binaryScanProgress.elapsed_seconds)}</strong></>
                          ) : (
                            <>Elapsed: calculating...</>
                          )}
                        </Typography>
                      </Box>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Typography variant="body2" color="text.secondary">
                          {binaryScanProgress.estimated_remaining_seconds !== undefined ? (
                            <>Remaining: <strong>{formatTimeSeconds(binaryScanProgress.estimated_remaining_seconds)}</strong></>
                          ) : (
                            <>Remaining: estimating...</>
                          )}
                        </Typography>
                      </Box>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Typography variant="body2" color="text.secondary">
                          {binaryScanProgress.estimated_total_seconds !== undefined ? (
                            <>Total: ~{formatTimeSeconds(binaryScanProgress.estimated_total_seconds)}</>
                          ) : (
                            <>Total: ~2-4 minutes</>
                          )}
                        </Typography>
                      </Box>
                    </Box>
                    {/* Parallel scan indicator */}
                    {(binaryScanProgress.current_phase === "pattern_scan" || 
                      binaryScanProgress.current_phase === "cve_lookup" ||
                      binaryScanProgress.current_phase === "sensitive_scan") && (
                      <Typography variant="caption" color="info.main" sx={{ mt: 1, display: "block" }}>
                        ⚡ Running parallel scans (pattern + CVE + sensitive) for faster results
                      </Typography>
                    )}
                  </Box>
                </Paper>
              )}
              {binaryLoading && !binaryScanProgress && (
                <Paper sx={{ p: 4, textAlign: "center" }}>
                  <CircularProgress size={60} sx={{ mb: 2 }} />
                  <Typography variant="h6" gutterBottom>
                    Starting binary analysis...
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Preparing upload and analysis environment
                  </Typography>
                  <Button
                    variant="outlined"
                    color="error"
                    size="small"
                    onClick={cancelBinaryScan}
                    startIcon={<StopIcon />}
                    sx={{ mt: 2 }}
                  >
                    Cancel
                  </Button>
                </Paper>
              )}
              {binaryResult && !binaryLoading && (
                <>
                  <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 2, gap: 1, flexWrap: "wrap" }}>
                    <Button
                      variant="outlined"
                      color="primary"
                      startIcon={exportingBinary ? <CircularProgress size={20} /> : <DownloadIcon />}
                      onClick={(e) => setBinaryExportAnchor(e.currentTarget)}
                      disabled={exportingBinary}
                    >
                      Export
                    </Button>
                    <Menu
                      anchorEl={binaryExportAnchor}
                      open={Boolean(binaryExportAnchor)}
                      onClose={() => setBinaryExportAnchor(null)}
                    >
                      <MenuItem onClick={() => exportBinaryResult("markdown")}>
                        Export as Markdown
                      </MenuItem>
                      <MenuItem onClick={() => exportBinaryResult("pdf")}>
                        Export as PDF
                      </MenuItem>
                      <MenuItem onClick={() => exportBinaryResult("docx")}>
                        Export as Word
                      </MenuItem>
                    </Menu>
                    <Button
                      variant="contained"
                      color="success"
                      startIcon={savingReport ? <CircularProgress size={20} /> : <SaveIcon />}
                      onClick={saveBinaryReport}
                      disabled={savingReport}
                    >
                      {savingReport ? "Saving..." : "Save Report"}
                    </Button>
                    {binaryAutoSaved && (
                      <Chip 
                        icon={<CheckIcon />} 
                        label="Auto-saved" 
                        color="success" 
                        size="small" 
                        variant="outlined"
                      />
                    )}
                  </Box>
                  
                  {/* NEW: Unified Binary Results with APK-like tabs */}
                  <UnifiedBinaryResults result={binaryResult} onSaveReport={saveBinaryReport} />
                  
                  {/* Entropy Visualization - Compact Version */}
                  <Accordion sx={{ mt: 3 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        📊 Entropy Analysis
                        <Chip label="Advanced" size="small" variant="outlined" />
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Alert severity="info" sx={{ mb: 2 }}>
                        <strong>What is entropy?</strong> A measure of randomness in data (0-8 scale). 
                        High entropy (&gt;7) suggests encrypted or compressed content.
                        Packed malware often shows high entropy. Normal code typically shows 4-6 entropy.
                      </Alert>
                      <Box sx={{ maxHeight: 400, overflow: "auto" }}>
                        <EntropyVisualizer file={binaryFile} />
                      </Box>
                    </AccordionDetails>
                  </Accordion>

                  {/* Deep Vulnerability Hunt Results - from integrated scan */}
                  {/* Hide or warn about false positives for legitimate software */}
                  {vulnHuntResult && !binaryResult?.is_legitimate_software && (
                    <Paper sx={{ p: 3, mt: 4, border: '2px solid', borderColor: 'error.main' }}>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <BugReportIcon color="error" />
                          <Typography variant="h6">Vulnerability Hunt Results</Typography>
                        </Box>
                        <Box sx={{ display: "flex", gap: 1 }}>
                          <Chip 
                            label={`Risk Score: ${vulnHuntResult.risk_score}/100`}
                            color={vulnHuntResult.risk_score >= 70 ? "error" : vulnHuntResult.risk_score >= 40 ? "warning" : "success"}
                            size="small"
                          />
                          <Button
                            size="small"
                            variant="outlined"
                            onClick={() => setVulnHuntResult(null)}
                          >
                            Clear
                          </Button>
                        </Box>
                      </Box>

                      {/* Executive Summary */}
                      <Alert severity={vulnHuntResult.risk_score >= 70 ? "error" : vulnHuntResult.risk_score >= 40 ? "warning" : "info"} sx={{ mb: 3 }}>
                        <Typography variant="body2">{vulnHuntResult.executive_summary}</Typography>
                      </Alert>

                      {/* Stats Grid */}
                      <Grid container spacing={2} sx={{ mb: 3 }}>
                        <Grid item xs={6} sm={3}>
                          <Paper sx={{ p: 2, textAlign: 'center', bgcolor: alpha(theme.palette.error.main, 0.1) }}>
                            <Typography variant="h4" color="error.main">{vulnHuntResult.vulnerabilities.length}</Typography>
                            <Typography variant="caption">Vulnerabilities</Typography>
                          </Paper>
                        </Grid>
                        <Grid item xs={6} sm={3}>
                          <Paper sx={{ p: 2, textAlign: 'center', bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                            <Typography variant="h4" color="primary">{vulnHuntResult.passes_completed}</Typography>
                            <Typography variant="caption">Passes</Typography>
                          </Paper>
                        </Grid>
                        <Grid item xs={6} sm={3}>
                          <Paper sx={{ p: 2, textAlign: 'center', bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
                            <Typography variant="h4" color="warning.main">{vulnHuntResult.targets_identified}</Typography>
                            <Typography variant="caption">Targets</Typography>
                          </Paper>
                        </Grid>
                        <Grid item xs={6} sm={3}>
                          <Paper sx={{ p: 2, textAlign: 'center', bgcolor: alpha(theme.palette.info.main, 0.1) }}>
                            <Typography variant="h4" color="info.main">{vulnHuntResult.total_functions_analyzed}</Typography>
                            <Typography variant="caption">Functions</Typography>
                          </Paper>
                        </Grid>
                      </Grid>

                      {/* Vulnerabilities List */}
                      {vulnHuntResult.vulnerabilities.length > 0 && (
                        <Box sx={{ mb: 3 }}>
                          <Typography variant="subtitle1" sx={{ mb: 2, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
                            <SecurityIcon color="error" /> Found Vulnerabilities
                          </Typography>
                          {vulnHuntResult.vulnerabilities.map((vuln: VulnerabilityFinding, idx: number) => (
                            <Accordion key={vuln.id || idx} sx={{ mb: 1 }}>
                              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                                  <Chip 
                                    label={vuln.severity.toUpperCase()} 
                                    size="small"
                                    sx={{ 
                                      bgcolor: getSeverityColor(vuln.severity),
                                      color: 'white',
                                      fontWeight: 600,
                                      minWidth: 70,
                                    }}
                                  />
                                  <Box sx={{ flex: 1 }}>
                                    <Typography variant="body2" fontWeight={600}>{vuln.title}</Typography>
                                    <Typography variant="caption" color="text.secondary">
                                      {vuln.function_name} @ {vuln.entry_address} | {vuln.category}
                                      {vuln.cwe_id && ` | ${vuln.cwe_id}`}
                                    </Typography>
                                  </Box>
                                  <Chip 
                                    label={`CVSS ~${vuln.cvss_estimate}`}
                                    size="small"
                                    variant="outlined"
                                    color={vuln.cvss_estimate >= 7 ? "error" : vuln.cvss_estimate >= 4 ? "warning" : "success"}
                                  />
                                </Box>
                              </AccordionSummary>
                              <AccordionDetails>
                                <Grid container spacing={2}>
                                  <Grid item xs={12}>
                                    <Typography variant="body2" sx={{ mb: 2 }}>{vuln.description}</Typography>
                                  </Grid>
                                  
                                  {vuln.technical_details && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" color="primary" gutterBottom>Technical Details</Typography>
                                      <Paper sx={{ p: 2, bgcolor: 'background.default' }}>
                                        <Typography variant="body2" component="pre" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                                          {vuln.technical_details}
                                        </Typography>
                                      </Paper>
                                    </Grid>
                                  )}
                                  
                                  {vuln.code_snippet && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" color="warning.main" gutterBottom>Vulnerable Code</Typography>
                                      <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
                                        <Typography variant="body2" component="pre" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                          {vuln.code_snippet}
                                        </Typography>
                                      </Paper>
                                    </Grid>
                                  )}
                                  
                                  {vuln.proof_of_concept && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" color="error" gutterBottom>Proof of Concept</Typography>
                                      <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.error.main, 0.1) }}>
                                        <Typography variant="body2" component="pre" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                          {vuln.proof_of_concept}
                                        </Typography>
                                      </Paper>
                                    </Grid>
                                  )}
                                  
                                  {vuln.exploitation_steps && vuln.exploitation_steps.length > 0 && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" color="error" gutterBottom>Exploitation Steps</Typography>
                                      <List dense>
                                        {vuln.exploitation_steps.map((step, i) => (
                                          <ListItem key={i}>
                                            <ListItemIcon sx={{ minWidth: 32 }}>
                                              <Typography variant="caption" color="error">{i + 1}.</Typography>
                                            </ListItemIcon>
                                            <ListItemText primary={step} primaryTypographyProps={{ variant: 'body2' }} />
                                          </ListItem>
                                        ))}
                                      </List>
                                    </Grid>
                                  )}
                                  
                                  {vuln.remediation && (
                                    <Grid item xs={12} md={6}>
                                      <Typography variant="subtitle2" color="success.main" gutterBottom>Remediation</Typography>
                                      <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.success.main, 0.1) }}>
                                        <Typography variant="body2">{vuln.remediation}</Typography>
                                      </Paper>
                                    </Grid>
                                  )}
                                  
                                  {vuln.ai_reasoning && (
                                    <Grid item xs={12}>
                                      <Typography variant="subtitle2" color="info.main" gutterBottom>AI Analysis Reasoning</Typography>
                                      <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                                        {vuln.ai_reasoning}
                                      </Typography>
                                    </Grid>
                                  )}
                                </Grid>
                              </AccordionDetails>
                            </Accordion>
                          ))}
                        </Box>
                      )}

                      {/* Recommended Focus Areas */}
                      {vulnHuntResult.recommended_focus_areas && vulnHuntResult.recommended_focus_areas.length > 0 && (
                        <Box>
                          <Typography variant="subtitle2" sx={{ mb: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
                            <InfoIcon color="info" /> Recommended Focus Areas
                          </Typography>
                          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                            {vulnHuntResult.recommended_focus_areas.map((area, idx) => (
                              <Chip key={idx} label={area} size="small" variant="outlined" />
                            ))}
                          </Box>
                        </Box>
                      )}
                    </Paper>
                  )}
                  
                  {/* Show notice for legitimate software with vuln hunt results */}
                  {vulnHuntResult && binaryResult?.is_legitimate_software && (
                    <Alert 
                      severity="info" 
                      sx={{ mt: 4 }}
                      action={
                        <Button size="small" onClick={() => setVulnHuntResult(null)}>
                          Dismiss
                        </Button>
                      }
                    >
                      <Typography variant="body2">
                        <strong>VulnHuntr Results Hidden:</strong> This binary was identified as legitimate software from a known publisher.
                        Automated vulnerability scanners often report false positives for legitimate software features like process creation,
                        registry access, and network communication. The {vulnHuntResult.vulnerabilities.length} findings were likely false positives.
                      </Typography>
                    </Alert>
                  )}
                </>
              )}
              {!binaryFile && !binaryResult && (
                <Box sx={{ textAlign: "center", py: 8, color: "text.secondary" }}>
                  <BinaryIcon sx={{ fontSize: 64, opacity: 0.3 }} />
                  <Typography variant="h6" sx={{ mt: 2 }}>
                    Upload a binary file to analyze
                  </Typography>
                  <Typography variant="body2">
                    Extract strings, imports, metadata, and detect secrets
                  </Typography>
                </Box>
              )}
            </Grid>
          </Grid>
        </TabPanel>

        {/* APK Tab - Unified Scanner */}
        <TabPanel value={activeTab} index={1}>
          <Alert 
            severity="info" 
            sx={{ mb: 3, bgcolor: alpha("#22c55e", 0.1) }}
            action={
              <Button 
                component={Link} 
                to="/learn/apk-analysis" 
                size="small" 
                startIcon={<SchoolIcon />}
                sx={{ color: "#22c55e" }}
              >
                Learning Guide
              </Button>
            }
          >
            <Typography variant="body2">
              <strong>New to APK analysis?</strong> Check out our comprehensive guide covering Android security, permissions, attack surfaces, and 40+ VRAgent analysis tools.
            </Typography>
          </Alert>
          {/* Scanner or Results */}
          {!unifiedApkResult ? (
            <UnifiedApkScanner
              apkFile={apkFile}
              onFileSelect={(f) => {
                setApkFile(f);
                setUnifiedApkResult(null);
                setUnifiedJadxSessionId(null);
                setAutoSavedReport(false);
              }}
              onScanComplete={(result) => {
                setUnifiedApkResult(result);
                // Auto-save the report
                if (result && apkFile) {
                  autoSaveUnifiedResult(result, apkFile.name);
                }
                // Also set legacy state for compatibility with save functions
                if (result) {
                  setApkResult({
                    filename: result.filename,
                    package_name: result.package_name,
                    version_name: result.version_name,
                    version_code: result.version_code,
                    min_sdk: result.min_sdk,
                    target_sdk: result.target_sdk,
                    permissions: result.permissions.map(p => ({ ...p })) as any,
                    dangerous_permissions_count: result.dangerous_permissions_count,
                    components: result.components as any,
                    strings_count: 0,
                    secrets: result.secrets as any,
                    urls: result.urls,
                    native_libraries: result.native_libraries,
                    security_issues: result.security_issues as any,
                    ai_analysis: undefined,
                    ai_report_functionality: result.ai_functionality_report,
                    ai_report_security: result.ai_security_report,
                    ai_architecture_diagram: result.ai_architecture_diagram,
                    activities: [],
                    services: [],
                    receivers: [],
                    providers: [],
                    uses_features: [],
                    debuggable: false,
                    allow_backup: false,
                  });
                }
              }}
              onJadxSessionReady={(sessionId) => {
                setUnifiedJadxSessionId(sessionId);
              }}
            />
          ) : (
            <Box>
              {/* Results Header with Actions */}
              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3, flexWrap: "wrap", gap: 2 }}>
                <Button
                  variant="outlined"
                  onClick={() => {
                    setUnifiedApkResult(null);
                    setUnifiedJadxSessionId(null);
                    setApkFile(null);
                    setApkResult(null);
                    setAutoSavedReport(false);
                  }}
                  startIcon={<RefreshIcon />}
                >
                  Analyze New APK
                </Button>
                <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
                  {autoSavedReport && (
                    <Chip 
                      icon={<CheckIcon />} 
                      label="Auto-saved" 
                      color="success" 
                      size="small" 
                      variant="outlined"
                    />
                  )}
                  <Button
                    variant="outlined"
                    color="primary"
                    startIcon={exportingUnified ? <CircularProgress size={20} /> : <DownloadIcon />}
                    onClick={(e) => setUnifiedExportAnchor(e.currentTarget)}
                    disabled={exportingUnified}
                  >
                    Export
                  </Button>
                  <Menu
                    anchorEl={unifiedExportAnchor}
                    open={Boolean(unifiedExportAnchor)}
                    onClose={() => setUnifiedExportAnchor(null)}
                  >
                    <MenuItem onClick={() => exportUnifiedApkResult("markdown")}>
                      📝 Export as Markdown
                    </MenuItem>
                    <MenuItem onClick={() => exportUnifiedApkResult("pdf")}>
                      📄 Export as PDF
                    </MenuItem>
                    <MenuItem onClick={() => exportUnifiedApkResult("docx")}>
                      📑 Export as Word
                    </MenuItem>
                  </Menu>
                  <Button
                    variant="contained"
                    color="success"
                    startIcon={savingReport ? <CircularProgress size={20} /> : <SaveIcon />}
                    onClick={saveApkReport}
                    disabled={savingReport}
                  >
                    {savingReport ? "Saving..." : "Save Again"}
                  </Button>
                </Box>
              </Box>
              
              {/* Unified Results */}
              <UnifiedApkResults
                result={unifiedApkResult}
                jadxSessionId={unifiedJadxSessionId}
                apkFile={apkFile}
                onBrowseSource={() => {
                  // Scroll to JADX browser section if needed
                  const jadxSection = document.getElementById("jadx-source-browser");
                  if (jadxSection) jadxSection.scrollIntoView({ behavior: "smooth" });
                }}
                onEnhancedSecurityComplete={(result) => setEnhancedSecurityResult(result)}
              />
              
              {/* JADX Source Browser - Now integrated */}
              {unifiedJadxSessionId && apkFile && (
                <Box id="jadx-source-browser" sx={{ mt: 4, scrollMarginTop: "80px" }}>
                  <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <CodeIcon color="primary" /> Browse Decompiled Source
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Navigate the decompiled Java source code • Search classes & methods • Analyze crypto usage
                  </Typography>
                  <JadxDecompiler 
                    apkFile={apkFile} 
                    onDecompilationComplete={(result) => setJadxResult(result)}
                    initialSessionId={unifiedJadxSessionId}
                    initialSourceTree={unifiedApkResult?.source_tree}
                    initialTotalClasses={unifiedApkResult?.total_classes}
                    initialTotalFiles={unifiedApkResult?.total_files}
                  />
                </Box>
              )}
            </Box>
          )}
        </TabPanel>

        {/* Docker Tab */}
        <TabPanel value={activeTab} index={2}>
          {!status?.docker_available ? (
            <Alert severity="warning">
              Docker is not available. Please install Docker to use this feature.
            </Alert>
          ) : (
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 3 }}>
                  <Typography variant="h6" gutterBottom>
                    Select Docker Image
                  </Typography>
                  <Autocomplete
                    options={dockerImages.map((img) => img.name)}
                    value={selectedImage}
                    onChange={(_, v) => {
                      setSelectedImage(v || "");
                      setDockerResult(null);
                    }}
                    freeSolo
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        label="Image Name"
                        placeholder="e.g., nginx:latest"
                        fullWidth
                      />
                    )}
                  />
                  <Button
                    variant="contained"
                    fullWidth
                    sx={{ mt: 2 }}
                    onClick={analyzeDocker}
                    disabled={dockerLoading || !selectedImage}
                    startIcon={dockerLoading ? <CircularProgress size={20} /> : <SecurityIcon />}
                  >
                    {dockerLoading ? "Analyzing..." : "Analyze Image"}
                  </Button>

                  <Divider sx={{ my: 3 }} />

                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="subtitle2">
                      Local Images ({filteredDockerImages.length}{dockerImageFilter ? ` of ${dockerImages.length}` : ""})
                    </Typography>
                    <Tooltip title="Refresh local images">
                      <IconButton
                        size="small"
                        onClick={refreshDockerImages}
                        disabled={dockerImagesLoading}
                      >
                        {dockerImagesLoading ? <CircularProgress size={18} /> : <RefreshIcon fontSize="small" />}
                      </IconButton>
                    </Tooltip>
                  </Box>

                  <TextField
                    size="small"
                    fullWidth
                    placeholder="Search local images..."
                    value={dockerImageFilter}
                    onChange={(e) => setDockerImageFilter(e.target.value)}
                    InputProps={{
                      startAdornment: <SearchIcon sx={{ mr: 1, color: "text.secondary" }} />,
                      endAdornment: dockerImageFilter && (
                        <IconButton size="small" onClick={() => setDockerImageFilter("")}>
                          <CloseIcon fontSize="small" />
                        </IconButton>
                      ),
                    }}
                    sx={{ mb: 1 }}
                  />

                  {dockerImagesLoading ? (
                    <Box sx={{ textAlign: "center", py: 3 }}>
                      <CircularProgress size={24} />
                      <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                        Scanning for Docker images...
                      </Typography>
                    </Box>
                  ) : filteredDockerImages.length === 0 ? (
                    <Box sx={{ textAlign: "center", py: 3, color: "text.secondary" }}>
                      <DockerIcon sx={{ fontSize: 32, opacity: 0.3 }} />
                      <Typography variant="body2" sx={{ mt: 1 }}>
                        {dockerImageFilter ? "No images match your search" : "No local Docker images found"}
                      </Typography>
                      {!dockerImageFilter && (
                        <Typography variant="caption">
                          Pull images with: docker pull &lt;image&gt;
                        </Typography>
                      )}
                    </Box>
                  ) : (
                    <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                      {filteredDockerImages.map((img, idx) => (
                        <ListItem
                          key={idx}
                          button
                          onClick={() => {
                            setSelectedImage(img.name);
                            setDockerResult(null);
                          }}
                          selected={selectedImage === img.name}
                          sx={{
                            borderRadius: 1,
                            mb: 0.5,
                            "&.Mui-selected": {
                              bgcolor: "primary.main",
                              color: "primary.contrastText",
                              "&:hover": { bgcolor: "primary.dark" },
                            },
                          }}
                        >
                          <ListItemIcon sx={{ minWidth: 36 }}>
                            <DockerIcon
                              fontSize="small"
                              sx={{ color: selectedImage === img.name ? "inherit" : "primary.main" }}
                            />
                          </ListItemIcon>
                          <ListItemText
                            primary={
                              <Typography
                                variant="body2"
                                sx={{
                                  fontFamily: "monospace",
                                  fontWeight: selectedImage === img.name ? 600 : 400,
                                }}
                              >
                                {img.name}
                              </Typography>
                            }
                            secondary={
                              <Typography
                                variant="caption"
                                sx={{ color: selectedImage === img.name ? "inherit" : "text.secondary" }}
                              >
                                {img.size} • ID: {img.id.slice(0, 12)}
                              </Typography>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  )}
                </Paper>
              </Grid>
              <Grid item xs={12} md={8}>
                {dockerLoading && (
                  <Box sx={{ textAlign: "center", py: 4 }}>
                    <CircularProgress />
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                      Analyzing Docker image layers...
                    </Typography>
                  </Box>
                )}
                {dockerResult && !dockerLoading && (
                  <>
                    <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 2 }}>
                      <Button
                        variant="contained"
                        color="success"
                        startIcon={savingReport ? <CircularProgress size={20} /> : <SaveIcon />}
                        onClick={saveDockerReport}
                        disabled={savingReport}
                      >
                        {savingReport ? "Saving..." : "Save Report"}
                      </Button>
                    </Box>
                    <DockerResults result={dockerResult} />
                  </>
                )}
                {!selectedImage && !dockerResult && (
                  <Box sx={{ textAlign: "center", py: 8, color: "text.secondary" }}>
                    <DockerIcon sx={{ fontSize: 64, opacity: 0.3 }} />
                    <Typography variant="h6" sx={{ mt: 2 }}>
                      Select a Docker image to analyze
                    </Typography>
                    <Typography variant="body2">
                      Inspect layers for secrets, credentials, and misconfigurations
                    </Typography>
                  </Box>
                )}
              </Grid>
            </Grid>
          )}
        </TabPanel>

        {/* Saved Reports Tab */}
        <TabPanel value={activeTab} index={3}>
          <Box sx={{ mb: 3, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <Typography variant="h6">
              Saved Analysis Reports
            </Typography>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={loadSavedReports}
              disabled={reportsLoading}
            >
              Refresh
            </Button>
          </Box>

          {reportsLoading && (
            <Box sx={{ textAlign: "center", py: 4 }}>
              <CircularProgress />
            </Box>
          )}

          {!reportsLoading && savedReports.length === 0 && (
            <Box sx={{ textAlign: "center", py: 8, color: "text.secondary" }}>
              <HistoryIcon sx={{ fontSize: 64, opacity: 0.3 }} />
              <Typography variant="h6" sx={{ mt: 2 }}>
                No saved reports yet
              </Typography>
              <Typography variant="body2">
                Analyze a binary, APK, or Docker image and save the report
              </Typography>
            </Box>
          )}

          {!reportsLoading && savedReports.length > 0 && (
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Title</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Risk Level</TableCell>
                    <TableCell>Date</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {savedReports.map((report) => (
                    <TableRow key={report.id} hover>
                      <TableCell>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          {report.analysis_type === 'binary' && <BinaryIcon fontSize="small" color="primary" />}
                          {report.analysis_type === 'apk' && <ApkIcon fontSize="small" color="success" />}
                          {report.analysis_type === 'docker' && <DockerIcon fontSize="small" color="info" />}
                          <Box>
                            <Typography variant="body2" fontWeight="medium">
                              {report.title}
                            </Typography>
                            {report.filename && (
                              <Typography variant="caption" color="text.secondary">
                                {report.filename}
                              </Typography>
                            )}
                          </Box>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={report.analysis_type.toUpperCase()}
                          size="small"
                          color={
                            report.analysis_type === 'binary' ? 'primary' :
                            report.analysis_type === 'apk' ? 'success' : 'info'
                          }
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>
                        {report.risk_level ? (
                          <Chip
                            label={report.risk_level}
                            size="small"
                            sx={{
                              bgcolor: alpha(getSeverityColor(report.risk_level), 0.2),
                              color: getSeverityColor(report.risk_level),
                              fontWeight: 600,
                            }}
                          />
                        ) : (
                          <Typography variant="body2" color="text.secondary">—</Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {new Date(report.created_at).toLocaleDateString()}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {new Date(report.created_at).toLocaleTimeString()}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
                          {viewingReportId === report.id && (
                            <Chip 
                              label="Viewing" 
                              size="small" 
                              color="success" 
                              sx={{ mr: 1 }}
                            />
                          )}
                          <Tooltip title="View Report">
                            <IconButton
                              size="small"
                              color="success"
                              onClick={() => viewSavedReport(report.id)}
                              disabled={loadingReportView}
                            >
                              {loadingReportView && viewingReportId === report.id ? (
                                <CircularProgress size={18} />
                              ) : (
                                <ViewIcon fontSize="small" />
                              )}
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Export to Markdown">
                            <IconButton
                              size="small"
                              color="primary"
                              onClick={() => exportSavedReport(report.id, 'markdown')}
                            >
                              <ArticleIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Export to PDF">
                            <IconButton
                              size="small"
                              color="primary"
                              onClick={() => exportSavedReport(report.id, 'pdf')}
                            >
                              <PdfIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Export to Word">
                            <IconButton
                              size="small"
                              color="primary"
                              onClick={() => exportSavedReport(report.id, 'docx')}
                            >
                              <WordIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Share to conversation">
                            <IconButton
                              size="small"
                              color="secondary"
                              onClick={() => {
                                setReportToShare(report);
                                setShareDialogOpen(true);
                              }}
                            >
                              <ShareIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete Report">
                            <IconButton
                              size="small"
                              color="error"
                              onClick={() => deleteReport(report.id)}
                            >
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </TabPanel>
      </Container>

      {/* Floating AI Chat Panel - appears when APK analysis is complete */}
      <ApkChatPanel
        unifiedScanResult={unifiedApkResult}
        selectedFinding={null}
        currentSourceCode={null}
        currentSourceClass={null}
      />

      {/* Guided Walkthrough Panel - helps users understand the analysis */}
      <GuidedWalkthrough
        unifiedScanResult={unifiedApkResult}
        onNavigateToTab={(tabIndex) => setActiveTab(tabIndex)}
      />

      {/* Share Report Dialog */}
      <ShareToConversationDialog
        open={shareDialogOpen}
        onClose={() => {
          setShareDialogOpen(false);
          setReportToShare(null);
        }}
        shareType="report"
        itemId={reportToShare?.id || 0}
        itemTitle={reportToShare?.title || 'RE Analysis Report'}
        itemSeverity={reportToShare?.risk_level}
        itemDetails={{
          type: reportToShare?.analysis_type ? `${reportToShare.analysis_type.toUpperCase()} Analysis` : undefined,
          filePath: reportToShare?.filename,
          projectName: 'Reverse Engineering Hub',
        }}
        onShareSuccess={() => {
          // Optionally show a success snackbar
        }}
      />

      {/* Bottom Navigation */}
      <Box sx={{ mt: 4, mb: 4, textAlign: "center" }}>
        <Button
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate("/learn")}
          sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
        >
          Back to Learning Hub
        </Button>
      </Box>
    </>
    </LearnPageLayout>
  );
}
